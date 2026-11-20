#!/usr/bin/env python3
"""
hybridstore.py - Phase II hybrid dedup + compression engine (prototype).

Pipeline per input file:
  1. Modality check on the file's first bytes, before any chunking (magic
     bytes). Media / already-compressed containers up to 64 MiB are stored as
     a single object; larger ones are chunked like everything else but packed
     separately and only probed with a fast codec.
  2. Everything else is cut with FastCDC-style content-defined chunking
     (256-entry gear table, normalized masks, min/avg/max sizes). Files are
     read as a stream in 8 MiB segments, so memory use does not grow with
     file size.
  3. Each chunk is keyed by its raw 32-byte SHA-256 digest. A hit in the
     dedup index writes only an 8-byte pointer into the file manifest.
  4. Unique chunks are appended to ~1 MiB "packs" that are compressed as one
     block (keeps cross-chunk context) with the best of zstd / zlib; if
     neither is strictly smaller, the pack is stored raw. With pack_target=0
     each chunk is its own block and a trained zstd dictionary is used.
  5. Every stored block has a 16-byte header:
        magic(3) 'HCB' | flags(1) | orig_len(u32) | stored_len(u32) | crc32(u32)
     crc32 is over the ORIGINAL bytes, so it checks the codec too.
  6. Each file also records its whole-file SHA-256; unpack/verify recompute
     it, so a restore is either bit-exact or it fails loudly.

Incremental backups: a store holds a chain of snapshots. `backup` appends new
packs plus a new manifest to an existing store; the manifest records the chunk
index entries it added, so the next run dedups against everything already
stored without re-reading it. Older snapshots are never rewritten.

The neural codec is an explicit stub (see NeuralCodec). It is off by default
because a learned image codec is lossy and the project goal is integrity.

Usage:
  python hybridstore.py pack   <input_dir> <store_file>       new store (overwrites)
  python hybridstore.py backup <input_dir> <store_file>       add a snapshot (creates if missing)
  python hybridstore.py list   <store_file> [--skipped]
  python hybridstore.py unpack <store_file> <output_dir> [--snapshot N] [--force]
  python hybridstore.py verify <store_file> [--allow-partial]
  python hybridstore.py repair <store_file>                    fix damaged footers (loses nothing)
  python hybridstore.py prune  <store_file> [--remove N ...] [--keep-last N] [--keep-daily N]
                               [--keep-weekly N] [--keep-monthly N] [--dry-run]

Exit codes: 0 ok, 1 integrity error, 2 refused (would overwrite data; see --force),
3 finished with warnings (items skipped or changed while read / symlinks not
restored), 4 store locked by another backup. Format: FORMAT.md.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import socket
import stat
import struct
import sys
import threading
import time
import traceback
import zlib
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import numpy as np

try:
    import zstandard as zstd  # optional
except ImportError:  # pragma: no cover
    zstd = None

# --------------------------------------------------------------------------
# Binary layout
# --------------------------------------------------------------------------
STORE_MAGIC = b"HCSTORE1"           # 8-byte file signature (also ends every footer)
FOOTER = struct.Struct("<Q8s")      # manifest offset, magic
BLOCK_MAGIC = b"HCB"
HDR = struct.Struct("<3sBIII")      # 16 bytes
assert HDR.size == 16
MANIFEST_V2 = b"HCM2"               # snapshot manifests; v1 manifests have no magic
MANIFEST_V3 = b"HCM3"               # v2 + per-entry metadata (kind, mtime, mode, attrs) + skipped list

CODEC_RAW, CODEC_ZLIB, CODEC_ZSTD, CODEC_NEURAL = 0, 1, 2, 3
CODEC_MASK = 0x07
FLAG_MEDIA = 0x08                   # payload is media / already-compressed data
FLAG_MANIFEST = 0x10                # block holds a manifest
FLAG_DICT = 0x20                    # block holds the trained zstd dictionary
FLAG_USES_DICT = 0x40               # zstd payload was coded with the dictionary
FLAG_ENCRYPTED = 0x80               # payload = 12-byte nonce | ChaCha20-Poly1305 ciphertext | 16-byte tag
CODEC_KEYS = 7                      # the key block of an encrypted store (right after STORE_MAGIC)
CODEC_NAMES = {0: "raw", 1: "zlib", 2: "zstd", 3: "neural"}

SEGMENT = 8 << 20                   # streaming read size
WHOLE_MEDIA_MAX = 64 << 20          # media up to this size is stored as one object
HASH_PIECE = 1 << 20                # per-thread piece when hashing a large segment
PREP_MAX = 8 << 20                  # files up to this size are read+chunked in worker threads
# Decompression limit: a block may expand to at most max(BLOCK_FLOOR, BLOCK_RATIO x its
# stored size). Real packs are ~1 MiB and media objects <= 64 MiB, so this only stops
# hostile or corrupt headers from making the reader allocate gigabytes.
BLOCK_FLOOR = 256 << 20
BLOCK_RATIO = 256
# A file is only reused by size + mtime if its mtime is at least this much older
# than the snapshot that read it (covers coarse filesystem timestamps, e.g. FAT's 2 s).
RACY_NS = 3_000_000_000

# Entry kinds (manifest v3)
KIND_FILE, KIND_DIR, KIND_LINK, KIND_DIRLINK = 0, 1, 2, 3
# Windows attributes that are restored (read-only, hidden, system, archive, not-indexed)
WIN_ATTR_KEEP = 0x1 | 0x2 | 0x4 | 0x20 | 0x2000
WIN_ATTR_NORMAL = 0x80
# Offline | recall-on-open | recall-on-data-access: OneDrive / cloud placeholders
CLOUD_ATTRS = 0x1000 | 0x40000 | 0x400000


class IntegrityError(Exception):
    pass


class PasswordError(IntegrityError):
    """The store is encrypted and no (or a wrong) password was given."""


# --------------------------------------------------------------------------
# Encryption. An encrypted store has a key block right after STORE_MAGIC:
#     'HCK1' | u8 kdf (1 = scrypt) | u8 log2 N | u8 r | u8 p | 16-byte salt
#     | 12-byte nonce | 48 bytes: the 32-byte data key sealed with
#       ChaCha20-Poly1305 under scrypt(password, salt), AAD = the 24 bytes before the nonce
# Every other block (dictionary, packs, manifests) is compressed first, then
# sealed with the data key: payload = nonce | ciphertext | tag, AAD = the first
# 12 header bytes (magic, flags, original length, stored length). The header's
# crc32 then covers the sealed payload, so damage can be told apart from a
# wrong key and located without the password. Block headers, footers and the
# store size stay readable: an observer learns block sizes and the number of
# snapshots, not names, contents or chunk hashes.
# --------------------------------------------------------------------------
KEY_MAGIC = b"HCK1"
KEY_BLOCK = struct.Struct("<4sBBBB16s12s48s")
SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P = 17, 8, 1          # 128 MiB, ~0.5 s per unlock (OWASP minimum)
SEAL_PAD = 4096                                       # sealed plaintext is padded to a multiple of this
# Random 96-bit nonces are safe for 2^32 messages per key (NIST SP 800-38D); stop
# well before that. At ~1 MiB per pack this is far beyond any real store.
MAX_SEALED_BLOCKS = 1 << 30
PASSWORD_ENV = "HYBRIDSTORE_PASSWORD"
_password: str | None = None
_prompt_ok = False                                    # the CLI turns this on; the library never prompts
_KEYS: dict[bytes, bytes] = {}                        # sha256(key block) -> data key, unlocked this process


def set_password(pw: str | None):
    """Password for encrypted stores opened or created by this process."""
    global _password
    _password = pw


def _interactive() -> bool:
    """True only for a real terminal. On Windows `NUL` and some pipes report
    isatty() == True, and getpass would then wait on the console forever."""
    try:
        if not (sys.stdin and sys.stdin.isatty()):
            return False
        if os.name == "nt":
            import ctypes, msvcrt
            mode = ctypes.c_uint32()
            return bool(ctypes.windll.kernel32.GetConsoleMode(msvcrt.get_osfhandle(sys.stdin.fileno()),
                                                              ctypes.byref(mode)))
        return True
    except (OSError, ValueError, AttributeError):
        return False


def _password_for(prompt: str, confirm: bool = False) -> str | None:
    global _password
    if _password is None and os.environ.get(PASSWORD_ENV):
        return os.environ[PASSWORD_ENV]
    if _password is None and _prompt_ok and _interactive():
        import getpass
        pw = getpass.getpass(prompt)
        if confirm and getpass.getpass("repeat the password: ") != pw:
            raise PasswordError("the two passwords differ")
        _password = pw
    return _password


def _aead(key: bytes):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError as e:
        raise IntegrityError("encrypted stores need the 'cryptography' package: pip install cryptography") from e
    return ChaCha20Poly1305(key)


def _kek(password: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=1 << log_n, r=r, p=p,
                          maxmem=(128 * r << log_n) + (64 << 20), dklen=32)


def make_key_block(password: str, key: bytes | None = None) -> tuple[bytes, bytes]:
    """A new key block (header + payload) sealing `key` (default: a fresh
    random data key) under `password`. Returns (block, key)."""
    if not password:
        raise PasswordError("an empty password is not allowed")
    key = key or os.urandom(32)
    salt, nonce = os.urandom(16), os.urandom(12)
    head = KEY_MAGIC + bytes([1, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P]) + salt
    wrapped = _aead(_kek(password, salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)).encrypt(nonce, key, head)
    payload = head + nonce + wrapped
    _KEYS[hashlib.sha256(payload).digest()] = key
    hdr = HDR.pack(BLOCK_MAGIC, CODEC_KEYS, len(payload), len(payload), zlib.crc32(payload) & 0xFFFFFFFF)
    return hdr + payload, key


def open_key_block(payload: bytes, password: str | None = None) -> bytes:
    """The data key sealed in a key block's payload."""
    if len(payload) != KEY_BLOCK.size:
        raise IntegrityError("the key block has the wrong size")
    magic, kdf, log_n, r, p, salt, nonce, wrapped = KEY_BLOCK.unpack(payload)
    # Bounded so a hostile key block cannot make us allocate gigabytes (RFC 7914 section 2).
    if magic != KEY_MAGIC or kdf != 1 or not (14 <= log_n <= 20 and 1 <= r <= 16 and 1 <= p <= 4):
        raise IntegrityError("the key block is damaged or of an unknown kind")
    cached = _KEYS.get(hashlib.sha256(payload).digest())
    if cached is not None:
        return cached
    pw = password if password is not None else _password_for("store password: ")
    if pw is None:
        raise PasswordError(f"this store is encrypted: give its password (--password-file FILE, the "
                            f"{PASSWORD_ENV} environment variable, or type it when asked)")
    try:
        from cryptography.exceptions import InvalidTag
    except ImportError:
        InvalidTag = ValueError
    try:
        key = _aead(_kek(pw, salt, log_n, r, p)).decrypt(nonce, wrapped, payload[:24])
    except InvalidTag:
        raise PasswordError("wrong password (or a damaged key block: `repair` rebuilds it if the store "
                            "has parity)") from None
    _KEYS[hashlib.sha256(payload).digest()] = key
    return key


# --------------------------------------------------------------------------
# Encryption pins. Nothing inside a store can prove it was not swapped for an
# unencrypted one (a stripped key block, or a whole new file), so this computer
# remembers each store it has opened or created encrypted, as an empty marker
# file named after the store's path, and refuses to read it unencrypted later.
# Creating an unencrypted store at that path (pack without --encrypt) is the
# owner's choice and clears the pin. HYBRIDSTORE_STATE=<dir> moves the markers,
# HYBRIDSTORE_STATE=off turns pins off. Markers hold no names or secrets.
# --------------------------------------------------------------------------
STATE_ENV = "HYBRIDSTORE_STATE"
_password_named = False             # the CLI was given --password-file for this one store


def _pin_path(store: str) -> str | None:
    d = os.environ.get(STATE_ENV)
    if d is not None and d.strip().lower() in ("", "off", "0", "none"):
        return None
    if d is None:
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "state")
        d = os.path.join(base, "hybridstore")
    key = os.path.normcase(os.path.realpath(os.path.abspath(store)))
    return os.path.join(d, "encrypted-stores", hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest())


def _pinned(store: str) -> str | None:
    """The marker's path when `store` was last seen encrypted on this computer."""
    p = _pin_path(store)
    return p if p and os.path.exists(p) else None


def _set_pin(store: str, encrypted: bool) -> None:
    """Record (or clear) that `store` is encrypted. Best effort: never raises."""
    p = _pin_path(store)
    if not p:
        return
    try:
        if encrypted:
            if not os.path.exists(p):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "ab").close()
        elif os.path.exists(p):
            os.remove(p)
    except OSError:
        pass


class StoreLockedError(Exception):
    """Another process (or another writer in this process) is writing the store."""


class RestoreConflictError(Exception):
    """unpack would overwrite existing files and overwrite=False."""

    def __init__(self, conflicts: list[str]):
        self.conflicts = conflicts
        more = f" (and {len(conflicts) - 5} more)" if len(conflicts) > 5 else ""
        super().__init__(f"{len(conflicts)} item(s) already exist in the output folder and would be "
                         f"overwritten: {', '.join(conflicts[:5])}{more}. Nothing was written. Restore into "
                         f"an empty folder, or pass overwrite=True / --force to replace them")


class RestoreSpaceError(ValueError):
    """The snapshot's files do not fit in the free space of the output disk."""


class _StoreLock:
    """Exclusive OS lock on '<store>.lock', held for the whole write. The OS
    drops it if the process dies, so a crash never leaves a stale lock."""

    REGION = 1 << 20     # lock a byte past the info text, so other processes can still read it

    def __init__(self, store_path: str):
        self.path = store_path + ".lock"
        while True:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o644)
            try:
                self._lock(fd)
            except OSError:
                try:
                    os.lseek(fd, 0, 0)
                    holder = os.read(fd, 300).decode("utf-8", "replace").strip()
                except OSError:
                    holder = ""
                os.close(fd)
                raise StoreLockedError(f"{store_path} is being written by another backup"
                                       + (f" ({holder})" if holder else "")) from None
            try:   # the previous holder may have deleted the file between our open and lock
                same = os.path.samestat(os.fstat(fd), os.stat(self.path))
            except OSError:
                same = False
            if same:
                break
            self._unlock(fd); os.close(fd)
        os.lseek(fd, 0, 0); os.ftruncate(fd, 0)
        os.write(fd, f"pid {os.getpid()} on {socket.gethostname()} since "
                     f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n".encode())
        self.fd = fd

    def _lock(self, fd):
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, self.REGION, 0)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(self, fd):
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, self.REGION, 0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass

    def release(self):
        if self.fd is None:
            return
        fd, self.fd = self.fd, None
        if os.name == "nt":
            self._unlock(fd); os.close(fd)
            try:
                os.remove(self.path)       # fails harmlessly if another process has it open
            except OSError:
                pass
        else:
            try:
                os.remove(self.path)       # unlink while still locked: no window for a second holder
            except OSError:
                pass
            self._unlock(fd); os.close(fd)


# --------------------------------------------------------------------------
# FastCDC chunker (gear hash, normalized chunking)
# --------------------------------------------------------------------------
def _gear_table() -> np.ndarray:
    # Deterministic 256 x 64-bit table derived from SHA-256, so chunk
    # boundaries are reproducible across machines and runs.
    vals = [int.from_bytes(hashlib.sha256(b"gear" + bytes([i])).digest()[:8], "little")
            for i in range(256)]
    return np.array(vals, dtype=np.uint64)


GEAR = _gear_table()


def _top_mask(bits: int) -> int:
    # Use the HIGH bits of the gear hash: with h = (h << 1) + G[b], bit k
    # depends on only the last k+1 bytes, so low bits are weak boundary tests.
    return ((1 << bits) - 1) << (64 - bits)


class FastCDC:
    """Content-defined chunker.

    The gear hash h_i = sum_{k=0..63} G[b_{i-k}] << k  (mod 2^64) is exactly
    what the classic rolling update h = (h << 1) + G[b] produces once 64 bytes
    have been seen; because of the shift it only depends on the last 64 bytes.
    That lets us compute it for every position with 64 vectorized numpy
    passes instead of a per-byte Python loop. Boundary selection then follows
    FastCDC normalized chunking: a stricter mask before the average size, a
    looser one after it, and hard min/max limits.

    Streaming: a boundary is only tested at least min_size (>= 64) bytes past
    the start of the current chunk, so its hash never needs bytes from before
    that chunk. Hashing a buffer that starts at a chunk boundary therefore
    gives exactly the same cuts as hashing the whole file at once.
    """

    def __init__(self, min_size=2048, avg_size=8192, max_size=65536, norm_level=2):
        assert min_size >= 64 and min_size < avg_size < max_size
        self.min_size, self.avg_size, self.max_size = min_size, avg_size, max_size
        bits = avg_size.bit_length() - 1
        self.mask_s = np.uint64(_top_mask(bits + norm_level))  # harder to match
        self.mask_l = np.uint64(_top_mask(bits - norm_level))  # easier to match

    @staticmethod
    def _gear_hash(buf) -> np.ndarray:
        """Gear hash at every position of buf (bytes before buf count as 0).
        Doubling: with H_m[i] = sum_{k<m} G[b_{i-k}] << k,
        H_2m[i] = H_m[i] + (H_m[i-m] << m), so 6 passes give H_64."""
        h = GEAR[np.frombuffer(buf, dtype=np.uint8)]
        t = np.empty_like(h)
        m = 1
        with np.errstate(over="ignore"):
            while m < 64:
                t[:m] = h[:m]
                np.left_shift(h[:-m], np.uint64(m), out=t[m:])
                np.add(t[m:], h[m:], out=t[m:])
                h, t = t, h
                m <<= 1
        return h

    def _hashes(self, data) -> np.ndarray:
        return self._gear_hash(data)

    def _candidates(self, data, pool=None) -> tuple[np.ndarray, np.ndarray]:
        """Positions whose hash passes the strict / loose mask. With a thread
        pool, large buffers are split into pieces (each re-reads the 63 bytes
        before it, so the result is identical); numpy releases the GIL."""
        n = len(data)

        def piece(p, q):
            s = max(0, p - 63)
            h = self._gear_hash(mv[s:q])[p - s:]
            cl = np.flatnonzero((h & self.mask_l) == 0)
            cs = cl[(h[cl] & self.mask_s) == 0]   # strict mask bits include the loose ones
            return cs + p, cl + p

        with memoryview(data) as mv:
            if pool is None or n < 2 * HASH_PIECE:
                return piece(0, n)
            parts = list(pool.map(lambda p: piece(p, min(p + HASH_PIECE, n)), range(0, n, HASH_PIECE)))
        return (np.concatenate([a for a, _ in parts]), np.concatenate([b for _, b in parts]))

    def _cuts(self, data, final: bool, pool=None) -> list[int]:
        """Cut points in `data` (which must start at a chunk boundary). With
        final=False, stop at the first chunk whose end could still depend on
        bytes not yet read."""
        n = len(data)
        if n == 0 or (not final and self.max_size > n):
            return []
        if n <= self.min_size:
            return [n]
        cand_s, cand_l = self._candidates(data, pool)
        cuts, start = [], 0
        while start < n:
            if not final and start + self.max_size > n:
                break
            if n - start <= self.min_size:
                cuts.append(n)
                break
            lo = start + self.min_size          # first eligible position
            mid = start + self.avg_size
            hi = min(start + self.max_size, n)
            # Region 1: [lo, mid) with the strict mask
            i = np.searchsorted(cand_s, lo)
            if i < len(cand_s) and cand_s[i] < min(mid, hi):
                cut = int(cand_s[i]) + 1
            else:
                # Region 2: [mid, hi) with the loose mask
                j = np.searchsorted(cand_l, min(mid, hi))
                if j < len(cand_l) and cand_l[j] < hi:
                    cut = int(cand_l[j]) + 1
                else:
                    cut = hi
            cuts.append(cut)
            start = cut
        return cuts

    def cut_points(self, data: bytes) -> list[int]:
        return self._cuts(data, final=True)

    def chunks(self, data: bytes):
        start = 0
        for end in self.cut_points(data):
            yield data[start:end]
            start = end

    def stream_chunks(self, f, segment: int = SEGMENT, pool=None):
        """Yield chunks from a binary file object, holding at most about
        segment + max_size bytes in memory. `pool` (optional) parallelises
        the hashing of each segment; never pass a pool from inside one of
        its own worker threads."""
        buf = bytearray()
        eof = False
        while not eof:
            data = f.read(segment)
            if data:
                buf += data
            else:
                eof = True
            start = 0
            for end in self._cuts(buf, final=eof, pool=pool):
                yield bytes(buf[start:end])
                start = end
            del buf[:start]


class _HashingReader:
    """Wraps a binary file; tracks SHA-256 and byte count of what was read."""

    def __init__(self, f):
        self.f, self.sha, self.size = f, hashlib.sha256(), 0

    def read(self, n=-1):
        d = self.f.read(n)
        self.sha.update(d)
        self.size += len(d)
        return d


# --------------------------------------------------------------------------
# Modality detection (done on the file's first bytes, BEFORE chunking)
# --------------------------------------------------------------------------
_MEDIA_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"), (b"BM", "bmp"),
    (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"),
    (b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x28\xb5\x2f\xfd", "zstd"), (b"%PDF", "pdf"),
]


def detect_modality(data: bytes) -> str | None:
    """Return a media/container type name, or None for generic bytes.
    Only the first 16 bytes are needed."""
    if data[:4] == b"RIFF" and data[8:12] in (b"WEBP", b"WAVE", b"AVI "):
        return data[8:12].decode().strip().lower()
    if data[4:8] == b"ftyp":
        return "mp4"
    for magic, name in _MEDIA_MAGIC:
        if data.startswith(magic):
            return name
    return None


IMAGE_TYPES = {"png", "jpeg", "gif", "webp"}
# Detected, but usually uncompressed (PCM audio, bitmaps): route them like
# generic data so they get chunked and fully compressed. "BM" is also only a
# 2-byte magic, so treating it as media misrouted ordinary files.
UNCOMPRESSED_TYPES = {"wave", "bmp", "tiff"}


def media_kind(head: bytes) -> str | None:
    """Modality used for routing: None means chunk + compress normally."""
    kind = detect_modality(head)
    return None if kind in UNCOMPRESSED_TYPES else kind


def dhash64(data: bytes) -> int | None:
    """64-bit difference hash for near-duplicate detection (needs Pillow)."""
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data)).convert("L").resize((9, 8))
        px = np.asarray(im, dtype=np.int16)
        bits = (px[:, 1:] > px[:, :-1]).flatten()
        return int("".join("1" if b else "0" for b in bits), 2)
    except Exception:
        return None


# --------------------------------------------------------------------------
# Codecs
# --------------------------------------------------------------------------
class NeuralCodec:
    """STUB. A learned image codec (e.g. a CompressAI scale-hyperprior model)
    would plug in here. It is deliberately not implemented: such codecs are
    lossy, need PyTorch + model weights, and cannot satisfy the bit-exact
    round-trip this store guarantees. A real integration would have to store
    either the original or a lossless residual next to the latents."""

    enabled = False

    def encode(self, data: bytes) -> bytes:
        raise NotImplementedError("neural codec is a stub; see class docstring")

    def decode(self, payload: bytes, orig_len: int) -> bytes:
        raise NotImplementedError("neural codec is a stub; see class docstring")


class BlockCodec:
    def __init__(self, zstd_level=19, zlib_level: int | None = None, media_zstd_level=3):
        """Default: one zstd pass. zlib_level adds zlib as a second candidate
        (it almost never beats zstd at 19 and costs ~3x zstd-19's time on top);
        without zstandard installed, zlib-9 is used. Media blocks are only
        probed with a fast zstd level, since they are almost always
        incompressible. encode() is safe to call from several threads: each
        thread gets its own compressor objects."""
        self.zstd_level = zstd_level
        self.media_zstd_level = media_zstd_level
        self.zlib_level = zlib_level if zlib_level is not None else (9 if zstd is None else None)
        self.zd = zstd.ZstdDecompressor() if zstd else None
        self._dict = self.zd_dict = None
        self._tls = threading.local()
        self.neural = NeuralCodec()
        self.cipher = None              # ChaCha20Poly1305 when the store is encrypted

    def set_key(self, key: bytes | None):
        self.cipher = _aead(key) if key else None

    def _compressors(self):
        c = getattr(self._tls, "c", None)
        if c is None or c[3] is not self._dict:
            zc = zstd.ZstdCompressor(level=self.zstd_level) if zstd else None
            zm = zstd.ZstdCompressor(level=self.media_zstd_level) if zstd else None
            zdc = zstd.ZstdCompressor(level=self.zstd_level, dict_data=self._dict) if self._dict else None
            c = self._tls.c = (zc, zm, zdc, self._dict)
        return c

    def set_dictionary(self, dict_bytes: bytes):
        """Small chunks lose the cross-chunk context a whole-stream compressor
        sees. A shared zstd dictionary trained on sample chunks restores much
        of it while keeping every chunk independently decodable."""
        if zstd is None:
            raise IntegrityError("store uses a zstd dictionary but zstandard is not installed")
        d = zstd.ZstdCompressionDict(dict_bytes)
        d.precompute_compress(level=self.zstd_level)
        self._dict = d
        self.zd_dict = zstd.ZstdDecompressor(dict_data=d)

    def encode(self, data: bytes, flags: int = 0) -> tuple[bytes, dict]:
        """Return (header + payload, info). Picks the smallest candidate and
        falls back to raw unless compression is strictly smaller."""
        best_codec, best = CODEC_RAW, data
        zc, zm, zdc, _ = self._compressors()
        candidates = []
        if flags & FLAG_MEDIA:
            if zm:
                candidates.append((CODEC_ZSTD, lambda: zm.compress(data)))
            else:
                candidates.append((CODEC_ZLIB, lambda: zlib.compress(data, 1)))
        else:
            if self.zlib_level is not None:
                candidates.append((CODEC_ZLIB, lambda: zlib.compress(data, self.zlib_level)))
            if zc:
                candidates.append((CODEC_ZSTD, lambda: zc.compress(data)))
            if zdc and not flags & (FLAG_MANIFEST | FLAG_DICT):
                candidates.append((CODEC_ZSTD | FLAG_USES_DICT, lambda: zdc.compress(data)))
        for codec, fn in candidates:
            out = fn()
            if len(out) < len(best):
                best_codec, best = codec, out
        flags |= best_codec
        olen = len(data)
        if self.cipher is not None:
            # Sealed: u32 orig_len | compressed | zero padding, so neither the plaintext
            # size nor the exact compressed size shows in the clear (the header's
            # orig_len is 0). Matters for media files, which are stored one per block.
            flags |= FLAG_ENCRYPTED
            inner = struct.pack("<II", olen, len(best)) + best
            inner += b"\0" * (-len(inner) % SEAL_PAD)
            nonce = os.urandom(12)
            aad = HDR.pack(BLOCK_MAGIC, flags, 0, 12 + len(inner) + 16, 0)[:12]
            best = nonce + self.cipher.encrypt(nonce, inner, aad)
            crc = zlib.crc32(best) & 0xFFFFFFFF
            olen = 0
        else:
            crc = zlib.crc32(data) & 0xFFFFFFFF
        hdr = HDR.pack(BLOCK_MAGIC, flags, olen, len(best), crc)
        return hdr + best, {"codec": best_codec & CODEC_MASK, "dict": bool(best_codec & FLAG_USES_DICT),
                            "raw_fallback": best_codec == CODEC_RAW}

    def decode_block(self, hdr: bytes, payload: bytes, off: int) -> tuple[bytes, int]:
        """Decode one block given its 16 header bytes and payload."""
        magic, flags, olen, slen, crc = HDR.unpack(hdr)
        if magic != BLOCK_MAGIC:
            raise IntegrityError(f"bad block magic at {off}")
        if len(payload) != slen:
            raise IntegrityError(f"truncated payload at {off}")
        if olen > max(BLOCK_FLOOR, BLOCK_RATIO * slen):
            raise IntegrityError(f"block at {off} claims an implausible size ({olen:,} bytes from {slen:,})")
        sealed = bool(flags & FLAG_ENCRYPTED)
        if not sealed and self.cipher is not None:
            # Every block of an encrypted store is sealed. An unsealed one was not written
            # by someone holding the key: reading it would let anyone add snapshots.
            raise IntegrityError(f"block at {off} is not encrypted, but this store is: it was not written "
                                 f"with the store's key (added or altered by someone else)")
        if sealed:
            if zlib.crc32(payload) & 0xFFFFFFFF != crc:
                raise IntegrityError(f"CRC mismatch in encrypted block at {off} (damaged on disk)")
            if self.cipher is None:
                raise PasswordError(f"block at {off} is encrypted and no key is loaded")
            if slen < 28:
                raise IntegrityError(f"encrypted block at {off} is too short")
            try:
                inner = self.cipher.decrypt(payload[:12], payload[12:], hdr[:12])
            except Exception:
                raise IntegrityError(f"encrypted block at {off} failed authentication (altered, "
                                     f"or sealed with another key; repeated failures on intact "
                                     f"CRCs can also mean bad RAM)") from None
            olen, clen = struct.unpack_from("<II", inner)
            payload = inner[8:8 + clen]
            if len(payload) != clen:
                raise IntegrityError(f"encrypted block at {off} is malformed")
            if olen > max(BLOCK_FLOOR, BLOCK_RATIO * slen):
                raise IntegrityError(f"block at {off} claims an implausible size ({olen:,} bytes)")
            if flags & CODEC_MASK == CODEC_RAW:
                payload = payload[:olen]
        codec = flags & CODEC_MASK
        try:
            if codec == CODEC_RAW:
                data = payload
            elif codec == CODEC_ZLIB:
                # Bounded: never produce more than the header's length.
                d = zlib.decompressobj()
                data = d.decompress(payload, max(olen, 1))
                if d.unconsumed_tail or not d.eof:
                    raise IntegrityError(f"zlib stream at {off} is longer than its header says")
            elif codec == CODEC_ZSTD:
                if not self.zd:
                    raise IntegrityError("zstd block but zstandard not installed")
                dec = self.zd
                if flags & FLAG_USES_DICT:
                    if not self.zd_dict:
                        raise IntegrityError(f"dictionary block missing for {off}")
                    dec = self.zd_dict
                data = dec.decompress(payload, max_output_size=olen)
            elif codec == CODEC_NEURAL:
                data = self.neural.decode(payload, olen)
            else:
                raise IntegrityError(f"unknown codec {codec} at {off}")
        except IntegrityError:
            raise
        except Exception as e:
            raise IntegrityError(f"decode failed at {off}: {e}") from e
        if len(data) != olen or (not sealed and (zlib.crc32(data) & 0xFFFFFFFF) != crc):
            raise IntegrityError(f"CRC/length mismatch in block at {off}")
        return data, flags

    def decode_at(self, buf, off: int) -> tuple[bytes, int, int]:
        """Decode the block at `off` in an in-memory buffer.
        Returns (data, flags, next_offset)."""
        if off + HDR.size > len(buf):
            raise IntegrityError(f"truncated header at {off}")
        slen = HDR.unpack_from(buf, off)[3]
        p0 = off + HDR.size
        if p0 + slen > len(buf):
            raise IntegrityError(f"truncated payload at {off}")
        data, flags = self.decode_block(bytes(buf[off:p0]), bytes(buf[p0:p0 + slen]), off)
        return data, flags, p0 + slen


# --------------------------------------------------------------------------
# Store layout
#
# Store file:  STORE_MAGIC | [dict block] | snapshot 1 | snapshot 2 | ...
# Snapshot:    pack blocks ... | manifest block | footer(manifest offset, STORE_MAGIC)
# The newest footer is the last 16 bytes of the file. Earlier footers stay in
# place (16 unused bytes each), so an interrupted append can be recovered by
# scanning back to the last complete one.
#
# A "pack" is one 16-byte-header block whose (decoded) payload is
#     u32 count | count x u32 chunk lengths | chunk bytes ...
# A chunk is addressed by an 8-byte pointer: (pack_id << 20) | index_in_pack.
# Pack ids are global across all snapshots in the store.
#
# v2 manifest payload:
#     'HCM2' | u64 prev_manifest_offset (0 = first) | u64 unix time
#     | u16 len + label (utf-8)
#     | u32 first_pack_id | u32 n_new_packs | n x u64 pack offsets
#     | u32 n_index | n x 32-byte digest | n x u64 pointer   (chunks added here)
#     | u32 n_files | per file: u16 len + path (utf-8, '/' separated)
#                               | u64 size | 32-byte sha256 | u32 n | n x u64 ptr
# v3 manifest ('HCM3', written by this version): as v2 up to n_files, then
#     per entry: u16 len + path | u8 kind | u64 size | 32-byte sha256
#                | i64 mtime_ns (-1 = unknown) | u32 st_mode | u32 windows attrs
#                | u32 n | n x u64 ptr
#     | u32 n_skipped | per skipped: u16 len + path | u16 len + reason (utf-8)
#   kind: 0 file, 1 directory (no data), 2 symlink, 3 directory symlink; a
#   symlink's "content" is its target path in utf-8.
# v1 manifests (older stores) start directly with u32 n_packs and have no
# index; appending to one rebuilds the index by hashing its chunks once.
# See FORMAT.md for the full specification.
# --------------------------------------------------------------------------
PTR_SHIFT = 20
PTR_IDX_MASK = (1 << PTR_SHIFT) - 1
_ENTRY3 = struct.Struct("<BQ32sqIII")   # kind, size, sha256, mtime_ns, mode, attrs, n_ptrs


@dataclass
class FileEntry:
    path: str
    size: int
    sha256: bytes
    pointers: list[int] = field(default_factory=list)  # 8-byte chunk pointers
    kind: int = KIND_FILE
    mtime_ns: int = -1          # -1: not recorded (v1/v2 stores, add_file())
    mode: int = 0               # st_mode; 0 = not recorded
    attrs: int = 0              # Windows file attributes; 0 = not recorded


EMPTY_SHA = hashlib.sha256(b"").digest()


@dataclass
class Snapshot:
    offset: int                 # manifest block offset
    version: int
    prev: int
    created: int
    label: str
    first_pack: int
    packs: list[int]            # offsets of packs added by this snapshot
    entries: list[FileEntry]
    index_digests: bytes = b""  # 32 * n
    index_ptrs: list[int] = field(default_factory=list)
    block_end: int = 0          # end of the manifest block (footer follows)
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (path, reason), v3
    damaged: str = ""           # non-empty: the manifest could not be read; entries are lost

    @property
    def input_bytes(self) -> int:
        return sum(e.size for e in self.entries if e.kind == KIND_FILE)

    @property
    def files(self) -> list[FileEntry]:
        return [e for e in self.entries if e.kind == KIND_FILE]


@dataclass
class Stats:
    files: int = 0
    input_bytes: int = 0
    chunks_total: int = 0
    chunks_unique: int = 0
    dedup_bytes: int = 0
    media_files: int = 0
    packs: int = 0
    raw_fallback_blocks: int = 0
    raw_fallback_bytes: int = 0
    codec_counts: dict = field(default_factory=lambda: {n: 0 for n in CODEC_NAMES.values()})
    near_dup_images: int = 0
    dict_blocks: int = 0
    dict_bytes: int = 0
    store_bytes: int = 0
    manifest_bytes: int = 0
    snapshot: int = 1           # 1-based number of the snapshot just written
    added_bytes: int = 0        # bytes this run added to the store file
    dirs: int = 0
    links: int = 0
    reused_files: int = 0       # unchanged since the previous snapshot: not read again
    reused_bytes: int = 0
    skipped: list = field(default_factory=list)   # (path, reason) of files that could not be read
    changed: list = field(default_factory=list)   # paths still changing after a re-read (stored anyway)
    parity: str = ""            # "built" / "updated" / "" (none) / "warning: ..."
    precheck: str = ""          # what the check of the existing store before writing found / did
    precheck_fixed: bool = False    # it rebuilt damaged bytes from parity (a disk worth watching)
    readback: int = 0           # new blocks read back and proven before the snapshot was published


def _encode_pack(chunks: list[bytes]) -> bytes:
    return struct.pack(f"<I{len(chunks)}I", len(chunks), *map(len, chunks)) + b"".join(chunks)


def _decode_pack(payload: bytes) -> list[bytes]:
    try:
        (n,) = struct.unpack_from("<I", payload)
        if 4 + 4 * n > len(payload):
            raise struct.error("chunk count past end of pack")
        lens = struct.unpack_from(f"<{n}I", payload, 4)
    except struct.error as e:
        raise IntegrityError(f"corrupt pack table: {e}") from e
    off, out = 4 + 4 * n, []
    for ln in lens:
        out.append(payload[off:off + ln]); off += ln
    if off != len(payload):
        raise IntegrityError("pack length table does not match payload")
    return out


def _build_manifest(prev: int, created: int, label: str, first_pack: int, packs: list[int],
                    index: list[tuple[bytes, int]], entries: list[FileEntry],
                    skipped: list[tuple[str, str]]) -> bytes:
    """Serialize a v3 manifest (see FORMAT.md)."""
    lab = label.encode("utf-8", "surrogateescape")[:65535]
    parts = [MANIFEST_V3,
             struct.pack("<QQH", prev, created, len(lab)), lab,
             struct.pack("<II", first_pack, len(packs)),
             np.asarray(packs, dtype="<u8").tobytes(),
             struct.pack("<I", len(index)), b"".join(d for d, _ in index),
             np.asarray([p for _, p in index], dtype="<u8").tobytes(),
             struct.pack("<I", len(entries))]
    for e in entries:
        p = e.path.encode("utf-8", "surrogateescape")[:65535]
        parts.append(struct.pack("<H", len(p)) + p)
        parts.append(_ENTRY3.pack(e.kind, e.size, e.sha256, e.mtime_ns, e.mode & 0xFFFFFFFF,
                                  e.attrs & 0xFFFFFFFF, len(e.pointers)))
        parts.append(np.asarray(e.pointers, dtype="<u8").tobytes())
    parts.append(struct.pack("<I", len(skipped)))
    for path, reason in skipped:
        p = path.encode("utf-8", "surrogateescape")[:65535]
        r = reason.encode("utf-8", "replace")[:65535]
        parts.append(struct.pack("<H", len(p)) + p + struct.pack("<H", len(r)) + r)
    return b"".join(parts)


def _norm_path(rel: str) -> str:
    return rel.replace(os.sep, "/") if os.sep != "/" else rel


def _meta(st: os.stat_result) -> tuple[int, int, int]:
    return st.st_mtime_ns, st.st_mode, getattr(st, "st_file_attributes", 0)


def _sig(st: os.stat_result) -> tuple[int, int]:
    """What must not change while a file is being read."""
    return st.st_size, st.st_mtime_ns


def _is_link(path: str) -> bool:
    return os.path.islink(path) or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def _make_junction(target: str, dest: str, e: "FileEntry") -> bool:
    """Recreate a Windows junction as a junction. A junction is stored as a
    directory link whose recorded st_mode is a directory (a real symlink has
    S_IFLNK), so stores written before this need no change. Junctions need no
    privilege or Developer Mode, unlike symlinks. False (caller makes a
    symlink instead) if this entry is not a junction or the target cannot be
    a junction target (relative or a network path)."""
    if os.name != "nt" or e.kind != KIND_DIRLINK or not stat.S_ISDIR(e.mode):
        return False
    t = target[4:] if target.startswith("\\\\?\\") else target
    if t.upper().startswith("UNC\\") or not os.path.isabs(t) or t[1:2] != ":":
        return False
    import _winapi
    _winapi.CreateJunction(t, dest)
    return True


# Restore metadata is applied through handles, never by name: between the containment checks and the
# end of a restore, anyone who can write in the output folder could swap a restored file or folder (or
# one of its parents) for a link, and a chmod / utime by name would then change whatever it points at.
#   POSIX:   a file's mode and mtime are set on the temp file's own descriptor before it is renamed
#            into place; a folder is reached from the output folder one name at a time, each opened
#            with O_NOFOLLOW | O_DIRECTORY, and changed through that descriptor. No fallback by name.
#   Windows: each entry is opened without following reparse points, refused if it is one, and changed
#            only if the handle's final path is inside the output folder's final path.

def _safe_mode(mode: int) -> int:
    """Permission bits from a store, without setuid / setgid (files and folders)."""
    return stat.S_IMODE(mode) & ~(stat.S_ISUID | stat.S_ISGID)


def _meta_fd(fd: int, e: "FileEntry"):
    """POSIX: restore mtime and mode on an open descriptor."""
    if e.mtime_ns >= 0:
        os.utime(fd, ns=(e.mtime_ns, e.mtime_ns))
    if e.mode:
        os.fchmod(fd, _safe_mode(e.mode))


def _dir_meta_beneath(root_fd: int, parts: list[str], e: "FileEntry"):
    """POSIX: restore a folder's metadata, reaching it from root_fd one name at a
    time without following any link. OSError if any step is not a real folder."""
    flags = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.dup(root_fd)
    try:
        for name in parts:
            nfd = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = nfd
        _meta_fd(fd, e)
    finally:
        os.close(fd)


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = [("CreationTime", ctypes.c_longlong), ("LastAccessTime", ctypes.c_longlong),
                    ("LastWriteTime", ctypes.c_longlong), ("ChangeTime", ctypes.c_longlong),
                    ("FileAttributes", wintypes.DWORD)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                  wintypes.DWORD]
    _k32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                wintypes.DWORD]
    _k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD,
                                               wintypes.DWORD]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]


def _win_open_attr(path: str):
    """Windows: a handle that can read and write path's attributes and times,
    on the entry itself (a link or junction is opened, not followed)."""
    h = _k32.CreateFileW(path, 0x80 | 0x100, 0x7, None, 3, 0x02000000 | 0x00200000, None)
    if h is None or h == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error(), path)
    return h


def _win_final_path(h, path: str) -> str:
    buf = ctypes.create_unicode_buffer(32768)
    n = _k32.GetFinalPathNameByHandleW(h, buf, 32768, 0)
    if not n or n >= 32768:
        raise ctypes.WinError(ctypes.get_last_error(), path)
    return os.path.normcase(buf.value)


def _win_root(root: str) -> str:
    """Windows: the output folder's final path, for _win_set_meta."""
    h = _win_open_attr(root)
    try:
        return _win_final_path(h, root)
    finally:
        _k32.CloseHandle(h)


def _win_set_meta(path: str, root_final: str, mtime_ns: int | None, attrs: int | None):
    """Windows: set times (mtime_ns, both access and write) and/or attributes on
    path through one handle, refusing a link / junction and anything whose final
    path is not inside root_final."""
    h = _win_open_attr(path)
    try:
        info = _FileBasicInfo()
        if not _k32.GetFileInformationByHandleEx(h, 0, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error(), path)
        if info.FileAttributes & 0x400:
            raise OSError(0, "it is a link now, so it was left alone", path)
        final = _win_final_path(h, path)
        if not final.startswith(root_final.rstrip("\\") + "\\"):
            raise OSError(0, "it is no longer inside the output folder, so it was left alone", path)
        info = _FileBasicInfo()                       # zero = leave unchanged
        if mtime_ns is not None and mtime_ns >= 0:
            info.LastAccessTime = info.LastWriteTime = mtime_ns // 100 + 116444736000000000
        if attrs is not None:
            info.FileAttributes = (attrs & WIN_ATTR_KEEP) or WIN_ATTR_NORMAL
        if not _k32.SetFileInformationByHandle(h, 0, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error(), path)
    finally:
        _k32.CloseHandle(h)


def _make_writable(path: str, root_final: str | None):
    """Clear read-only / hidden / system so an existing file can be replaced
    (Windows). POSIX needs no change to replace or delete a file, so nothing is
    changed; only the old behaviour of failing on another user's file is kept."""
    if os.name == "nt":
        _win_set_meta(path, root_final, None, 0)
    else:
        euid = os.geteuid()
        if euid != 0 and os.lstat(path).st_uid != euid:
            raise PermissionError(1, "Operation not permitted", path)


def _apply_meta_win(path: str, e: "FileEntry", root_final: str):
    """Windows: restore mtime and attributes (read-only included) in one step."""
    attrs = None
    if e.attrs:
        attrs = e.attrs
    elif e.mode and not e.mode & stat.S_IWUSR and e.kind == KIND_FILE:
        attrs = 0x1
    _win_set_meta(path, root_final, e.mtime_ns, attrs)


def _safe_parts(path: str) -> list[str]:
    """Split a manifest path on / or \\ and reject anything that could escape
    the output directory."""
    parts = re.split(r"[\\/]", path)
    bad = (not parts or any(p in ("", ".", "..") for p in parts)
           or (os.name == "nt" and any(":" in p for p in parts)))
    if bad:
        raise IntegrityError(f"unsafe path in manifest: {path!r}")
    return parts


CASE_INSENSITIVE_FS = os.name == "nt" or sys.platform == "darwin"
_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | \
    {f"{d}{i}" for d in ("COM", "LPT") for i in list("123456789") + ["\u00b9", "\u00b2", "\u00b3"]}
_WIN_BAD_CHARS = re.compile(r'[<>"|?*\x00-\x1f]')
LINK_TARGET_MAX = 64 * 1024          # longer than any path a system accepts


def _unportable(parts: list[str]) -> str:
    """Why this path cannot be created on this system ('' when it can). Such
    entries are legitimate on the system that made the store (aux.c on Linux),
    so restore skips them with a warning instead of failing."""
    for p in parts:
        if "\x00" in p:
            return "the name contains a NUL character"
        if os.name != "nt":
            continue
        if any("\udc80" <= ch <= "\udcff" for ch in p):
            return f"{p!r} is not valid Unicode, which Windows needs"
        if _WIN_BAD_CHARS.search(p):
            return f"{p!r} contains a character Windows does not allow in names"
        if p[-1] in ". ":
            return f"{p!r} ends with a dot or space, which Windows drops"
        if p.split(".")[0].rstrip(" ").upper() in _WIN_RESERVED:
            return f"{p!r} is a reserved device name on Windows"
    return ""


def _existing_ancestor(path: str) -> str:
    while not os.path.isdir(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return path


class StoreWriter:
    """Writes a new store, or (append=True) adds a snapshot to an existing one."""

    def __init__(self, path: str, chunker: FastCDC | None = None, codec: BlockCodec | None = None,
                 pack_target: int = 1 << 20, near_dup_hamming: int = 6,
                 append: bool = False, label: str = "", workers: int | None = None,
                 max_pending_bytes: int = 256 << 20, parity: bool | None = None,
                 encrypt: bool = False, password: str | None = None, cloud_files: bool = False,
                 precheck: bool = True):
        """workers: threads for reading/chunking small files, hashing large
        ones and compressing packs (default: CPU count, max 16; 1 = no
        threads). Output is byte-identical whatever the worker count, except
        for the manifest timestamp.

        Holds an exclusive lock on '<path>.lock' until close()/abort(); a
        second writer gets StoreLockedError instead of silently losing a
        snapshot. A new store (append=False or no store yet) is written to
        '<path>.hcs-new' and only replaces <path> when close() succeeds.

        parity: None (default) = a new store gets a Reed-Solomon sidecar
        '<path>.hcp' and an existing sidecar is kept up to date; True = also
        create one for an existing store that has none; False = no parity
        (a new store's stale sidecar is removed).

        encrypt: seal every block of a NEW store with a random key, itself
        sealed under the password (argument, set_password(), or the
        HYBRIDSTORE_PASSWORD environment variable). Appending to an encrypted
        store needs the same password and always stays encrypted.

        precheck (append only): before anything is written, prove the
        existing store intact, because a new snapshot reuses (dedups against)
        its data. With parity, every shard is hashed against its record and
        damage parity can rebuild is rebuilt (hash-proven); without parity
        (or where it does not reach), every pack is decoded and CRC-checked.
        Any damage that remains refuses the backup (IntegrityError) and
        changes nothing. Independently of this, close() always reads back
        every block the run wrote and proves each new chunk against its
        SHA-256 before the footer publishes the snapshot."""
        self.parity_mode = parity
        self.precheck = precheck
        self.encrypt, self.password = encrypt, password
        self.cloud_files = cloud_files          # False: skip (and report) cloud placeholders
        self.lock = _StoreLock(path)
        try:
            self._init(path, chunker, codec, pack_target, near_dup_hamming, append, label,
                       workers, max_pending_bytes)
        except BaseException:
            self.lock.release()
            raise

    def _init(self, path, chunker, codec, pack_target, near_dup_hamming, append, label,
              workers, max_pending_bytes):
        self._finished = False
        self.started = time.time()       # snapshot time = start of the run (every read is after it)
        self.path = path
        self.chunker = chunker or FastCDC()
        self.codec = codec or BlockCodec()
        self.pack_target = pack_target
        self.label = label
        self.index: dict[bytes, int] = {}      # raw 32-byte digest -> pointer
        self.new_index: list[tuple[bytes, int]] = []
        self.pack_offsets: list[int] = []      # pack_id -> file offset
        self.prev_manifest = 0
        self.has_dict = False
        self.stats = Stats()
        self.prev_snapshots: list[Snapshot] = []
        self.recovered_bytes = 0               # tail bytes dropped from an interrupted write
        if append and os.path.exists(path) and os.path.getsize(path) > 0:
            proven = 0
            if self.precheck:          # before opening: a rebuilt manifest may be what opening needs
                proven = _precheck_parity(path, self.stats)
            with StoreReader(path, codec=self.codec, load_index=True, password=self.password) as r:
                if self.encrypt and not r.encrypted:
                    raise IntegrityError(f"{path} is not encrypted, but encryption was asked for (--encrypt, or a "
                                         f"password for `backup`: --password-file / {PASSWORD_ENV}). Nothing was "
                                         f"backed up: if this store was encrypted, it has been replaced. Encryption "
                                         f"is chosen when a store is created (pack --encrypt into a new store); to "
                                         f"back up into an unencrypted store, give no password")
                if r.tail_snapshot is not None:
                    raise IntegrityError(
                        f"{path}: the newest snapshot (#{len(r.snapshots) + 1}) is complete but its footer "
                        f"is damaged or missing, so it is not visible. Nothing was changed. Run "
                        f"`hybridstore.py repair {path}` to restore it, then back up again")
                if self.precheck:
                    _precheck_blocks(r, proven, self.stats)
                self.pack_offsets = list(r.pack_offsets)
                self.index = r.index
                self.prev_manifest = r.snapshots[-1].offset
                self.has_dict = r.has_dict
                self.prev_snapshots = r.snapshots
                self.stats.snapshot = len(r.snapshots) + 1
                end = r.end
                self.recovered_bytes = r.file_size - r.end
            self.f = open(path, "r+b")
            self.f.truncate(end)
            self.f.seek(end)
            self.pos = self.start = end
            self.created = False
        else:
            self.codec.set_key(None)
            pin = _pinned(path) if append and not self.encrypt else None
            if pin:
                raise PasswordError(f"{path} was encrypted when this computer last opened it, but it is "
                                    f"missing now: nothing was backed up, so your files are not written "
                                    f"unencrypted. To recreate it encrypted, give the password (--password-file "
                                    f"or {PASSWORD_ENV}); to start an unencrypted store there, use `pack`")
            if self.encrypt:
                pw = self.password if self.password is not None else _password_for(
                    "password for the new store: ", confirm=True)
                if pw is None:
                    raise PasswordError(f"--encrypt needs a password (--password-file FILE or the "
                                        f"{PASSWORD_ENV} environment variable)")
                key_block, key = make_key_block(pw)
                self.codec.set_key(key)
            self.f = open(path + ".hcs-new", "wb")
            self.f.write(STORE_MAGIC)
            self.pos = self.start = len(STORE_MAGIC)
            if self.encrypt:
                self.f.write(key_block)
                self.pos += len(key_block)
            self.created = True
        self.header_end = self.pos
        self.first_new_pack = len(self.pack_offsets)
        self.next_pack = len(self.pack_offsets)  # id of the pack being filled
        self.open_pack: list[bytes] = []
        self.open_pack_bytes = 0
        self.open_flags = 0
        self.entries: list[FileEntry] = []
        self.image_hashes: list[int] = []
        self.near_dup_hamming = near_dup_hamming
        if workers is None:
            workers = min(os.cpu_count() or 1, 16)
        self.workers = max(1, workers)
        self.pool = ThreadPoolExecutor(self.workers, thread_name_prefix="hcs") if self.workers > 1 else None
        self.pending: deque = deque()            # (future, payload_len) in pack-id order
        self.pending_bytes = 0
        self.max_pending_bytes = max_pending_bytes

    # ---- packs ----
    def _write_block(self, block: bytes, info: dict, payload_len: int):
        if self.codec.cipher is not None and len(self.pack_offsets) + len(self.prev_snapshots) >= MAX_SEALED_BLOCKS:
            raise IntegrityError("this encrypted store has reached its per-key block limit; start a new store")
        self.pack_offsets.append(self.pos)
        self.f.write(block)
        self.pos += len(block)
        st = self.stats
        st.packs += 1
        st.codec_counts[CODEC_NAMES[info["codec"]]] += 1
        st.dict_blocks += info["dict"]
        if info["raw_fallback"]:
            st.raw_fallback_blocks += 1
            st.raw_fallback_bytes += payload_len

    def _write_next(self):
        fut, n = self.pending.popleft()
        self.pending_bytes -= n
        self._write_block(*fut.result(), n)

    def _drain(self):
        """Write every pack still being compressed, in order."""
        while self.pending:
            self._write_next()

    def _flush(self):
        """Close the open pack: compress it (on the pool when there is one)
        and queue it for writing. Packs are always written in id order."""
        if not self.open_pack:
            return
        payload = _encode_pack(self.open_pack)
        flags = self.open_flags
        self.open_pack, self.open_pack_bytes = [], 0
        self.next_pack += 1
        if self.pool is None:
            self._write_block(*self.codec.encode(payload, flags), len(payload))
            return
        self.pending.append((self.pool.submit(self.codec.encode, payload, flags), len(payload)))
        self.pending_bytes += len(payload)
        while self.pending and (self.pending[0][0].done() or self.pending_bytes > self.max_pending_bytes
                                or len(self.pending) > 4 * self.workers):
            self._write_next()

    def _put(self, data: bytes, flags: int = 0, alone: bool = False, digest: bytes | None = None) -> int:
        if digest is None:
            digest = hashlib.sha256(data).digest()
        self.stats.chunks_total += 1
        ptr = self.index.get(digest)
        if ptr is not None:
            self.stats.dedup_bytes += len(data)
            return ptr
        if self.open_pack and (alone or flags != self.open_flags):
            self._flush()                  # media never shares a pack with other data
        self.open_flags = flags
        ptr = (self.next_pack << PTR_SHIFT) | len(self.open_pack)
        self.open_pack.append(data)
        self.open_pack_bytes += len(data)
        if alone or self.open_pack_bytes >= self.pack_target or len(self.open_pack) >= PTR_IDX_MASK:
            self._flush()
        self.index[digest] = ptr
        self.new_index.append((digest, ptr))
        self.stats.chunks_unique += 1
        return ptr

    # ---- ingest ----
    def add_stream(self, rel_path: str, f, meta: tuple | None = None):
        """Add one file from a seekable binary file object. meta is
        (mtime_ns, st_mode, windows_attrs) or None when unknown."""
        st = self.stats
        head = f.read(16)
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)
        kind = media_kind(head)
        if size <= PREP_MAX:
            self._add_prepared(rel_path, self._prepare_bytes(f.read()), meta)
            return
        hr = _HashingReader(f)
        entry = FileEntry(_norm_path(rel_path), 0, b"")
        if meta:
            entry.mtime_ns, entry.mode, entry.attrs = meta
        if kind is not None and size <= WHOLE_MEDIA_MAX:
            st.media_files += 1
            data = hr.read()
            self._note_image(kind, dhash64(data) if kind in IMAGE_TYPES else None)
            entry.pointers.append(self._put(data, FLAG_MEDIA, alone=True))
        else:
            flags = 0
            if kind is not None:
                st.media_files += 1
                flags = FLAG_MEDIA
            for chunk in self.chunker.stream_chunks(hr, pool=self.pool):
                entry.pointers.append(self._put(chunk, flags))
        entry.size, entry.sha256 = hr.size, hr.sha.digest()
        st.files += 1
        st.input_bytes += hr.size
        self.entries.append(entry)

    def _note_image(self, kind, h):
        if h is not None:
            if any(bin(h ^ o).count("1") <= self.near_dup_hamming for o in self.image_hashes):
                self.stats.near_dup_images += 1   # reported only; see README
            self.image_hashes.append(h)

    def _prepare_bytes(self, data: bytes):
        """Everything per-file that does not touch writer state: routing,
        chunking and hashing. Safe to run in a worker thread."""
        kind = media_kind(data[:16])
        sha = hashlib.sha256(data).digest()
        if kind is not None:
            dh = dhash64(data) if kind in IMAGE_TYPES else None
            return kind, len(data), sha, [data], [sha], dh
        chunks = list(self.chunker.chunks(data))
        return kind, len(data), sha, chunks, [hashlib.sha256(c).digest() for c in chunks], None

    def _prepare_path(self, full: str):
        """Read and prepare a small file. Returns (prep, meta); prep is None
        for a file that should be streamed (large, or grew past PREP_MAX).
        Returns the OSError instead of raising it, for skip-and-report."""
        try:
            with open(full, "rb") as fh:
                fst = os.fstat(fh.fileno())
                meta = _meta(fst)
                if fst.st_size > PREP_MAX:
                    return None, meta, True
                data = fh.read(PREP_MAX + 1)
                stable = _sig(os.fstat(fh.fileno())) == _sig(fst)
        except OSError as e:
            return e
        return (None if len(data) > PREP_MAX else self._prepare_bytes(data)), meta, stable

    def _add_prepared(self, rel_path: str, prep, meta: tuple | None = None):
        kind, size, sha, chunks, digests, dh = prep
        st = self.stats
        entry = FileEntry(_norm_path(rel_path), size, sha)
        if meta:
            entry.mtime_ns, entry.mode, entry.attrs = meta
        if kind is not None:
            st.media_files += 1
            self._note_image(kind, dh)
            entry.pointers.append(self._put(chunks[0], FLAG_MEDIA, alone=True, digest=digests[0]))
        else:
            for c, d in zip(chunks, digests):
                entry.pointers.append(self._put(c, 0, digest=d))
        st.files += 1
        st.input_bytes += size
        self.entries.append(entry)

    def add_file(self, rel_path: str, data: bytes):
        self.add_stream(rel_path, io.BytesIO(data))

    def train_dictionary(self, samples: list[bytes], dict_size: int = 112 * 1024):
        """Train a zstd dictionary and store it as the first block. Only
        possible on a new, still-empty store."""
        if not self.created or self.pos != self.header_end:
            return False
        if not zstd or len(samples) < 8 or sum(map(len, samples)) < 8 * dict_size:
            return False
        try:
            d = zstd.train_dictionary(dict_size, samples).as_bytes()
        except Exception:
            return False
        block, _ = self.codec.encode(d, FLAG_DICT)
        self.f.write(block)
        self.pos += len(block)
        self.codec.set_dictionary(d)
        self.has_dict = True
        self.stats.dict_bytes = len(block)
        return True

    def _walk(self, root: str):
        """Yield (full_path, kind, lstat) in a stable order (top-down; in each
        directory: its subdirectories, then its files, each sorted by name):
        every directory (so empty ones and their metadata survive), symlinks /
        junctions as links (never followed), regular files. Uses scandir, so
        on Windows the stat comes from the directory listing for free.
        Directories that cannot be listed are reported as skipped.

        The store being written and its sidecars (<store>.hcs-new, .lock,
        .hcp, .cat, .sem, ...) are left out when the store sits inside the
        folder: otherwise every backup would copy the store into itself."""
        own = os.path.normcase(os.path.basename(self.path))
        own_dir = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(self.path))))

        def is_own(path, name):
            n = os.path.normcase(name)
            return (n == own or n.startswith(own + ".")) and os.path.normcase(os.path.realpath(path)) == own_dir

        def visit(path):
            try:
                with os.scandir(path) as it:
                    ents = list(it)
            except OSError as e:
                self._skip(os.path.relpath(path, root) if path != root else ".", e)
                return
            dirs, files = [], []
            for de in ents:
                if is_own(path, de.name):
                    continue
                try:
                    if de.is_symlink() or (hasattr(de, "is_junction") and de.is_junction()):
                        isdir = de.is_dir()
                        (dirs if isdir else files).append((de.name, KIND_DIRLINK if isdir else KIND_LINK, de))
                    elif de.is_dir(follow_symlinks=False):
                        dirs.append((de.name, KIND_DIR, de))
                    elif de.is_file(follow_symlinks=False):
                        files.append((de.name, KIND_FILE, de))
                except OSError:
                    continue                       # vanished while listing
            dirs.sort(key=lambda t: t[0]); files.sort(key=lambda t: t[0])
            subdirs = []
            for _, kind, de in dirs + files:
                full = de.path
                try:
                    # Files: the listing's cached stat is only a prefilter for reuse
                    # (add_tree re-stats candidates); NTFS updates it lazily.
                    # Directories / links: always an exact lstat, since it is stored.
                    st = de.stat(follow_symlinks=False) if kind == KIND_FILE else os.lstat(full)
                except OSError as e:
                    self._skip(os.path.relpath(full, root), e)
                    continue
                if kind == KIND_FILE and not self.cloud_files and \
                        getattr(st, "st_file_attributes", 0) & CLOUD_ATTRS:
                    self.stats.skipped.append((_norm_path(os.path.relpath(full, root)),
                                               "cloud placeholder, not downloaded (reading it would download it; "
                                               "use --cloud-files to include)"))
                    continue
                yield full, kind, st
                if kind == KIND_DIR:
                    subdirs.append(full)
            for d in subdirs:
                yield from visit(d)
        yield from visit(root)

    def _skip(self, rel: str, e: BaseException):
        reason = getattr(e, "strerror", None) or str(e) or type(e).__name__
        self.stats.skipped.append((_norm_path(rel), reason))

    def _add_special(self, rel: str, full: str, kind: int, st: os.stat_result | None = None):
        """A directory or symlink entry (no file data read)."""
        st = st or os.lstat(full)
        e = FileEntry(_norm_path(rel), 0, EMPTY_SHA, kind=kind)
        e.mtime_ns, e.mode, e.attrs = _meta(st)
        if kind in (KIND_LINK, KIND_DIRLINK):
            target = os.readlink(full).encode("utf-8", "surrogateescape")
            e.size, e.sha256 = len(target), hashlib.sha256(target).digest()
            if target:
                e.pointers.append(self._put(target))
            self.stats.links += 1
        else:
            self.stats.dirs += 1
        self.entries.append(e)

    def _previous_files(self, label: str) -> dict[str, FileEntry]:
        """Files of the newest earlier snapshot of the same source folder that
        are safe to reuse by size + mtime: recorded in a v3 manifest, and not
        modified within RACY_NS of that snapshot being taken (a write in the
        same timestamp tick as the read could otherwise go unnoticed)."""
        want = os.path.normcase(label)
        for s in reversed(self.prev_snapshots):
            if os.path.normcase(s.label) == want:
                if s.version < 3:
                    return {}
                limit = s.created * 1_000_000_000 - RACY_NS
                return {e.path: e for e in s.entries
                        if e.kind == KIND_FILE and 0 <= e.mtime_ns < limit}
        return {}

    def add_tree(self, root: str, use_dictionary: bool | None = None, sample_budget: int = 8 << 20,
                 rehash: bool = False):
        """Back up a directory tree. A file that cannot be read (locked by
        another program, permission denied, vanished) is skipped and listed
        in stats.skipped and the manifest instead of failing the whole run.

        Unchanged files are not read again: a file whose size and mtime match
        the previous snapshot of the same folder reuses that snapshot's chunk
        list (its current mtime / permissions / attributes are still
        recorded). rehash=True reads and hashes every file regardless."""
        # A dictionary pays off when chunks are compressed alone; with large
        # solid packs it mostly costs its own size, so default to it only then.
        if use_dictionary is None:
            use_dictionary = self.pack_target <= 64 * 1024
        if not self.label:
            self.label = os.path.abspath(root)
        items = list(self._walk(root))
        reuse: dict[str, tuple[FileEntry, os.stat_result]] = {}
        prev = {} if rehash else self._previous_files(os.path.abspath(root))
        if prev:
            for full, kind, st in items:
                if kind == KIND_FILE:
                    p = prev.get(_norm_path(os.path.relpath(full, root)))
                    if p is not None and p.size == st.st_size and p.mtime_ns == st.st_mtime_ns:
                        try:
                            st = os.lstat(full)     # exact values (the listing's may be stale)
                        except OSError:
                            continue                # read normally; any error is reported there
                        if p.size == st.st_size and p.mtime_ns == st.st_mtime_ns:
                            reuse[full] = (p, st)
        files = [full for full, kind, _ in items if kind == KIND_FILE and full not in reuse]
        if use_dictionary and self.created and self.pos == self.header_end:
            seen, samples, budget = set(), [], sample_budget
            for full in files:
                try:
                    with open(full, "rb") as fh:
                        if media_kind(fh.read(16)) is not None:
                            continue
                        fh.seek(0)
                        for c in self.chunker.stream_chunks(fh, pool=self.pool):
                            k = hashlib.sha256(c).digest()
                            if k not in seen:
                                seen.add(k); samples.append(c); budget -= len(c)
                            if budget <= 0:
                                break
                except OSError:
                    continue            # reported when the file itself is added
                if budget <= 0:
                    break
            self.train_dictionary(samples)
        prepared = self._prepared(files)
        st_ = self.stats
        for full, kind, fst in items:
            rel = os.path.relpath(full, root)
            try:
                if kind != KIND_FILE:
                    self._add_special(rel, full, kind, fst)
                    continue
                hit = reuse.get(full)
                if hit is not None:
                    p, exact = hit
                    e = FileEntry(_norm_path(rel), p.size, p.sha256, p.pointers)
                    e.mtime_ns, e.mode, e.attrs = _meta(exact)
                    self.entries.append(e)
                    st_.files += 1
                    st_.input_bytes += p.size
                    st_.reused_files += 1
                    st_.reused_bytes += p.size
                    continue
                pfull, res = next(prepared)
                if pfull != full:
                    raise RuntimeError(f"internal error: file order mismatch ({pfull} vs {full})")
                for attempt in (1, 2):
                    mark = (len(self.entries), st_.files, st_.input_bytes, st_.media_files)
                    if self._add_file(rel, full, res):
                        break
                    if attempt == 2:
                        st_.changed.append(_norm_path(rel))
                        break
                    # Changed while it was read: drop that copy and read it once more.
                    del self.entries[mark[0]:]
                    st_.files, st_.input_bytes, st_.media_files = mark[1:]
                    res = self._prepare_path(full)
            except OSError as e:
                self._skip(rel, e)

    def _add_file(self, rel: str, full: str, res) -> bool:
        """Add one regular file (prepared in a worker, or streamed here).
        Returns False if its size or mtime changed while it was being read:
        the copy may then mix old and new content. The entry keeps the mtime
        from before the read, so the next backup reads the file again."""
        if isinstance(res, BaseException):
            raise res
        if res is not None and res[0] is not None:
            prep, meta, stable = res
            self._add_prepared(rel, prep, meta)
            return stable
        with open(full, "rb") as fh:
            before = os.fstat(fh.fileno())
            self.add_stream(rel, fh, _meta(before))
            return _sig(os.fstat(fh.fileno())) == _sig(before)

    def _prepared(self, files):
        """Yield (path, result) in input order, where result is what
        _prepare_path returns: (prep-or-None, meta, stable) or an OSError. With a
        pool, small files are read, chunked and hashed ahead in worker
        threads (bounded look-ahead, so memory stays around
        4 x workers x PREP_MAX at worst). Without one, result is None."""
        if self.pool is None:
            for full in files:
                yield full, None
            return
        ahead: deque = deque()
        it = iter(files)
        limit = 4 * self.workers
        try:
            for full in it:
                ahead.append((full, self.pool.submit(self._prepare_path, full)))
                if len(ahead) >= limit:
                    break
            while ahead:
                full, fut = ahead.popleft()
                nxt = next(it, None)
                if nxt is not None:
                    ahead.append((nxt, self.pool.submit(self._prepare_path, nxt)))
                yield full, fut.result()
        finally:
            for _, fut in ahead:
                fut.cancel()

    def _shutdown(self):
        if self.pool is not None:
            for fut, _ in self.pending:
                fut.cancel()
            self.pool.shutdown(wait=True)
            self.pool = None
        self.pending.clear()
        self.pending_bytes = 0

    def close(self) -> Stats:
        """Finish the snapshot. On any error the run is rolled back (abort)
        and the exception re-raised; the lock is always released."""
        try:
            return self._close()
        except BaseException:
            self.abort()
            raise

    def _close(self) -> Stats:
        try:
            self._flush()
            self._drain()
        finally:
            self._shutdown()
        manifest = _build_manifest(self.prev_manifest, int(self.started), self.label, self.first_new_pack,
                                   self.pack_offsets[self.first_new_pack:], self.new_index,
                                   self.entries, self.stats.skipped)
        block, _ = self.codec.encode(manifest, FLAG_MANIFEST)
        moff = self.pos
        self.f.write(block)
        self.pos += len(block)
        # Make sure packs + manifest are on disk before the footer that
        # publishes them; a crash before this point leaves the old footer valid.
        self.f.flush(); os.fsync(self.f.fileno())
        self._read_back(moff)                  # raises -> close() rolls the run back; nothing is published
        self.f.write(FOOTER.pack(moff, STORE_MAGIC))
        self.pos += FOOTER.size
        self.f.flush(); os.fsync(self.f.fileno())
        self.f.close()
        self._finished = True                  # complete on disk: abort() must not undo it now
        if self.created:
            try:
                os.replace(self.path + ".hcs-new", self.path)
            except OSError as e:
                raise OSError(e.errno, f"could not replace {self.path} ({e.strerror}); "
                                       f"the new store is complete at {self.path}.hcs-new") from e
            _set_pin(self.path, self.codec.cipher is not None)    # the owner chose this store's encryption
        self.stats.parity = self._update_parity()
        self.lock.release()
        self.stats.manifest_bytes = len(block)
        self.stats.store_bytes = self.pos
        self.stats.added_bytes = self.pos - self.start + (len(STORE_MAGIC) if self.created else 0)
        return self.stats

    def _read_back(self, moff: int):
        """Read every block this run wrote back from the file, decode it
        (CRC / authentication) and prove each new chunk against the SHA-256 it
        was indexed under, before the footer publishes the snapshot. Catches a
        bad encode, a short or misplaced write, and RAM or controller errors on
        the way to the disk. (A freshly written block may come back from the OS
        cache rather than the platter; the next backup's precheck reads it
        from disk.)"""
        want: dict[int, list] = {}
        for d, p in self.new_index:
            want.setdefault(p >> PTR_SHIFT, []).append((p & PTR_IDX_MASK, d))
        offs = self.pack_offsets[self.first_new_pack:] + [moff]
        ends = offs[1:] + [self.pos]
        with open(self.f.name, "rb") as f:
            for i, (off, end) in enumerate(zip(offs, ends)):
                pid = self.first_new_pack + i
                what = "the new file list (manifest)" if off == moff else f"new pack {pid}"
                f.seek(off)
                raw = f.read(end - off)
                try:
                    data, _, nxt = self.codec.decode_at(raw, 0)
                    if nxt != len(raw):
                        raise IntegrityError("its length does not match what was written")
                    if off != moff:
                        chunks = _decode_pack(data)
                        for idx, d in want.pop(pid, ()):
                            if idx >= len(chunks) or hashlib.sha256(chunks[idx]).digest() != d:
                                raise IntegrityError(f"chunk {idx} does not match the data that was read")
                except IntegrityError as e:
                    raise IntegrityError(f"read-back check failed: {what} at byte {off:,} is not what was "
                                         f"written ({e}). The snapshot was NOT published and the store is "
                                         f"unchanged. Repeated failures point at RAM, the cable / USB "
                                         f"enclosure or the disk") from None
                self.stats.readback += 1
        if want:
            raise IntegrityError(f"read-back check failed: chunks indexed in pack(s) {sorted(want)[:5]} were "
                                 f"never written. The snapshot was NOT published and the store is unchanged")

    def _update_parity(self) -> str:
        """Bring the parity sidecar up to date (under the store lock). A
        failure here never fails the backup: the snapshot is already safe."""
        par = Parity(self.path)
        try:
            if self.created:
                if self.parity_mode is False:
                    if par.exists():
                        os.remove(par.path)          # it belonged to the store just replaced
                    return ""
                par.build()
                return "built"
            if par.exists() and self.parity_mode is not False:
                par.update(self.start)
                return "updated"
            if self.parity_mode:
                par.build()
                return "built"
            return ""
        except (OSError, IntegrityError) as e:
            return f"warning: parity not updated ({e})"

    def abort(self):
        """Discard everything written by this run (a new store's temp file
        is deleted; an existing store is truncated back to where it was)."""
        try:
            self._shutdown()
            if self._finished:
                pass
            elif self.created:
                self.f.close()
                if os.path.exists(self.path + ".hcs-new"):
                    os.remove(self.path + ".hcs-new")
            elif not self.f.closed:
                self.f.truncate(self.start)
                self.f.close()
        except OSError:
            pass
        finally:
            self.lock.release()


class StoreReader:
    """Reads blocks from disk on demand; memory use does not grow with store
    or file size (apart from the manifests and a small pack cache)."""

    def __init__(self, path: str, codec: BlockCodec | None = None, cache_bytes: int = 256 << 20,
                 load_index: bool = False, password: str | None = None):
        self.f = open(path, "rb")
        self.path = path
        try:
            self._open(codec, cache_bytes, load_index, password)
        except Exception:
            self.f.close()
            raise

    def _open(self, codec, cache_bytes, load_index, password=None):
        self.codec = codec or BlockCodec()
        self.f.seek(0, os.SEEK_END)
        self.file_size = size = self.f.tell()
        if size < 8 + FOOTER.size or self._read(0, 8) != STORE_MAGIC:
            raise IntegrityError("not a hybrid store")
        self.has_dict = self.encrypted = False
        self.key_block, self.dict_off = None, None
        pos = len(STORE_MAGIC)
        hdr = self._read(pos, HDR.size)
        if len(hdr) == HDR.size and hdr[:3] == BLOCK_MAGIC and hdr[3] == CODEC_KEYS:
            _, _, olen, slen, crc = HDR.unpack(hdr)
            if slen > 1 << 16:          # a key block is ~100 bytes: a larger length is damage
                raise IntegrityError("the key block of this encrypted store is damaged (`repair` rebuilds it "
                                     "from parity)")
            payload = self.f.read(slen)
            if len(payload) != slen or olen != slen or zlib.crc32(payload) & 0xFFFFFFFF != crc:
                raise IntegrityError("the key block of this encrypted store is damaged (`repair` rebuilds it "
                                     "from parity)")
            self.codec.set_key(open_key_block(payload, password))
            self.key_block, self.encrypted = hdr + payload, True
            pos += HDR.size + slen
            hdr = self._read(pos, HDR.size)
            _set_pin(self.path, True)
        else:
            self.codec.set_key(None)
            pin = _pinned(self.path)
            if pin:
                raise PasswordError(f"{self.path} was encrypted when this computer last opened it, but now it is "
                                    f"not: it may have been replaced. Nothing was read. If you replaced it with an "
                                    f"unencrypted store yourself, delete the marker {pin} and run again")
            if _password_named:
                raise PasswordError(f"{self.path} is not encrypted, but a password file was given for it: it may "
                                    f"have been replaced with an unencrypted copy. Nothing was read. For an "
                                    f"unencrypted store, give no password")
        if size > pos + HDR.size and len(hdr) == HDR.size and hdr[:3] == BLOCK_MAGIC and hdr[3] & FLAG_DICT:
            d, _, end = self._block(pos)
            self.codec.set_dictionary(d)
            self.has_dict, self.dict_off = True, pos
            pos = end
        self.data_start = pos
        moff, self.end = self._locate_footer(size)
        try:
            chain = self._chain(moff, load_index)
        except IntegrityError as e:
            # A manifest in the chain is damaged. The layout is strictly sequential, so
            # walking the block headers still finds every snapshot and every pack; only
            # the damaged snapshots' file lists are lost.
            chain = self._chain_by_walking(load_index, e)
        self.snapshots: list[Snapshot] = chain
        self.pack_offsets: list[int] = []
        # Where each pack must end: the next pack of its snapshot, or that
        # snapshot's manifest. A damaged length field in a block header then
        # fails at once instead of making the reader allocate up to the rest
        # of the store before the CRC rejects it.
        self.pack_ends: list[int] = []
        for s in chain:
            if s.first_pack != len(self.pack_offsets):
                raise IntegrityError(f"pack ids out of order in snapshot at {s.offset}")
            self.pack_offsets.extend(s.packs)
            self.pack_ends.extend(list(s.packs[1:]) + [s.offset] if s.packs else [])
        self.entries = chain[-1].entries        # newest snapshot (v1 API)
        self._cache: OrderedDict[int, list[bytes]] = OrderedDict()
        self._cache_max = cache_bytes           # decoded-pack cache budget
        self._cache_used = 0
        self.index: dict[bytes, int] = {}
        if load_index:
            self._build_index()
        self.tail_snapshot = self._find_tail_snapshot() if self.end != size else None
        if self.end != size:
            print(f"warning: {self._tail_message()}", file=sys.stderr)
        self.damaged = [i for i, s in enumerate(chain, 1) if s.damaged]
        if self.damaged:
            print(f"warning: the file list of snapshot(s) {self.damaged} is damaged and cannot be read; "
                  f"the other snapshots are readable. `verify` lists all damage; `prune --remove "
                  f"{' '.join(map(str, self.damaged))}` rebuilds the store without them", file=sys.stderr)

    def _chain(self, moff: int, load_index: bool) -> list[Snapshot]:
        """Follow the manifests' prev links back from the newest one."""
        chain, off = [], moff
        while True:
            m, flags, bend = self._block(off)
            if not flags & FLAG_MANIFEST:
                raise IntegrityError(f"footer/chain does not point at a manifest ({off})")
            snap = self._parse_manifest(m, off, load_index)
            snap.block_end = bend
            chain.append(snap)
            if snap.version == 1 or snap.prev == 0:
                break
            if not 8 <= snap.prev < off:
                raise IntegrityError(f"bad snapshot chain link at {off}")
            off = snap.prev
        chain.reverse()
        if chain[0].version >= 2 and chain[0].prev != 0:
            raise IntegrityError("snapshot chain does not start at the first snapshot")
        return chain

    def _walk_blocks(self, start: int, stop: int):
        """Walk forward from a block boundary reading only headers. Yields
        ("block", off, flags, end), ("footer", off, intact, end) for the 16
        bytes after each manifest, and ("bad", off, None, None) where the
        bytes are neither (the walk stops there)."""
        pos, after_manifest = start, None
        while pos < stop:
            raw = self._read(pos, HDR.size)
            if after_manifest is not None:          # a manifest is always followed by its footer
                ok = (len(raw) == FOOTER.size and raw[8:] == STORE_MAGIC
                      and struct.unpack_from("<Q", raw)[0] == after_manifest)
                yield "footer", pos, ok, pos + FOOTER.size
                pos += FOOTER.size
                after_manifest = None
                continue
            if len(raw) != HDR.size or raw[:3] != BLOCK_MAGIC:
                yield "bad", pos, None, None
                return
            flags, end = raw[3], pos + HDR.size + HDR.unpack(raw)[3]
            if end > stop:
                yield "bad", pos, None, None
                return
            yield "block", pos, flags, end
            after_manifest = pos if flags & FLAG_MANIFEST else None
            pos = end

    def _chain_by_walking(self, load_index: bool, cause: IntegrityError) -> list[Snapshot]:
        start = self.data_start
        chain, packs, n_packs, prev = [], [], 0, 0
        for kind, off, flags, end in self._walk_blocks(start, self.end):
            if kind == "bad":
                raise IntegrityError(f"{cause}; walking the store block by block also failed at {off}")
            if kind == "footer" or not flags & FLAG_MANIFEST:
                if kind == "block":
                    packs.append(off)
                continue
            try:
                m, _, _ = self._block(off)
                snap = self._parse_manifest(m, off, load_index)
                if snap.first_pack != n_packs or snap.packs != packs:
                    raise IntegrityError(f"manifest at {off} does not match the packs before it")
            except IntegrityError as e:
                snap = Snapshot(off, 0, prev, 0, "", n_packs, packs, [], damaged=f"manifest damaged ({e})")
            snap.block_end = end
            chain.append(snap)
            n_packs += len(packs)
            packs, prev = [], off
        if not chain or chain[-1].block_end + FOOTER.size != self.end:
            raise IntegrityError(f"{cause}; walking the store block by block did not reach its end")
        return chain

    def _find_tail_snapshot(self) -> tuple[int, int] | None:
        """Bytes follow the last complete snapshot. If they hold a complete
        snapshot (packs + manifest, fsynced before its footer) whose footer is
        missing or damaged, return (manifest_offset, manifest_end); None means
        an interrupted write that published nothing."""
        last = self.snapshots[-1]
        packs = []
        for kind, off, flags, end in self._walk_blocks(self.end, self.file_size):
            if kind != "block":
                return None
            if not flags & FLAG_MANIFEST:
                packs.append(off)
                continue
            try:
                m, _, _ = self._block(off)
                snap = self._parse_manifest(m, off, False)
            except IntegrityError:
                return None
            ok = (snap.prev == last.offset and snap.first_pack == len(self.pack_offsets)
                  and snap.packs == packs and self.file_size - end <= FOOTER.size)
            return (off, end) if ok else None
        return None

    def _tail_message(self) -> str:
        extra = self.file_size - self.end
        if self.tail_snapshot is not None:
            return (f"the newest snapshot (#{len(self.snapshots) + 1}) is complete but its footer is damaged "
                    f"or missing, so only snapshots 1..{len(self.snapshots)} are visible; "
                    f"`hybridstore.py repair` restores it")
        return (f"{extra:,} bytes after the last complete snapshot hold no complete snapshot (an interrupted "
                f"write, or the store was cut short so newer snapshots may be missing); "
                f"the next backup discards them")

    # ---- low level ----
    def _read(self, off: int, n: int) -> bytes:
        self.f.seek(off)
        return self.f.read(n)

    def _block(self, off: int, end: int | None = None) -> tuple[bytes, int, int]:
        """The block at off. end, when known from the store layout, is where it
        must finish; the length in a damaged header is caught before reading."""
        hdr = self._read(off, HDR.size)
        if len(hdr) != HDR.size:
            raise IntegrityError(f"truncated header at {off}")
        slen = HDR.unpack(hdr)[3]
        if end is not None and off + HDR.size + slen != end:
            raise IntegrityError(f"block header at {off} is damaged: its length ({slen:,}) does not match "
                                 f"the store layout ({end - off - HDR.size:,})")
        if off + HDR.size + slen > self.file_size:
            raise IntegrityError(f"block header at {off} is damaged: its length ({slen:,}) runs past the "
                                 f"end of the store")
        payload = self.f.read(slen)
        data, flags = self.codec.decode_block(hdr, payload, off)
        return data, flags, off + HDR.size + slen

    def _locate_footer(self, size: int) -> tuple[int, int]:
        moff, magic = FOOTER.unpack(self._read(size - FOOTER.size, FOOTER.size))
        if magic == STORE_MAGIC:
            if not 8 <= moff < size - FOOTER.size:
                raise IntegrityError("footer offset out of range")
            return moff, size
        # The tail is not a footer: an append was interrupted. Walk back to
        # the newest earlier footer whose manifest still decodes.
        win, ml = 1 << 20, len(STORE_MAGIC)
        hi = size
        while hi > 8:
            lo = max(8, hi - win)
            # read a little past hi so a magic straddling the window edge is seen
            buf = self._read(lo, min(hi + ml - 1, size) - lo)
            starts, p = [], buf.find(STORE_MAGIC)
            while p != -1:
                if lo + p < hi:
                    starts.append(lo + p)
                p = buf.find(STORE_MAGIC, p + 1)
            for s in reversed(starts):
                fstart, end = s - 8, s + ml
                if fstart < 8:
                    continue
                cand = struct.unpack("<Q", self._read(fstart, 8))[0]
                if 8 <= cand < fstart:
                    try:
                        _, flags, bend = self._block(cand)
                        if flags & FLAG_MANIFEST and bend == fstart:
                            return cand, end
                    except IntegrityError:
                        pass
            hi = lo
        raise IntegrityError("no valid footer found")

    @staticmethod
    def _parse_manifest(m: bytes, off: int, keep_index: bool) -> Snapshot:
        try:
            if m[:4] in (MANIFEST_V2, MANIFEST_V3):
                v3 = m[:4] == MANIFEST_V3
                prev, created, ll = struct.unpack_from("<QQH", m, 4)
                o = 4 + 18
                label = m[o:o + ll].decode("utf-8"); o += ll
                first_pack, npk = struct.unpack_from("<II", m, o); o += 8
                packs = np.frombuffer(m, dtype="<u8", count=npk, offset=o).tolist(); o += 8 * npk
                (ni,) = struct.unpack_from("<I", m, o); o += 4
                if o + 40 * ni > len(m):
                    raise ValueError("index section past end of manifest")
                digests, ptrs = b"", []
                if keep_index:
                    digests = m[o:o + 32 * ni]
                    ptrs = np.frombuffer(m, dtype="<u8", count=ni, offset=o + 32 * ni).tolist()
                o += 40 * ni
                version = 3 if v3 else 2
            else:
                v3 = False
                (npk,) = struct.unpack_from("<I", m)
                packs = np.frombuffer(m, dtype="<u8", count=npk, offset=4).tolist()
                o = 4 + 8 * npk
                prev = created = first_pack = 0
                label, digests, ptrs, version = "", b"", [], 1
            (n,) = struct.unpack_from("<I", m, o); o += 4
            entries = []
            for _ in range(n):
                (pl,) = struct.unpack_from("<H", m, o); o += 2
                path = m[o:o + pl].decode("utf-8", "surrogateescape" if v3 else "strict"); o += pl
                if v3:
                    kind, size, sha, mt, mode, attrs, cnt = _ENTRY3.unpack_from(m, o); o += _ENTRY3.size
                    if kind > KIND_DIRLINK:
                        raise ValueError(f"unknown entry kind {kind}")
                else:
                    size, sha, cnt = struct.unpack_from("<Q32sI", m, o); o += 44
                    kind, mt, mode, attrs = KIND_FILE, -1, 0, 0
                if cnt > max(size, 1):
                    raise ValueError(f"entry {path!r} has more chunks ({cnt:,}) than bytes ({size:,})")
                ptr_list = np.frombuffer(m, dtype="<u8", count=cnt, offset=o).tolist(); o += 8 * cnt
                entries.append(FileEntry(path, size, sha, ptr_list, kind, mt, mode, attrs))
            skipped = []
            if v3:
                (ns,) = struct.unpack_from("<I", m, o); o += 4
                for _ in range(ns):
                    (pl,) = struct.unpack_from("<H", m, o); o += 2
                    path = m[o:o + pl].decode("utf-8", "surrogateescape"); o += pl
                    (rl,) = struct.unpack_from("<H", m, o); o += 2
                    skipped.append((path, m[o:o + rl].decode("utf-8", "replace"))); o += rl
            if o != len(m):
                raise ValueError("trailing bytes in manifest")
        except (struct.error, ValueError, UnicodeDecodeError) as e:
            raise IntegrityError(f"corrupt manifest at {off}: {e}") from e
        return Snapshot(off, version, prev, created, label, first_pack, packs, entries, digests, ptrs,
                        skipped=skipped)

    def _build_index(self):
        for s in self.snapshots:
            if s.damaged:
                continue                # its chunks are simply stored again when next seen
            if s.version >= 2:
                d = s.index_digests
                for i, p in enumerate(s.index_ptrs):
                    self.index[d[32 * i:32 * i + 32]] = p
            else:
                # v1 stores carry no index: hash every chunk once.
                for k in range(len(s.packs)):
                    pid = s.first_pack + k
                    for i, c in enumerate(self._pack(pid)):
                        self.index.setdefault(hashlib.sha256(c).digest(), (pid << PTR_SHIFT) | i)

    # ---- data ----
    def _pack(self, pid: int) -> list[bytes]:
        pack = self._cache.get(pid)
        if pack is not None:
            self._cache.move_to_end(pid)
            return pack
        if pid >= len(self.pack_offsets):
            raise IntegrityError(f"pointer to missing pack {pid}")
        pack = _decode_pack(self._block(self.pack_offsets[pid], self.pack_ends[pid])[0])
        self._cache[pid] = pack
        self._cache_used += sum(map(len, pack)) + 64 * len(pack)
        while self._cache_used > self._cache_max and len(self._cache) > 1:
            _, old = self._cache.popitem(last=False)
            self._cache_used -= sum(map(len, old)) + 64 * len(old)
        return pack

    def _chunk(self, ptr: int) -> bytes:
        pid, idx = ptr >> PTR_SHIFT, ptr & PTR_IDX_MASK
        pack = self._pack(pid)
        if idx >= len(pack):
            raise IntegrityError(f"pointer past end of pack {pid}")
        return pack[idx]

    def _snapshot(self, snapshot: int | None) -> Snapshot:
        if snapshot is None or snapshot == -1:
            snapshot = len(self.snapshots)
        if not 1 <= snapshot <= len(self.snapshots):
            raise ValueError(f"snapshot {snapshot} does not exist (store has {len(self.snapshots)})")
        s = self.snapshots[snapshot - 1]
        if s.damaged:
            raise IntegrityError(f"snapshot {snapshot}: {s.damaged}; its files cannot be listed or restored")
        return s

    def iter_file(self, e: FileEntry):
        """Yield the file's chunks; raises IntegrityError as soon as the data
        runs past the recorded size (a damaged or hostile file list could
        otherwise repeat one chunk without end), and at the end if the
        reassembled file does not match its recorded size and SHA-256."""
        h, n = hashlib.sha256(), 0
        for p in e.pointers:
            c = self._chunk(p)
            n += len(c)
            if n > e.size:
                raise IntegrityError(f"{e.path}: its data runs past its recorded size ({e.size:,} bytes); "
                                     f"the file list is damaged")
            h.update(c)
            yield c
        if n != e.size or h.digest() != e.sha256:
            raise IntegrityError(f"SHA-256 mismatch restoring {e.path}")

    def read_file(self, e: FileEntry) -> bytes:
        return b"".join(self.iter_file(e))

    def _restore_plan(self, snap: Snapshot, warnings: list[str]) -> list[tuple[list[str], FileEntry]]:
        """Check every path of a snapshot before anything is written. Paths no
        backup can produce (escaping the folder, listed twice, or lying inside
        a symlink of the same snapshot) raise IntegrityError. Paths this system
        cannot hold (Windows device names, names differing only in case on a
        case-insensitive disk) are skipped with a warning, with everything
        below them."""
        keyed, links, seen = [], set(), set()
        for e in snap.entries:
            parts = _safe_parts(e.path)
            key = "/".join(parts)
            if key in seen:
                raise IntegrityError(f"unsafe file list: {e.path} appears twice in the snapshot")
            seen.add(key)
            if e.kind in (KIND_LINK, KIND_DIRLINK):
                links.add(key)
            keyed.append((parts, key, e))
        plan, skipped, folded = [], set(), {}
        for parts, key, e in keyed:
            above = ["/".join(parts[:i]) for i in range(1, len(parts))]
            inside_link = next((a for a in above if a in links), None)
            if inside_link is not None:
                raise IntegrityError(f"unsafe file list: {e.path} lies inside the symlink {inside_link}; "
                                     f"no backup contains that")
            if any(a in skipped for a in above):
                skipped.add(key)
                continue
            why = _unportable(parts)
            if not why and CASE_INSENSITIVE_FS:
                other = folded.setdefault(key.casefold(), e.path)
                if other != e.path:
                    why = f"this system ignores case in names, and {other} has the same name"
            if why:
                warnings.append(f"{e.path}: not restored ({why})")
                skipped.add(key)
                continue
            plan.append((parts, e))
        return plan

    def unpack(self, out_dir: str, snapshot: int | None = None, overwrite: bool = False,
               fsync: bool = False) -> list[str]:
        """Restore a snapshot: files, directories (including empty ones),
        modification times, read-only / permission bits (not setuid/setgid),
        Windows hidden / system attributes and symlinks. Returns warnings for
        things that could not be restored (e.g. symlinks on Windows without
        the privilege to create them, names Windows cannot hold).

        The restore is safe with stores from anywhere:
        - every path is checked first; nothing is written outside out_dir,
          nothing is written through a symlink, and symlinks are created last,
          after re-checking where each one goes;
        - every file is first written to a new temporary file (created
          exclusively, never through an existing link) and its size and
          SHA-256 are proven; only when ALL files and link targets are proven
          are they renamed into place, so a damaged store changes nothing in
          out_dir (also with overwrite=True);
        - the files must fit in the free space, checked before writing.

        Existing files, links or folders in the way are never replaced unless
        overwrite=True: the whole snapshot is checked first and
        RestoreConflictError lists them before anything is written.

        snapshot=None means the newest. If the newest snapshot's footer is
        damaged, IntegrityError says so instead of quietly restoring an older
        one; pass that older snapshot's number explicitly, or run repair.

        fsync=True makes each restored file durable before it is renamed into
        place (and, on POSIX, each directory at the end): slower, but a power
        cut right after the restore cannot leave empty or partial files."""
        if snapshot is None and self.tail_snapshot is not None:
            raise IntegrityError(f"{self._tail_message()}. Nothing was restored; to restore the newest "
                                 f"readable snapshot instead, ask for it by number "
                                 f"(--snapshot {len(self.snapshots)})")
        root = os.path.realpath(out_dir)
        snap = self._snapshot(snapshot)
        warnings: list[str] = []
        plan = self._restore_plan(snap, warnings)
        if not overwrite and os.path.isdir(root):
            clash = []
            for parts, e in plan:
                dest = os.path.join(root, *parts)
                if e.kind == KIND_DIR:
                    if os.path.lexists(dest) and not os.path.isdir(dest):
                        clash.append(e.path)
                elif os.path.lexists(dest):
                    clash.append(e.path)
            if clash:
                raise RestoreConflictError(clash)
        need = sum(e.size for _, e in plan if e.kind == KIND_FILE)
        free = shutil.disk_usage(_existing_ancestor(root)).free
        if need > free:
            raise RestoreSpaceError(f"the snapshot's files need {need:,} bytes but only {free:,} are free "
                                    f"at {root}; nothing was restored")

        def inside(p):
            return p == root or p.startswith(root + os.sep)

        def parent_of(parts, e):
            # Resolved now, so a link already in the folder that leads outside is caught.
            parent = os.path.realpath(os.path.join(root, *parts[:-1]))
            if not inside(parent):
                raise IntegrityError(f"unsafe path: {e.path} would be written outside {root} "
                                     f"(a link in the way leads elsewhere)")
            return parent

        created: list[str] = []         # folders this restore made; removed again if it fails

        def mkdirs(d):
            missing, p = [], d
            while not os.path.lexists(p):
                missing.append(p)
                p = os.path.dirname(p)
            os.makedirs(d, exist_ok=True)
            created.extend(reversed(missing))

        staged, dirs, links, moved = [], [], [], 0    # staged: (temp file, destination, entry)
        root_final = root_fd = None
        try:
            # 1. write and prove everything, changing nothing that exists
            mkdirs(root)
            if os.name == "nt":
                root_final = _win_root(root)
            else:
                root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
            for parts, e in plan:
                if e.kind == KIND_DIR:
                    dest = os.path.join(parent_of(parts, e), parts[-1])
                    if os.path.lexists(dest) and not inside(os.path.realpath(dest)):
                        raise IntegrityError(f"unsafe path: {e.path} is a link in the output folder "
                                             f"that leads outside {root}")
                    mkdirs(dest)
                    dirs.append((dest, e, parts))
                elif e.kind in (KIND_LINK, KIND_DIRLINK):
                    if e.size > LINK_TARGET_MAX:
                        raise IntegrityError(f"{e.path}: symlink target of {e.size:,} bytes; the file list "
                                             f"is damaged")
                    links.append((parts, e, self.read_file(e).decode("utf-8", "surrogateescape")))
                else:
                    parent = parent_of(parts, e)
                    dest = os.path.join(parent, parts[-1])
                    if os.path.isdir(dest) and not _is_link(dest):
                        raise RestoreConflictError([e.path])      # a folder is where the file goes
                    mkdirs(parent)
                    staged.append((self._write_temp(parent, e, fsync), dest, e))
            # 2. everything is proven: move the files into place
            for tmp, dest, e in staged:
                if _is_link(dest):
                    os.unlink(dest)                 # replace the link itself, never its target
                elif os.path.lexists(dest):
                    _make_writable(dest, root_final)
                os.replace(tmp, dest)
                moved += 1
                if os.name == "nt":                 # POSIX: already set on the temp file
                    _apply_meta_win(dest, e, root_final)
        except BaseException:
            if root_fd is not None:
                os.close(root_fd)
            for tmp, _, _ in staged[moved:]:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            for d in reversed(created):
                try:
                    os.rmdir(d)                     # only if still empty
                except OSError:
                    pass
            raise
        # 3. links last; where each goes is checked again now that the files exist
        for parts, e, target in links:
            try:
                parent = parent_of(parts, e)
                dest = os.path.join(parent, parts[-1])
                os.makedirs(parent, exist_ok=True)
                if _is_link(dest):
                    os.unlink(dest)
                elif os.path.isdir(dest):
                    raise OSError(0, "a directory is in the way")
                elif os.path.lexists(dest):
                    _make_writable(dest, root_final)
                    os.remove(dest)
                if not _make_junction(target, dest, e):
                    os.symlink(target, dest, target_is_directory=e.kind == KIND_DIRLINK)
            except OSError as ex:
                warnings.append(f"{e.path}: symlink -> {target} not created ({ex.strerror or ex})")
        try:
            for dest, e, parts in sorted(dirs, key=lambda d: d[1].path.count("/"), reverse=True):
                try:                        # after the contents, so the mtime sticks
                    if os.name == "nt":
                        _apply_meta_win(dest, e, root_final)
                    else:
                        _dir_meta_beneath(root_fd, parts, e)
                except OSError as ex:
                    warnings.append(f"{e.path}: metadata not restored ({ex.strerror or ex})")
        finally:
            if root_fd is not None:
                os.close(root_fd)
        if fsync and os.name != "nt":       # Windows cannot open a directory to fsync it
            for d in {root} | {os.path.dirname(os.path.join(root, *parts)) for parts, _ in plan}:
                try:
                    fd = os.open(d, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                except OSError:
                    pass
        return warnings

    def _write_temp(self, parent: str, e: FileEntry, fsync: bool) -> str:
        """Write a file's data, proven by size and SHA-256, to a new temporary
        file in parent. The name is random and the file is created exclusively,
        so an existing file or link with that name is never written through."""
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
        for _ in range(100):
            tmp = os.path.join(parent, f".hcs-{secrets.token_hex(6)}.partial")
            try:
                fd = os.open(tmp, flags, 0o666)
                break
            except FileExistsError:
                continue
        else:
            raise OSError(f"could not create a temporary file in {parent}")
        try:
            with os.fdopen(fd, "wb") as fh:
                for c in self.iter_file(e):
                    fh.write(c)
                fh.flush()
                if os.name != "nt":
                    _meta_fd(fh.fileno(), e)    # on this file itself, before it is moved into place
                if fsync:
                    os.fsync(fh.fileno())
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        return tmp

    def check_layout(self):
        """Every byte from the header to the newest footer must belong to a
        block, a manifest or a footer, in the order the writer produced them,
        and every superseded footer must still point at its manifest. Reads
        only block headers."""
        def end_of(off):
            hdr = self._read(off, HDR.size)
            if len(hdr) != HDR.size or hdr[:3] != BLOCK_MAGIC:
                raise IntegrityError(f"no block header at {off}")
            return off + HDR.size + HDR.unpack(hdr)[3]
        pos = len(STORE_MAGIC)
        if self.encrypted:
            pos = end_of(pos)
        if self.has_dict:
            pos = end_of(pos)
        for s in self.snapshots:
            for off in s.packs:
                if off != pos:
                    raise IntegrityError(f"store layout broken: pack at {off}, expected {pos}")
                pos = end_of(off)
            if s.offset != pos:
                raise IntegrityError(f"store layout broken: manifest at {s.offset}, expected {pos}")
            pos = s.block_end
            moff, magic = FOOTER.unpack(self._read(pos, FOOTER.size).ljust(FOOTER.size, b"\0"))
            if magic != STORE_MAGIC or moff != s.offset:
                raise IntegrityError(f"damaged snapshot footer at {pos}")
            pos += FOOTER.size
        if pos != self.end:
            raise IntegrityError(f"store layout broken: {self.end - pos:,} unaccounted bytes before the footer")

    def scan(self, snapshot: int | None = None, strict: bool = True) -> dict:
        """Check everything and collect EVERY problem instead of stopping at the
        first. snapshot=None checks the whole store: byte layout, every pack's
        CRC (including packs no file uses any more), that every dedup-index
        entry points at a chunk with that SHA-256 (a bad index would corrupt
        future backups), and every file of every snapshot. strict=True also
        reports bytes past the last complete snapshot.

        Returns {"problems": [str], "damaged_files": {snapshot: [(path, why)]},
        "bad_packs": {pack_id: why}, "files": regular files covered}."""
        problems: list[str] = []
        bad_packs: dict[int, str] = {}
        damaged: dict[int, list] = {}
        if strict and self.end != self.file_size:
            problems.append(self._tail_message())
        if snapshot is None:
            nums = list(range(1, len(self.snapshots) + 1))
            try:
                self.check_layout()
            except IntegrityError as e:
                problems.append(str(e))
            for num, s in enumerate(self.snapshots, 1):
                want = {}
                if s.damaged:
                    problems.append(f"snapshot {num}: {s.damaged}; its file list is lost "
                                    f"(`prune --remove {num}` rebuilds the store without it)")
                elif s.version >= 2:
                    m, _, _ = self._block(s.offset)
                    full = self._parse_manifest(m, s.offset, keep_index=True)
                    want = {p: full.index_digests[32 * i:32 * i + 32] for i, p in enumerate(full.index_ptrs)}
                seen = 0
                for k in range(len(s.packs)):
                    pid = s.first_pack + k
                    try:
                        chunks = self._pack(pid)
                    except IntegrityError as e:
                        bad_packs[pid] = str(e)
                        problems.append(f"pack {pid} (added by snapshot {num}) is damaged: {e}")
                        continue
                    for i, c in enumerate(chunks):
                        d = want.get((pid << PTR_SHIFT) | i)
                        if d is not None:
                            seen += 1
                            if hashlib.sha256(c).digest() != d:
                                problems.append(f"dedup index entry for pack {pid} chunk {i} is wrong "
                                                f"(snapshot {num}); later backups could reuse bad data")
                if seen != len(want) and not any(s.first_pack + k in bad_packs for k in range(len(s.packs))):
                    problems.append(f"dedup index of snapshot {num} points outside its packs")
        else:
            nums = [snapshot if snapshot != -1 else len(self.snapshots)]
            self._snapshot(nums[0])             # ValueError / IntegrityError for a bad number
        done: dict[tuple, str | None] = {}
        n = 0
        for num in nums:
            s = self.snapshots[num - 1]
            try:
                self._restore_plan(s, [])       # paths no backup produces: restore would refuse them
            except IntegrityError as x:
                problems.append(f"snapshot {num}: {x}")
            for e in s.entries:
                n += e.kind == KIND_FILE
                key = (e.sha256, e.size, tuple(e.pointers))
                if key not in done:
                    err = next((f"its data is in damaged pack {p >> PTR_SHIFT}" for p in e.pointers
                                if p >> PTR_SHIFT in bad_packs), None)
                    if err is None:
                        try:
                            for _ in self.iter_file(e):
                                pass
                        except IntegrityError as x:
                            err = str(x)
                    done[key] = err
                if done[key]:
                    damaged.setdefault(num, []).append((e.path, done[key]))
        for num, bad in damaged.items():
            total = len(self.snapshots[num - 1].entries)
            problems.append(f"snapshot {num}: {len(bad)} of {total} item(s) cannot be restored intact")
        par = Parity(self.f.name)
        pstat = par.check() if snapshot is None and par.exists() else None
        return {"problems": problems, "damaged_files": damaged, "bad_packs": bad_packs, "files": n,
                "parity": pstat}

    def verify(self, snapshot: int | None = None, strict: bool = True) -> int:
        """Like scan(), but raises IntegrityError if anything is wrong.
        Returns the number of regular files covered."""
        rep = self.scan(snapshot, strict)
        p = rep["problems"]
        if p:
            raise IntegrityError(p[0] + (f" (and {len(p) - 1} more problem(s); `verify` lists them all)"
                                         if len(p) > 1 else ""))
        return rep["files"]

    def unused_ranges(self) -> list[tuple[int, int]]:
        """Byte ranges no snapshot depends on (superseded footers)."""
        return [(s.block_end, s.block_end + FOOTER.size) for s in self.snapshots[:-1]]

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------
# Parity: Reed-Solomon recovery data in a sidecar '<store>.hcp'
#
# The store file is cut into shards of SHARD bytes; every K consecutive data
# shards form a group, and M parity shards are computed for it (systematic
# Reed-Solomon over GF(256) with a Cauchy matrix). Each shard's 16-byte BLAKE2b
# is recorded, so damaged shards are located exactly and treated as erasures:
# any M damaged shards per group (data or parity) can be rebuilt. Parity covers
# EVERY byte of the store (packs, manifests, footers, the dictionary), so no
# region is a single point of failure. A rebuilt shard is written back only if
# its hash equals the recorded one: stale or wrong parity can never write
# anything but the exact original bytes. See FORMAT.md, section 7.
# --------------------------------------------------------------------------
PARITY_MAGIC = b"HCPAR001"
PAR_HDR = struct.Struct("<8sIHHQI32sI")          # magic, shard, k, m, covered, groups, reserved, crc
PARITY_SHARD, PARITY_K, PARITY_M = 64 << 10, 16, 2
# Interleaving: groups are formed across a "super-group" of DEPTH x K shards
# (16 MiB), data shard i of group j being store shard i*DEPTH + j. A burst of
# damage then spreads over DEPTH groups: with M = 2, any 2 MiB burst per 16 MiB
# is repairable instead of 128 KiB per 1 MiB. Stored in the header's first
# reserved u16 (0 = 1 = no interleaving, the original layout).
PARITY_DEPTH = 16


def _gf_tables():
    exp = np.zeros(512, dtype=np.uint8)
    log = np.zeros(256, dtype=np.int32)
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    exp[255:510] = exp[:255]
    mul = np.zeros((256, 256), dtype=np.uint8)
    a = np.arange(1, 256)
    for c in range(1, 256):
        mul[c, 1:] = exp[(log[c] + log[a]) % 255]
    return exp, log, mul


_GF_EXP, _GF_LOG, _GF_MUL = _gf_tables()


def _gf_inv(a: int) -> int:
    return int(_GF_EXP[255 - _GF_LOG[a]])


def _gf_mul(a: int, b: int) -> int:
    return int(_GF_MUL[a, b])


def _cauchy(k: int, m: int) -> list[list[int]]:
    """M x K Cauchy matrix: every square submatrix is invertible, so any K of
    the K+M shards determine the rest."""
    return [[_gf_inv(j ^ (m + i)) for i in range(k)] for j in range(m)]


def _gf_invert(a: list[list[int]]) -> list[list[int]]:
    n = len(a)
    a = [row[:] + [int(i == r) for i in range(n)] for r, row in enumerate(a)]
    for col in range(n):
        piv = next(r for r in range(col, n) if a[r][col])
        a[col], a[piv] = a[piv], a[col]
        inv = _gf_inv(a[col][col])
        a[col] = [_gf_mul(v, inv) for v in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                f = a[r][col]
                a[r] = [v ^ _gf_mul(f, w) for v, w in zip(a[r], a[col])]
    return [row[n:] for row in a]


def _gf_combine(coefs: list[int], shards: list[np.ndarray]) -> np.ndarray:
    out = np.zeros(len(shards[0]), dtype=np.uint8)
    for c, s in zip(coefs, shards):
        if c:
            out ^= s if c == 1 else _GF_MUL[c][s]
    return out


def _shard_hash(b) -> bytes:
    return hashlib.blake2b(b, digest_size=16).digest()


class Parity:
    """The '<store>.hcp' sidecar. Layout: a 64-byte header, then one fixed-size
    record per group: u32 group | u32 data_len | (K+M) x 16-byte BLAKE2b (data
    shards zero-padded to SHARD, then parity shards) | u32 crc32 of the fields
    before it | M x SHARD parity bytes. Groups are interleaved inside
    super-groups of DEPTH x K shards; see FORMAT.md section 7."""

    def __init__(self, store: str):
        self.store, self.path = store, store + ".hcp"

    # ---- layout ----
    def _rec_size(self, k, m, shard):
        return 8 + 16 * (k + m) + 4 + m * shard

    def _read_header(self, f):
        raw = f.read(PAR_HDR.size)
        if len(raw) != PAR_HDR.size:
            raise IntegrityError("parity file header is truncated")
        magic, shard, k, m, covered, groups, res, crc = PAR_HDR.unpack(raw)
        if magic != PARITY_MAGIC or zlib.crc32(raw[:-4]) & 0xFFFFFFFF != crc:
            raise IntegrityError("parity file header is damaged")
        depth = struct.unpack_from("<H", res)[0] or 1
        if not (shard and 0 < m and 0 < k and k + m <= 255 and depth <= 1024
                and groups == -(-covered // (k * shard))):
            raise IntegrityError("parity file header is inconsistent")
        return shard, k, m, covered, depth

    @staticmethod
    def _header(shard, k, m, covered, depth):
        groups = -(-covered // (k * shard))
        res = struct.pack("<H", depth).ljust(32, b"\0")
        raw = PAR_HDR.pack(PARITY_MAGIC, shard, k, m, covered, groups, res, 0)
        return raw[:-4] + struct.pack("<I", zlib.crc32(raw[:-4]) & 0xFFFFFFFF)

    def params(self) -> dict | None:
        """shard / k / m / depth of the existing sidecar (None: none or unreadable)."""
        try:
            with open(self.path, "rb") as f:
                shard, k, m, _, depth = self._read_header(f)
        except (OSError, IntegrityError):
            return None
        return {"shard": shard, "k": k, "m": m, "depth": depth}

    @staticmethod
    def _supers(size, shard, k, depth):
        """(super-group number, first store byte, number of groups) for a store
        of `size` bytes. Every super-group but the last has `depth` groups; the
        last has just enough for its shards, so small stores pay no more."""
        span = depth * k * shard
        for sg in range(-(-size // span)):
            base = sg * span
            ng = depth if base + span <= size else -(-(-(-(size - base) // shard)) // k)
            yield sg, base, ng

    @staticmethod
    def _super_data(sf, base, ng, k, shard, size):
        """[k, ng, shard] array: [i, j] is data shard i of group j, i.e. store
        shard i*ng + j of the super-group (zero-padded past the end)."""
        n = max(0, min(k * ng * shard, size - base))
        sf.seek(base)
        raw = sf.read(n)
        buf = np.zeros(k * ng * shard, dtype=np.uint8)
        buf[:len(raw)] = np.frombuffer(raw, dtype=np.uint8)
        return buf.reshape(k, ng, shard)

    @staticmethod
    def _offsets(base, ng, j, k, shard):
        return [base + (i * ng + j) * shard for i in range(k)]

    @staticmethod
    def _len(a, total, shard):
        return max(0, min(shard, total - a))

    def _record(self, g, data, n, k, m, shard):
        C = _cauchy(k, m)
        par = [_gf_combine(C[j], data) for j in range(m)]
        head = struct.pack("<II", g, n) + b"".join(_shard_hash(s) for s in data + par)
        return head + struct.pack("<I", zlib.crc32(head) & 0xFFFFFFFF) + b"".join(p.tobytes() for p in par)

    def _parse_record(self, raw, g, k, m, shard):
        hl = 8 + 16 * (k + m)
        if len(raw) != self._rec_size(k, m, shard):
            return None
        head, crc = raw[:hl], struct.unpack_from("<I", raw, hl)[0]
        if zlib.crc32(head) & 0xFFFFFFFF != crc or struct.unpack_from("<I", head)[0] != g:
            return None
        n = struct.unpack_from("<I", head, 4)[0]
        hashes = [head[8 + 16 * i:24 + 16 * i] for i in range(k + m)]
        o = hl + 4
        par = [np.frombuffer(raw, dtype=np.uint8, count=shard, offset=o + j * shard) for j in range(m)]
        return n, hashes, par

    def _write_supers(self, pf, sf, supers, k, m, shard, depth, size):
        rs = self._rec_size(k, m, shard)
        for sg, base, ng in supers:
            arr = self._super_data(sf, base, ng, k, shard, size)
            pf.seek(PAR_HDR.size + sg * depth * rs)
            for j in range(ng):
                offs = self._offsets(base, ng, j, k, shard)
                n = sum(self._len(a, size, shard) for a in offs)
                pf.write(self._record(sg * depth + j, [arr[i, j] for i in range(k)], n, k, m, shard))

    # ---- writing ----
    def exists(self) -> bool:
        return os.path.exists(self.path)

    def build(self, shard=PARITY_SHARD, k=PARITY_K, m=PARITY_M, depth=PARITY_DEPTH) -> dict:
        """(Re)compute parity for the whole store into a new sidecar."""
        if not (0 < m and 0 < k and k + m <= 255 and 1 <= depth <= 1024):
            raise ValueError("parity: need 1 <= m, k + m <= 255, 1 <= depth <= 1024")
        tmp = self.path + "-new"
        size = os.path.getsize(self.store)
        with open(self.store, "rb") as sf, open(tmp, "wb") as pf:
            pf.write(self._header(shard, k, m, size, depth))
            self._write_supers(pf, sf, self._supers(size, shard, k, depth), k, m, shard, depth, size)
            pf.flush()
            os.fsync(pf.fileno())
        os.replace(tmp, self.path)
        return {"covered": size, "bytes": os.path.getsize(self.path), "m": m, "depth": depth}

    def update(self, from_offset: int) -> dict:
        """After an append (or truncation) at from_offset: recompute only the
        super-groups from the one holding from_offset to the end. The bytes of
        that super-group before from_offset are checked against their recorded
        hashes first, so damage in old data is never baked into new parity."""
        size = os.path.getsize(self.store)
        with open(self.path, "r+b") as pf, open(self.store, "rb") as sf:
            shard, k, m, covered, depth = self._read_header(pf)
            rs = self._rec_size(k, m, shard)
            keep = min(from_offset, covered)
            sg0 = keep // (depth * k * shard)
            old = list(self._supers(covered, shard, k, depth))
            if sg0 < len(old) and old[sg0][1] < keep:
                _, base, ng = old[sg0]
                arr = self._super_data(sf, base, ng, k, shard, size)
                for j in range(ng):
                    g = sg0 * depth + j
                    pf.seek(PAR_HDR.size + g * rs)
                    rec = self._parse_record(pf.read(rs), g, k, m, shard)
                    for i, a in enumerate(self._offsets(base, ng, j, k, shard)):
                        if a >= keep:
                            continue
                        if a + shard <= keep:
                            cur = arr[i, j].tobytes()
                        elif keep == covered:              # pure append: the old tail shard was zero-padded
                            cur = arr[i, j][:keep - a].tobytes() + b"\0" * (shard - (keep - a))
                        else:
                            continue                       # bytes after the cut changed legitimately
                        if rec is None or _shard_hash(cur) != rec[1][i]:
                            raise IntegrityError(f"stored bytes before offset {from_offset:,} do not match their "
                                                 f"parity record; run `repair` (parity was not updated)")
            new = list(self._supers(size, shard, k, depth))
            self._write_supers(pf, sf, new[sg0:], k, m, shard, depth, size)
            groups = -(-size // (k * shard))
            pf.truncate(PAR_HDR.size + groups * rs)
            pf.seek(0)
            pf.write(self._header(shard, k, m, size, depth))
            pf.flush()
            os.fsync(pf.fileno())
        return {"covered": size, "supers_written": len(new) - sg0}

    # ---- checking / repairing ----
    def check(self, fix: bool = False) -> dict:
        """Hash every shard of the store against the parity records. With
        fix=True, damaged data shards are rebuilt and written back in place
        (only when the rebuilt bytes hash to the recorded value)."""
        res = {"covered": 0, "size": os.path.getsize(self.store), "groups": 0, "bad_shards": 0,
               "repaired_shards": 0, "unrepairable_groups": [], "bad_records": [], "header_ok": True}
        try:
            pf = open(self.path, "rb")
        except OSError:
            res["header_ok"] = False
            return res
        with pf, open(self.store, "r+b" if fix else "rb") as sf:
            try:
                shard, k, m, covered, depth = self._read_header(pf)
            except IntegrityError as e:
                res["header_ok"] = False
                res["error"] = str(e)
                return res
            res.update(covered=covered, groups=-(-covered // (k * shard)), m=m, depth=depth)
            rs, C = self._rec_size(k, m, shard), _cauchy(k, m)
            size = res["size"]
            for sg, base, ng in self._supers(covered, shard, k, depth):
                # Only the covered bytes: bytes appended after `covered` (an interrupted write) are
                # not part of any shard, and must not make the last shard look damaged.
                arr = self._super_data(sf, base, ng, k, shard, min(size, covered))
                pf.seek(PAR_HDR.size + sg * depth * rs)
                for j in range(ng):
                    g = sg * depth + j
                    rec = self._parse_record(pf.read(rs), g, k, m, shard)
                    if rec is None:
                        res["bad_records"].append(g)
                        continue
                    _, hashes, par = rec
                    data = [arr[i, j] for i in range(k)]
                    offs = self._offsets(base, ng, j, k, shard)
                    bad = [i for i in range(k) if _shard_hash(data[i]) != hashes[i]
                           or self._len(offs[i], size, shard) < self._len(offs[i], covered, shard)]
                    if not bad:
                        continue
                    res["bad_shards"] += len(bad)
                    good_par = [t for t in range(m) if _shard_hash(par[t]) == hashes[k + t]]
                    if len(bad) > len(good_par):
                        res["unrepairable_groups"].append(g)
                        continue
                    # Solve for the bad data shards from the good ones + enough good parity.
                    rows, vecs = [], []
                    for i in range(k):
                        if i not in bad:
                            rows.append([int(t == i) for t in range(k)])
                            vecs.append(data[i])
                    for t in good_par[:len(bad)]:
                        rows.append(C[t])
                        vecs.append(par[t])
                    inv = _gf_invert(rows)
                    fixed = {i: _gf_combine(inv[i], vecs) for i in bad}
                    if any(_shard_hash(fixed[i]) != hashes[i] for i in bad):
                        res["unrepairable_groups"].append(g)       # parity does not belong to this data
                        continue
                    if fix:
                        for i in bad:
                            ln = self._len(offs[i], covered, shard)
                            if ln:
                                sf.seek(offs[i])
                                sf.write(fixed[i][:ln].tobytes())
                        res["repaired_shards"] += len(bad)
            if fix and res["repaired_shards"]:
                sf.flush()
                os.fsync(sf.fileno())
        return res


def parity_summary(c: dict) -> str:
    if not c["header_ok"]:
        return "parity: none" if "error" not in c else f"parity: unusable ({c['error']})"
    parts = [f"parity covers {c['covered']:,} of {c['size']:,} store bytes"]
    if c["bad_shards"]:
        parts.append(f"{c['bad_shards']} damaged shard(s) found"
                     + (f", {len(c['unrepairable_groups'])} group(s) beyond repair" if c["unrepairable_groups"]
                        else ", all repairable with `repair`"))
    else:
        parts.append("no damaged shards")
    if c["bad_records"]:
        parts.append(f"{len(c['bad_records'])} parity record(s) damaged (rebuilt by `repair` once the store "
                     f"verifies)")
    return "; ".join(parts)


def _refuse_damaged(path: str, problems: list[str]) -> IntegrityError:
    more = f" (and {len(problems) - 1} more problem(s))" if len(problems) > 1 else ""
    return IntegrityError(
        f"{path}: the check before writing found damage in the existing store: {problems[0]}{more}. "
        f"Nothing was written: a new snapshot reuses existing data, so it would depend on the damage. "
        f"`hybridstore.py verify {path}` lists what is affected and `python doctor.py fix {path}` says what "
        f"can be done (copy the store elsewhere first if the disk may be failing). `backup --no-precheck` "
        f"skips this check")


def _precheck_parity(path: str, stats: "Stats") -> int:
    """First half of the pre-write check (caller holds the store lock): hash
    every shard against the parity records. Damage parity can rebuild is
    rebuilt, each shard proven against its recorded hash; damage it cannot
    rebuild refuses the write before any byte is changed. Returns how far
    (store bytes) the store is now proven intact; 0 = parity proved nothing
    and every pack must be checked by decoding it."""
    par = Parity(path)
    if not par.exists():
        stats.precheck = "no parity: every pack decoded and CRC-checked"
        return 0
    c = par.check()
    if not c["header_ok"]:
        stats.precheck = f"parity unusable ({c.get('error', 'unreadable')}): every pack decoded and CRC-checked"
        return 0
    if c["unrepairable_groups"]:
        raise _refuse_damaged(path, [f"{c['bad_shards']} damaged {PARITY_SHARD >> 10} KiB shard(s), "
                                     f"{len(c['unrepairable_groups'])} group(s) beyond what parity can rebuild"])
    if c["bad_shards"]:
        c = par.check(fix=True)
        stats.precheck_fixed = True
        stats.precheck = (f"REBUILT {c['repaired_shards']} damaged {PARITY_SHARD >> 10} KiB shard(s) from parity "
                          f"before writing (each proven against its recorded hash). Damage that appears on its "
                          f"own can mean a failing disk")
    else:
        stats.precheck = f"all {c['covered']:,} bytes proven against parity"
    if c["bad_records"]:
        stats.precheck += (f"; {len(c['bad_records'])} parity record(s) damaged, so every pack was also "
                           f"decoded and CRC-checked")
        return 0
    return c["covered"]


def _precheck_blocks(r: "StoreReader", proven: int, stats: "Stats"):
    """Second half: the byte layout, every snapshot's file list, and every
    pack not already proven by parity (decoded, CRC / authentication checked)."""
    problems = []
    try:
        r.check_layout()
    except IntegrityError as e:
        problems.append(str(e))
    decoded = 0
    for num, s in enumerate(r.snapshots, 1):
        if s.damaged:
            problems.append(f"snapshot {num}: {s.damaged}")
        for k in range(len(s.packs)):
            pid = s.first_pack + k
            if r.pack_ends[pid] <= proven:
                continue
            try:
                r._pack(pid)
                decoded += 1
            except IntegrityError as e:
                problems.append(f"pack {pid} (snapshot {num}) is damaged: {e}")
    if problems:
        raise _refuse_damaged(r.f.name, problems)
    if proven and decoded:
        stats.precheck += f"; {decoded} pack(s) past the parity decoded and CRC-checked"


def repair(path: str, dry_run: bool = False) -> list[str]:
    """Fix what can be fixed without losing anything, under the store lock:

    * the newest snapshot is complete but its footer is damaged or was never
      written: its footer is written again, which makes it visible;
    * an older snapshot's footer is damaged: it is rewritten in place (only
      `verify` and recovery read old footers);
    * bytes after the last snapshot hold no complete snapshot (an interrupted
      write): they are cut off, as the next backup would do.

    Damaged packs or manifests cannot be repaired here: `verify` lists them,
    and `prune --remove` can rebuild the store without damaged snapshots.
    Returns a description of each change made (empty: nothing to do)."""
    if dry_run:
        return _repair_plan(path)
    lock = _StoreLock(path)
    try:
        done = []
        par = Parity(path)
        if par.exists():
            c = par.check(fix=True)
            if c["repaired_shards"]:
                done.append(f"rebuilt {c['repaired_shards']} damaged {PARITY_SHARD >> 10} KiB shard(s) "
                            f"from parity (each checked against its recorded hash)")
            if c["unrepairable_groups"]:
                done.append(f"could NOT rebuild {len(c['unrepairable_groups'])} group(s): too many damaged "
                            f"shards, or the parity does not match the store")
        done += _repair_footers(path)
        if par.exists():
            c = par.check()
            if not c["header_ok"] or c["bad_records"] or c["unrepairable_groups"] or c["covered"] != c["size"]:
                with StoreReader(path) as r:
                    clean = not r.scan()["problems"]
                if clean:
                    par.build(**(par.params() or {}))
                    done.append("rebuilt the parity file from the verified store")
        return done
    finally:
        lock.release()


def _repair_plan(path: str) -> list[str]:
    """What repair would do; changes nothing."""
    plan = []
    par = Parity(path)
    if par.exists():
        c = par.check()
        if c["bad_shards"]:
            plan.append(f"would rebuild damaged {PARITY_SHARD >> 10} KiB shard(s) from parity "
                        f"({c['bad_shards']} found; {len(c['unrepairable_groups'])} group(s) beyond repair)")
        if not c["header_ok"] or c["bad_records"] or c["covered"] != c["size"]:
            plan.append("would rebuild the parity file if the store then verifies")
    try:
        with StoreReader(path) as r:
            for s in r.snapshots[:-1]:
                if r._read(s.block_end, FOOTER.size) != FOOTER.pack(s.offset, STORE_MAGIC):
                    plan.append(f"would rewrite the damaged footer at byte {s.block_end:,}")
            if r.tail_snapshot is not None:
                plan.append("would write the missing/damaged footer of the newest snapshot")
            elif r.end != r.file_size:
                plan.append(f"would cut off {r.file_size - r.end:,} trailing bytes that hold no snapshot")
    except IntegrityError as e:
        plan.append(f"the store does not open yet ({e}); parity repair runs first")
    return plan


def _repair_footers(path: str) -> list[str]:
    """Footer / tail part of repair (the caller holds the lock)."""
    done = []
    with StoreReader(path) as r:
        tail, end, size = r.tail_snapshot, r.end, r.file_size
        fix = []
        for s in r.snapshots[:-1]:
            if r._read(s.block_end, FOOTER.size) != FOOTER.pack(s.offset, STORE_MAGIC):
                fix.append((s.block_end, s.offset))
    if not fix and end == size:
        return done
    with open(path, "r+b") as f:
        for pos, moff in fix:
            f.seek(pos)
            f.write(FOOTER.pack(moff, STORE_MAGIC))
            done.append(f"rewrote the damaged footer at byte {pos:,}")
        if tail is not None:
            f.truncate(tail[1])
            f.seek(tail[1])
            f.write(FOOTER.pack(tail[0], STORE_MAGIC))
            done.append("wrote the missing/damaged footer of the newest snapshot, which is visible again")
        elif end != size:
            f.truncate(end)
            done.append(f"cut off {size - end:,} bytes of an interrupted write (they held no snapshot)")
        f.flush()
        os.fsync(f.fileno())
    return done


def change_password(path: str, old: str | None, new: str) -> None:
    """Seal the store's data key under a new password (the data is not
    re-encrypted). Copies of the store made before still open with the old
    password. Refuses if the parity check finds damage."""
    lock = _StoreLock(path)
    try:
        with StoreReader(path, password=old) as r:
            if not r.encrypted:
                raise IntegrityError(f"{path} is not encrypted")
            key, kb = _KEYS[hashlib.sha256(r.key_block[HDR.size:]).digest()], r.key_block
        par = Parity(path)
        if par.exists():
            c = par.check()
            if c["bad_shards"] or c["bad_records"] or not c["header_ok"]:
                raise IntegrityError("the parity check found damage; run `repair` first")
        block, _ = make_key_block(new, key)
        assert len(block) == len(kb)
        with open(path, "r+b") as f:
            f.seek(len(STORE_MAGIC))
            f.write(block)
            f.flush()
            os.fsync(f.fileno())
        _KEYS.pop(hashlib.sha256(kb[HDR.size:]).digest(), None)
        if par.exists():
            par.build(**(par.params() or {}))
    finally:
        lock.release()


# --------------------------------------------------------------------------
# Deleting snapshots (prune)
# --------------------------------------------------------------------------
def select_snapshots(snaps: list[Snapshot], keep_last: int = 0, keep_daily: int = 0,
                     keep_weekly: int = 0, keep_monthly: int = 0) -> set[int]:
    """1-based numbers of the snapshots a retention policy keeps. Rules are
    applied per source folder (label), newest first, and their results are
    combined: keep_last N keeps the N newest; keep_daily N keeps the newest
    snapshot of each of the N most recent days that have one (local time);
    weekly uses ISO weeks, monthly calendar months."""
    import datetime
    groups: dict[str, list[int]] = {}
    for i, s in enumerate(snaps, 1):
        groups.setdefault(os.path.normcase(s.label), []).append(i)
    keep: set[int] = set()
    bucket = {"day": lambda d: d.isoformat(), "week": lambda d: d.isocalendar()[:2],
              "month": lambda d: (d.year, d.month)}
    for ids in groups.values():
        newest = sorted(ids, key=lambda i: (snaps[i - 1].created, i), reverse=True)
        keep.update(newest[:max(keep_last, 0)])
        for n, kind in ((keep_daily, "day"), (keep_weekly, "week"), (keep_monthly, "month")):
            seen = set()
            for i in newest:
                k = bucket[kind](datetime.date.fromtimestamp(snaps[i - 1].created))
                if k not in seen:
                    if len(seen) >= n:
                        break
                    seen.add(k)
                    keep.add(i)
    return keep


@dataclass
class PruneStats:
    kept: list[int]
    removed: list[int]
    bytes_before: int = 0
    bytes_after: int = 0
    packs_copied: int = 0       # still fully (or mostly) used: copied byte-for-byte
    packs_repacked: int = 0     # mostly unused: live chunks recompressed into new packs
    packs_dropped: int = 0      # no kept snapshot uses them
    new_packs: int = 0          # packs written by repacking
    dry_run: bool = False


def prune(path: str, remove, repack_below: float = 0.5, level: int = 19, dry_run: bool = False,
          workers: int | None = None) -> PruneStats:
    """Delete the given 1-based snapshots and reclaim their space.

    The store is rewritten to '<path>.hcs-new' under the store lock: kept
    snapshots keep their order, labels, times and skipped lists (snapshot
    numbers shift down). Packs no kept snapshot uses are dropped; a pack
    whose live bytes are at least `repack_below` of its contents is copied
    byte-for-byte; the live chunks of sparser packs are recompressed into new
    packs. The new store is fully verified before it replaces the old one,
    so an error or crash at any point leaves the original untouched. Needs
    free space for the new store next to the old one."""
    remove = set(remove)
    lock = _StoreLock(path)
    out = path + ".hcs-new"
    try:
        with StoreReader(path, load_index=True) as r:
            snaps = r.snapshots
            bad = sorted(i for i in remove if not 1 <= i <= len(snaps))
            if bad:
                raise ValueError(f"snapshot(s) {bad} do not exist (store has {len(snaps)})")
            kept = [i for i in range(1, len(snaps) + 1) if i not in remove]
            if not kept:
                raise ValueError("refusing to remove every snapshot")
            dmg = [i for i in kept if snaps[i - 1].damaged]
            if dmg:
                raise ValueError(f"snapshot(s) {dmg} are damaged (their file lists are lost) and cannot be "
                                 f"kept; add them to --remove to rebuild the store without them")
            ps = PruneStats(kept, sorted(remove), bytes_before=r.end, bytes_after=r.end, dry_run=dry_run)
            if not remove:
                return ps

            digest: dict[int, bytes] = {}
            for s in snaps:
                if s.version >= 2:
                    d = s.index_digests
                    for k, p in enumerate(s.index_ptrs):
                        digest[p] = d[32 * k:32 * k + 32]
            n_chunks: dict[int, int] = {}
            for p in digest:
                n_chunks[p >> PTR_SHIFT] = n_chunks.get(p >> PTR_SHIFT, 0) + 1
            used: dict[int, set[int]] = {}
            for i in kept:
                for e in snaps[i - 1].entries:
                    for p in e.pointers:
                        used.setdefault(p >> PTR_SHIFT, set()).add(p & PTR_IDX_MASK)

            def raw_block(off):
                slen = HDR.unpack(r._read(off, HDR.size))[3]
                return r._read(off, HDR.size + slen)

            # Decide, per live pack, copy or repack (in first-use order per kept snapshot).
            mode: dict[int, str] = {}
            plan: list[list[int]] = []
            for i in kept:
                order = []
                for e in snaps[i - 1].entries:
                    for p in e.pointers:
                        pid = p >> PTR_SHIFT
                        if pid not in mode:
                            total = n_chunks.get(pid)
                            if total is not None and len(used[pid]) >= total:
                                mode[pid] = "copy"
                            else:
                                chunks = r._pack(pid)
                                live = sum(len(chunks[k]) for k in used[pid])
                                full = sum(map(len, chunks)) or 1
                                mode[pid] = "copy" if live / full >= repack_below else "repack"
                            order.append(pid)
                plan.append(order)
            ps.packs_copied = sum(m == "copy" for m in mode.values())
            ps.packs_repacked = sum(m == "repack" for m in mode.values())
            ps.packs_dropped = len(r.pack_offsets) - len(mode)
            if dry_run:
                dropped = sum(len(raw_block(r.pack_offsets[pid])) for pid in range(len(r.pack_offsets))
                              if pid not in mode)
                ps.bytes_after = r.end - dropped            # estimate: ignores repack savings
                return ps

            codec = BlockCodec(zstd_level=level)
            codec.cipher = r.codec.cipher            # same key: copied packs stay readable
            nw = max(1, workers if workers is not None else min(os.cpu_count() or 1, 16))
            pool = ThreadPoolExecutor(nw, thread_name_prefix="hcs-prune") if nw > 1 else None
            f = open(out, "wb")
            try:
                f.write(STORE_MAGIC)
                pos = len(STORE_MAGIC)
                if r.encrypted:
                    f.write(r.key_block); pos += len(r.key_block)
                if r.has_dict:
                    blk = raw_block(r.dict_off)
                    f.write(blk); pos += len(blk)
                    codec.set_dictionary(r._block(r.dict_off)[0])
                new_offsets: list[int] = []
                remap: dict[int, int] = {}
                prev = 0
                for j, i in enumerate(kept):
                    s = snaps[i - 1]
                    first = len(new_offsets)
                    new_index: list[tuple[bytes, int]] = []
                    pending: deque = deque()     # ("copy", raw, pid, count) | ("repack", future, [(old_ptr, digest)])

                    def write_one():
                        nonlocal pos
                        kind, a, b, *rest = pending.popleft()
                        npid = len(new_offsets)
                        new_offsets.append(pos)
                        if kind == "copy":
                            f.write(a); pos += len(a)
                            for k in range(rest[0]):
                                op, np_ = (b << PTR_SHIFT) | k, (npid << PTR_SHIFT) | k
                                remap[op] = np_
                                new_index.append((digest.get(op) or hashlib.sha256(r._chunk(op)).digest(), np_))
                        else:
                            blk = a.result()[0] if pool else a
                            f.write(blk); pos += len(blk)
                            ps.new_packs += 1
                            for k, (op, dg) in enumerate(b):
                                remap[op] = (npid << PTR_SHIFT) | k
                                new_index.append((dg, (npid << PTR_SHIFT) | k))

                    batches: dict[int, list] = {}     # pack flags -> [(old_ptr, digest, chunk)]

                    def submit(flags):
                        items = batches.pop(flags)
                        payload = _encode_pack([c for _, _, c in items])
                        job = pool.submit(codec.encode, payload, flags) if pool else codec.encode(payload, flags)[0]
                        pending.append(("repack", job, [(op, dg) for op, dg, _ in items]))
                        while len(pending) > 4 * nw:
                            write_one()

                    for pid in plan[j]:
                        off = r.pack_offsets[pid]
                        if mode[pid] == "copy":
                            blk = raw_block(off)
                            count = n_chunks.get(pid) or len(r._pack(pid))
                            pending.append(("copy", blk, pid, count))
                            while len(pending) > 4 * nw:
                                write_one()
                            continue
                        flags = HDR.unpack(r._read(off, HDR.size))[1] & FLAG_MEDIA
                        chunks = r._pack(pid)
                        for k in sorted(used[pid]):
                            op = (pid << PTR_SHIFT) | k
                            dg = digest.get(op) or hashlib.sha256(chunks[k]).digest()
                            b = batches.setdefault(flags, [])
                            b.append((op, dg, chunks[k]))
                            if sum(len(c) for _, _, c in b) >= 1 << 20 or len(b) >= PTR_IDX_MASK:
                                submit(flags)
                    for flags in list(batches):
                        submit(flags)
                    while pending:
                        write_one()
                    entries = [FileEntry(e.path, e.size, e.sha256, [remap[p] for p in e.pointers],
                                         e.kind, e.mtime_ns, e.mode, e.attrs) for e in s.entries]
                    manifest = _build_manifest(prev, s.created, s.label, first, new_offsets[first:],
                                               new_index, entries, s.skipped)
                    block, _ = codec.encode(manifest, FLAG_MANIFEST)
                    moff = pos
                    f.write(block); pos += len(block)
                    f.write(FOOTER.pack(moff, STORE_MAGIC)); pos += FOOTER.size
                    prev = moff
                f.flush(); os.fsync(f.fileno())
            finally:
                f.close()
                if pool:
                    pool.shutdown(wait=True)
        # Prove the new store before it replaces the old one.
        with StoreReader(out) as r2:
            if len(r2.snapshots) != len(kept):
                raise IntegrityError("pruned store has the wrong number of snapshots")
            r2.verify()
        had_parity = Parity(path).exists()
        if had_parity:
            Parity(out).build(**(Parity(path).params() or {}))
        os.replace(out, path)
        if had_parity:
            os.replace(out + ".hcp", path + ".hcp")
        ps.bytes_after = os.path.getsize(path)
        return ps
    except BaseException:
        for leftover in (out, out + ".hcp", out + ".hcp-new"):
            try:
                if os.path.exists(leftover):
                    os.remove(leftover)
            except OSError:
                pass
        raise
    finally:
        lock.release()


def _fmt(st: Stats) -> str:
    r = st.input_bytes / st.store_bytes if st.store_bytes else 0
    return (f"snapshot={st.snapshot} files={st.files} input={st.input_bytes:,}B "
            f"added={st.added_bytes:,}B store={st.store_bytes:,}B ratio={r:.2f}x\n"
            f"unchanged files reused={st.reused_files} ({st.reused_bytes:,}B not read) "
            f"dirs={st.dirs} links={st.links}\n"
            f"chunks total={st.chunks_total} unique={st.chunks_unique} dedup_saved={st.dedup_bytes:,}B "
            f"packs={st.packs}\n"
            f"media_files={st.media_files} near_dup_images={st.near_dup_images} "
            f"raw_fallback_blocks={st.raw_fallback_blocks} ({st.raw_fallback_bytes:,}B)\n"
            f"codecs={st.codec_counts} dict_coded={st.dict_blocks} dict={st.dict_bytes:,}B "
            f"manifest={st.manifest_bytes:,}B")


def _write(store: str, src: str, append: bool, level: int = 19, workers: int | None = None,
           rehash: bool = False, parity: bool | None = None, pack_mb: float = 1,
           encrypt: bool = False, cloud_files: bool = False, precheck: bool = True,
           catalog: bool = True) -> int:
    if not os.path.isdir(src):
        print(f"error: {src} is not a directory", file=sys.stderr)
        return 2
    t0 = time.time()
    w = StoreWriter(store, codec=BlockCodec(zstd_level=level), append=append, workers=workers, parity=parity,
                    pack_target=max(1 << 16, int(pack_mb * (1 << 20))), encrypt=encrypt,
                    cloud_files=cloud_files, precheck=precheck)
    if w.stats.precheck:
        print(f"{'warning: ' if w.stats.precheck_fixed else ''}checked before writing "
              f"({time.time() - t0:.1f}s): {w.stats.precheck}", file=sys.stderr if w.stats.precheck_fixed else sys.stdout)
    elif append and not w.created and not precheck:
        print("warning: --no-precheck: the existing store was not checked before writing", file=sys.stderr)
    if w.recovered_bytes:
        print(f"note: discarded {w.recovered_bytes:,} bytes left by an interrupted earlier run",
              file=sys.stderr)
    try:
        w.add_tree(src, rehash=rehash)
        st = w.close()
    except BaseException:
        w.abort()
        raise
    dt = time.time() - t0
    print(_fmt(st))
    read = st.input_bytes - st.reused_bytes
    print(f"time={dt:.1f}s (read {read / 1e6:.1f} MB at {read / 1e6 / dt if dt else 0:.1f} MB/s)")
    print(f"read back and proved {st.readback} new block(s) before publishing the snapshot")
    if st.changed:
        print(f"warning: {len(st.changed)} file(s) kept changing while they were read (read twice); they "
              f"are stored, but each copy may mix old and new content. The next backup reads them again:",
              file=sys.stderr)
        for path in st.changed[:50]:
            print(f"  {path}", file=sys.stderr)
    if st.parity.startswith("warning"):
        print(st.parity, file=sys.stderr)
    elif st.parity:
        print(f"parity {st.parity}: {store}.hcp")
    if st.skipped:
        _print_skipped(st.skipped)
    if w.created and w.encrypt:
        # A new encrypted store: any catalog or semantic index at this path described whatever was here
        # before (readable or not, present or not) and keeps it unencrypted beside the encrypted store.
        cat_ok = _remove_plain_sidecars(store, sem=True)
    else:
        cat_ok = _update_catalog(store) if catalog else True
    return 3 if (st.skipped or st.changed or st.parity.startswith("warning") or st.precheck_fixed
                 or not cat_ok) else 0


def _remove_plain_sidecars(store: str, sem: bool = False) -> bool:
    """Delete the unencrypted sidecars that must not sit beside an encrypted
    store: its catalog (<store>.cat, the catalog's journal and damaged catalogs
    set aside as <store>.cat.bad-*) and, with sem=True (the store was just
    created, so any index there describes what was here before), its semantic
    index (<store>.sem and journal). Otherwise a .sem is kept: beside an
    encrypted store one is only built on purpose (--allow-plaintext-index).
    Each deletion is named in a note. False = one could not be deleted (warned)."""
    import glob
    failed = []

    def drop(paths, lock_for):
        paths = [q for q in paths if os.path.lexists(q)]
        if not paths:
            return
        try:
            lock = _StoreLock(lock_for)         # not while a catalog / index update is writing it
        except (StoreLockedError, OSError) as e:
            failed.extend((q, e) for q in paths)
            return
        try:
            for q in paths:
                try:
                    os.remove(q)
                    print(f"note: deleted {q}: it described this store's files unencrypted, "
                          f"and the store is encrypted", file=sys.stderr)
                except OSError as e:
                    failed.append((q, e))
        finally:
            lock.release()

    cat = store + ".cat"
    drop([cat, cat + "-journal", *sorted(glob.glob(glob.escape(cat) + ".bad-*"))], cat)
    if sem:
        drop([store + ".sem", store + ".sem-journal"], store + ".sem")
    for q, e in failed:
        print(f"warning: {q} describes this store's files unencrypted beside the encrypted store, but "
              f"could not be deleted ({e}); delete it", file=sys.stderr)
    return not failed


def _update_catalog(store: str) -> bool:
    """Bring <store>.cat up to date after a write. The data is already safe, so
    a failure here only warns. Encrypted stores get no catalog (one found there
    is left over and deleted). False = warned."""
    try:
        import hybridstore_catalog as hc
        with StoreReader(store) as r:
            if r.encrypted:
                return _remove_plain_sidecars(store)
            st = hc.update_store(store, r, log=lambda m: print(m, file=sys.stderr))
        print(hc.summary(st))
        return True
    except StoreLockedError:
        print("note: the catalog is being updated by another run; it will catch up", file=sys.stderr)
        return True
    except Exception as e:
        print(f"warning: catalog not updated ({type(e).__name__}: {e}); the snapshot itself is complete. "
              f"`hybridstore.py catalog {store}` retries", file=sys.stderr)
        return False


def _prune_cli(a) -> int:
    policy = a.keep_last or a.keep_daily or a.keep_weekly or a.keep_monthly
    if not policy and not a.remove:
        print("error: say what to delete: --remove N... and/or a --keep-* policy", file=sys.stderr)
        return 2
    with StoreReader(a.store) as r:
        snaps = r.snapshots
        remove = set(a.remove)
        if policy:
            keep = select_snapshots(snaps, a.keep_last, a.keep_daily, a.keep_weekly, a.keep_monthly)
            remove |= set(range(1, len(snaps) + 1)) - keep
    if not remove:
        print("nothing to delete: every snapshot is kept by the policy")
        return 0
    t0 = time.time()
    ps = prune(a.store, remove, repack_below=a.repack_below, level=a.level, dry_run=a.dry_run,
               workers=a.workers)
    for i in range(1, len(snaps) + 1):
        s = snaps[i - 1]
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.created)) if s.created else "(v1)"
        print(f"{'delete' if i in remove else 'keep  '} #{i:<3} {when}  {len(s.files):>7} files  {s.label}")
    verb = "would be" if ps.dry_run else "were"
    print(f"packs: {ps.packs_copied} kept as-is, {ps.packs_repacked} repacked into {ps.new_packs} new, "
          f"{ps.packs_dropped} dropped")
    saved = ps.bytes_before - ps.bytes_after
    print(f"store {ps.bytes_before:,} -> {ps.bytes_after:,} bytes ({saved:,} {verb} freed"
          f"{', not counting repacking' if ps.dry_run else ''}); {len(ps.removed)} snapshot(s) {verb} deleted")
    if not ps.dry_run:
        print(f"new store verified; remaining snapshots renumbered 1..{len(ps.kept)}; "
              f"time={time.time() - t0:.1f}s")
        if os.path.exists(a.store + ".cat") and not _update_catalog(a.store):
            return 3
    return 0


def _report(r: "StoreReader", strict: bool = True, limit: int = 20) -> int:
    """Full verify: print every problem and every damaged file. 0 = intact, 1 = damage."""
    rep = r.scan(strict=strict)
    pline = parity_summary(rep["parity"]) if rep["parity"] else \
        "parity: none (`hybridstore.py parity <store>` adds Reed-Solomon recovery data)"
    if not rep["problems"]:
        print(f"verified {rep['files']} files across {len(r.snapshots)} snapshot(s): layout, blocks, "
              f"index and files all intact")
        print(pline)
        return 0
    print(pline, file=sys.stderr)
    print(f"DAMAGE FOUND: {len(rep['problems'])} problem(s)", file=sys.stderr)
    for p in rep["problems"]:
        print(f"  {p}", file=sys.stderr)
    for num, bad in sorted(rep["damaged_files"].items()):
        print(f"snapshot {num}: {len(bad)} item(s) cannot be restored intact:", file=sys.stderr)
        for path, why in bad[:limit]:
            print(f"  {path}: {why}", file=sys.stderr)
        if len(bad) > limit:
            print(f"  ... and {len(bad) - limit} more", file=sys.stderr)
    ok = [i for i in range(1, len(r.snapshots) + 1)
          if i not in rep["damaged_files"] and not r.snapshots[i - 1].damaged]
    print(f"intact snapshots: {ok or 'none'} of {len(r.snapshots)}", file=sys.stderr)
    return 1


def _print_skipped(skipped, limit=50):
    print(f"warning: {len(skipped)} item(s) could not be read and are NOT in this snapshot:",
          file=sys.stderr)
    for path, reason in skipped[:limit]:
        print(f"  {path}: {reason}", file=sys.stderr)
    if len(skipped) > limit:
        print(f"  ... and {len(skipped) - limit} more (run `list --skipped`)", file=sys.stderr)


def main(argv) -> int:
    ap = argparse.ArgumentParser(prog="hybridstore", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--password-file", metavar="FILE", default=None,
                        help=f"password of an encrypted store (first line of FILE); else the {PASSWORD_ENV} "
                             f"environment variable, else a prompt")
    _add = sub.add_parser
    sub.add_parser = lambda *x, **kw: _add(*x, parents=[common], **kw)
    for name, hlp in (("pack", "pack a directory into a NEW store (overwrites)"),
                      ("backup", "add a snapshot of a directory (creates the store if missing)")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("--cloud-files", action="store_true",
                       help="also read OneDrive / cloud placeholder files (downloads them); default: skip "
                            "and report them")
        p.add_argument("--encrypt", action="store_true",
                       help="new store only: seal everything with ChaCha20-Poly1305 under a password "
                            "(scrypt). Appending to an encrypted store needs the password, nothing else"
                            + (f". Implied when a password is given (--password-file / {PASSWORD_ENV}): `backup` "
                               f"then refuses an unencrypted store and creates a missing one encrypted"
                               if name == "backup" else ". Implied by --password-file"))
        p.add_argument("input_dir"); p.add_argument("store")
        p.add_argument("--level", type=int, default=19,
                       help="zstd level 1-22 (default 19; 9 is ~15x faster for ~10%% less ratio)")
        p.add_argument("--workers", type=int, default=None,
                       help="threads (default: CPU count, max 16; 1 = single-threaded)")
        p.add_argument("--no-catalog", action="store_true",
                       help="do not create / update the catalog (<store>.cat) that lets agents search without "
                            "decoding the store")
        p.add_argument("--pack-mb", type=float, default=1, metavar="MB",
                       help="solid pack size (default 1). 4 is ~5%% smaller on text but each first "
                            "read of a file decodes up to 4 MB (~3x slower random reads)")
        if name == "backup":
            p.add_argument("--rehash", action="store_true",
                           help="read every file, even ones whose size and mtime are unchanged")
            p.add_argument("--no-precheck", action="store_true",
                           help="skip proving the existing store intact before writing (on by default: it "
                                "reads the whole store once: about 7 s per GB from a USB hard disk)")
        else:
            p.add_argument("--force", action="store_true",
                           help="replace an existing store (all its snapshots are lost)")
            p.add_argument("--no-parity", action="store_true",
                           help="do not write Reed-Solomon recovery data (<store>.hcp, ~12.5%% of the store)")
    p = sub.add_parser("list", help="list snapshots")
    p.add_argument("store")
    p.add_argument("--skipped", action="store_true", help="also list items each snapshot could not read")
    p = sub.add_parser("unpack", help="restore a snapshot (default: newest)")
    p.add_argument("store"); p.add_argument("output_dir")
    p.add_argument("--snapshot", type=int, default=None, help="1-based snapshot number")
    p.add_argument("--force", action="store_true",
                   help="replace files / links that already exist in output_dir (default: refuse)")
    p.add_argument("--fsync", action="store_true",
                   help="make every restored file durable before renaming it into place (slower)")
    p = sub.add_parser("repair", help="rebuild damaged bytes from parity, fix footers (loses nothing)")
    p.add_argument("store")
    p.add_argument("--dry-run", action="store_true", help="only say what would be repaired")
    p = sub.add_parser("parity", help="add or refresh Reed-Solomon recovery data (<store>.hcp)")
    p.add_argument("store")
    p.add_argument("--remove", action="store_true", help="delete the recovery data instead")
    p.add_argument("--m", type=int, default=None, metavar="M",
                   help=f"parity shards per {PARITY_K} data shards (default: keep the current, else "
                        f"{PARITY_M} = 12.5%%; 4 = 25%%, survives 4 MiB bursts per 16 MiB)")
    p.add_argument("--depth", type=int, default=None, metavar="D",
                   help=f"interleaving depth (default {PARITY_DEPTH}; 1 = the original layout)")
    p = sub.add_parser("catalog", help="build / update the catalog (<store>.cat) agents use to find and search "
                                       "without decoding the store")
    p.add_argument("store")
    p.add_argument("--rebuild", action="store_true", help="discard the catalog and build it again from the store")
    p = sub.add_parser("passwd", help="change the password of an encrypted store")
    p.add_argument("store")
    p.add_argument("--new-password-file", metavar="FILE", default=None,
                   help="new password (first line of FILE); default: prompt twice")
    p = sub.add_parser("prune", help="delete snapshots and reclaim their space (by number and/or policy)")
    p.add_argument("store")
    p.add_argument("--remove", type=int, nargs="+", default=[], metavar="N",
                   help="snapshot numbers to delete (as shown by `list`)")
    for opt, hlp in (("--keep-last", "keep the N newest snapshots"),
                     ("--keep-daily", "keep the newest snapshot of each of the last N days that have one"),
                     ("--keep-weekly", "same, per ISO week"),
                     ("--keep-monthly", "same, per calendar month")):
        p.add_argument(opt, type=int, default=0, metavar="N", help=hlp + " (per source folder)")
    p.add_argument("--dry-run", action="store_true", help="show what would be deleted; change nothing")
    p.add_argument("--repack-below", type=float, default=0.5, metavar="F",
                   help="recompress packs whose live fraction is below F (default 0.5); 0 = never")
    p.add_argument("--level", type=int, default=19, help="zstd level for repacked data (default 19)")
    p.add_argument("--workers", type=int, default=None, help="compression threads")
    p = sub.add_parser("verify", help="check the whole store: layout, every block, index and file")
    p.add_argument("store")
    p.add_argument("--allow-partial", action="store_true",
                   help="do not fail on bytes left by an interrupted write / a cut-short store")
    a = ap.parse_args(argv)
    global _prompt_ok, _password_named
    saved = (_prompt_ok, _password, sys.stderr, _password_named, sys.stdout)
    _prompt_ok = True
    tail = sys.stderr = _StderrTail(_TermSafe.wrap(sys.stderr))   # a store must not drive the terminal
    sys.stdout = _TermSafe.wrap(sys.stdout)
    try:
        code = _main(a)
    except Exception as e:      # not a known error: a bug. Record it for `doctor.py bugs`, then fail as before
        sys.stderr = saved[2]
        log_event({"kind": "crash", "cmd": a.cmd, "store": _abs(getattr(a, "store", None)),
                   "error": f"{type(e).__name__}: {e}", "signature": crash_signature(e),
                   "traceback": "".join(traceback.format_exception(e))[-8000:], "version": _source_version()})
        print("hybridstore: internal error, recorded in the event log (`python doctor.py bugs` shows it)",
              file=sys.stderr)
        raise
    finally:            # main() may be called in-process (tests, other tools): leave no state behind
        _prompt_ok = saved[0]
        _password_named = saved[3]
        set_password(saved[1])
        sys.stderr, sys.stdout = saved[2], saved[4]
    if code:
        log_event({"kind": "error", "cmd": a.cmd, "store": _abs(getattr(a, "store", None)), "exit": code,
                   "message": tail.text()})
    return code


# --------------------------------------------------------------------------
# Event log: failed commands and crashes, read by doctor.py (the error manager).
# One JSON object per line in %LOCALAPPDATA%\hybridstore\events.jsonl (or
# ~/.local/state/hybridstore/events.jsonl); HYBRIDSTORE_LOG=<file> moves it,
# HYBRIDSTORE_LOG=off turns it off. Never holds passwords or file contents.
# --------------------------------------------------------------------------
EVENT_LOG_ENV = "HYBRIDSTORE_LOG"
EVENT_LOG_MAX = 5 << 20                 # rotated to events.jsonl.1 beyond this


def event_log_path() -> str | None:
    p = os.environ.get(EVENT_LOG_ENV)
    if p is not None:
        return None if p.strip().lower() in ("", "off", "0", "none") else p
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "hybridstore", "events.jsonl")


def log_event(ev: dict) -> None:
    """Append one event; never raises (logging must not break a backup)."""
    p = event_log_path()
    if not p:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
        if os.path.exists(p) and os.path.getsize(p) > EVENT_LOG_MAX:
            os.replace(p, p + ".1")
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "pid": os.getpid(), **ev},
                          ensure_ascii=False, default=str)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def crash_signature(e: BaseException) -> str:
    """Same bug, same signature: the exception type plus the functions of this
    project it passed through (no line numbers, so it survives small edits)."""
    here = os.path.dirname(os.path.abspath(__file__))
    frames = [f"{os.path.basename(fr.filename)}:{fr.name}" for fr in traceback.extract_tb(e.__traceback__)
              if os.path.dirname(os.path.abspath(fr.filename)) == here]
    return hashlib.sha1(f"{type(e).__name__}|{'|'.join(frames[-6:])}".encode()).hexdigest()[:12]


def _abs(p: str | None) -> str | None:
    return os.path.abspath(p) if p else None


def _source_version() -> str:
    try:
        with open(__file__, "rb") as f:
            return hashlib.sha1(f.read()).hexdigest()[:10]
    except OSError:
        return "?"


class _StderrTail:
    """Passes stderr through and keeps its last few KB for the event log."""

    def __init__(self, inner, keep: int = 4000):
        self._inner, self._keep, self._buf = inner, keep, ""

    def write(self, s):
        self._buf = (self._buf + s)[-self._keep:]
        return self._inner.write(s) if self._inner else len(s)

    def flush(self):
        if self._inner:
            self._inner.flush()

    def text(self) -> str:
        return self._buf.strip()

    def __getattr__(self, name):
        return getattr(self._inner, name)


# Characters a terminal acts on instead of showing: C0/C1 controls other than tab and
# newline (ESC starts CSI/OSC sequences that move the cursor, retitle the window, write
# the clipboard; 0x9b is a one-byte CSI), DEL, line/paragraph separators, the bidi
# embeddings, overrides and isolates that reorder text on screen, and lone surrogates
# (bytes of a name that were not UTF-8). Joiners, LRM/RLM and the other format
# characters ordinary text needs are left alone.
_TERM_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\ud800-\udfff]")


def term_safe(text: str) -> str:
    """`text` with each terminal-unsafe character shown as a visible \\xNN / \\uNNNN escape."""
    def esc(m):
        o = ord(m.group())
        if 0xDC80 <= o <= 0xDCFF:           # surrogateescape: the original byte
            o -= 0xDC00
        return f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}"
    return _TERM_UNSAFE.sub(esc, text)


def _is_terminal(stream) -> bool:
    try:
        return bool(stream and stream.isatty())
    except (OSError, ValueError, AttributeError):
        return False


class _TermSafe:
    """Wraps a stream that is a terminal so nothing printed to it (store labels, paths,
    skip reasons, link targets, file text, error messages quoting them) can drive the
    terminal. Only terminals are wrapped: piped or redirected output stays byte-for-byte."""

    def __init__(self, inner):
        self._inner = inner

    @classmethod
    def wrap(cls, stream):
        return cls(stream) if _is_terminal(stream) and not isinstance(stream, cls) else stream

    def write(self, s):
        return self._inner.write(term_safe(s))

    def __getattr__(self, name):
        return getattr(self._inner, name)


@contextlib.contextmanager
def terminal_safe_output():
    """Wrap sys.stdout and sys.stderr while inside, when they are terminals."""
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _TermSafe.wrap(sys.stdout), _TermSafe.wrap(sys.stderr)
    try:
        yield
    finally:
        sys.stdout, sys.stderr = saved


def _main(a) -> int:
    global _password_named
    if a.password_file:
        with open(a.password_file, encoding="utf-8") as fh:
            set_password(fh.readline().rstrip("\r\n"))
        _password_named = True      # every command takes one store: it must be encrypted

    try:
        if a.cmd == "passwd":
            if a.new_password_file:
                with open(a.new_password_file, encoding="utf-8") as fh:
                    new = fh.readline().rstrip("\r\n")
            else:
                import getpass
                if not (sys.stdin and sys.stdin.isatty()):
                    print("error: give --new-password-file (no terminal to prompt on)", file=sys.stderr)
                    return 2
                new = getpass.getpass("new password: ")
                if getpass.getpass("repeat the new password: ") != new:
                    print("error: the two passwords differ", file=sys.stderr)
                    return 2
            change_password(a.store, None, new)
            print("password changed (the data key is unchanged; older copies of the store still open with "
                  "the old password)")
            return 0
        if a.cmd == "pack":
            if not a.force and os.path.exists(a.store) and os.path.getsize(a.store) > 0:
                try:
                    with StoreReader(a.store) as r:
                        what = f"a store with {len(r.snapshots)} snapshot(s)"
                except (IntegrityError, OSError):
                    what = "a file that is not empty"
                print(f"error: {a.store} is {what}; `pack` would replace it. Use `backup` to add a "
                      f"snapshot, or `pack --force` to replace it", file=sys.stderr)
                return 2
            # --password-file names this store's password, so it is a demand for encryption
            # (the variable may serve other stores too, so it alone does not encrypt a new store)
            return _write(a.store, a.input_dir, append=False, level=a.level, workers=a.workers,
                          parity=False if a.no_parity else None, pack_mb=a.pack_mb,
                          encrypt=a.encrypt or bool(a.password_file),
                          cloud_files=a.cloud_files, catalog=not a.no_catalog)
        if a.cmd == "backup":
            # A store password is a demand for encryption: never append plaintext to an unencrypted
            # store, or create one, when the store this job protects with a password was replaced or deleted.
            encrypt = a.encrypt or bool(a.password_file) or bool(os.environ.get(PASSWORD_ENV))
            return _write(a.store, a.input_dir, append=True, level=a.level, workers=a.workers,
                          rehash=a.rehash, pack_mb=a.pack_mb, encrypt=encrypt,
                          cloud_files=a.cloud_files, precheck=not a.no_precheck, catalog=not a.no_catalog)
        if a.cmd == "prune":
            return _prune_cli(a)
        if a.cmd == "catalog":
            import hybridstore_catalog as hc
            try:
                st = hc.update_store(a.store, rebuild=a.rebuild, log=lambda m: print(m, file=sys.stderr))
            except hc.CatalogError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            print(hc.summary(st))
            return 0
        if a.cmd == "parity":
            lock = _StoreLock(a.store)
            try:
                par = Parity(a.store)
                if a.remove:
                    if par.exists():
                        os.remove(par.path)
                    print("parity removed")
                    return 0
                with StoreReader(a.store) as r:
                    if r.scan()["problems"]:
                        print("error: the store has damage; parity is only built over a verified store "
                              "(run `verify` / `repair` first)", file=sys.stderr)
                        return 1
                opts = par.params() or {}
                if a.m is not None:
                    opts["m"] = a.m
                if a.depth is not None:
                    opts["depth"] = a.depth
                info = par.build(**opts)
                print(f"parity written: {par.path}, {info['bytes']:,} bytes for {info['covered']:,} store bytes "
                      f"({100 * info['bytes'] / max(info['covered'], 1):.1f}%; m={info['m']}, "
                      f"interleave depth {info['depth']})")
                return 0
            finally:
                lock.release()
        if a.cmd == "repair" and a.dry_run:
            plan = repair(a.store, dry_run=True)
            for d in plan:
                print(d)
            print("nothing to repair" if not plan else "(dry run: nothing was changed)")
            return 0
        if a.cmd == "repair":
            done = repair(a.store)
            for d in done:
                print(d)
            if not done:
                print("nothing to repair")
            with StoreReader(a.store) as r:
                return _report(r, strict=True)
        with StoreReader(a.store) as r:
            if a.cmd == "list":
                print(f"{'#':>3}  {'created':19}  {'files':>7}  {'bytes':>15}  {'skipped':>7}  source")
                for i, s in enumerate(r.snapshots, 1):
                    if s.damaged:
                        print(f"{i:>3}  DAMAGED: file list unreadable ({s.damaged})")
                        continue
                    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.created)) if s.created else "(v1 store)"
                    print(f"{i:>3}  {when:19}  {len(s.files):>7}  {s.input_bytes:>15,}  {len(s.skipped):>7}  {s.label}")
                    if a.skipped:
                        for path, reason in s.skipped:
                            print(f"       skipped {path}: {reason}")
                print(f"store size {r.end:,} bytes")
                if r.tail_snapshot is not None:
                    print(f"error: {r._tail_message()}", file=sys.stderr)
                    return 3
            elif a.cmd == "unpack":
                try:
                    warnings = r.unpack(a.output_dir, a.snapshot, overwrite=a.force, fsync=a.fsync)
                except (RestoreConflictError, RestoreSpaceError) as e:
                    print(f"error: {e}", file=sys.stderr)
                    return 2
                for w in warnings:
                    print(f"warning: {w}", file=sys.stderr)
                print("ok" if not warnings else f"ok, with {len(warnings)} warning(s)")
                return 3 if warnings else 0
            else:
                return _report(r, strict=not a.allow_partial)
        return 0
    except StoreLockedError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    except PasswordError as e:
        print(f"error: {e}", file=sys.stderr)
        return 5
    except (IntegrityError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
