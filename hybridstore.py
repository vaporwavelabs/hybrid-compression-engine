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
  python hybridstore.py unpack <store_file> <output_dir> [--snapshot N]
  python hybridstore.py verify <store_file> [--allow-partial]

Exit codes: 0 ok, 1 integrity error, 3 finished with warnings (items skipped /
symlinks not restored), 4 store locked by another backup. Format: FORMAT.md.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import socket
import stat
import struct
import sys
import threading
import time
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

# Entry kinds (manifest v3)
KIND_FILE, KIND_DIR, KIND_LINK, KIND_DIRLINK = 0, 1, 2, 3
# Windows attributes that are restored (read-only, hidden, system, archive, not-indexed)
WIN_ATTR_KEEP = 0x1 | 0x2 | 0x4 | 0x20 | 0x2000
WIN_ATTR_NORMAL = 0x80


class IntegrityError(Exception):
    pass


class StoreLockedError(Exception):
    """Another process (or another writer in this process) is writing the store."""


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
        crc = zlib.crc32(data) & 0xFFFFFFFF
        hdr = HDR.pack(BLOCK_MAGIC, flags | best_codec, len(data), len(best), crc)
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
        if len(data) != olen or (zlib.crc32(data) & 0xFFFFFFFF) != crc:
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
    skipped: list = field(default_factory=list)   # (path, reason) of files that could not be read


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


def _norm_path(rel: str) -> str:
    return rel.replace(os.sep, "/") if os.sep != "/" else rel


def _meta(st: os.stat_result) -> tuple[int, int, int]:
    return st.st_mtime_ns, st.st_mode, getattr(st, "st_file_attributes", 0)


def _is_link(path: str) -> bool:
    return os.path.islink(path) or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def _set_win_attrs(path: str, attrs: int):
    import ctypes
    ctypes.windll.kernel32.SetFileAttributesW(path, (attrs & WIN_ATTR_KEEP) or WIN_ATTR_NORMAL)


def _make_writable(path: str):
    """Clear read-only / hidden / system so an existing file can be replaced."""
    if os.name == "nt":
        _set_win_attrs(path, 0)
    else:
        os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) | stat.S_IWUSR)


def _apply_meta(path: str, e: "FileEntry"):
    """Restore mtime, then permissions / attributes (read-only last, so the
    mtime can still be set)."""
    if e.mtime_ns >= 0:
        os.utime(path, ns=(e.mtime_ns, e.mtime_ns))
    if os.name == "nt":
        if e.attrs:
            _set_win_attrs(path, e.attrs)
        elif e.mode and not e.mode & stat.S_IWUSR and e.kind == KIND_FILE:
            _set_win_attrs(path, 0x1)
    elif e.mode:
        os.chmod(path, stat.S_IMODE(e.mode))


def _safe_parts(path: str) -> list[str]:
    """Split a manifest path on / or \\ and reject anything that could escape
    the output directory."""
    parts = re.split(r"[\\/]", path)
    bad = (not parts or any(p in ("", ".", "..") for p in parts)
           or (os.name == "nt" and any(":" in p for p in parts)))
    if bad:
        raise IntegrityError(f"unsafe path in manifest: {path!r}")
    return parts


class StoreWriter:
    """Writes a new store, or (append=True) adds a snapshot to an existing one."""

    def __init__(self, path: str, chunker: FastCDC | None = None, codec: BlockCodec | None = None,
                 pack_target: int = 1 << 20, near_dup_hamming: int = 6,
                 append: bool = False, label: str = "", workers: int | None = None,
                 max_pending_bytes: int = 256 << 20):
        """workers: threads for reading/chunking small files, hashing large
        ones and compressing packs (default: CPU count, max 16; 1 = no
        threads). Output is byte-identical whatever the worker count, except
        for the manifest timestamp.

        Holds an exclusive lock on '<path>.lock' until close()/abort(); a
        second writer gets StoreLockedError instead of silently losing a
        snapshot. A new store (append=False or no store yet) is written to
        '<path>.hcs-new' and only replaces <path> when close() succeeds."""
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
        self.recovered_bytes = 0               # tail bytes dropped from an interrupted write
        if append and os.path.exists(path) and os.path.getsize(path) > 0:
            with StoreReader(path, codec=self.codec, load_index=True) as r:
                self.pack_offsets = list(r.pack_offsets)
                self.index = r.index
                self.prev_manifest = r.snapshots[-1].offset
                self.has_dict = r.has_dict
                self.stats.snapshot = len(r.snapshots) + 1
                end = r.end
                self.recovered_bytes = r.file_size - r.end
            self.f = open(path, "r+b")
            self.f.truncate(end)
            self.f.seek(end)
            self.pos = self.start = end
            self.created = False
        else:
            self.f = open(path + ".hcs-new", "wb")
            self.f.write(STORE_MAGIC)
            self.pos = self.start = len(STORE_MAGIC)
            self.created = True
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
                    return None, meta
                data = fh.read(PREP_MAX + 1)
        except OSError as e:
            return e
        return (None if len(data) > PREP_MAX else self._prepare_bytes(data)), meta

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
        if not self.created or self.pos != len(STORE_MAGIC):
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
        """Yield (full_path, kind) in a stable order: every directory (so
        empty ones and their metadata survive), symlinks / junctions as links
        (never followed), regular files. Directories that cannot be listed
        are reported as skipped."""
        def onerror(e):
            self._skip(os.path.relpath(e.filename, root) if e.filename else root, e)
        for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
            dirnames.sort()
            keep = []
            for name in dirnames:
                full = os.path.join(dirpath, name)
                if _is_link(full):
                    yield full, KIND_DIRLINK
                else:
                    yield full, KIND_DIR
                    keep.append(name)
            dirnames[:] = keep
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if _is_link(full):
                    yield full, KIND_LINK
                elif os.path.isfile(full):
                    yield full, KIND_FILE

    def _skip(self, rel: str, e: BaseException):
        reason = getattr(e, "strerror", None) or str(e) or type(e).__name__
        self.stats.skipped.append((_norm_path(rel), reason))

    def _add_special(self, rel: str, full: str, kind: int):
        """A directory or symlink entry (no file data read)."""
        st = os.lstat(full)
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

    def add_tree(self, root: str, use_dictionary: bool | None = None, sample_budget: int = 8 << 20):
        """Back up a directory tree. A file that cannot be read (locked by
        another program, permission denied, vanished) is skipped and listed
        in stats.skipped and the manifest instead of failing the whole run."""
        # A dictionary pays off when chunks are compressed alone; with large
        # solid packs it mostly costs its own size, so default to it only then.
        if use_dictionary is None:
            use_dictionary = self.pack_target <= 64 * 1024
        if not self.label:
            self.label = os.path.abspath(root)
        items = list(self._walk(root))
        files = [full for full, kind in items if kind == KIND_FILE]
        if use_dictionary and self.created and self.pos == len(STORE_MAGIC):
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
        for full, kind in items:
            rel = os.path.relpath(full, root)
            try:
                if kind != KIND_FILE:
                    self._add_special(rel, full, kind)
                    continue
                pfull, res = next(prepared)
                assert pfull == full
                if isinstance(res, BaseException):
                    raise res
                prep, meta = res if res is not None else (None, None)
                if prep is not None:
                    self._add_prepared(rel, prep, meta)
                else:
                    with open(full, "rb") as fh:
                        self.add_stream(rel, fh, meta or _meta(os.fstat(fh.fileno())))
            except OSError as e:
                self._skip(rel, e)

    def _prepared(self, files):
        """Yield (path, result) in input order, where result is what
        _prepare_path returns: (prep-or-None, meta) or an OSError. With a
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
        new_packs = self.pack_offsets[self.first_new_pack:]
        label = self.label.encode("utf-8")[:65535]
        digests = b"".join(d for d, _ in self.new_index)
        ptrs = np.asarray([p for _, p in self.new_index], dtype="<u8").tobytes()
        parts = [MANIFEST_V3,
                 struct.pack("<QQH", self.prev_manifest, int(time.time()), len(label)), label,
                 struct.pack("<II", self.first_new_pack, len(new_packs)),
                 np.asarray(new_packs, dtype="<u8").tobytes(),
                 struct.pack("<I", len(self.new_index)), digests, ptrs,
                 struct.pack("<I", len(self.entries))]
        for e in self.entries:
            p = e.path.encode("utf-8", "surrogateescape")[:65535]
            parts.append(struct.pack("<H", len(p)) + p)
            parts.append(_ENTRY3.pack(e.kind, e.size, e.sha256, e.mtime_ns, e.mode & 0xFFFFFFFF,
                                      e.attrs & 0xFFFFFFFF, len(e.pointers)))
            parts.append(np.asarray(e.pointers, dtype="<u8").tobytes())
        parts.append(struct.pack("<I", len(self.stats.skipped)))
        for path, reason in self.stats.skipped:
            p = path.encode("utf-8", "surrogateescape")[:65535]
            r = reason.encode("utf-8", "replace")[:65535]
            parts.append(struct.pack("<H", len(p)) + p + struct.pack("<H", len(r)) + r)
        manifest = b"".join(parts)
        block, _ = self.codec.encode(manifest, FLAG_MANIFEST)
        moff = self.pos
        self.f.write(block)
        self.pos += len(block)
        # Make sure packs + manifest are on disk before the footer that
        # publishes them; a crash before this point leaves the old footer valid.
        self.f.flush(); os.fsync(self.f.fileno())
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
        self.lock.release()
        self.stats.manifest_bytes = len(block)
        self.stats.store_bytes = self.pos
        self.stats.added_bytes = self.pos - self.start + (len(STORE_MAGIC) if self.created else 0)
        return self.stats

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
                 load_index: bool = False):
        self.f = open(path, "rb")
        try:
            self._open(codec, cache_bytes, load_index)
        except Exception:
            self.f.close()
            raise

    def _open(self, codec, cache_bytes, load_index):
        self.codec = codec or BlockCodec()
        self.f.seek(0, os.SEEK_END)
        self.file_size = size = self.f.tell()
        if size < 8 + FOOTER.size or self._read(0, 8) != STORE_MAGIC:
            raise IntegrityError("not a hybrid store")
        self.has_dict = False
        if size > 8 + HDR.size and HDR.unpack(self._read(8, HDR.size))[1] & FLAG_DICT:
            d, _, _ = self._block(8)
            self.codec.set_dictionary(d)
            self.has_dict = True
        moff, self.end = self._locate_footer(size)
        if self.end != size:
            print(f"warning: ignoring {size - self.end:,} trailing bytes from an interrupted "
                  f"write; using the last complete snapshot", file=sys.stderr)
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
        self.snapshots: list[Snapshot] = chain
        self.pack_offsets: list[int] = []
        for s in chain:
            if s.first_pack != len(self.pack_offsets):
                raise IntegrityError(f"pack ids out of order in snapshot at {s.offset}")
            self.pack_offsets.extend(s.packs)
        self.entries = chain[-1].entries        # newest snapshot (v1 API)
        self._cache: OrderedDict[int, list[bytes]] = OrderedDict()
        self._cache_max = cache_bytes           # decoded-pack cache budget
        self._cache_used = 0
        self.index: dict[bytes, int] = {}
        if load_index:
            self._build_index()

    # ---- low level ----
    def _read(self, off: int, n: int) -> bytes:
        self.f.seek(off)
        return self.f.read(n)

    def _block(self, off: int) -> tuple[bytes, int, int]:
        hdr = self._read(off, HDR.size)
        if len(hdr) != HDR.size:
            raise IntegrityError(f"truncated header at {off}")
        slen = HDR.unpack(hdr)[3]
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
        pack = _decode_pack(self._block(self.pack_offsets[pid])[0])
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
            return self.snapshots[-1]
        if not 1 <= snapshot <= len(self.snapshots):
            raise ValueError(f"snapshot {snapshot} does not exist (store has {len(self.snapshots)})")
        return self.snapshots[snapshot - 1]

    def iter_file(self, e: FileEntry):
        """Yield the file's chunks; raises IntegrityError at the end if the
        reassembled file does not match its recorded size and SHA-256."""
        h, n = hashlib.sha256(), 0
        for p in e.pointers:
            c = self._chunk(p)
            h.update(c)
            n += len(c)
            yield c
        if n != e.size or h.digest() != e.sha256:
            raise IntegrityError(f"SHA-256 mismatch restoring {e.path}")

    def read_file(self, e: FileEntry) -> bytes:
        return b"".join(self.iter_file(e))

    def unpack(self, out_dir: str, snapshot: int | None = None) -> list[str]:
        """Restore a snapshot: files, directories (including empty ones),
        modification times, read-only / permission bits, Windows hidden /
        system attributes and symlinks. Symlinks are created last, so no
        restored file is ever written through one. Returns warnings for
        things that could not be restored (e.g. symlinks on Windows without
        the privilege to create them)."""
        root = os.path.realpath(out_dir)
        os.makedirs(root, exist_ok=True)
        warnings, dirs, links = [], [], []

        def inside(p):
            return p == root or p.startswith(root + os.sep)

        for e in self._snapshot(snapshot).entries:
            dest = os.path.join(root, *_safe_parts(e.path))
            if not inside(os.path.realpath(os.path.dirname(dest))):
                raise IntegrityError(f"unsafe path in manifest: {e.path}")
            if e.kind == KIND_DIR:
                if not inside(os.path.realpath(dest)):
                    raise IntegrityError(f"unsafe path in manifest: {e.path}")
                os.makedirs(dest, exist_ok=True)
                dirs.append((dest, e))
                continue
            if e.kind in (KIND_LINK, KIND_DIRLINK):
                links.append((dest, e))
                continue
            dest = os.path.realpath(dest)
            if not dest.startswith(root + os.sep):
                raise IntegrityError(f"unsafe path in manifest: {e.path}")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            tmp = dest + ".hcs-partial"
            try:
                with open(tmp, "wb") as fh:
                    for c in self.iter_file(e):
                        fh.write(c)
                if os.path.exists(dest):
                    _make_writable(dest)
                os.replace(tmp, dest)
            except BaseException:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise
            _apply_meta(dest, e)
        for dest, e in links:
            target = self.read_file(e).decode("utf-8", "surrogateescape")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                if _is_link(dest):
                    os.unlink(dest)
                elif os.path.isdir(dest):
                    raise OSError(0, "a directory is in the way")
                elif os.path.lexists(dest):
                    _make_writable(dest)
                    os.remove(dest)
                os.symlink(target, dest, target_is_directory=e.kind == KIND_DIRLINK)
            except OSError as ex:
                warnings.append(f"{e.path}: symlink -> {target} not created ({ex.strerror or ex})")
        for dest, e in sorted(dirs, key=lambda d: d[1].path.count("/"), reverse=True):
            try:
                _apply_meta(dest, e)        # after the contents, so the mtime sticks
            except OSError as ex:
                warnings.append(f"{e.path}: metadata not restored ({ex.strerror or ex})")
        return warnings

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

    def verify(self, snapshot: int | None = None, strict: bool = True) -> int:
        """Check one snapshot's files, or (snapshot=None) the whole store.
        Returns the number of regular files covered.

        Whole-store checks: the byte layout (check_layout), every pack's CRC
        (including packs no file uses any more), that every dedup-index entry
        really points at a chunk with that SHA-256 (a bad index would corrupt
        future backups), and every file's SHA-256. strict=True also fails if
        the store has bytes past its last complete snapshot (an interrupted
        write, or a store that was cut short and fell back to an older
        snapshot)."""
        if strict and self.end != self.file_size:
            raise IntegrityError(
                f"{self.file_size - self.end:,} bytes after the last complete snapshot: the store was "
                f"cut short or a write was interrupted, so newer snapshots may be missing. "
                f"The next backup discards them; verify with strict=False / --allow-partial to check the rest")
        snaps = self.snapshots if snapshot is None else [self._snapshot(snapshot)]
        if snapshot is None:
            self.check_layout()
            for s in self.snapshots:
                if s.version >= 2:
                    m, _, _ = self._block(s.offset)
                    full = self._parse_manifest(m, s.offset, keep_index=True)
                    want = {p: full.index_digests[32 * i:32 * i + 32] for i, p in enumerate(full.index_ptrs)}
                else:
                    want = {}
                seen = 0
                for k in range(len(s.packs)):
                    pid = s.first_pack + k
                    for i, c in enumerate(self._pack(pid)):
                        d = want.get((pid << PTR_SHIFT) | i)
                        if d is not None:
                            seen += 1
                            if hashlib.sha256(c).digest() != d:
                                raise IntegrityError(f"dedup index entry for pack {pid} chunk {i} is wrong")
                if seen != len(want):
                    raise IntegrityError(f"dedup index of snapshot at {s.offset} points outside its packs")
        done, n = set(), 0
        for s in snaps:
            for e in s.entries:
                key = (e.sha256, e.size, tuple(e.pointers))
                if key not in done:
                    for _ in self.iter_file(e):
                        pass
                    done.add(key)
                n += e.kind == KIND_FILE
        return n

    def unused_ranges(self) -> list[tuple[int, int]]:
        """Byte ranges no snapshot depends on (superseded footers)."""
        return [(s.block_end, s.block_end + FOOTER.size) for s in self.snapshots[:-1]]

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _fmt(st: Stats) -> str:
    r = st.input_bytes / st.store_bytes if st.store_bytes else 0
    return (f"snapshot={st.snapshot} files={st.files} input={st.input_bytes:,}B "
            f"added={st.added_bytes:,}B store={st.store_bytes:,}B ratio={r:.2f}x\n"
            f"chunks total={st.chunks_total} unique={st.chunks_unique} dedup_saved={st.dedup_bytes:,}B "
            f"packs={st.packs}\n"
            f"media_files={st.media_files} near_dup_images={st.near_dup_images} "
            f"raw_fallback_blocks={st.raw_fallback_blocks} ({st.raw_fallback_bytes:,}B)\n"
            f"codecs={st.codec_counts} dict_coded={st.dict_blocks} dict={st.dict_bytes:,}B "
            f"manifest={st.manifest_bytes:,}B")


def _write(store: str, src: str, append: bool, level: int = 19, workers: int | None = None) -> int:
    if not os.path.isdir(src):
        print(f"error: {src} is not a directory", file=sys.stderr)
        return 2
    t0 = time.time()
    w = StoreWriter(store, codec=BlockCodec(zstd_level=level), append=append, workers=workers)
    if w.recovered_bytes:
        print(f"note: discarded {w.recovered_bytes:,} bytes left by an interrupted earlier run",
              file=sys.stderr)
    try:
        w.add_tree(src)
        st = w.close()
    except BaseException:
        w.abort()
        raise
    dt = time.time() - t0
    print(_fmt(st))
    print(f"time={dt:.1f}s ({st.input_bytes / 1e6 / dt if dt else 0:.1f} MB/s)")
    if st.skipped:
        _print_skipped(st.skipped)
        return 3
    return 0


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
    for name, hlp in (("pack", "pack a directory into a NEW store (overwrites)"),
                      ("backup", "add a snapshot of a directory (creates the store if missing)")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("input_dir"); p.add_argument("store")
        p.add_argument("--level", type=int, default=19,
                       help="zstd level 1-22 (default 19; 9 is ~15x faster for ~10%% less ratio)")
        p.add_argument("--workers", type=int, default=None,
                       help="threads (default: CPU count, max 16; 1 = single-threaded)")
    p = sub.add_parser("list", help="list snapshots")
    p.add_argument("store")
    p.add_argument("--skipped", action="store_true", help="also list items each snapshot could not read")
    p = sub.add_parser("unpack", help="restore a snapshot (default: newest)")
    p.add_argument("store"); p.add_argument("output_dir")
    p.add_argument("--snapshot", type=int, default=None, help="1-based snapshot number")
    p = sub.add_parser("verify", help="check the whole store: layout, every block, index and file")
    p.add_argument("store")
    p.add_argument("--allow-partial", action="store_true",
                   help="do not fail on bytes left by an interrupted write / a cut-short store")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "pack":
            return _write(a.store, a.input_dir, append=False, level=a.level, workers=a.workers)
        if a.cmd == "backup":
            return _write(a.store, a.input_dir, append=True, level=a.level, workers=a.workers)
        with StoreReader(a.store) as r:
            if a.cmd == "list":
                print(f"{'#':>3}  {'created':19}  {'files':>7}  {'bytes':>15}  {'skipped':>7}  source")
                for i, s in enumerate(r.snapshots, 1):
                    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.created)) if s.created else "(v1 store)"
                    print(f"{i:>3}  {when:19}  {len(s.files):>7}  {s.input_bytes:>15,}  {len(s.skipped):>7}  {s.label}")
                    if a.skipped:
                        for path, reason in s.skipped:
                            print(f"       skipped {path}: {reason}")
                print(f"store size {r.end:,} bytes")
            elif a.cmd == "unpack":
                warnings = r.unpack(a.output_dir, a.snapshot)
                for w in warnings:
                    print(f"warning: {w}", file=sys.stderr)
                print("ok" if not warnings else f"ok, with {len(warnings)} warning(s)")
                return 3 if warnings else 0
            else:
                n = r.verify(strict=not a.allow_partial)
                print(f"verified {n} files across {len(r.snapshots)} snapshot(s): layout, blocks, "
                      f"index and files all intact")
        return 0
    except StoreLockedError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    except (IntegrityError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
