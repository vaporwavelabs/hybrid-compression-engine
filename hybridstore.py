#!/usr/bin/env python3
"""
hybridstore.py - Phase II hybrid dedup + compression engine (prototype).

Pipeline per input file:
  1. Modality check on the WHOLE file before any chunking (magic bytes).
     Media / already-compressed containers are stored as a single object
     (no CDC slicing, so container headers are never split).
  2. Everything else is cut with FastCDC-style content-defined chunking
     (256-entry gear table, normalized masks, min/avg/max sizes).
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

The neural codec is an explicit stub (see NeuralCodec). It is off by default
because a learned image codec is lossy and the project goal is integrity.

Usage:
  python hybridstore.py pack   <input_dir> <store_file>
  python hybridstore.py unpack <store_file> <output_dir>
  python hybridstore.py verify <store_file>
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field

import numpy as np

try:
    import zstandard as zstd  # optional
except ImportError:  # pragma: no cover
    zstd = None

# --------------------------------------------------------------------------
# Binary layout
# --------------------------------------------------------------------------
STORE_MAGIC = b"HCSTORE1"           # 8-byte file signature
FOOTER = struct.Struct("<Q8s")      # manifest offset, magic
BLOCK_MAGIC = b"HCB"
HDR = struct.Struct("<3sBIII")      # 16 bytes
assert HDR.size == 16

CODEC_RAW, CODEC_ZLIB, CODEC_ZSTD, CODEC_NEURAL = 0, 1, 2, 3
CODEC_MASK = 0x07
FLAG_MEDIA = 0x08                   # payload is a whole media/container file
FLAG_MANIFEST = 0x10                # block holds the manifest
FLAG_DICT = 0x20                    # block holds the trained zstd dictionary
FLAG_USES_DICT = 0x40               # zstd payload was coded with the dictionary
CODEC_NAMES = {0: "raw", 1: "zlib", 2: "zstd", 3: "neural"}


class IntegrityError(Exception):
    pass


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
    """

    def __init__(self, min_size=2048, avg_size=8192, max_size=65536, norm_level=2):
        assert min_size >= 64 and min_size < avg_size < max_size
        self.min_size, self.avg_size, self.max_size = min_size, avg_size, max_size
        bits = avg_size.bit_length() - 1
        self.mask_s = np.uint64(_top_mask(bits + norm_level))  # harder to match
        self.mask_l = np.uint64(_top_mask(bits - norm_level))  # easier to match

    def _hashes(self, data: bytes) -> np.ndarray:
        g = GEAR[np.frombuffer(data, dtype=np.uint8)]
        h = np.zeros(len(data), dtype=np.uint64)
        with np.errstate(over="ignore"):
            for k in range(64):
                if k >= len(data):
                    break
                h[k:] += g[: len(data) - k] << np.uint64(k)
        return h

    def cut_points(self, data: bytes) -> list[int]:
        n = len(data)
        if n <= self.min_size:
            return [n] if n else []
        h = self._hashes(data)
        cand_s = np.flatnonzero((h & self.mask_s) == 0)
        cand_l = np.flatnonzero((h & self.mask_l) == 0)
        cuts, start = [], 0
        while start < n:
            if n - start <= self.min_size:
                cuts.append(n)
                break
            lo = start + self.min_size          # first eligible position
            mid = start + self.avg_size
            hi = min(start + self.max_size, n)
            cut = None
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

    def chunks(self, data: bytes):
        start = 0
        for end in self.cut_points(data):
            yield data[start:end]
            start = end


# --------------------------------------------------------------------------
# Modality detection (done on whole files, BEFORE chunking)
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
    """Return a media/container type name, or None for generic bytes."""
    if data[:4] == b"RIFF" and data[8:12] in (b"WEBP", b"WAVE", b"AVI "):
        return data[8:12].decode().strip().lower()
    if data[4:8] == b"ftyp":
        return "mp4"
    for magic, name in _MEDIA_MAGIC:
        if data.startswith(magic):
            return name
    return None


IMAGE_TYPES = {"png", "jpeg", "gif", "bmp", "tiff", "webp"}


def dhash64(data: bytes) -> int | None:
    """64-bit difference hash for near-duplicate detection (needs Pillow)."""
    try:
        import io
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
    def __init__(self, zstd_level=19, zlib_level=9):
        self.zstd_level, self.zlib_level = zstd_level, zlib_level
        self.zc = zstd.ZstdCompressor(level=zstd_level) if zstd else None
        self.zd = zstd.ZstdDecompressor() if zstd else None
        self.zc_dict = self.zd_dict = None
        self.neural = NeuralCodec()

    def set_dictionary(self, dict_bytes: bytes):
        """Small chunks lose the cross-chunk context a whole-stream compressor
        sees. A shared zstd dictionary trained on sample chunks restores much
        of it while keeping every chunk independently decodable."""
        d = zstd.ZstdCompressionDict(dict_bytes)
        self.zc_dict = zstd.ZstdCompressor(level=self.zstd_level, dict_data=d)
        self.zd_dict = zstd.ZstdDecompressor(dict_data=d)

    def encode(self, data: bytes, flags: int = 0) -> tuple[bytes, dict]:
        """Return (header + payload, info). Picks the smallest candidate and
        falls back to raw unless compression is strictly smaller."""
        best_codec, best = CODEC_RAW, data
        candidates = [(CODEC_ZLIB, lambda: zlib.compress(data, self.zlib_level))]
        if self.zc:
            candidates.append((CODEC_ZSTD, lambda: self.zc.compress(data)))
        if self.zc_dict and not flags & (FLAG_MEDIA | FLAG_MANIFEST | FLAG_DICT):
            candidates.append((CODEC_ZSTD | FLAG_USES_DICT, lambda: self.zc_dict.compress(data)))
        for codec, fn in candidates:
            out = fn()
            if len(out) < len(best):
                best_codec, best = codec, out
        crc = zlib.crc32(data) & 0xFFFFFFFF
        hdr = HDR.pack(BLOCK_MAGIC, flags | best_codec, len(data), len(best), crc)
        return hdr + best, {"codec": best_codec & CODEC_MASK, "dict": bool(best_codec & FLAG_USES_DICT),
                            "raw_fallback": best_codec == CODEC_RAW}

    def decode_at(self, buf: memoryview, off: int) -> tuple[bytes, int, int]:
        """Decode the block at `off`. Returns (data, flags, next_offset)."""
        if off + HDR.size > len(buf):
            raise IntegrityError(f"truncated header at {off}")
        magic, flags, olen, slen, crc = HDR.unpack_from(buf, off)
        if magic != BLOCK_MAGIC:
            raise IntegrityError(f"bad block magic at {off}")
        p0 = off + HDR.size
        if p0 + slen > len(buf):
            raise IntegrityError(f"truncated payload at {off}")
        payload = bytes(buf[p0:p0 + slen])
        codec = flags & CODEC_MASK
        try:
            if codec == CODEC_RAW:
                data = payload
            elif codec == CODEC_ZLIB:
                data = zlib.decompress(payload)
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
        return data, flags, p0 + slen


# --------------------------------------------------------------------------
# Store writer / reader
#
# Store file:  STORE_MAGIC | [dict block] | pack blocks ... | manifest block | footer
# A "pack" is one 16-byte-header block whose (decoded) payload is
#     u32 count | count x u32 chunk lengths | chunk bytes ...
# Unique chunks are appended to the open pack and compressed together, so
# small chunks keep cross-chunk context (pack_target=0 = one chunk per block).
# A chunk is addressed by an 8-byte pointer: (pack_id << 20) | index_in_pack.
# --------------------------------------------------------------------------
PTR_SHIFT = 20
PTR_IDX_MASK = (1 << PTR_SHIFT) - 1


@dataclass
class FileEntry:
    path: str
    size: int
    sha256: bytes
    pointers: list[int] = field(default_factory=list)  # 8-byte chunk pointers


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


def _encode_pack(chunks: list[bytes]) -> bytes:
    return struct.pack(f"<I{len(chunks)}I", len(chunks), *map(len, chunks)) + b"".join(chunks)


def _decode_pack(payload: bytes) -> list[bytes]:
    (n,) = struct.unpack_from("<I", payload)
    lens = struct.unpack_from(f"<{n}I", payload, 4)
    off, out = 4 + 4 * n, []
    for ln in lens:
        out.append(payload[off:off + ln]); off += ln
    if off != len(payload):
        raise IntegrityError("pack length table does not match payload")
    return out


class StoreWriter:
    def __init__(self, path: str, chunker: FastCDC | None = None, codec: BlockCodec | None = None,
                 pack_target: int = 1 << 20, near_dup_hamming: int = 6):
        self.f = open(path, "wb")
        self.f.write(STORE_MAGIC)
        self.pos = len(STORE_MAGIC)
        self.chunker = chunker or FastCDC()
        self.codec = codec or BlockCodec()
        self.pack_target = pack_target
        self.index: dict[bytes, int] = {}      # raw 32-byte digest -> pointer
        self.refcount: dict[int, int] = {}
        self.pack_offsets: list[int] = []      # pack_id -> file offset
        self.open_pack: list[bytes] = []
        self.open_pack_bytes = 0
        self.entries: list[FileEntry] = []
        self.image_hashes: list[int] = []
        self.near_dup_hamming = near_dup_hamming
        self.stats = Stats()

    # ---- packs ----
    def _flush(self, flags: int = 0):
        if not self.open_pack:
            return
        payload = _encode_pack(self.open_pack)
        block, info = self.codec.encode(payload, flags)
        self.pack_offsets.append(self.pos)
        self.f.write(block)
        self.pos += len(block)
        st = self.stats
        st.packs += 1
        st.codec_counts[CODEC_NAMES[info["codec"]]] += 1
        st.dict_blocks += info["dict"]
        if info["raw_fallback"]:
            st.raw_fallback_blocks += 1
            st.raw_fallback_bytes += len(payload)
        self.open_pack, self.open_pack_bytes = [], 0

    def _put(self, data: bytes, media: bool = False) -> int:
        digest = hashlib.sha256(data).digest()
        self.stats.chunks_total += 1
        ptr = self.index.get(digest)
        if ptr is not None:
            self.refcount[ptr] += 1
            self.stats.dedup_bytes += len(data)
            return ptr
        if media:
            self._flush()                  # media never shares a pack
        pack_id = len(self.pack_offsets)
        ptr = (pack_id << PTR_SHIFT) | len(self.open_pack)
        self.open_pack.append(data)
        self.open_pack_bytes += len(data)
        if media:
            self._flush(FLAG_MEDIA)
        elif self.open_pack_bytes >= self.pack_target or len(self.open_pack) >= PTR_IDX_MASK:
            self._flush()
        self.index[digest] = ptr
        self.refcount[ptr] = 1
        self.stats.chunks_unique += 1
        return ptr

    # ---- ingest ----
    def add_file(self, rel_path: str, data: bytes):
        st = self.stats
        st.files += 1
        st.input_bytes += len(data)
        entry = FileEntry(rel_path, len(data), hashlib.sha256(data).digest())
        kind = detect_modality(data)
        if kind is not None:
            st.media_files += 1
            if kind in IMAGE_TYPES:
                h = dhash64(data)
                if h is not None:
                    if any(bin(h ^ o).count("1") <= self.near_dup_hamming for o in self.image_hashes):
                        st.near_dup_images += 1   # reported only; see README
                    self.image_hashes.append(h)
            entry.pointers.append(self._put(data, media=True))
        else:
            for chunk in self.chunker.chunks(data):
                entry.pointers.append(self._put(chunk))
        self.entries.append(entry)

    def train_dictionary(self, samples: list[bytes], dict_size: int = 112 * 1024):
        """Train a zstd dictionary and store it as the first block. Must be
        called before any add_file()."""
        if not zstd or len(samples) < 8 or sum(map(len, samples)) < 8 * dict_size:
            return False
        try:
            d = zstd.train_dictionary(dict_size, samples).as_bytes()
        except Exception:
            return False
        assert self.pos == len(STORE_MAGIC), "dictionary must be the first block"
        block, _ = self.codec.encode(d, FLAG_DICT)
        self.f.write(block)
        self.pos += len(block)
        self.codec.set_dictionary(d)
        self.stats.dict_bytes = len(block)
        return True

    @staticmethod
    def _walk(root: str):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if not os.path.islink(full) and os.path.isfile(full):
                    yield full

    def add_tree(self, root: str, use_dictionary: bool | None = None, sample_budget: int = 8 << 20):
        # A dictionary pays off when chunks are compressed alone; with large
        # solid packs it mostly costs its own size, so default to it only then.
        if use_dictionary is None:
            use_dictionary = self.pack_target <= 64 * 1024
        files = list(self._walk(root))
        if use_dictionary:
            seen, samples, budget = set(), [], sample_budget
            for full in files:
                with open(full, "rb") as fh:
                    data = fh.read()
                if detect_modality(data) is not None:
                    continue
                for c in self.chunker.chunks(data):
                    k = hashlib.sha256(c).digest()
                    if k not in seen and budget > 0:
                        seen.add(k); samples.append(c); budget -= len(c)
                if budget <= 0:
                    break
            self.train_dictionary(samples)
        for full in files:
            with open(full, "rb") as fh:
                self.add_file(os.path.relpath(full, root), fh.read())

    def close(self) -> Stats:
        self._flush()
        parts = [struct.pack("<I", len(self.pack_offsets)),
                 np.asarray(self.pack_offsets, dtype="<u8").tobytes(),
                 struct.pack("<I", len(self.entries))]
        for e in self.entries:
            p = e.path.encode("utf-8")
            parts.append(struct.pack("<H", len(p)) + p)
            parts.append(struct.pack("<Q32sI", e.size, e.sha256, len(e.pointers)))
            parts.append(np.asarray(e.pointers, dtype="<u8").tobytes())
        manifest = b"".join(parts)
        block, _ = self.codec.encode(manifest, FLAG_MANIFEST)
        moff = self.pos
        self.f.write(block)
        self.pos += len(block)
        self.f.write(FOOTER.pack(moff, STORE_MAGIC))
        self.pos += FOOTER.size
        self.f.close()
        self.stats.manifest_bytes = len(block)
        self.stats.store_bytes = self.pos
        return self.stats


class StoreReader:
    def __init__(self, path: str, codec: BlockCodec | None = None, cache_packs: int = 64):
        with open(path, "rb") as fh:
            self.buf = memoryview(fh.read())
        self.codec = codec or BlockCodec()
        if len(self.buf) < 8 + FOOTER.size or bytes(self.buf[:8]) != STORE_MAGIC:
            raise IntegrityError("not a hybrid store")
        moff, magic = FOOTER.unpack_from(self.buf, len(self.buf) - FOOTER.size)
        if magic != STORE_MAGIC:
            raise IntegrityError("bad footer")
        if len(self.buf) > 8 + HDR.size and HDR.unpack_from(self.buf, 8)[1] & FLAG_DICT:
            d, _, _ = self.codec.decode_at(self.buf, 8)
            self.codec.set_dictionary(d)
        manifest, flags, _ = self.codec.decode_at(self.buf, moff)
        if not flags & FLAG_MANIFEST:
            raise IntegrityError("footer does not point at manifest")
        self.pack_offsets, self.entries = self._parse_manifest(manifest)
        self._cache: dict[int, list[bytes]] = {}
        self._cache_max = cache_packs

    @staticmethod
    def _parse_manifest(m: bytes):
        try:
            (np_,) = struct.unpack_from("<I", m)
            packs = np.frombuffer(m, dtype="<u8", count=np_, offset=4).tolist()
            off = 4 + 8 * np_
            (n,) = struct.unpack_from("<I", m, off); off += 4
            out = []
            for _ in range(n):
                (pl,) = struct.unpack_from("<H", m, off); off += 2
                path = m[off:off + pl].decode("utf-8"); off += pl
                size, sha, cnt = struct.unpack_from("<Q32sI", m, off); off += 44
                ptrs = np.frombuffer(m, dtype="<u8", count=cnt, offset=off).tolist(); off += 8 * cnt
                out.append(FileEntry(path, size, sha, ptrs))
        except (struct.error, ValueError, UnicodeDecodeError) as e:
            raise IntegrityError(f"corrupt manifest: {e}") from e
        return packs, out

    def _chunk(self, ptr: int) -> bytes:
        pid, idx = ptr >> PTR_SHIFT, ptr & PTR_IDX_MASK
        pack = self._cache.get(pid)
        if pack is None:
            if pid >= len(self.pack_offsets):
                raise IntegrityError(f"pointer to missing pack {pid}")
            pack = _decode_pack(self.codec.decode_at(self.buf, self.pack_offsets[pid])[0])
            if len(self._cache) >= self._cache_max:
                self._cache.pop(next(iter(self._cache)))
            self._cache[pid] = pack
        if idx >= len(pack):
            raise IntegrityError(f"pointer past end of pack {pid}")
        return pack[idx]

    def read_file(self, e: FileEntry) -> bytes:
        data = b"".join(self._chunk(p) for p in e.pointers)
        if len(data) != e.size or hashlib.sha256(data).digest() != e.sha256:
            raise IntegrityError(f"SHA-256 mismatch restoring {e.path}")
        return data

    def unpack(self, out_dir: str):
        root = os.path.realpath(out_dir)
        for e in self.entries:
            dest = os.path.realpath(os.path.join(root, e.path))
            if not dest.startswith(root + os.sep):
                raise IntegrityError(f"unsafe path in manifest: {e.path}")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(self.read_file(e))

    def verify(self) -> int:
        for e in self.entries:
            self.read_file(e)
        return len(self.entries)


def _fmt(st: Stats) -> str:
    r = st.input_bytes / st.store_bytes if st.store_bytes else 0
    return (f"files={st.files} input={st.input_bytes:,}B store={st.store_bytes:,}B ratio={r:.2f}x\n"
            f"chunks total={st.chunks_total} unique={st.chunks_unique} dedup_saved={st.dedup_bytes:,}B "
            f"packs={st.packs}\n"
            f"media_files={st.media_files} near_dup_images={st.near_dup_images} "
            f"raw_fallback_blocks={st.raw_fallback_blocks} ({st.raw_fallback_bytes:,}B)\n"
            f"codecs={st.codec_counts} dict_coded={st.dict_blocks} dict={st.dict_bytes:,}B "
            f"manifest={st.manifest_bytes:,}B")


def main(argv):
    cmd = argv[0] if argv else ""
    if not ((cmd in ("pack", "unpack") and len(argv) == 3) or (cmd == "verify" and len(argv) == 2)):
        print(__doc__)
        return 2
    if cmd == "pack":
        w = StoreWriter(argv[2])
        w.add_tree(argv[1])
        print(_fmt(w.close()))
    elif cmd == "unpack":
        StoreReader(argv[1]).unpack(argv[2])
        print("ok")
    else:
        print(f"verified {StoreReader(argv[1]).verify()} files bit-exact")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
