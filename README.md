# Hybrid dedup + compression engine (Phase II prototype)

## 1. Summary of the write-up

The paper argues that classic codecs (LZ77, DEFLATE, LZMA) only see redundancy inside a small sliding window, so storage systems should layer three things:

1. **Content-defined chunking + hashing.** FastCDC cuts the stream at content-defined boundaries (stable under inserts/shifts), SHA-256 keys each chunk, and a dedup index turns repeats into 8-byte pointers. This is cheap and runs inline.
2. **Modality routing.** Media is detected and sent to a perceptual-hash (near-duplicate) and neural-codec track; text/code/binaries go to a lossless track.
3. **Entropy coding with a safety net.** zstd (optionally with dictionaries) or ANS, with a raw fallback when compression would expand the data.

It lists five Phase I bugs and Phase II fixes: a naive XOR boundary test (fix: a gear hash with normalized masks), no expansion check (fix: raw fallback), chunking media before detecting it (fix: detect first, whole-file media), hex-string hash keys (fix: raw 32-byte digests), and no on-disk header (fix: a 16-byte header with magic, flags, length, CRC32). It ends with a three-tier deployment: inline dedup, near-line zstd, and offline GPU neural archival.

## 2. What's in this folder

| File | Purpose |
|---|---|
| `hybridstore.py` | The engine and CLI: `pack <dir> <store>`, `unpack <store> <dir>`, `verify <store>` |
| `bench.py` | Builds the sample datasets, checks round trips, runs the corruption test, compares against baselines |
| `bench_results.txt` | Output of the last benchmark run |

Requirements: Python 3.10+, numpy, `zstandard` (optional; without it only zlib is used), and Pillow (optional, for near-duplicate image hashing).

### How each Phase II fix is implemented

* **FastCDC:** a 256-entry 64-bit gear table derived from SHA-256 (deterministic), with normalized chunking (a strict mask before the 8 KiB average, a loose mask after it) and 2 KiB / 64 KiB min/max sizes. Boundaries use the *high* bits of the hash, because in `h = (h<<1)+G[b]` the low bits depend on only the last few bytes. The hash is computed with numpy in 64 passes, and a test confirms it matches the rolling update exactly. A 3-byte prepend re-aligned all 110 boundaries on 1 MiB of random data.
* **Dedup index:** `dict[bytes(32)] -> int` pointer. Each pointer is 8 bytes: `pack_id << 20 | index`.
* **Media before chunking:** magic-byte detection for PNG, JPEG, GIF, BMP, TIFF, WebP, MP4, PDF, ZIP, gzip, bzip2, xz, 7z and zstd, run on the whole file. These files are stored as one object in their own block and are never sliced.
* **Expansion guard:** each block tries zlib-9 and zstd-19 and keeps the smallest. If no candidate is strictly smaller than the input, the block is written raw (codec bits = 0).
* **16-byte header:** `'HCB' | flags u8 | orig_len u32 | stored_len u32 | crc32(original) u32`. The CRC is computed on the decoded bytes, so it also catches codec bugs.
* **Integrity:** every file also stores its SHA-256. `unpack` and `verify` recompute it and raise `IntegrityError` if it doesn't match, so a restore is bit-exact or it fails. Unpack also rejects path traversal in the manifest.
* **Neural codec:** `NeuralCodec` is a clearly marked stub and is disabled. Learned image codecs are lossy and need PyTorch plus model weights, which conflicts with this project's bit-exact goal.

### One addition beyond the paper: solid packs

When each ~8 KiB chunk was compressed on its own, the result lost badly to plain `zstd -19` (3.49x vs 5.86x on code). This is because each chunk loses the context of its neighbours. Two fixes were tested:
* **Trained zstd dictionary** (per-chunk mode, `pack_target=0`): 3.49x → 4.34x.
* **Solid 1 MiB packs** (the default): unique chunks are appended to a pack, and the pack is compressed as one block: 5.35x. Restic and Borg use the same approach. The cost is that reading one chunk means decoding up to 1 MiB.

## 3. Measured results (this container, single thread, pure Python)

| Dataset | Input | Hybrid (packs) | Hybrid (per-chunk+dict) | zstd-3 | zstd-19 | zstd-19 --long |
|---|---|---|---|---|---|---|
| Code: Python stdlib, one copy | 10.3 MB | **5.35x** | 4.34x | 4.40x | 5.86x | 5.87x |
| Backups: 3 snapshots, ~3% files edited per night | 30.9 MB | **15.71x** | 12.80x | 4.40x | 5.97x | 17.43x |
| Mixed: logs, JSON, JPEG/PNG, random, gzip | 11.1 MB | **1.97x** | 1.92x | 1.87x | 1.97x | 1.97x |

* **Round trip:** 2,164/2,164 files were bit-exact in both modes on all three sets. This was checked independently by comparing the restored files byte-for-byte with the originals.
* **Corruption:** 200 out of 200 random single-bit flips in a store were detected (by CRC, SHA-256 or a structure check). None restored silently wrong data.
* **Throughput:** about 2–5 MB/s pack and 45–330 MB/s unpack. Packing is slow because it is pure Python trying both zlib-9 and zstd-19 on every block. It is not tuned.

**What the numbers say**
* Dedup is where the gains come from, and only when data repeats. On backups it removed 20.5 MB of the 30.9 MB before compression ran.
* On a single copy of source code, dedup barely helps (114 KB saved), and plain zstd-19 still beats the engine by about 9%.
* `zstd --long` (a 128 MiB window) beat the engine on backups too (17.4x vs 15.7x) because all the snapshots fit in its window. The engine's advantage is structural rather than in the ratio: random access per chunk, dedup across files and volumes far larger than any window, and per-block integrity checks.
* JPEGs, gzip and random data don't compress. They went through the raw fallback, which is the correct behaviour.

## 4. Claims in the write-up that look unsupported

* **The benchmark ratio table** (zstd 2.5–3.2x, FastCDC+zstd 4.1–5.8x, neural 8–24x, hybrid 6.5–14.2x, and the MB/s figures) has no source, dataset or method, and none of the references support it. These ratios depend almost entirely on how much the data repeats: here the same engine scored 1.97x on one dataset and 15.7x on another. The table also puts *lossy* neural ratios next to *lossless* ones, which isn't a like-for-like comparison.
* **"Filters 30–50% of redundant writes"** in Tier 1 is uncited and depends on the workload. It was 1% on the code set here and 66% on the backup set.
* **"FastCDC + zstd-19 beats zstd-3 by about 2x"** did not hold up when chunks were compressed one at a time. That only happens with solid packing or real duplication.
* **The citations are not tied to claims.** Almost every paragraph cites the same block [1]–[8]. Refs 1/5 and 3/6 are duplicates, ref 9 is never cited, and ref 7 is a vendor blog.
* **arXiv 2609.21309** would be a September 2026 paper. That date is plausible today and not in the future, but its existence could not be checked from here because arxiv.org is blocked in this environment. Check it before relying on it.
* **The cross-entropy formula** (H(p,q) = H(p) + KL(p‖q)) is missing from the paste, but the prose describes it correctly.
* **pHash near-duplicate delta + neural codec vs. integrity:** a pixel residual against a master image cannot rebuild the original JPEG/PNG *file bytes*, and neural codecs are lossy. Either one breaks bit-exact restore unless the original or a lossless file-level delta is also stored. In this run, the dHash check also flagged 10 of 13 synthetic images as "near duplicates" because they share a gradient, so thresholds need real tuning before anything is merged on that basis. Near-duplicates are only reported here; nothing acts on them.

## 5. Suggested next steps

Use zstd's own long-distance matching inside packs, delta-compress similar chunks (find them by sketch or resemblance), persist the index and handle refcounts/GC, use multiple threads for compression, and add a lossless JPEG recompressor (for example, a Brunsli/JPEG XL-style transcode) instead of a lossy neural codec.
