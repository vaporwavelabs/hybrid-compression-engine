# RDCv004 / RDCv003 — research compression store, prototype v3 (code version 3.1.6, see CHANGELOG.md)

Local research prototype by Arc, built from the agreed Arc/WEB/SEEKER design and the landscape
lessons (`../landscape/similar_systems.db`, lessons 1–15). **Not production software.** No
repository was modified and nothing was pushed. v1/v2 files in the parent directory are untouched
(v2 is only imported read-only for benchmarks).

Files: `rdc3.py` (format + CLI), `test_rdc3.py` (pytest acceptance suite), `gen_datasets.py`
(seeded datasets), `bench_v3.py` (benchmark harness), `corruption_report.py` (tamper/parity
drills), `make_report.py` (renders BENCHMARKS.md), `measurements-v3.json`, `corruption-v3.json`,
`BENCHMARKS.md`, `test-results-v3.txt`, `requirements-v3.txt`; 3.0.1 adds `CHANGELOG.md`,
`test-results-v3.0.1.txt`, `measurements-v3.0.1-subset.json`, and `peer/` (WEB and SEEKER
adversarial scripts with their 3.0.1/3.0.2 results); 3.0.2 adds `test-results-v3.0.2.txt`.

v3.1 adds `rdc4.py` (RDCv004 solid-pack writer/reader, reads RDCv003 too, CLI), `test_rdc4.py`,
`compat_fixtures/` (archives written by the v3.0.2 code, restored by the tests), `bench_v31.py`,
`sweep_v31.py`, `corruption_report_v31.py`, `make_report_v31.py`, `measurements-v3.1.json`,
`sweep-v3.1.json`, `sweep-v3.1-defaults.json`, `corruption-v3.1.json`, `BENCHMARKS-v3.1.md`,
`test-results-v3.1*.txt`, and v3.1 peer results in `peer/`. `rdc3.py` keeps the RDCv003 format of 3.0.2
(it has since gained the 3.1.5/3.1.6 backend and safety fixes; `rdc3.__version__` is 3.1.6) and
still writes RDCv003 (`rdc4.py pack --format 3`).

## v3.1: RDCv004 solid packs

**Why.** Per-chunk zstd-3 (RDCv003) loses context across chunks; HCSTORE1's solid packs compressed
better on versioned/logs/mixed. RDCv004 keeps dedup per chunk but compresses deduped chunks together.

**Write path.** Same scan and FastCDC chunker as v3 (defaults now 2 KiB min / 8 KiB avg / 32 KiB
max, because smaller chunks dedup more once the compressor no longer pays a per-chunk cost) → dedup
by chunk id with byte-for-byte confirmation → unique chunks appended in first-seen order to the
current pack; a pack is closed when adding the next chunk would pass `pack_size` (default 2 MiB,
range 64 KiB–15 MiB) — **chunks never span packs** → each pack is one zstd frame (default level
19, content size written, hash_log/chain_log capped at 20), stored raw if zstd does not shrink it
→ optional ChaCha20-Poly1305 per pack (nonce domain 2, index = pack number) → pack tag → parity
over the data region → manifest → atomic no-clobber publish. `threads=N` compresses up to N packs
in parallel (per-thread compressors, at most N packs in flight, results written in order), so the
archive is byte-identical for any thread count (tested).

**Read path.** Same header/manifest authentication as v3, then strict validation of the pack
table: codec ∈ {0 raw, 1 zstd}, raw packs have stored == raw, every declared pack raw length ≤
`Limits4.max_pack` (16 MiB) and ≤ `pack_size`+`max_chunk`, chunks tile packs exactly (in order,
no gaps, no overlap, no chunk past the end of its pack, every pack non-empty and fully used, every
chunk referenced). Per pack: verify the stored-byte tag **before** decrypt or decode (parity repair
+ re-verify if it fails) → decrypt → bounded decode (frame content size must equal the declared
raw length, `max_output_size` = declared length, window ≤ 16 MiB, no trailing data) → per chunk:
slice and check the chunk id. Per file SHA-256 and the root hash as before. Restore keeps at most
2 decoded packs in memory (LRU), so restore memory is bounded by ~2 × pack size plus buffers.

**Random access.** `rdc4.py unpack A DEST --only PATH` (repeatable; API `restore(..., paths=[...])`)
restores only the named files and decodes only the packs that hold their chunks (`pack_decodes`
in the result; tested to equal the needed set, and to succeed when an unrelated pack is corrupt).
The manifest is still authenticated and validated in full.

**Compatibility.** `rdc4.restore/verify/repair/list_archive/open_archive` dispatch on magic:
RDCv003 archives (including `--dict`/`--delta` and keyed+parity) restore unchanged — tested on
fixtures written by the v3.0.2 code. rdc3.py refuses RDCv004 (bad magic).

**RDCv004 format.** Header identical to RDCv003 except magic `RDCv004\n`. Manifest:
`{v:4, hash, level, pack_size, chunker:{min,avg,max,gear,seed}, packs:[[codec,raw_len,stored_len,tag]],
chunks:[[pack_index,raw_len,chunk_id]], files:[[path,size,sha256,[chunk refs]]], dirs, parity}`.
Data region = pack_0 || pack_1 || … (contiguous; offsets implicit). Chunk offsets inside a pack are
implicit from the order of `chunks`. Parity, paths, tags and keys as in RDCv003.

**Defaults and why** (all figures in BENCHMARKS-v3.1.md):
- Level 19: in the defaults sweep, level 15 stored 2.7–7.1% more and level 9 8.7–12.7% more
  (versioned/logs/mixed); 19 is the only level that reaches HCSTORE1's ratio. `--level 9` is the
  fast alternate (benchmarked as v3.1-L9).
- 2 MiB packs: 4 MiB saved at most 0.7% and raised restore RSS by up to ~13 MiB (two decoded
  packs are cached); 1 MiB cost 0.7–2.0%.
- 8 KiB average chunks: versioned is ~19% smaller than with 32 KiB chunks (more dedup of small
  edits); logs and mixed are 1.6% and 0.8% larger (more chunks = more manifest). Chosen because
  dedup across versions is the store's purpose.
- hash_log/chain_log capped at 20: zstd's own level-19 parameters for a 2 MiB source raised encoder
  RSS to 121–141 MiB single-threaded; the cap keeps it at 82–104 MiB (v3.0.2 baseline 71–95 MiB in
  the same benchmark) at a 0.1–0.6% ratio cost (`zstd_overrides={}` rows of the defaults sweep).
  With 4 threads encoder RSS is 92–154 MiB.
- Long-distance matching / larger window log: not used. Packs are independent frames of ≤ 2 MiB, so
  the window already covers a whole pack; LDM only helps when matches are farther apart than the
  window, which cannot happen inside a 2 MiB frame. Cross-pack redundancy is handled by dedup.
- 1 thread: deterministic either way; threads raise speed (v3.1-t4) at the cost of ~1 extra pack
  buffer + compressor context per thread in RSS.

**Trade-off (honest).** v3.1 stores fewer bytes than v3.0.2 on every compressible dataset and is
roughly level with HCSTORE1 (slightly better on versioned/mixed, slightly worse on logs), but
single-threaded zstd-19 encodes much slower than v3.0.2's zstd-3 (logs is the slowest set). With 4
threads it is faster than HCSTORE1 everywhere but still slower than v3.0.2. Decode speed is within
~25% of v3.0.2 (sometimes faster). Incompressible data (random32) is 0.3% larger than v3.0.2 because
8 KiB chunks mean a larger manifest. Use `--format 3` or `--level 9` when encode speed matters more than size.

## Quick start

```
pip install -r requirements-v3.txt      # Windows: use 64-bit Python (see Windows)
python rdc3.py pack  <dir-or-file> out.rdc3 [--parity 10,2[,65536]] [--dict] [--delta] [--encrypt] [--gear public|seeded|keyed] [--hash sha256|blake3]
python rdc3.py verify out.rdc3          # exit 4 = damaged but repairable, 1 = refused
python rdc3.py repair out.rdc3 fixed.rdc3   # parity rebuild into a NEW file, then re-verify
python rdc3.py unpack out.rdc3 destdir [--recover]
RDC_PASSWORD=... python rdc3.py pack --encrypt ...   # password only via environment
python -m pytest -q test_rdc3.py
python rdc4.py pack <dir> out.rdc4 [--level 19] [--pack-size 2097152] [--threads 4] [--parity 10,2 | --no-parity] [--encrypt] [--format 3]
python rdc4.py unpack out.rdc4 destdir [--only path/in/archive] [--sparse] [--strict-names]   # also restores RDCv003 archives
python rdc4.py verify out.rdc4 [--packs N/T]   # N/T: partial rotating check, see "3.1.5" below
python -m pytest -q test_rdc3.py test_rdc4.py
python gen_datasets.py && python bench_v3.py --runs 3 && python corruption_report.py && python make_report.py
```

## Pipeline

Write: scan tree (no symlink following; symlinks/special files refused) → FastCDC chunking
(normalized, 8 KiB min / 32 KiB avg / 128 KiB max default) → dedup by chunk id (SHA-256,
HMAC-SHA256 when keyed, or BLAKE3) with byte-for-byte confirmation of every dedup hit → per-chunk
codec = smallest of zstd(level), zstd+trained dictionary (`--dict`), delta+zstd against a similar
earlier chunk (`--delta`, experimental), else **raw** → optional ChaCha20-Poly1305 (`--encrypt`) →
authenticate stored bytes (HMAC-SHA256 keyed, SHA-256 otherwise) → optional RS(k+m,k) parity
over the stored data region → manifest + root hash → temp file, fsync, no-clobber `link()`
publish, directory fsync.

Read: header limits and exact file length → authenticate header+manifest (before decrypting or
decompressing) → decrypt manifest (AEAD) → bounded decompress → strict JSON (duplicate keys,
trailing bytes, non-canonical encoding rejected) → full schema validation → root hash check.
Per chunk: verify stored-byte tag **before** decrypt/decode; if it fails and parity exists, repair
from parity and re-verify; decode with advertised length as hard cap, window cap, dictionary id
check, trailing bytes rejected; check chunk id of decoded bytes. Per file: SHA-256. Whole tree:
root hash recomputed from restored digests.

## RDCv003 format

```
offset 0   header (120 bytes, big-endian)
           8s  magic "RDCv003\n"
           B   minor version = 0
           B   flags: bit0 KEYED, bit1 ENCRYPTED (others must be 0; ENCRYPTED requires KEYED)
           H   reserved = 0
           16s scrypt salt (zero when unkeyed)
           B   scrypt log2(N) (0 when unkeyed; 10..20 accepted), r=8, p=1
           3s  reserved = 0
           Q   manifest stored length
           Q   manifest raw (decompressed) length   (<= 64 MiB)
           Q   payload length
           32s root  = TAG("rdc3-root\0" || canonical({files:[[path,size,sha256]...], dirs}))
           32s tag   = TAG(header[0:88] || manifest_stored)
88+32      manifest_stored = zstd(canonical JSON) [ChaCha20-Poly1305, nonce (1,0), AAD = header[0:88]]
...        payload = data region || parity region
           data region   = [dictionary] || chunk_0 || chunk_1 || ...   (contiguous, implicit offsets)
           parity region = for each group: m parity shards
file size MUST equal 120 + manifest_stored + payload (no trailing bytes, no truncation)
```

TAG = HMAC-SHA256(mac_key, ·) when keyed, else SHA-256 (detection only). Keys: scrypt(password,
salt) → master; mac/enc/id/gear subkeys = HMAC-SHA256(master, "rdc3/<label>").

Manifest JSON (canonical, sorted keys, exact key sets):
`{v:3, hash, level, chunker:{min,avg,max,gear,seed}, dict:[raw_len,stored_len,tag]|null,
chunks:[[codec,raw_len,stored_len,chunk_id,stored_tag,delta_base]], files:[[path,size,sha256,[chunk refs]]],
dirs:[path], parity:{k,m,shard,groups:[[k+m shard tags]]}|null}`.
Codecs: 0 raw (stored == raw), 1 zstd, 2 zstd+dictionary, 3 delta+zstd (base must be an earlier,
non-delta chunk; depth 1). Compressed codecs must be strictly smaller than raw (canonical
fallback). Every chunk must be referenced. Chunk nonce = (0, index+1); dictionary (0,0).

Parity: data region split into groups of k shards × `shard` bytes (last group shrinks to
ceil(len/k), zero-padded). m Cauchy-matrix Reed–Solomon parity shards per group over GF(2^8)
(own numpy implementation, systematic, any k of k+m shards reconstruct). Each shard has its own
tag, so damaged shards are *identified* and treated as erasures: up to m bad shards per group are
repaired; more are refused.

Paths: relative POSIX, UTF-8, no empty / `.` / `..` components, no leading `/`, no `\`, no `:`,
no control chars, max 4096 bytes, unique, no file used as a directory, reserved prefix
`.rdc3-staging-` refused.

## Safety properties (each has a test)

- Fail closed by default; `--recover` is the only skip-and-warn mode, and it still publishes
  only files whose SHA-256 verified (damaged files are listed, never written).
- Restore never truncates or overwrites: conflicts are checked before anything is written; files
  are staged in a private directory inside the destination, verified against SHA-256 and the root
  hash, fsynced, then published with `link()` (fails if the name exists). Directory components
  are opened with `O_NOFOLLOW` relative to directory descriptors, so symlinked components are
  refused. A failure after the first publish raises `PublicationError` (published list,
  `durability_confirmed=False`), distinct from `IntegrityError` (nothing published).
- Writer refuses output inside the source tree, output equal to input, existing outputs, and
  symlinks in the source; detects files changing while read.
- Expansion and disk-space caps (3.0.1, keyed rule 3.0.2): for **unkeyed** archives the declared
  output may not exceed 1000× the archive size (outputs ≤ 64 MiB exempt). **Keyed** archives
  (password, header/manifest HMAC verified) have no ratio cap by default, because only the
  password holder could have declared those sizes; an explicit `--max-expansion N`
  (API `max_expansion=N`) still enforces a cap on them. Restore always requires free space for
  output + 64 MiB + 5% on the destination filesystem before staging. Violations raise `LimitError`
  and write nothing. A failed restore removes a destination directory it created.
  **Note:** legitimate zero-filled/sparse files and disk images exceed the unkeyed default cap
  (measured: 300 MiB of zeros packs unkeyed to 448 bytes, about 702,000:1). Restore those with
  `--max-expansion 0` (API `max_expansion=0`) to disable the cap, or pack them with a password.
- Bounded resources: chunk ≤ 1 MiB, zstd window ≤ 8 MiB, manifest ≤ 64 MiB, total restored output
  ≤ 64 GiB (repeated-pointer amplification), file/chunk count caps, scrypt cost bounds. Data is
  streamed in 1 MiB reads; payload/raw spools live on disk (anonymous temp files).
- Decode work is bounded (3.1.1, reworked 3.1.3): restore and verify read in piece order while the
  replayed 2-pack cache cost stays within `--max-decode` (default max(256 MiB, 4× used pack bytes)).
  Above that they decode each needed pack once, in pack order, and keep only the **unique** verified
  pieces: in RAM up to 64 MiB (`Limits4.spill_memory`), then in an unnamed temp file (`--temp-dir`
  for verify; the destination's staging folder for restore). Files are then written/hashed
  sequentially from that copy. A forged 4.5 KB archive that cost ~94 GiB of decoding in 3.1.0
  costs 3 pack decodes. `--max-decode 0` / `--force-sequential` forces piece order with no temp
  disk and warns first when that would be costly (3.1.2).
- Memory (3.1.3): piece references are held as 4-byte arrays and the restore plan is per chunk, not
  per reference. Measured on a 44 MiB manifest with 12 M references: peak RSS 1,658 MiB (3.1.2) →
  552 MiB (3.1.3), almost all of it Python's JSON parse of the manifest itself.
- Parity is on by default from 3.1.2: RS(12,10), 64 KiB shards, about +20% size. A flipped byte
  is repaired in flight on restore, and `repair` rebuilds a clean copy. `--no-parity` turns it off.
- Lossless only. No lossy, perceptual, or neural modes.

## Tests

`python -m pytest -v test_rdc3.py` → see `test-results-v3.txt`. Covers round trips (empty tree,
empty file, tiny, multi-block large, random, highly redundant, duplicate files, nested/empty dirs,
single-file source, every codec/parity/encryption/hash/gear variant), vectorized gear hash
equals the rolling reference, CDC insert resilience, keyed gear changes boundaries, RS any-m
erasures, truncation and trailing bytes, bit-flip fuzz (plain and encrypted), header
reserved/flag bits, duplicate JSON keys, non-canonical manifest, 12 unsafe path forms,
duplicate/conflicting paths, 13 bad length/offset/codec/reference cases, payload length
mismatch, 64 MiB decompression bomb (bounded heap), pointer amplification cap, root-hash
verification, wrong/missing password and HMAC forgery, writer self-ingestion/overwrite/symlinks,
pack and restore failpoints (`PublicationError`), bounded memory independent of input size,
restore conflict/no-partial/symlinked destination, recover mode, parity drills (bit-flip →
verify → repair → byte-identical re-verify; drop m shards → repair; m+1 → refused, nothing
published) and CLI exit codes.

Peer regressions adapted as pass/fail gates (same intent, v3 API):
WEB `test_web_regressions.py` → `test_web_existing_destination_survives_validation_failure`,
`test_web_validation_failure_leaves_no_new_destination`, `test_web_manifest_rejects_trailing_bytes`,
`test_web_codec_block_rejects_trailing_bytes`, `test_web_verify_rejects_unsafe_manifest_path`,
`test_web_basic_roundtrip`. SEEKER `debug_regressions.py` → `test_seeker_restore_never_overwrites_existing_file`,
`test_seeker_integrity_failure_preserves_existing_file`, `test_seeker_codec_block_rejects_trailing_payload`
(v3 has no zlib codec, so the zlib case is applied to zstd frames + JUNK), `test_seeker_manifest_rejects_unconsumed_bytes`.
Parser-hardening tests forge unkeyed archives with recomputed SHA-256 tags (what an attacker can
do without a key) so the decoder checks themselves are exercised. A local mutation check
(disabling individual checks in a scratch copy) confirmed each targeted check is caught by at least one test.

**v3.1 (`test_rdc4.py`, 81 tests; full suite 163 → `test-results-v3.1.txt`, no-blake3 venv
`test-results-v3.1-noblake3.txt`):** RDCv004 round trips (levels, pack sizes, threads, parity,
encryption, blake3, gears, tiny chunks, uncapped zstd params), thread-count determinism, empty
tree, raw packs, multi-pack with no chunk split; pack corruption refused with nothing published;
pack authenticated before decode (decoder spy); chunk hash checked after unpacking; truncated pack;
oversized declared pack; frame larger than declared (bounded heap, with and without content size);
5 chunk spanning/tiling forgeries; random-access restore decodes exactly the needed packs and
survives corruption of an unrelated pack; restore and pack memory bounds; framing, fuzz, header and
manifest strictness; 9 unsafe paths; 12 bad-field forgeries; keyed forgery; expansion cap
(unkeyed refused / keyed skipped / explicit enforced) and a forged 2 GiB-from-one-pack
amplification; free space; created-destination cleanup; writer safety; failpoints; invalid
parameters; no-overwrite and symlinks; recover mode; parity flip/repair byte-identical, drop m /
m+1, encrypted parity; WEB and SEEKER regressions re-targeted at RDCv004; v3.0.2 fixtures
(plain, dict+delta, keyed+parity) restore/verify/list/repair; format-3 writing; CLI.
Mutation check (scratch copy): removing the chunk-hash check, pack authentication, or the pack
cache bound each fails a test; removing rdc4's decoded-length check is not caught because the
shared `_zstd_decode` enforces the same length (redundant check).

Peer scripts (`peer/`, unmodified): run against `rdc3.py` (their target API) — WEB 20/20, SEEKER
rev2 20/20 PASS. Also run against rdc4 through `peer/shim_rdc4_run.py`, which routes rdc3's
pack/restore/verify/repair/Archive to rdc4 (and drops `delta`/`use_dict`, which RDCv004 lacks):
WEB 20/20; SEEKER 19/20. The one SEEKER failure is its amplification forger, which writes a v3
chunk table into the RDCv004 file and is refused as `IntegrityError: manifest schema` rather than
`LimitError`. `test_seeker_amplification_forged_v4_refused_limit` covers the same attack in
RDCv004 form (refused with `LimitError`, nothing created).

## External libraries

| library | version | license | use |
|---|---|---|---|
| zstandard (python-zstandard, bundles libzstd) | 0.25.0 / libzstd 1.5.7 | BSD-3-Clause (libzstd BSD/GPLv2 dual) | codecs |
| numpy | 2.5.4 | BSD-3-Clause | vectorized gear hash, GF(256) RS |
| cryptography | 43.0.0 | Apache-2.0 OR BSD-3-Clause | scrypt, ChaCha20-Poly1305 |
| blake3 (optional) | 1.0.11 | CC0-1.0 OR Apache-2.0 | optional chunk hash |
| pytest (tests) | 9.2.0 | MIT | tests |
| restic (benchmark only, static binary) | 0.17.3 | BSD-2-Clause | comparison |
| borg (benchmark only, standalone binary) | 1.4.0 | BSD-3-Clause | comparison |

FastCDC chunker and Reed–Solomon are original code in `rdc3.py` (no third-party chunker/RS
library). `zfec` (GPL-2+) and `reedsolo` were evaluated and **not used**. The hybrid engine
(`_ref/`, pinned 60ba952) was run unmodified only as a benchmark comparator. `vaporwavelabs/Data-chunk`
(8e864f7, "HalvePack") has **no license**, so none of its code was copied or executed; it is a
browser TypeScript/Vite UI without an archive format or CLI, so it was not benchmarked.

## Limitations (honest)

- Prototype, single-threaded pure Python + C codecs. Throughput numbers are for this box, warm
  page cache, synthetic data; do not generalize.
- Per-chunk compression loses cross-chunk context; HCSTORE1's 1 MiB solid packs with zstd-19
  beat plain v3 on ratio for some sets (see BENCHMARKS.md). `--dict` helped little here and its
  trained dictionary is overhead on small archives; delta+zstd is experimental (depth-1 bases,
  resemblance sketch of 3 features).
- Unkeyed archives use SHA-256: detects accidental damage, **does not** stop an attacker who can
  rewrite the archive (tests demonstrate this by forging). Use a password for authentication.
- Encrypted archives reveal total archive size, manifest size and payload length. Chunk
  lengths and boundaries live only in the encrypted manifest (the payload has no per-chunk
  framing) and the keyed gear table avoids public-table chunk-size fingerprinting, but this
  has not been reviewed by a cryptographer. scrypt cost 2^15 by default. Password only via `RDC_PASSWORD`.
- Header and manifest are not parity-protected: damage there is detected and refused, not
  repaired. Parity repairs only the data region, up to m identified bad shards per group.
  Parity overhead ≈ m/k plus per-shard tags.
- Single archive, no incremental append; dedup is within one archive (versioned data benchmarked
  as one tree of 8 snapshots, whereas restic/borg add snapshots incrementally to a repo).
- Not preserved: permissions, owners, timestamps, xattrs, ACLs, hard links, symlinks (refused),
  special files (refused). Sparse holes are not recorded; `unpack --sparse` (3.1.5) recreates holes
  for all-zero pieces on restore.
- Case/normalization collisions (`A` vs `a`, NFC vs NFD `café`) are accepted on write. 3.1.5 checks
  them before staging on every platform in rdc4 only (rdc3 `unpack` has no collision check yet; planned for 3.1.7) (see "Name collisions" below).
- **Parity does not cover the manifest** (or the header). One flipped byte there is detected and
  refused, and `repair` cannot fix it (WEB run 5, `sim_parity_gaps.py`). Keep a second copy of
  archives that matter. A tail copy of header+manifest is planned for RDCv005.
- **Parity groups are contiguous.** Each RS(12,10) group is 10 consecutive 64 KiB shards, so a single
  contiguous burst that reaches 3 or more shards of one group cannot be repaired: measured, a burst of
  192 KiB starting off a shard boundary touched 4 shards and failed, while a 128 KiB shard-aligned
  burst was repaired. Striped/interleaved RS is planned for RDCv005.
- Memory: Python heap stays bounded (test: 8 vs 48 MiB input), but the manifest and chunk index
  are held in memory (≈ hundreds of bytes per unique chunk), and scrypt uses 32 MiB in keyed mode.
- Recover mode is file-granular (a file with any unrecoverable chunk is skipped entirely). In
  RDCv004 one damaged pack (without parity) makes every file with a chunk in that pack
  unrecoverable — a larger blast radius than RDCv003's single chunk.
- RDCv004 restore keeps only 2 decoded packs; a file whose chunks jump between many old packs
  (dedup back-references) re-decodes packs, costing time, not correctness. Random access still
  needs the whole manifest in memory.
- RDCv004 single-threaded encode at the zstd-19 default is several times slower than RDCv003;
  measured figures in BENCHMARKS-v3.1.md.

### Windows (supported, path-based; 3.1.6 fixes the 3.1.5 publish failure on real Windows)

- **3.1.6 rename call.** The handle-based rename below is now made with
  `ntdll.NtSetInformationFile(FileRenameInformation)` (same folder handle, leaf name,
  ReplaceIfExists=FALSE), because kernel32 `SetFileInformationByHandle(FileRenameInfo)` returned
  winerror 123 for a RootDirectory-relative name on real Windows. NTSTATUS is mapped through
  `RtlNtStatusToDosError`; winerror 123 joins the `MoveFileExW(MOVEFILE_WRITE_THROUGH)` fallback
  list (still never `MOVEFILE_REPLACE_EXISTING`). The 3.1.5 wording below is kept for history.
  **Do not use 3.1.5 on Windows.**

- **Use 64-bit Python** on Windows (`python -c "import struct; print(struct.calcsize('P') * 8)"` must
  print 64). The ctypes publish code, the `cryptography` and `zstandard` wheels and the memory limits
  are only meant for 64-bit builds.
- 3.1.5 publish: one handle-based path for restored files, archive outputs (`pack`, `repair`) and
  RDCv003 writes made through `rdc4`. The destination folder is opened with `CreateFileW`
  (`FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, no `FILE_SHARE_DELETE`, so it cannot be
  renamed or swapped for a junction while held) and refused if it is a reparse point; the staged file
  gets `FlushFileBuffers` on its own handle and is renamed with `SetFileInformationByHandle(FileRenameInfo,
  ReplaceIfExists=FALSE, RootDirectory=<folder handle>)`. Only if that call is unsupported (winerror
  1, 50 or 87) does it fall back to `MoveFileExW(MOVEFILE_WRITE_THROUGH)`, never with
  `MOVEFILE_REPLACE_EXISTING`. An existing name (winerror 183/80) is `FileExistsError`; 5/32/33 are
  retried as in 3.1.4. Restore reports `publish` (`handle_rename` or `movefile_write_through`).
- **Write-through is not a full crash guarantee.** Windows has no directory fsync, so
  `directories_fsynced` is always `false` there; the file data is flushed and the rename is requested
  write-through, but no public Windows API promises the new name survives every power cut.
- The parent folders on the way to the publish folder are still checked by path (`lstat` per
  component), so the residual race below now only applies to those intermediate folders.

- Restore picks its mode automatically: descriptor-relative (`dir_fd`, `O_NOFOLLOW`) on POSIX,
  path-based **portable** mode where those are missing (Windows Python). `restore(..., portable=True)`
  or env `RDC_PORTABLE=1` forces portable mode anywhere; the result reports `mode`.
- Portable mode keeps the same contract: conflict pre-check, everything staged and SHA-256/root
  checked before anything is published, no-clobber publication (`os.link`; on FAT/exFAT,
  `os.rename`, which refuses an existing target on Windows), `PublicationError` once anything is
  published, `--recover` and `--only`. Every path component is `lstat`-checked and refused if it is
  a symlink, a junction or any other reparse point.
- Residual risk vs POSIX: the checks are by path, so a local process racing to swap an
  already-checked folder for a junction between the check and the link is not excluded. Restore
  into a folder only you can write to.
- Names Windows would reinterpret are refused before anything is written: `CON`, `PRN`, `AUX`,
  `NUL`, `COM0-9`, `LPT0-9` (with any extension), `<>"|?*`, trailing dots/spaces, and paths that
  collide case-insensitively. `:` `\` and control characters were already refused everywhere.
- All files are opened with `O_BINARY`. Directory fsync does not exist on Windows; the result says
  `directories_fsynced: false` there. `rdc3.restore` hands off to the same portable path.
- Tested by running the full suite with `RDC_SIM_NT=1` (conftest removes `O_DIRECTORY`,
  `O_NOFOLLOW`, `pwrite`, `pread`, `fchmod` and `dir_fd` support), plus dedicated portable tests.
  3.1.6: the changelog records real-Windows runs on the 3090 (NTFS C: on Python 3.12 and 3.14, exFAT
  D: on 3.12), but their result files (`test-results-v3.1.6-3090-*.txt`) are not in this source
  bundle, so this README cannot quote them.
- 3.1.4: publishing retries only Windows errors 5, 32 and 33 (antivirus/indexer locks) with a
  bounded ~3 s backoff; `FileExistsError` still fails at once, and a lock that outlives the budget is
  raised instead of falling back to `os.rename`. Backup reads open with `CreateFileW` +
  `FILE_FLAG_OPEN_REPARSE_POINT` and refuse any reparse point; staged files are checked after create.
  These Windows-only branches have not been executed on real Windows yet.

### Keyed chunking is not a secrecy guarantee (3.1.4)

- `gear='keyed'` keeps cut points stable per password, but published work (Truong et al.,
  "Breaking and Fixing Content-Defined Chunking", CCS 2025) recovers Gear/Rabin keys from visible
  chunk lengths in borg, restic, tarsnap and others. Do not rely on the keyed gear for privacy.
- What protects an encrypted RDCv004 archive is that chunk boundaries are never visible: each pack
  (about 2 MiB of many chunks) and the manifest (pack table, chunk list, parity layout) are sealed with
  AEAD as a whole, and the header holds only sizes of those sealed blobs. Outsiders see pack count
  and lengths, not chunk lengths. A test (`test_no_chunk_metadata_outside_aead`) guards this.
- Rule for future versions: never add a plaintext per-chunk index or length table.

## 3.1.5 additions

### Security: run `python rdc4.py`, or `python -P -m rdc4`
- `python -m rdc4` puts the *current folder* first on `sys.path`. Started from inside a restore
  destination, a restored `argparse.py`/`json.py`/... would run (WEB run 9, reproduced by SEEKER).
  3.1.5 removes that entry at the very top of `rdc4.py` (and `rdc3.py`) before any other import, unless
  the current folder is the tool's own folder. Recommended anyway: `python rdc4.py ...`, or on Python
  3.11+ `python -P -m rdc4 ...` (`-P` never adds the current folder). Test:
  `test_python_m_from_restore_destination_does_not_run_restored_module`.

### zstd backends
- Order: `zstandard` → stdlib `compression.zstd` (Python 3.14+) → `backports.zstd`. Env
  `RDC_ZSTD_BACKEND=zstandard|compression.zstd|backports.zstd` forces one (error if missing). Frames are
  identical in format; archives written by one backend are read by the others (tested).
- Every backend decodes with a hard window cap of 2^24 (16 MiB, `window_log_max=24`); the per-format
  limit is checked from the frame header first (a small header parser is used for the stdlib API,
  which does not report the window size).
- RDCv003 dictionary training (`--format 3 --dict`) needs `zstandard`; with another backend it stops
  with a clear error instead of silently packing without a dictionary. Reading dictionary archives
  and writing delta archives work on every backend.

### Durability (`sync_mode`, `directories_fsynced`)
- Every durable sync (staged files, the archive temp file, directory fsyncs) goes through
  `_durable_sync`: `fsync`, plus `fcntl(F_FULLFSYNC)` on macOS, where plain `fsync` does not flush the
  drive cache. If `F_FULLFSYNC` is refused (some external/network volumes), plain `fsync` is what was
  done and is what gets reported. Reports (`pack`, `repair`, `unpack`) carry `sync_mode`
  (`full_fsync` only if every sync achieved it, else `fsync`) and `directories_fsynced` (true only when
  directory syncs actually ran). macOS full syncs are slower; not yet run on a real Mac.

### Partial verify: `verify --packs N/T`
- Checks only packs whose index `i` satisfies `i % T == N`: each selected pack's stored-bytes tag
  (HMAC-SHA256 keyed, SHA-256 unkeyed) and, for encrypted archives, its ChaCha20-Poly1305 tag
  (decrypt only), plus all k+m shard hashes of every parity group whose data range overlaps a selected
  pack. No zstd decoding and no file digests (the manifest and root are authenticated on open, as
  always). Running N = 0 .. T-1 (for example one slice per day) covers every pack and every shard at
  least once. Exit 4 when the slice finds damage, as for a full verify. RDCv004 only.

### Sparse restore: `unpack --sparse`
- Opt-in. Every piece is still hashed; all-zero pieces are skipped with a seek, and the file is
  truncated to its full size before the durable sync, so a file ending in zeros has the right
  length. Output bytes are identical (tested by hash); on Linux the test also checks fewer allocated
  blocks. Windows NTFS zero-fills the gaps unless a file is marked sparse (not done here), so the
  output is correct there but not smaller.

### Name collisions (`--strict-names`)
- rdc4 only (rdc3 has no collision check until 3.1.7). One key function (`collision_key`) runs before staging on every platform. Before staging, restore
  creates a test name in a temporary folder inside the destination and looks it up in upper case and
  in NFD. If either lookup finds it, the destination is case- or normalization-insensitive and
  colliding names are refused up front (nothing written): macOS-style key = NFD + casefold; NTFS-style
  key = per-character `upper()` kept only if it stays one character, so `straße`/`strasse` are allowed
  but `Readme.md`/`README.md` are not; normalization-only = NFD.
- On a case- and normalization-sensitive destination (Linux), such names restore fine but produce a
  warning (`name_warnings` in the report); `--strict-names` refuses them. The Windows-rules check of
  portable mode uses the same key. Python's Unicode tables only approximate a volume's own case table,
  so the no-clobber publish stays the final backstop.
