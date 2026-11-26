# Changelog

## 3.1.6 review notes (unreleased; code and format unchanged)
- Test only: `test_pack_memory_independent_of_input_size` absolute cap raised 40 -> 48 MiB; the
  growth bound (< 8 MiB from 8 to 48 MiB input) is unchanged. It failed on every Python 3.14 run
  (42.4 MiB fixed overhead, same as frozen 3.1.4), which hid real 3.14 results behind a known red.
- README: Windows section updated for the 3.1.6 `NtSetInformationFile` rename; it still described
  the 3.1.5 kernel32 call and said no real-Windows run had happened.
- Missing from the bundle: `test-results-v3.1.6-3090-*.txt`, cited in the 3.1.6 entry below.
- `rdc3.__version__` bumped '3.0.2' -> '3.1.6': rdc3.py carries 3.1.5/3.1.6 fixes (zstd backends and
  window check, sys.path guard, cryptography floor). The string is not written into archives, so
  RDCv003 output is unchanged; README wording updated to match.
- Test only: the descriptor-relative skip reason no longer blames RDC_SIM_NT on real Windows, where it
  fires without that switch set.
- Test only: new `need_links` fixture (conftest.py) probes whether the filesystem under `tmp_path` can
  create symlinks/hard links and skips instead of failing when it cannot. Applied to the 12 tests whose
  own setup makes links; on exFAT D: of the 3090 11 of them failed with WinError 1 (exFAT has neither).
  The rdc code paths they exercise are unchanged and still run wherever links exist.

## 3.1.6 (2026-11-13) — format unchanged; Windows publish fix
- Real-Windows run on the 3090 (Python 3.12, NTFS D:) failed 210/272: kernel32 `SetFileInformationByHandle(FileRenameInfo)` returns winerror 123 for a RootDirectory-relative name. `RDC_SIM_NT` could not catch this.
- `_NtApi.rename_by_handle` now calls `ntdll.NtSetInformationFile(FileRenameInformation)` with the same folder handle and leaf name (ReplaceIfExists=FALSE); NTSTATUS mapped via `RtlNtStatusToDosError` (name collision -> 183 -> FileExistsError). Probe on the 3090 confirmed it renames correctly.
- winerror 123 added to the write-through fallback list (still never REPLACE_EXISTING), per WEB, so one unexpected refusal cannot stop every write.
- zstandard backend: frame window read from the header and refused above the cap before decoding; one-shot decode ignored `max_window_size` for frames that record their content size (SEEKER). The stdlib/backports backends had the same gap (found on the 3090, Python 3.14 `compression.zstd`); both now check the header window first. Test `test_backend_window_cap_with_content_size`.
- `cryptography` below 46.0.7 now warns once when keyed mode starts (was only in requirements).
- Tests: portable-mode checks use the mode restore() actually uses (`RDC_PORTABLE=1` failed 3 tests in 3.1.5; SEEKER).
- README: collision check is rdc4-only; rdc3 `unpack` gets it in 3.1.7 (SEEKER, medium, not a regression).
- `RDC_SIM_NT` cannot emulate kernel32 (it runs on Linux), so it cannot reject folder-relative names; the real-Windows tests are the guard and must run on the 3090 before any Windows release.
- 3090 results: NTFS C: Python 3.12 and 3.14, exFAT D: Python 3.12, see test-results-v3.1.6-3090-*.txt. exFAT has no hard links, symlinks or folder fsync, so link tests fail there by design of the drive.
- v3.1.5 must not be used on Windows.

## 3.1.5 (2026-11-13) — format unchanged (RDCv004 / RDCv003); WEB sweep runs 1-9, frozen scope
1. **Security: `sys.path[0]` hijack.** `python -m rdc4` (and `-m rdc3`) started from a folder holding a
   restored `argparse.py` ran it. The current folder is now removed from `sys.path` at the very top
   of the module, before any other import, unless it is the tool's own folder. README recommends
   `python rdc4.py` or `python -P -m rdc4`. Regression test plants the module by restoring it.
2. **Windows publish: one handle-based path** (`_nt_publish`): folder opened with
   `FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT` and no `FILE_SHARE_DELETE` (reparse points
   refused), `FlushFileBuffers` on the staged file's handle, `SetFileInformationByHandle(FileRenameInfo,
   ReplaceIfExists=FALSE, RootDirectory=folder)`. `MoveFileExW(MOVEFILE_WRITE_THROUGH)` (never
   `REPLACE_EXISTING`) only on winerror 1/50/87; 183/80 → `FileExistsError`; 5/32/33 retried. Used for
   restored files and, through `rdc3._WIN_PUBLISH`, for archive outputs. `directories_fsynced` stays
   false on Windows. ctypes is imported only on `win32` (module top); error mapping and fallback
   selection are unit-tested with a fake API. The non-Windows `_link_noclobber` no longer has any
   rename fallback.
3. **zstd backends:** `zstandard` → `compression.zstd` (3.14+) → `backports.zstd`, `RDC_ZSTD_BACKEND`
   forces one; `window_log_max=24` hard cap on all; frame-header parser for the stdlib API (checked
   against `zstandard`). RDCv003 dictionary training stays `zstandard`-only with a clear error.
4. `requirements-v3.txt`: `cryptography>=46.0.7`. README: Windows needs 64-bit Python.
5. **`verify --packs N/T`**: rotating partial verify (packs with `index % T == N`: stored tags, AEAD
   tags when encrypted, shard hashes of overlapping parity groups; no zstd decode). Exact semantics in
   README.
6. **`unpack --sparse`** (opt-in): all pieces hashed, all-zero pieces seeked over, file truncated to
   full size before the durable sync. Same output hash; fewer allocated blocks on Linux (tested).
7. **Name collisions:** one `collision_key` run before staging on all platforms, driven by a
   destination probe (test name looked up in other case and in NFD). macOS key NFD+casefold, NTFS key
   1:1 per-character `upper()` (`straße`/`strasse` allowed again). Linux: warning by default,
   `--strict-names` refuses.
8. **`_durable_sync(fd)`**: `fsync` + `F_FULLFSYNC` on macOS (recorded as plain `fsync` if refused);
   used for staged files, the archive temp file and directory fsyncs. Reports carry `sync_mode` and
   an honest `directories_fsynced`.
9. Test: tampered RDCv003 dictionary (unkeyed, fuzzed content, all hashes/root recomputed) is refused;
   with only the post-decode chunk-id check disabled, wrong bytes come out (so that check is load-bearing).
   Dictionary load errors now map to `IntegrityError`.
10. Test pinning header/manifest HMAC before manifest decryption (RDCv003 and RDCv004).
11. `ELOOP` from the POSIX no-follow source open is now `IntegrityError`.
12. Regression tests: `..`/`.` directory entries; symlinks planted at a file path (live and dangling)
    and as a folder (before restore and during staging), POSIX and portable modes.
13. README: parity does not cover the manifest; a contiguous burst reaching 3+ shards of one group
    (measured: 192 KiB, unaligned) defeats RS(12,10).
- Version strings: `__version__ = '3.1.5'`, docstring/`--help` say v3.1.5.
- Deferred to RDCv005 (format change): tail copy of header+manifest, striped/interleaved RS groups.
  Deferred: streaming `--only` restore.

## 3.1.4 (2026-11-12) — format unchanged (RDCv004); room findings from WEB's sweep and SEEKER's tests
1. **Windows publish locks.** `os.link`/`os.rename` retry only winerror 5, 32, 33 with a bounded ~3 s
   backoff. `FileExistsError` fails at once; a lock that outlives the budget is raised, never followed
   by a silent `os.rename`.
2. **Link-safe backup reads.** New `_open_nofollow_read`: `O_NOFOLLOW` on POSIX, `CreateFileW` +
   `FILE_FLAG_OPEN_REPARSE_POINT` on Windows (reparse points refused), lstat/fstat identity check
   elsewhere; inode 0 is refused as unprovable. Portable staging creates are checked after create.
3. **`--temp-dir` that does not exist** now gives a clean `LimitError` instead of a raw
   `FileNotFoundError` (SEEKER).
4. **README: keyed gear is not a secrecy guarantee** (CCS 2025 CDC attacks); encryption of whole packs
   and the manifest is what hides chunk lengths. New test `test_no_chunk_metadata_outside_aead`.
5. Deferred: `compression.zstd` (Python 3.14) fallback. RDCv003 uses zstd dictionary training and
   raw-content dictionaries throughout, which the stdlib module does not cover one-for-one, so it needs
   its own change and tests. Windows-only branches still need a real Windows run.

## 3.1.3 (2026-11-12) — format unchanged (RDCv004); the user's four gaps
1. **Windows.** Restore no longer raises `NotImplementedError` without POSIX `dir_fd`: a path-based
   portable restore keeps the fail-closed / no-clobber / `PublicationError` contract and refuses
   symlinks, junctions and reparse points per component, Windows-reserved names and case-insensitive
   collisions. Pack-order staging and verify no longer use `pwrite`, `O_DIRECTORY` or `O_NOFOLLOW`.
   `O_BINARY` on every `os.open`; `_fsync_dir` skips on Windows; pack publication falls back to
   no-clobber `os.rename` where hard links are unsupported; junctions in a pack source are refused.
2. **Verify temp space.** Pack-order verify no longer stages the whole output in system temp. It keeps
   only unique verified pieces (RAM up to 64 MiB, then an unnamed temp file), checks free space for
   that before decoding, accepts `--temp-dir` / `temp_dir=`, and its error names both escape hatches.
   Report adds `spill: {bytes, on_disk}`. Restore uses the same mechanism (spill in its staging folder).
3. **Memory.** References are stored as `array('I')` (shared with the kept manifest), and the
   pack-order plan is per chunk instead of one tuple per reference. Measured: 12 M references /
   44 MiB manifest, peak RSS 1,658 → 552 MiB; staging peak on a 400 k-reference archive 42.6 → 0.6 MiB.
4. Docstring/README now say 3.1.3, matching `__version__`.
- Within the decode budget, restore now reads in piece order (as verify always did) instead of
  always going through pack order; above it, behaviour matches 3.1.1 (each pack decoded once).
- Tests: 172 + 14 new = 186 (2 blake3 skips without blake3). The whole suite also passes with
  `RDC_SIM_NT=1` (Windows-like `os`).

## 3.1.2 (2026-11-12) — format unchanged (RDCv004); safer defaults
- **Parity on by default.** `rdc4.pack()` and `rdc4.py pack` now write RS(12,10) parity with
  64 KiB shards (`DEFAULT_PARITY = (10, 2, 65536)`) unless told otherwise. `--no-parity`
  (API `parity=None`) turns it off; `--parity K,M[,SHARD]` still picks other settings, and
  `--parity` with `--no-parity` is an error. Archives written by older versions are read
  unchanged. `rdc3.py`'s own API/CLI is unchanged (RDCv003 stays byte-identical to 3.0.2).
- Cost of the default, from the v3.1 benchmark runs of the same (10, 2, 65536) setting
  (`measurements-v3.1.json`): about +20% stored size on every dataset (legacy +19.8%, logs
  +19.6%, mixed +19.9%, random32 +20.0%, versioned +19.8%); encode and decode times within
  run-to-run noise.
- `--max-decode 0` now has an alias `--force-sequential`, and when the replayed cost is above the
  default budget, verify emits a `RuntimeWarning` (printed to stderr by the CLI) before decoding and
  lists it in the report's new `warnings` field. Behaviour is otherwise unchanged (opt-in).
- Tests: 169 + 3 new = 172 (170 passed + 2 skipped without blake3): default parity repairs a
  flipped byte in restore and `repair`; CLI default / `--no-parity` / `--parity` / conflict;
  forced-sequential warning fires only when costly. Older tests now pass `parity=None`
  explicitly where they test the no-parity paths.

## 3.1.1 (2026-11-12) — format unchanged (RDCv004); fixes decode amplification found by SEEKER
- Restore now works in pack order: each needed pack is decoded at most once, its pieces are
  written straight into the staged files (positional writes), each chunk id is checked once per
  pack, and every staged file's SHA-256 is checked before anything is published. Fail-closed
  staging, no-clobber, `--recover`, `--only` and `PublicationError` behave as before.
  SEEKER's forged 4,502 B archive (1-byte pieces cycling across 3 × 16 MiB packs, ~94 GiB of
  decoding in 3.1.0) now restores with 3 pack decodes.
- `verify()` replays the 2-pack cache cost first. Within budget it checks sequentially as before;
  over budget it checks in pack order into a private temp dir (free space checked, removed
  afterwards). Legitimate shuffled-dedup archives still pass; nothing is refused on cost alone.
  Budget: `max_decode` / `--max-decode` on `verify` and `repair` (default max(256 MiB, 4 × used
  pack bytes); 0 = always sequential). Reports gain `verify_mode`, `sequential_decode_bytes` and
  `pack_decodes`.
- `rdc3._restore_into` gained an optional backward-compatible pack-order hook; RDCv003 behaviour
  unchanged.
- Tests: 163 + 6 new = 169 (167 passed + 2 skipped without blake3): thrash restore full/--only, thrash verify, max_decode=0, shuffled-dedup
  archive, forged digest under pack order incl. recover, normal archive stays sequential, CLI `--max-decode`.

## 3.1.0 (2026-11-09) — new format RDCv004 (solid packs); RDCv003 still read and writable
- New `rdc4.py` (version 3.1.0). Writes **RDCv004**: dedup per chunk (FastCDC, now 2/8/32 KiB
  default), unique chunks grouped into solid packs (default 2 MiB, `--pack-size`, 64 KiB–15 MiB),
  one zstd frame per pack (default level 19, `--level`; hash_log/chain_log capped at 20 to bound
  encoder memory), raw fallback per pack, optional `--threads N` (byte-identical output for any N).
- Reader: pack tag verified (or parity-repaired) before decrypt/decode; decode bounded by the
  declared pack length (≤ 16 MiB hard cap, window ≤ 16 MiB, content size must match, no trailing
  data); chunk ids verified after slicing; strict pack/chunk tiling validation; at most 2 decoded
  packs in memory during restore.
- Random-access restore: `unpack --only PATH` / `restore(paths=[...])` decodes only needed packs.
- All RDCv003 properties carried over: fail-closed staged no-clobber restore, `PublicationError`,
  recover mode, parity per group with identified bad shards, expansion cap (unkeyed 1000×, keyed
  uncapped unless `--max-expansion N`), free-space check, removal of a created destination.
- `rdc4.py` restores/verifies/repairs/lists RDCv003 archives (tested on fixtures written by
  v3.0.2: plain, dict+delta, keyed+parity). `--format 3` still writes RDCv003 via unchanged
  `rdc3.py` (byte-identical to 3.0.2); `--dict/--delta` are RDCv003-only.
- `rdc4` uses `rdc3.scan_source`/`check_tree` late-bound (shared path policy; lets WEB's
  monkeypatch-based archive forger work against rdc4).
- Tests: 82 (rdc3, unchanged) + 81 new in `test_rdc4.py` = 163 (161 + 2 skipped without blake3).
- Benchmarks (`bench_v31.py`, `BENCHMARKS-v3.1.md`): smaller than v3.0.2 on all compressible
  sets and about level with HCSTORE1@60ba952, but single-threaded encode is much slower than
  v3.0.2; see the report for exact figures.

## 3.0.2 (2026-11-09) — format unchanged (RDCv003)
- Keyed archives (password given, header/manifest HMAC verified) skip the expansion-ratio cap by
  default (`Limits.max_expansion_keyed = 0`). Unkeyed archives keep the 1000× default (outputs
  ≤ 64 MiB exempt). An explicit `--max-expansion N` / `max_expansion=N` still enforces a cap on
  keyed archives. The free-space check always applies.
- `LimitError` message now names `--max-expansion 0` and `max_expansion=0` explicitly.
- README: zero-filled/sparse files and disk images (e.g. 300 MiB zeros ≈ 700,000:1) exceed the
  unkeyed default and need `--max-expansion 0` (or a password).
- Tests 76 → 82: keyed 256 MiB zero file restores under defaults; same file unkeyed refused with the
  flag hint and restores with `--max-expansion 0`; 20-snapshot versioned tree restores under
  defaults (unkeyed and keyed); keyed archive with explicit cap refused; wrong password fails
  authentication before any cap decision.

## 3.0.1 (2026-11-09) — fixes from SEEKER's v3 adversarial review. Format unchanged (still RDCv003).
1. **Size amplification (medium).** `Archive` now refuses archives whose declared output exceeds
   `max_expansion` × archive size (default 1000×; outputs ≤ 64 MiB are exempt via
   `Limits.expansion_floor`). Override: `max_expansion=` on `Archive/verify/restore/repair/list_archive`,
   CLI `--max-expansion N` (0 disables). `restore` also checks `shutil.disk_usage` on the
   destination filesystem (or its parent when the destination is new) before staging and
   requires output + 64 MiB + 5% headroom. Both raise `LimitError` (subclass of `IntegrityError`)
   and write nothing. Per-chunk decode was already capped at the declared chunk length
   (frame content-size check + `max_output_size`); now covered by an explicit regression test.
   SEEKER's 475-byte → 2 GiB archive is refused.
2. **blake3 optional.** The blake3 round-trip variant is skipped when the module is missing.
3. **Failed restore cleanup.** If `restore` created the destination directory and then fails
   (any error except `PublicationError`), it removes that directory with `rmdir` (only if empty).
   Pre-existing destinations are never removed.
Tests: 70 → 76 (6 new v3.0.1 regressions; 2 existing assertions updated from "empty
destination remains" to "created destination removed").
