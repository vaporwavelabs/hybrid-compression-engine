# RDC Archiver v3: real progress bar, safer password, benchmarks

## In one paragraph

rdc4.py now has two new options that are only used when asked for: `--progress`, which reports how far
along it is, and `--password-stdin`, which takes the password through a private pipe. Without these
options, rdc4.py behaves exactly as before. Archives come out **byte-for-byte identical** to the
original v3.1.6, and the full test suite passes (280 passed, 8 skipped, 0 failed; the 6 extra tests are
new ones for these options). The window uses both options when it finds them, so you get a real
percentage bar with "about N min left". If it's pointed at an unchanged rdc4.py, it works as before.
Speed is the same within normal run-to-run noise.

## Benchmarks (cloud test machine: 4 CPU cores, Ubuntu 24.04, Python 3.12)

Test data: 164 MB of mixed research-style files. That's 60 MB of logs, 8 slightly edited versions of
a 6 MB document, 30 MB of random binary, 24 MB of measurements, and 2,000 small files. Settings: level
19 (the default), 4 threads. I ran the three versions in alternating order so a slow moment on the
machine couldn't favour one of them.

| | Original rdc4.py | New rdc4.py | New rdc4.py with `--progress` |
|---|---|---|---|
| Pack (median of 8 runs) | 13.9 s | 13.8 s | 14.2 s |
| Pack, fastest to slowest run | 13.2–14.6 s | 13.1–14.7 s | 13.8–15.3 s |
| Verify (median of 3) | 0.88 s | 0.91 s | 0.88 s |
| Unpack (median of 3) | 2.7 s | 2.3 s | 2.3 s |
| Archive size | 66,399,893 bytes | 66,399,893 bytes | 66,399,893 bytes |
| Archive SHA-256 | 95d8fb8a…30fa672 | same | same |
| Unpacked files identical to the source | yes | yes | yes |
| Progress lines printed | 0 | 0 | 43 (about 3 per second) |

**How to read this:** all three are within the machine's normal run-to-run spread of about ±5%. The
progress option adds one byte counter per piece of data and a few short lines per second, which is far
too little to measure. The archive is the same file to the last byte, which meets the project rule that
speed-related changes must leave the output byte-identical.

**Encrypted pack, password by environment vs by stdin:** 13.9 s vs 13.3 s. Both archives are the same
size apart from random encryption salt. An archive made with `--password-stdin` is read by the
*original* rdc4.py using the old `RDC_PASSWORD` method, so nothing is locked in.

### Window benchmarks

| Test | Result |
|---|---|
| Flood test: a fake rdc4 that writes 200,000 progress lines and 20,000 other lines as fast as it can | Finished in 0.5 s. The window never went more than 0.12 s between screen updates, and the log stayed at 121 lines. |
| Cancel a real 164 MB pack, 3 s in (new rdc4) | Stopped in 0.03–0.12 s. No archive or temporary file was left behind. |
| Cancel a real pack with the original rdc4 | Stopped in 0.07–0.11 s. Nothing left behind. |
| All earlier window tests (pack, encrypted, unpack, unpack-some, verify, damage and repair, wrong password, drag and drop, batch verify, search and Extract selected) | Pass with the new rdc4.py **and** with the original one |

## What changed in rdc4.py (all opt-in)

- `--progress` on pack, unpack, verify, repair and ls. It prints lines like
  `{"event": "progress", "stage": "pack", "done": 47185920, "total": 163856079}` on stderr, at most
  about 5 per second. The stages are pack (reading and compressing), parity (adding repair data),
  unpack, and verify (also used for repair's re-check). The final result line is unchanged, and errors
  still end with their usual error line.
- `--password-stdin` on every command. It reads the password from the first line of standard input
  instead of the `RDC_PASSWORD` environment variable.
- Nothing else changed: no format, default or code-path change. The full line-by-line change is in
  [rdc4-gui-addon.diff](rdc4-gui-addon.diff), about 100 added lines. New tests are in
  [test_gui_addon.py](test_gui_addon.py). They check archive bytes with and without progress (1 and 4
  threads), that progress counts only go up, unpack/verify/repair progress, that errors stay the last
  line, that stdin and environment passwords are interchangeable, and that defaults are unchanged.

rdc3.py is untouched. RDCv003 archives still unpack and verify. The bar just shows "working"
instead of a percentage while verifying one.

## Review of the "v3.3.0 consolidated build" notes (Komp2-v3.3.0-notes.txt)

The upload is release notes only, with no code, so there was nothing to merge file by file. I checked
each idea against our build:

| Idea in the notes | Does our build need it? | Done |
|---|---|---|
| Bounded event queue (don't let a chatty process fill memory) | **Yes, once progress streams.** I found that with a plain queue, a flood of progress lines would back up and delay the result by many seconds. | **Built**, in a stronger form. Progress isn't queued at all: the reader keeps only the newest position, so memory and redraw work stay the same however fast lines arrive. Flood test: 220,000 lines handled in 0.5 s. |
| Cap the log at 5,000 lines | Yes, cheap insurance for long batch sessions. | **Built.** The oldest lines are trimmed in batches, so trimming isn't done on every line. |
| Batch log writes (one insert per tick) | Not needed. Our log gets a handful of summary lines per job, not hundreds per second; progress goes to the bar, not the log. | Not done. Measured: no slowdown. |
| Limit how many messages are handled per screen update | Yes, it keeps the window responsive. | **Built** (200 per tick). |
| A general JobManager queue for every task | Not worth the complexity, as in the last review. Batch Verify already covers the useful case. | Not done |
| Kill-latency benchmark (`bench_host.py`) | A good idea. | **Done** as the cancel test above (0.03–0.12 s). |
| Its flag list `-t`, `-l`, `-k`, `--progress-json` | **Doesn't match our rdc4.py.** Ours uses `--threads`, `--level`, `--progress`, `--password-stdin`, and `unpack ARCHIVE DEST`. Code built on that list would fail against the real tool. | Not adopted |

If you get the actual v3.3.0 files, send them and I'll compare them line by line with ours.

## Recommendations

1. **Use the new rdc4.py together with the new window.** That gives the percentage bar and the safer
   password. Keep the backup the install steps make, so going back takes one command.
2. **Run the test suite on the 3090 PC once:** run `python -m pytest -q test_rdc4.py test_rdc3.py test_gui_addon.py` in the folder. Windows has
   different file handling, and the earlier Windows runs were all green.
3. **Big jobs:** the "about N min left" estimate is for the current stage. "Adding repair data" comes
   after and is usually much faster.
