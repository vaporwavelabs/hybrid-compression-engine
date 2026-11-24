"""Before/after benchmark for --threads auto and --parity light.

Usage (from the rdc folder, with the previous rdc4.py saved elsewhere next to a copy of rdc3.py):
    python bench/make_bench_data.py bench_data
    python bench/bench_ratio_speed.py bench_data path/to/old/rdc4.py rdc4.py

Runs, in alternating order: old and new with no options (command-line default), old and new with
--threads 4 (what the window used on a 4-core PC), and new with --parity light. Prints median pack time,
archive size and SHA-256, and checks a verify + unpack of the light archive gives back the source.
"""
import hashlib, json, os, shutil, statistics, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench_addon import same_tree, sha   # noqa: E402

DATA, OLD, NEW = (os.path.abspath(a) for a in sys.argv[1:4])
ROUNDS = int(os.environ.get('ROUNDS', '3'))
OUT = os.path.abspath('bench_out')
os.makedirs(OUT, exist_ok=True)
VARIANTS = [('old default', OLD, []), ('new default', NEW, []),
            ('old --threads 4', OLD, ['--threads', '4']), ('new --threads 4', NEW, ['--threads', '4']),
            ('new --parity light', NEW, ['--parity', 'light'])]
times, digests, sizes = {}, {}, {}
for r in range(ROUNDS):
    for name, rdc, extra in (VARIANTS if r % 2 == 0 else VARIANTS[::-1]):
        arc = os.path.join(OUT, name.replace(' ', '_') + '.rdc4')
        if os.path.exists(arc):
            os.remove(arc)
        t = time.perf_counter()
        p = subprocess.run([sys.executable, rdc, 'pack', DATA, arc] + extra, capture_output=True, text=True)
        if p.returncode:
            raise SystemExit(p.stderr)
        times.setdefault(name, []).append(time.perf_counter() - t)
        digests.setdefault(name, set()).add(sha(arc))
        sizes[name] = os.path.getsize(arc)
        print('round', r + 1, name, round(times[name][-1], 1), 's', flush=True)
light = os.path.join(OUT, 'new_--parity_light.rdc4')
dest = os.path.join(OUT, 'light-out')
shutil.rmtree(dest, ignore_errors=True)
for cmd in (['verify', light], ['unpack', light, dest]):
    assert subprocess.run([sys.executable, NEW] + cmd, capture_output=True).returncode == 0, cmd
print(json.dumps({n: dict(median_s=round(statistics.median(times[n]), 2), min_s=round(min(times[n]), 2),
                          max_s=round(max(times[n]), 2), bytes=sizes[n], sha256=sorted(digests[n]))
                  for n, *_ in VARIANTS}, indent=1))
print('light archive verifies and unpacks to the source:', same_tree(DATA, dest))
