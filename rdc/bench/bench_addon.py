"""Before/after benchmark for the opt-in rdc4.py GUI add-on (--progress, --password-stdin).

Usage (from the rdc folder, with the original v3.1.6 rdc4.py saved as rdc4-original-3.1.6.py):
    python bench/make_bench_data.py bench_data
    python bench/bench_addon.py bench_data rdc4-original-3.1.6.py rdc4.py

Packs, verifies and unpacks the data with: the original rdc4.py, the new one, and the new one with
--progress, in alternating order. Prints median times, archive sizes and SHA-256 (must be identical),
and checks the unpacked tree equals the source. Scratch files go to bench_out/ (delete it afterwards).
"""
import filecmp, hashlib, json, os, shutil, statistics, subprocess, sys, time

DATA, ORIG, NEW = (os.path.abspath(a) for a in sys.argv[1:4])
ROUNDS = int(os.environ.get('ROUNDS', '3'))
THREADS = os.environ.get('THREADS', '4')
OUT = os.path.abspath('bench_out')
os.makedirs(OUT, exist_ok=True)
VARIANTS = [('original', ORIG, []), ('new', NEW, []), ('new+progress', NEW, ['--progress'])]


def run(cmd):
    t = time.perf_counter()
    p = subprocess.run([sys.executable] + cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit('FAILED %s\n%s' % (cmd, p.stderr[-2000:]))
    return time.perf_counter() - t


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def same_tree(a, b):
    c = filecmp.dircmp(a, b)
    if c.left_only or c.right_only or c.funny_files:
        return False
    if filecmp.cmpfiles(a, b, c.common_files, shallow=False)[1:] != ([], []):
        return False
    return all(same_tree(os.path.join(a, d), os.path.join(b, d)) for d in c.common_dirs)


res = {n: {'pack': [], 'verify': [], 'unpack': []} for n, *_ in VARIANTS}
digests, sizes, trees = {}, {}, {}
for r in range(ROUNDS):
    for name, rdc, extra in (VARIANTS if r % 2 == 0 else VARIANTS[::-1]):
        arc, dest = os.path.join(OUT, name + '.rdc4'), os.path.join(OUT, 'out-' + name)
        if os.path.exists(arc):
            os.remove(arc)
        shutil.rmtree(dest, ignore_errors=True)
        res[name]['pack'].append(run([rdc, 'pack', DATA, arc, '--threads', THREADS] + extra))
        res[name]['verify'].append(run([rdc, 'verify', arc] + extra))
        res[name]['unpack'].append(run([rdc, 'unpack', arc, dest] + extra))
        digests.setdefault(name, set()).add(sha(arc))
        sizes[name] = os.path.getsize(arc)
        trees[name] = same_tree(DATA, dest)
        print('round', r + 1, name, {k: round(v[-1], 2) for k, v in res[name].items()}, flush=True)

print()
print('%-14s %9s %9s %9s %14s  %s' % ('variant', 'pack s', 'verify s', 'unpack s', 'archive bytes', 'unpacked == source'))
for name in res:
    m = {k: statistics.median(v) for k, v in res[name].items()}
    print('%-14s %9.2f %9.2f %9.2f %14d  %s' % (name, m['pack'], m['verify'], m['unpack'], sizes[name], trees[name]))
all_digests = set().union(*digests.values())
print('\narchives byte-identical across all variants and rounds:', len(all_digests) == 1, sorted(all_digests)[0][:16])
json.dump(dict(times=res, sizes=sizes, sha256={k: sorted(v) for k, v in digests.items()}, unpacked_equal=trees),
          open(os.path.join(OUT, 'results.json'), 'w'), indent=1)
