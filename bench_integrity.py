#!/usr/bin/env python3
"""Size, speed and damage benchmark, laid out like the 2026-11-16 RDC comparison
so the numbers line up row for row.

For each corpus (bench.py's code / backups / mixed generators):
  * store size alone and with the parity sidecar; ratio vs zstd-19 --long (tar)
  * pack and unpack MB/s, median of 3 (unpack also with --fsync)
  * 200 seeded single-bit flips (Random(20261116)) anywhere in store + sidecar;
    after each: `repair`, then a full restore compared file-by-file with the
    original tree. Outcome: refused (error), repaired-exact, or silent-wrong.

  python bench_integrity.py [--flips 200] [--corpora code,backups,mixed] [--json out.json]
"""
from __future__ import annotations

import argparse, contextlib, hashlib, io, json, os, random, shutil, statistics, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bench
import hybridstore as hs


def tree_hash(root):
    out = {}
    for d, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root).replace(os.sep, "/")] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def med(xs):
    return statistics.median(xs)


def run(name, root, work, flips, seed):
    size = bench.dir_bytes(root)
    want = tree_hash(root)
    zst = bench.baselines(root)["zstd-19 --long (tar)"]
    store = os.path.join(work, name + ".hcs")
    tp, tu, tf = [], [], []
    for i in range(3):
        for p in (store, store + ".hcp"):
            if os.path.exists(p):
                os.remove(p)
        t = time.perf_counter()
        w = hs.StoreWriter(store); w.add_tree(root); w.close()
        tp.append(time.perf_counter() - t)
        for fs, acc in ((False, tu), (True, tf)):
            out = os.path.join(work, f"out-{name}-{i}-{fs}")
            with hs.StoreReader(store) as r:
                t = time.perf_counter(); r.unpack(out, fsync=fs); acc.append(time.perf_counter() - t)
            assert tree_hash(out) == want, "round trip differs"
            shutil.rmtree(out)
    sb, pb = os.path.getsize(store), os.path.getsize(store + ".hcp")
    row = {"corpus": name, "input": size, "store": sb, "parity": pb, "ratio": size / sb,
           "ratio_with_parity": size / (sb + pb), "zstd_long": zst, "vs_zstd_pct": 100 * (sb / zst - 1),
           "pack_mbs": size / 1e6 / med(tp), "unpack_mbs": size / 1e6 / med(tu),
           "unpack_fsync_mbs": size / 1e6 / med(tf)}
    print(f"{name}: input {size:,} B, store {sb:,} B ({row['ratio']:.2f}x), +parity {pb:,} B "
          f"({100 * pb / sb:.1f}%, {row['ratio_with_parity']:.2f}x total); zstd --long {zst:,} B; "
          f"pack {row['pack_mbs']:.1f} MB/s, unpack {row['unpack_mbs']:.1f} MB/s "
          f"({row['unpack_fsync_mbs']:.1f} with --fsync)", flush=True)
    if flips:
        good_s, good_p = open(store, "rb").read(), open(store + ".hcp", "rb").read()
        rng = random.Random(seed)
        res = {"refused": 0, "repaired_exact": 0, "silent_wrong": 0, "in_parity_file": 0}
        t0 = time.time()
        for k in range(flips):
            open(store, "wb").write(good_s)
            open(store + ".hcp", "wb").write(good_p)
            pos = rng.randrange(len(good_s) + len(good_p))
            bit = 1 << rng.randrange(8)
            target, off = (store, pos) if pos < len(good_s) else (store + ".hcp", pos - len(good_s))
            res["in_parity_file"] += target.endswith(".hcp")
            with open(target, "r+b") as f:
                f.seek(off); b = f.read(1); f.seek(off); f.write(bytes([b[0] ^ bit]))
            out = os.path.join(work, f"flip-{name}")
            try:
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    hs.repair(store)
                    with hs.StoreReader(store) as r:
                        r.unpack(out)
                res["repaired_exact" if tree_hash(out) == want else "silent_wrong"] += 1
            except (hs.IntegrityError, ValueError):
                res["refused"] += 1
            shutil.rmtree(out, ignore_errors=True)
        row["flips"] = res
        print(f"  {flips} flips ({res['in_parity_file']} in the parity file): refused {res['refused']}, "
              f"repaired-exact {res['repaired_exact']}, silent-wrong {res['silent_wrong']}  "
              f"[{time.time() - t0:.0f} s]", flush=True)
    return row


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--flips", type=int, default=200)
    ap.add_argument("--seed", type=int, default=20261116)
    ap.add_argument("--corpora", default="code,backups,mixed")
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    os.makedirs(os.path.join(HERE, "bench_data"), exist_ok=True)
    work = tempfile.mkdtemp(prefix="hcs-bi-", dir=os.path.join(HERE, "bench_data"))
    makers = {"code": bench.make_code, "backups": bench.make_backups, "mixed": bench.make_mixed}
    rows = []
    try:
        for name in a.corpora.split(","):
            root = os.path.join(work, "src-" + name)
            os.makedirs(root)
            makers[name](root)
            rows.append(run(name, root, work, a.flips, a.seed))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
