#!/usr/bin/env python3
"""Real-data run under the time monitor: pack, unchanged re-backup, verify,
restore + compare with the source, encrypted pack, damage + repair, and a
zstd -19 --long baseline. Everything is written under --work.

  python real_run.py <source_dir> --work D:\\hcs-real [--password-file F] [--skip-baseline]
"""
from __future__ import annotations

import argparse, hashlib, io, json, os, random, shutil, subprocess, sys, tarfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
HS = [PY, os.path.join(HERE, "hybridstore.py")]
MON = [PY, os.path.join(HERE, "monitor.py")]


def step(name, cmd, results, total=None, watch=None, csv=None):
    print(f"\n=== {name} ===", flush=True)
    mon = MON + ["--label", name]
    if total is not None:
        mon += ["--total", str(total)]
    if watch:
        mon += ["--watch", watch]
    if csv:
        mon += ["--csv", csv]
    t = time.time()
    code = subprocess.call(mon + ["--"] + cmd)
    results.append({"step": name, "seconds": round(time.time() - t, 1), "exit": code})
    print(f"=== {name}: exit {code}, {time.time() - t:.1f} s ===", flush=True)
    return code


def _is_link(p):
    return os.path.islink(p) or (hasattr(os.path, "isjunction") and os.path.isjunction(p))


def real_files(root):
    """Files the backup stores as files: symlinks and junctions are stored as links, not
    followed (os.walk and tarfile would follow junctions on Windows)."""
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if not _is_link(os.path.join(d, x))]
        for f in fs:
            p = os.path.join(d, f)
            if not _is_link(p):
                yield p


def walk_hash(root):
    out = {}
    for p in real_files(root):
        h = hashlib.sha256()
        try:
            with open(p, "rb") as fh:
                for b in iter(lambda: fh.read(1 << 20), b""):
                    h.update(b)
        except OSError as e:
            out[os.path.relpath(p, root)] = f"unreadable: {e}"
            continue
        out[os.path.relpath(p, root)] = h.hexdigest()
    return out


def baseline(source, info, res):
    print("\n=== 9 baseline: tar | zstd -19 --long=27 (all threads) ===", flush=True)
    import zstandard as zstd
    t = time.time()

    class Count(io.RawIOBase):
        n = 0

        def writable(self):
            return True

        def write(self, b):
            self.n += len(b)
            return len(b)

    sink = Count()
    params = zstd.ZstdCompressionParameters.from_level(19, window_log=27, enable_ldm=True, threads=-1)
    with zstd.ZstdCompressor(compression_params=params).stream_writer(sink, closefd=False) as zw:
        with tarfile.open(fileobj=zw, mode="w|") as tf:
            src_root = os.path.abspath(source)
            fed = [0]

            def no_links(ti):        # same data as the store: links stay links, not followed
                p = os.path.join(src_root, ti.name[2:] if ti.name.startswith("./") else ti.name)
                if ti.name not in (".", "./") and _is_link(p):
                    return None
                fed[0] += ti.size if ti.isfile() else 0
                return ti
            tf.add(source, arcname=".", filter=no_links)
    info["zstd_long_bytes"] = sink.n
    info["zstd_input_bytes"] = fed[0]
    res.append({"step": "9 zstd baseline", "seconds": round(time.time() - t, 1), "exit": 0})
    print(f"zstd -19 --long: {fed[0]:,} bytes in -> {sink.n:,} bytes in {time.time() - t:.0f} s", flush=True)


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("--work", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--skip-baseline", action="store_true")
    ap.add_argument("--baseline-only", action="store_true", help="only run step 9 and add it to real_run.json")
    a = ap.parse_args(argv)
    os.makedirs(a.work, exist_ok=True)
    if a.baseline_only:
        jp = os.path.join(a.work, "real_run.json")
        info = json.load(open(jp)) if os.path.exists(jp) else {}
        res = [r for r in info.get("steps", []) if not r["step"].startswith("9")]
        baseline(a.source, info, res)
        info["steps"] = res
        json.dump(info, open(jp, "w"), indent=1)
        return 0
    store = os.path.join(a.work, "real.hcs")
    enc = os.path.join(a.work, "real-enc.hcs")
    restore = os.path.join(a.work, "restore")
    for p in (store, store + ".hcp", enc, enc + ".hcp"):
        if os.path.exists(p):
            os.remove(p)
    shutil.rmtree(restore, ignore_errors=True)
    res, info = [], {}
    total = sum(os.lstat(p).st_size for p in real_files(a.source))
    info["input_bytes"] = total
    print(f"source {a.source}: {total / 1e6:,.1f} MB", flush=True)

    step("1 pack (zstd 19, parity on)", HS + ["pack", a.source, store, "--force"], res, total, store,
         os.path.join(a.work, "pack.csv"))
    info["store_bytes"] = os.path.getsize(store)
    info["parity_bytes"] = os.path.getsize(store + ".hcp")
    step("2 backup, nothing changed", HS + ["backup", a.source, store], res, total, store)
    step("3 verify (layout, every block, index, files, parity)", HS + ["verify", store], res,
         info["store_bytes"], store)
    step("4 restore", HS + ["unpack", store, restore], res, info["store_bytes"], store)
    print("\n=== 5 compare restore with the source ===", flush=True)
    t = time.time()
    src_h, out_h = walk_hash(a.source), walk_hash(restore)
    import hybridstore as hs
    with hs.StoreReader(store) as r:
        skipped = [p for p, _ in r.snapshots[-1].skipped]
    norm = lambda k: k.replace(os.sep, "/")
    was_skipped = lambda k: any(norm(k) == p or norm(k).startswith(p + "/") for p in skipped)
    gone = sorted(set(src_h) - set(out_h))
    missing = [k for k in gone if not was_skipped(k)]
    extra = sorted(set(out_h) - set(src_h))
    # a file that differs is expected only if it changed after the pack (e.g. a live log)
    differ = sorted(k for k in set(src_h) & set(out_h) if src_h[k] != out_h[k])
    info["compare"] = {"files": len(src_h), "restored": len(out_h), "skipped_by_backup": len(gone) - len(missing),
                       "missing": len(missing), "extra": len(extra), "differ": len(differ),
                       "examples": (missing + differ)[:10], "skipped_examples": skipped[:10],
                       "seconds": round(time.time() - t, 1)}
    res.append({"step": "5 compare", "seconds": round(time.time() - t, 1), "exit": 0})
    print(json.dumps(info["compare"], indent=1), flush=True)
    shutil.rmtree(restore, ignore_errors=True)

    step("6 pack encrypted", HS + ["pack", a.source, enc, "--force", "--encrypt", "--password-file", a.password_file],
         res, total, enc)
    info["enc_store_bytes"] = os.path.getsize(enc)
    step("7 verify encrypted", HS + ["verify", enc, "--password-file", a.password_file], res,
         info["enc_store_bytes"], enc)

    print("\n=== 8 damage the store: one ~1 MiB burst + 100 random bit flips ===", flush=True)
    size = info["store_bytes"]
    rng = random.Random(20261116)
    with open(store, "r+b") as f:
        start = size // 3
        f.seek(start)
        f.write(os.urandom((15 << 16) - 1))
        for _ in range(100):
            o = rng.randrange(size)
            if start <= o < start + (15 << 16):
                continue
            f.seek(o)
            b = f.read(1)
            f.seek(o)
            f.write(bytes([b[0] ^ (1 << rng.randrange(8))]))
    step("8a verify the damaged store (should report damage)", HS + ["verify", store], res, size, store)
    step("8b repair", HS + ["repair", store], res, size, store)
    step("8c verify after repair", HS + ["verify", store], res, size, store)

    if not a.skip_baseline:
        baseline(a.source, info, res)

    info["steps"] = res
    with open(os.path.join(a.work, "real_run.json"), "w") as f:
        json.dump(info, f, indent=1)
    print("\n" + json.dumps(info, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
