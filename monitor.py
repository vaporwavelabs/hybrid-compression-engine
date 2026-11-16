#!/usr/bin/env python3
"""Run a hybridstore command and watch it: elapsed time, input read, output
written, throughput, ETA, CPU and memory, sampled every --every seconds.

  python monitor.py [--every 2] [--total BYTES] [--watch FILE] [--csv log.csv] -- <command ...>

--total is the input size (for % done and ETA; default: the size of the first
existing directory argument). --watch is a file whose size is the output
(default: the store argument, or its .hcs-new while a new store is written).
Prints a line every 10 s, a summary at the end, and returns the command's exit
code. Needs psutil.
"""
from __future__ import annotations

import argparse, csv, os, subprocess, sys, time

import psutil


def dir_bytes(p):
    n = 0
    link = lambda x: os.path.islink(x) or (hasattr(os.path, "isjunction") and os.path.isjunction(x))
    for d, dirs, fs in os.walk(p):
        dirs[:] = [x for x in dirs if not link(os.path.join(d, x))]   # the store keeps links as links
        for f in fs:
            try:
                n += os.lstat(os.path.join(d, f)).st_size
            except OSError:
                pass
    return n


def fmt_t(s):
    s = int(s)
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}"


def tree_stats(proc):
    procs = [proc] + proc.children(recursive=True)
    cpu = rss = rd = wr = 0
    for p in procs:
        try:
            with p.oneshot():
                t = p.cpu_times()
                cpu += t.user + t.system
                rss += p.memory_info().rss
                io = p.io_counters()
                rd += io.read_bytes
                wr += io.write_bytes
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return cpu, rss, rd, wr


def main(argv) -> int:
    if "--" not in argv:
        print(__doc__, file=sys.stderr)
        return 2
    i = argv.index("--")
    ap = argparse.ArgumentParser()
    ap.add_argument("--every", type=float, default=2.0)
    ap.add_argument("--total", type=int, default=None)
    ap.add_argument("--watch", default=None)
    ap.add_argument("--csv", default=None)
    ap.add_argument("--label", default="")
    a = ap.parse_args(argv[:i])
    cmd = argv[i + 1:]
    if not cmd:
        print("monitor: no command after --", file=sys.stderr)
        return 2
    # CreateProcess on Windows does not resolve 'dir/prog.exe' relative paths with '/'
    if os.path.exists(cmd[0]):
        cmd[0] = os.path.abspath(cmd[0])
    else:
        import shutil
        cmd[0] = shutil.which(cmd[0]) or cmd[0]
    total = a.total
    if total is None:
        d = next((x for x in cmd if os.path.isdir(x)), None)
        total = dir_bytes(d) if d else 0
    watch = a.watch or next((x for x in reversed(cmd) if x.endswith(".hcs")), None)
    ncpu = psutil.cpu_count() or 1
    t0 = time.time()
    proc = psutil.Popen(cmd)
    rows, last_print, peak_rss, prev = [], 0.0, 0, (t0, 0, 0.0)
    w = open(a.csv, "w", newline="") if a.csv else None
    cw = csv.writer(w) if w else None
    if cw:
        cw.writerow(["elapsed_s", "read_bytes", "write_bytes", "output_bytes", "cpu_s", "rss_bytes",
                     "read_MBps", "cpu_cores"])
    print(f"[monitor] {a.label or ' '.join(cmd[-3:])}: input {total / 1e6:,.1f} MB, sampling every {a.every:g} s",
          flush=True)
    while True:
        try:
            done = proc.wait(timeout=a.every)
        except psutil.TimeoutExpired:
            done = None
        now = time.time()
        cpu, rss, rd, wr = tree_stats(proc) if done is None else (prev[2], 0, rows[-1][1] if rows else 0,
                                                                  rows[-1][2] if rows else 0)
        out = 0
        if watch:
            for cand in (watch + "-new", watch):
                if os.path.exists(cand):
                    out = os.path.getsize(cand)
                    break
        peak_rss = max(peak_rss, rss)
        dt = max(now - prev[0], 1e-6)
        rate = (rd - prev[1]) / dt / 1e6
        cores = (cpu - prev[2]) / dt
        rows.append((now - t0, rd, wr, out, cpu, rss, rate, cores))
        if cw:
            cw.writerow([f"{now - t0:.1f}", rd, wr, out, f"{cpu:.1f}", rss, f"{rate:.2f}", f"{cores:.2f}"])
        prev = (now, rd, cpu)
        if done is not None:
            break
        if now - last_print >= 10:
            last_print = now
            avg = rd / (now - t0) if now > t0 else 0
            pct = min(100.0, 100 * rd / total) if total else 0
            eta = (total - rd) / avg if avg and total and rd < total else 0
            print(f"[monitor] {fmt_t(now - t0)}  read {rd / 1e6:9,.0f} MB ({pct:5.1f}%)  "
                  f"out {out / 1e6:8,.0f} MB  {rate:6.1f} MB/s now, {avg / 1e6:6.1f} avg  "
                  f"CPU {cores:4.1f}/{ncpu} cores  RAM {rss / 2**20:6,.0f} MiB  "
                  f"ETA {fmt_t(eta) if eta else '  -    '}", flush=True)
    el = time.time() - t0
    if w:
        w.close()
    rd = max(r[1] for r in rows)
    cpu_total = max(r[4] for r in rows)
    print(f"[monitor] done: exit {done}, {fmt_t(el)} ({el:.1f} s); read {rd / 1e6:,.1f} MB "
          f"({rd / 1e6 / el if el else 0:.1f} MB/s); output {rows[-1][3] / 1e6:,.1f} MB; "
          f"CPU {cpu_total:.0f} s ({cpu_total / el if el else 0:.1f} cores avg); peak RAM {peak_rss / 2**20:,.0f} MiB",
          flush=True)
    return done


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
