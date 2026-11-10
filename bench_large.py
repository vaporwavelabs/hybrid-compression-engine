#!/usr/bin/env python3
"""Large-file test: pack, verify and restore one big file and report peak
memory. The v1 engine held the whole file plus two 8-byte-per-byte hash
arrays in RAM (~17x the file size); the streaming engine should stay flat.

usage: python bench_large.py [size_GiB=2] [work_dir=./bench_data/large]
The file is log-like text built from a 64 MiB block repeated with small
random edits, so most chunks dedup and the run is bounded by chunking speed.
"""
import hashlib, os, random, shutil, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hybridstore as hs


def peak_rss_mb() -> float:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + \
                       [(n, ctypes.c_size_t) for n in (
                           "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                           "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                           "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        c = PMC(); c.cb = ctypes.sizeof(PMC)
        k32 = ctypes.WinDLL("kernel32"); psapi = ctypes.WinDLL("psapi")
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb)
        return c.PeakWorkingSetSize / 2**20
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def make_file(path, size):
    r = random.Random(3)
    words = [("w%x" % r.getrandbits(20)).encode() for _ in range(2000)]
    base = bytearray()
    while len(base) < 64 << 20:
        base += b"%d INFO " % r.getrandbits(32) + b" ".join(r.choice(words) for _ in range(10)) + b"\n"
    base = bytes(base[:64 << 20])
    h = hashlib.sha256()
    with open(path, "wb") as f:
        left = size
        while left:
            blk = bytearray(base)
            for _ in range(50):
                p = r.randrange(len(blk) - 8)
                blk[p:p + 8] = os.urandom(8)
            blk = bytes(blk[:left])
            f.write(blk); h.update(blk); left -= len(blk)
    return h.hexdigest()


def main():
    gib = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
    work = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                              "bench_data", "large")
    shutil.rmtree(work, ignore_errors=True)
    src, out = os.path.join(work, "src"), os.path.join(work, "out")
    os.makedirs(src)
    size = int(gib * 2**30)
    t = time.time(); digest = make_file(os.path.join(src, "big.log"), size)
    print(f"made {size:,}B test file in {time.time() - t:.0f}s")
    base_mb = peak_rss_mb()

    store = os.path.join(work, "big.hcs")
    t = time.time()
    w = hs.StoreWriter(store); w.add_tree(src); st = w.close()
    dt = time.time() - t
    print(f"pack:   {dt:.0f}s ({size / 1e6 / dt:.1f} MB/s), store {st.store_bytes:,}B "
          f"({size / st.store_bytes:.1f}x), peak memory so far {peak_rss_mb():.0f} MB")

    t = time.time()
    with hs.StoreReader(store) as r:
        r.verify()
    print(f"verify: {time.time() - t:.0f}s, peak memory so far {peak_rss_mb():.0f} MB")

    t = time.time()
    with hs.StoreReader(store) as r:
        r.unpack(out)
    h = hashlib.sha256()
    with open(os.path.join(out, "big.log"), "rb") as f:
        for b in iter(lambda: f.read(8 << 20), b""):
            h.update(b)
    print(f"unpack: {time.time() - t:.0f}s, restored file SHA-256 matches original: {h.hexdigest() == digest}")
    peak = peak_rss_mb()
    print(f"peak process memory {peak:.0f} MB for a {size / 2**20:,.0f} MiB file "
          f"(v1 engine would need ~{17 * size / 2**30:.0f} GiB); before packing: {base_mb:.0f} MB")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
