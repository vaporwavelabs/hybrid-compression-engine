#!/usr/bin/env python3
"""Self-contained checks for hybridstore (run: python test_hybridstore.py).
Needs git on PATH for the v1-compatibility test (it loads the v1 engine from
commit 60ba952)."""
import hashlib, importlib.util, io, os, random, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hybridstore as hs

os.makedirs(os.path.join(HERE, "bench_data"), exist_ok=True)   # gitignored; keeps temp data off C:
TMP = tempfile.mkdtemp(prefix="hcs-test-", dir=os.path.join(HERE, "bench_data"))
rng = random.Random(1)
passed = []


def check(name):
    def deco(fn):
        fn()
        passed.append(name)
        print(f"ok  {name}")
        return fn
    return deco


def tree(root, files):
    for rel, data in files.items():
        p = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(data)


def same_tree(a, b):
    fa = {os.path.relpath(os.path.join(d, f), a): os.path.join(d, f) for d, _, fs in os.walk(a) for f in fs}
    fb = {os.path.relpath(os.path.join(d, f), b): os.path.join(d, f) for d, _, fs in os.walk(b) for f in fs}
    assert fa.keys() == fb.keys(), (sorted(fa.keys() ^ fb.keys())[:5])
    for k in fa:
        assert open(fa[k], "rb").read() == open(fb[k], "rb").read(), k


def text(n, seed):
    r = random.Random(seed)
    words = [bytes(r.choice(b"abcdefghijklmnop") for _ in range(r.randint(2, 9))) for _ in range(400)]
    out = bytearray()
    while len(out) < n:
        out += b" ".join(r.choice(words) for _ in range(12)) + b"\n"
    return bytes(out[:n])


@check("streaming chunker gives the same cuts as whole-buffer chunking")
def _():
    c = hs.FastCDC()
    for n in (0, 1, 2048, 2049, 70_000, 3_000_000):
        data = os.urandom(n) if n % 2 else text(n, n)
        whole = list(c.chunks(data))
        for seg in (65_536, 100_000, 1 << 20, hs.SEGMENT):
            assert list(c.stream_chunks(io.BytesIO(data), seg)) == whole, (n, seg)


@check("doubling gear hash equals the 64-term definition; threaded hashing gives the same cuts")
def _():
    from concurrent.futures import ThreadPoolExecutor
    import numpy as np
    c = hs.FastCDC()
    data = os.urandom(300_000)
    g = hs.GEAR[np.frombuffer(data, dtype=np.uint8)]
    ref = np.zeros(len(data), dtype=np.uint64)
    with np.errstate(over="ignore"):
        for k in range(64):
            ref[k:] += g[:len(data) - k] << np.uint64(k)
    assert np.array_equal(c._gear_hash(data), ref)
    big = os.urandom(5_000_000) + text(4_500_000, 7)
    with ThreadPoolExecutor(8) as pool:
        assert c._cuts(big, True, pool) == c._cuts(big, True)
        assert list(c.stream_chunks(io.BytesIO(big), pool=pool)) == list(c.chunks(big))


@check("multi-threaded writer produces a byte-identical store to single-threaded")
def _():
    src = os.path.join(TMP, "mt")
    files = {f"t/{i}.txt": text(rng.randint(1_000, 400_000), 500 + i) for i in range(60)}
    files["big.log"] = text(20_000_000, 9)            # > PREP_MAX: streamed, pool-hashed
    files["dup.log"] = files["big.log"]
    files["rand.bin"] = os.urandom(3_000_000)
    files["pic.png"] = b"\x89PNG\r\n\x1a\n" + os.urandom(500_000)
    tree(src, files)
    real_time, outs = hs.time.time, []
    hs.time.time = lambda: 1_700_000_000.0
    try:
        for workers in (1, 8):
            store = os.path.join(TMP, f"mt{workers}.hcs")
            w = hs.StoreWriter(store, workers=workers); w.add_tree(src, use_dictionary=False); w.close()
            outs.append(open(store, "rb").read())
    finally:
        hs.time.time = real_time
    assert outs[0] == outs[1]
    with hs.StoreReader(os.path.join(TMP, "mt8.hcs")) as r:
        out = os.path.join(TMP, "mtout"); r.unpack(out); same_tree(src, out)


@check("WAV / BMP are chunked and fully compressed, not treated as media")
def _():
    pcm = bytes((i * 7 // 3) & 0xFF for i in range(2_000_000))
    wav = b"RIFF" + (len(pcm) + 36).to_bytes(4, "little") + b"WAVEfmt " + bytes(24) + pcm
    assert hs.detect_modality(wav[:16]) == "wave" and hs.media_kind(wav[:16]) is None
    assert hs.media_kind(b"BM" + bytes(14)) is None and hs.media_kind(b"\x89PNG\r\n\x1a\n" + bytes(8)) == "png"
    src = os.path.join(TMP, "wav"); tree(src, {"a.wav": wav})
    store = os.path.join(TMP, "wav.hcs")
    w = hs.StoreWriter(store); w.add_tree(src); st = w.close()
    assert st.media_files == 0 and st.store_bytes < len(wav) // 20, st.store_bytes


@check("incremental backup: snapshots restore bit-exact and dedup across runs")
def _():
    src = os.path.join(TMP, "inc")
    base = {f"dir/f{i}.txt": text(200_000, i) for i in range(20)}
    tree(src + "1", base)
    edited = dict(base)
    edited["dir/f3.txt"] = base["dir/f3.txt"][:5000] + b"INSERTED\n" + base["dir/f3.txt"][5000:]
    edited["new.bin"] = os.urandom(50_000)
    del edited["dir/f7.txt"]
    tree(src + "2", edited)
    store = os.path.join(TMP, "inc.hcs")
    w = hs.StoreWriter(store, append=True); w.add_tree(src + "1"); s1 = w.close()
    w = hs.StoreWriter(store, append=True); w.add_tree(src + "2"); s2 = w.close()
    assert s1.snapshot == 1 and s2.snapshot == 2
    assert s2.dedup_bytes > 0.9 * s2.input_bytes, s2
    assert s2.added_bytes < 0.2 * s1.added_bytes, (s1.added_bytes, s2.added_bytes)
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 2 and r.verify() == 20 + 20
        for i in (1, 2):
            out = os.path.join(TMP, f"inc_out{i}")
            r.unpack(out, snapshot=i)
            same_tree(src + str(i), out)
        assert all("\\" not in e.path for s in r.snapshots for e in s.entries)


@check("v1 stores still read, and can be appended to")
def _():
    code = subprocess.run(["git", "-C", HERE, "show", "60ba952:hybridstore.py"],
                          capture_output=True, check=True).stdout
    p = os.path.join(TMP, "hybridstore_v1.py")
    open(p, "wb").write(code)
    spec = importlib.util.spec_from_file_location("hybridstore_v1", p)
    v1 = importlib.util.module_from_spec(spec)
    sys.modules["hybridstore_v1"] = v1
    spec.loader.exec_module(v1)
    src = os.path.join(TMP, "v1src")
    tree(src, {f"a{i}.txt": text(100_000, 50 + i) for i in range(5)})
    store = os.path.join(TMP, "v1.hcs")
    w = v1.StoreWriter(store); w.add_tree(src); w.close()
    with hs.StoreReader(store) as r:
        assert r.snapshots[0].version == 1 and r.verify() == 5
    w = hs.StoreWriter(store, append=True); w.add_tree(src); st = w.close()
    assert st.chunks_unique == 0 and st.snapshot == 2, st      # all chunks deduped against v1 data
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 2 and r.verify() == 10
        out = os.path.join(TMP, "v1out"); r.unpack(out); same_tree(src, out)


@check("interrupted append: readers fall back to the last complete snapshot, next backup cleans up")
def _():
    src = os.path.join(TMP, "crash")
    tree(src, {f"x{i}.txt": text(300_000, 90 + i) for i in range(4)})
    store = os.path.join(TMP, "crash.hcs")
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w.close()
    good = os.path.getsize(store)
    tree(src, {"x9.txt": os.urandom(3_000_000)})
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w._flush(); w._drain(); w._shutdown()
    w.f.close(); w.lock.release()              # "crash": packs written, no manifest/footer; OS drops the lock
    assert os.path.getsize(store) > good
    with hs.StoreReader(store) as r:
        assert r.end == good and len(r.snapshots) == 1 and r.verify(strict=False) == 4
        try:
            r.verify()
            raise AssertionError("strict verify accepted a store with an interrupted write")
        except hs.IntegrityError:
            pass
    w = hs.StoreWriter(store, append=True)
    assert w.recovered_bytes > 0
    w.add_tree(src); w.close()
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 2 and r.end == os.path.getsize(store) and r.verify() == 9


@check("failed run is rolled back (abort)")
def _():
    store = os.path.join(TMP, "crash.hcs")
    before = open(store, "rb").read()
    w = hs.StoreWriter(store, append=True)
    w.add_file("junk.bin", os.urandom(2_000_000)); w._flush(); w._drain()
    w.abort()
    assert open(store, "rb").read() == before


@check("unsafe manifest paths are rejected")
def _():
    for bad in ("../x", "a/../../x", "/abs", "a//b", "..\\x", "a/./b"):
        try:
            hs._safe_parts(bad)
        except hs.IntegrityError:
            continue
        raise AssertionError(bad)
    assert hs._safe_parts("a/b\\c.txt") == ["a", "b", "c.txt"]


@check("large media (> 64 MiB) is streamed in chunks and restores bit-exact")
def _():
    src = os.path.join(TMP, "media")
    os.makedirs(src)
    p = os.path.join(src, "big.mp4")
    with open(p, "wb") as f:
        f.write(b"\x00\x00\x00\x18ftypmp42")
        for _ in range(70):
            f.write(os.urandom(1 << 20))
    store = os.path.join(TMP, "media.hcs")
    w = hs.StoreWriter(store); w.add_tree(src); st = w.close()
    assert st.media_files == 1 and st.chunks_total > 1000 and st.codec_counts["raw"] == st.packs, st
    with hs.StoreReader(store) as r:
        out = os.path.join(TMP, "media_out"); r.unpack(out); same_tree(src, out)


@check("bit flips in a multi-snapshot store are detected or hit only unused bytes")
def _():
    store = os.path.join(TMP, "inc.hcs")
    data = bytearray(open(store, "rb").read())
    with hs.StoreReader(store) as r:
        unused = r.unused_ranges()
    r7 = random.Random(7)
    caught = harmless = 0
    for _ in range(150):
        bad = bytearray(data)
        i = r7.randrange(8, len(bad) - hs.FOOTER.size)
        bad[i] ^= 1 << r7.randrange(8)
        p = store + ".bad"
        open(p, "wb").write(bad)
        try:
            with hs.StoreReader(p) as rr:
                rr.verify()
            assert any(a <= i < b for a, b in unused), f"undetected flip at {i}"
            harmless += 1
        except hs.IntegrityError:
            caught += 1
        os.remove(p)
    assert caught + harmless == 150


@check("store lock: a second writer (same process or another) is refused, and the lock is freed after")
def _():
    store = os.path.join(TMP, "lock.hcs")
    w = hs.StoreWriter(store, append=True); w.add_file("a.txt", b"one")
    try:
        hs.StoreWriter(store, append=True)
        raise AssertionError("second writer in the same process was allowed")
    except hs.StoreLockedError:
        pass
    other = subprocess.run([sys.executable, "-c",
        "import sys; sys.path.insert(0, sys.argv[1]); import hybridstore as hs\n"
        "try:\n hs.StoreWriter(sys.argv[2], append=True)\nexcept hs.StoreLockedError as e:\n print('LOCKED', e)",
        HERE, store], capture_output=True, text=True)
    assert "LOCKED" in other.stdout and "pid" in other.stdout, other
    w.close()
    assert not os.path.exists(store + ".lock")
    w = hs.StoreWriter(store, append=True); w.add_file("b.txt", b"two"); w.close()
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 2 and r.verify() == 2


def hold_exclusively(path):
    """Open a file so no other handle can read it (Windows), or remove read
    permission (POSIX). Returns a function that undoes it."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        h = k32.CreateFileW(path, 0x80000000, 0, None, 3, 0x80, None)   # GENERIC_READ, no sharing
        assert h not in (None, wintypes.HANDLE(-1).value), ctypes.get_last_error()
        return lambda: k32.CloseHandle(wintypes.HANDLE(h))
    os.chmod(path, 0)
    return lambda: os.chmod(path, 0o644)


@check("unreadable / locked files are skipped and reported; the rest of the backup completes")
def _():
    src = os.path.join(TMP, "locked")
    tree(src, {"ok1.txt": text(50_000, 1), "sub/big.log": text(9_000_000, 2), "busy.db": b"x" * 1000,
               "sub/busy_big.db": text(9_500_000, 3), "ok2.txt": text(50_000, 4)})
    undo = [hold_exclusively(os.path.join(src, "busy.db")),
            hold_exclusively(os.path.join(src, "sub", "busy_big.db"))]
    try:
        for workers in (1, 4):
            store = os.path.join(TMP, f"locked{workers}.hcs")
            w = hs.StoreWriter(store, workers=workers); w.add_tree(src); st = w.close()
            assert sorted(p for p, _ in st.skipped) == ["busy.db", "sub/busy_big.db"], st.skipped
            assert st.files == 3
            with hs.StoreReader(store) as r:
                assert r.verify() == 3 and [p for p, _ in r.snapshots[-1].skipped] == [p for p, _ in st.skipped]
        rc = hs.main(["backup", src, os.path.join(TMP, "locked_cli.hcs"), "--workers", "2"])
        assert rc == 3, rc
    finally:
        for u in undo:
            u()


@check("verify fails on a store that was cut short, even where reading falls back to an older snapshot")
def _():
    store = os.path.join(TMP, "inc.hcs")
    data = open(store, "rb").read()
    with hs.StoreReader(store) as r:
        first_end = r.snapshots[0].block_end + hs.FOOTER.size
    r9 = random.Random(9)
    for cut in [first_end + 1, len(data) - 1] + [r9.randrange(first_end + 1, len(data)) for _ in range(20)]:
        p = store + ".cut"
        open(p, "wb").write(data[:cut])
        with hs.StoreReader(p) as rr:
            assert len(rr.snapshots) == 1
            try:
                rr.verify()
                raise AssertionError(f"truncated store (cut at {cut}) passed verify")
            except hs.IntegrityError:
                pass
            assert rr.verify(strict=False) == 20
    assert hs.main(["verify", p]) == 1 and hs.main(["verify", p, "--allow-partial"]) == 0
    os.remove(p)


@check("decompression is bounded: bombs and oversized claims are rejected without big allocations")
def _():
    import tracemalloc, zlib
    c = hs.BlockCodec()
    bomb = zlib.compress(bytes(1 << 28), 9)          # 256 MiB of zeros in ~260 KB
    cases = [hs.HDR.pack(hs.BLOCK_MAGIC, hs.CODEC_ZLIB, 100, len(bomb), 0) + bomb,
             hs.HDR.pack(hs.BLOCK_MAGIC, hs.CODEC_ZLIB, 3_000_000_000, len(bomb), 0) + bomb,
             hs.HDR.pack(hs.BLOCK_MAGIC, hs.CODEC_ZSTD, 3_000_000_000, 9, 0) + bytes(9)]
    for blk in cases:
        tracemalloc.start()
        try:
            c.decode_block(blk[:16], blk[16:], 0)
            raise AssertionError("hostile block decoded")
        except hs.IntegrityError:
            pass
        peak = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
        assert peak < 20 << 20, peak


@check("metadata: empty dirs, mtimes, read-only, hidden (Windows) and symlinks round-trip")
def _():
    import stat as st_
    src = os.path.join(TMP, "meta")
    tree(src, {"a.txt": b"hello", "d/b.txt": b"world", "hid.txt": b"secret"})
    os.makedirs(os.path.join(src, "empty", "deeper"))
    for p, t in (("a.txt", 1_000_000_000), ("d/b.txt", 1_100_000_000), ("d", 1_200_000_000),
                 ("empty/deeper", 1_300_000_000)):
        os.utime(os.path.join(src, *p.split("/")), ns=(t * 10**9 + 123_456_700, t * 10**9 + 123_456_700))
    ro = os.path.join(src, "a.txt"); os.chmod(ro, st_.S_IREAD)
    if os.name == "nt":
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(os.path.join(src, "hid.txt"), 0x2)
    try:
        os.symlink(os.path.join("d", "b.txt"), os.path.join(src, "link.txt")); links = True
    except OSError:
        links = False                                # Windows without Developer Mode / admin
    store = os.path.join(TMP, "meta.hcs")
    w = hs.StoreWriter(store); w.add_tree(src); stats = w.close()
    assert stats.dirs == 3 and stats.links == links and stats.files == 3, stats
    out = os.path.join(TMP, "meta_out")
    for _ in range(2):                               # second restore overwrites read-only / hidden files
        with hs.StoreReader(store) as r:
            assert r.verify() == 3
            warnings = r.unpack(out)
    assert warnings == [], warnings
    same_tree(src, out)
    assert os.path.isdir(os.path.join(out, "empty", "deeper"))
    for p in ("a.txt", "d/b.txt", "d", "empty/deeper"):
        a, b = (os.stat(os.path.join(x, *p.split("/"))).st_mtime_ns for x in (src, out))
        assert a == b, (p, a, b)
    assert not os.access(os.path.join(out, "a.txt"), os.W_OK)
    if os.name == "nt":
        assert os.stat(os.path.join(out, "hid.txt")).st_file_attributes & 0x2
    if links:
        assert os.path.islink(os.path.join(out, "link.txt")) and os.readlink(os.path.join(out, "link.txt")) == os.path.join("d", "b.txt")
    for base in (src, out):
        os.chmod(os.path.join(base, "a.txt"), st_.S_IREAD | st_.S_IWRITE)


@check("a failed `pack` over an existing store leaves the old store untouched")
def _():
    store = os.path.join(TMP, "lock.hcs")
    before = open(store, "rb").read()
    w = hs.StoreWriter(store)                        # overwrite mode
    w.add_file("x.bin", os.urandom(100_000)); w.abort()
    assert open(store, "rb").read() == before and not os.path.exists(store + ".hcs-new")


if __name__ == "__main__":
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\nall {len(passed)} checks passed")
