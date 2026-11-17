#!/usr/bin/env python3
"""Self-contained checks for hybridstore (run: python test_hybridstore.py).
Needs git on PATH for the v1-compatibility test (it loads the v1 engine from
commit 60ba952)."""
import hashlib, importlib.util, io, os, random, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hybridstore as hs
np = hs.np

os.makedirs(os.path.join(HERE, "bench_data"), exist_ok=True)   # gitignored; keeps temp data off C:
TMP = tempfile.mkdtemp(prefix="hcs-test-", dir=os.path.join(HERE, "bench_data"))
rng = random.Random(1)
passed = []


ONLY = [x.strip().lower() for x in os.environ.get("HS_TEST_ONLY", "").split(",") if x.strip()]


def check(name):
    def deco(fn):
        if ONLY and not any(x in name.lower() for x in ONLY):     # HS_TEST_ONLY=parity,encrypt
            return fn
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
    for k in range(2):                               # second restore overwrites read-only / hidden files
        with hs.StoreReader(store) as r:
            assert r.verify() == 3
            if k:
                try:
                    r.unpack(out)
                    raise AssertionError("restore over existing files was not refused")
                except hs.RestoreConflictError as e:
                    assert "a.txt" in e.conflicts and "d/b.txt" in e.conflicts, e.conflicts
            warnings = r.unpack(out, overwrite=bool(k))
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


@check("unchanged files are reused by size + mtime; edits, racy mtimes, other folders and --rehash are handled")
def _():
    import stat as st_, time
    src = os.path.join(TMP, "skip")
    files = {f"f{i}.txt": text(300_000, 700 + i) for i in range(10)}
    tree(src, files)
    old = int(time.time() - 3600) * 10**9                 # whole seconds: NTFS keeps 100 ns steps
    for name in files:
        os.utime(os.path.join(src, name), ns=(old, old))
    open(os.path.join(src, "fresh.txt"), "wb").write(b"just written")   # mtime ~ now: racy
    store = os.path.join(TMP, "skip.hcs")
    w = hs.StoreWriter(store, append=True); w.add_tree(src); s1 = w.close()
    assert s1.reused_files == 0 and s1.files == 11
    # edit f3 (same size, newer mtime), make f5 read-only (mode change only, mtime unchanged)
    f3 = os.path.join(src, "f3.txt")
    open(f3, "r+b").write(b"EDITED")
    os.utime(f3, ns=(old + 10**9, old + 10**9))
    os.chmod(os.path.join(src, "f5.txt"), st_.S_IREAD)
    w = hs.StoreWriter(store, append=True); w.add_tree(src); s2 = w.close()
    assert s2.reused_files == 9 and s2.reused_bytes == 9 * 300_000, s2     # all but f3 and fresh.txt
    assert s2.chunks_total < 100, s2.chunks_total                          # only f3 + fresh.txt were chunked
    # a different folder with the same names, sizes and mtimes must not reuse anything
    other = os.path.join(TMP, "skip_other")
    tree(other, {n: os.urandom(len(d)) for n, d in files.items()})
    for name in files:
        os.utime(os.path.join(other, name), ns=(old, old))
    w = hs.StoreWriter(store, append=True); w.add_tree(other); s3 = w.close()
    assert s3.reused_files == 0, s3.reused_files
    # back to the first folder: its own previous snapshot is found again; --rehash reads everything
    w = hs.StoreWriter(store, append=True); w.add_tree(src); s4 = w.close()
    assert s4.reused_files >= 10, s4.reused_files
    w = hs.StoreWriter(store, append=True); w.add_tree(src, rehash=True); s5 = w.close()
    assert s5.reused_files == 0 and s5.dedup_bytes == s5.input_bytes, s5
    with hs.StoreReader(store) as r:
        assert r.verify() == 5 * 11 - 1                                    # snapshot 3 has 10 files
        for snap, folder in ((2, src), (3, other), (4, src)):
            out = os.path.join(TMP, f"skip_out{snap}")
            r.unpack(out, snapshot=snap); same_tree(folder, out)
            assert not os.access(os.path.join(out, "f5.txt"), os.W_OK) or folder == other
            os.chmod(os.path.join(out, "f5.txt"), st_.S_IREAD | st_.S_IWRITE)
        e = {x.path: x for x in r.snapshots[1].entries}
        assert (e["f5.txt"].mode & st_.S_IWRITE) == 0 and e["f3.txt"].mtime_ns == old + 10**9
    os.chmod(os.path.join(src, "f5.txt"), st_.S_IREAD | st_.S_IWRITE)
    assert hs.main(["backup", src, store, "--rehash"]) == 0


@check("prune deletes snapshots, reclaims space (copy + repack), keeps the rest bit-exact")
def _():
    base = os.path.join(TMP, "prune")
    shared = {f"lib/s{i}.txt": text(40_000, 900 + i) for i in range(40)}
    for dictionary in (False, True):
        store = os.path.join(TMP, f"prune{int(dictionary)}.hcs")
        trees = []
        for k in range(4):                           # each night: shared files + small and big unique ones
            src = f"{base}{int(dictionary)}_{k}"
            files = dict(shared)
            files.update({f"night/n{k}_{i}.txt": text(5_000, 1000 * k + i) for i in range(30)})
            files[f"night/big{k}.bin"] = os.urandom(1_500_000)
            tree(src, files); trees.append(src)
            # one source folder over time: copy into a fixed path so all snapshots share a label
            live = f"{base}{int(dictionary)}_live"
            shutil.rmtree(live, ignore_errors=True); shutil.copytree(src, live)
            w = hs.StoreWriter(store, append=True, pack_target=16 << 10 if dictionary else 1 << 20)
            w.add_tree(live); w.close()
        before = os.path.getsize(store)
        with hs.StoreReader(store) as r:
            old = [(s.label, s.created) for s in r.snapshots]
            assert r.has_dict == dictionary
        # without a dictionary: repack every partly-used pack, to exercise that path
        ps = hs.prune(store, {1, 3}, workers=4, repack_below=0.5 if dictionary else 1.0)
        assert ps.kept == [2, 4] and ps.removed == [1, 3], ps
        assert ps.packs_dropped > 0 and os.path.getsize(store) < before - 2_500_000, (before, ps)
        if not dictionary:
            assert ps.packs_repacked > 0, ps         # packs mixing night-1 and shared chunks
        with hs.StoreReader(store) as r:
            assert [(s.label, s.created) for s in r.snapshots] == [old[1], old[3]]
            assert r.verify() == 2 * 71
            for n, src in ((1, trees[1]), (2, trees[3])):
                out = os.path.join(TMP, f"prune_out{int(dictionary)}{n}")
                r.unpack(out, snapshot=n); same_tree(src, out)
    # the next backup still dedups against what is left and reuses unchanged files
    old_ns = int(__import__("time").time() - 3600) * 10**9
    for d, _, fs in os.walk(live):
        for name in fs:
            os.utime(os.path.join(d, name), ns=(old_ns, old_ns))
    w = hs.StoreWriter(store, append=True); w.add_tree(live); w.close()        # records the old mtimes
    w = hs.StoreWriter(store, append=True); w.add_tree(live); st = w.close()
    assert st.reused_files == 71 and st.chunks_unique == 0, st
    hs.prune(store, {1})
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 3 and r.verify() == 3 * 71


@check("prune policies, dry run and refusals")
def _():
    import datetime
    def snap(label, y, m, d, h=12):
        return hs.Snapshot(0, 3, 0, int(datetime.datetime(y, m, d, h).timestamp()), label, 0, [], [])
    snaps = [snap("A", 2026, 9, 1), snap("A", 2026, 10, 3), snap("A", 2026, 10, 30), snap("A", 2026, 11, 2),
             snap("A", 2026, 11, 2, 18), snap("A", 2026, 11, 3), snap("B", 2026, 1, 1)]
    assert hs.select_snapshots(snaps, keep_last=2) == {5, 6, 7}
    assert hs.select_snapshots(snaps, keep_daily=2) == {5, 6, 7}         # Nov 3, newest of Nov 2; B kept too
    assert hs.select_snapshots(snaps, keep_monthly=3) == {6, 3, 1, 7}
    assert hs.select_snapshots(snaps, keep_last=1, keep_weekly=2) == {6, 3, 7}   # Nov 2 + 3 share a week
    store = os.path.join(TMP, "prune0.hcs")
    data = open(store, "rb").read()
    ps = hs.prune(store, {1}, dry_run=True)
    assert ps.dry_run and ps.packs_dropped >= 0 and open(store, "rb").read() == data
    assert hs.main(["prune", store, "--keep-last", "5", "--dry-run"]) == 0
    for bad in ({1, 2}, {9}):
        try:
            hs.prune(store, bad); raise AssertionError(bad)
        except ValueError:
            pass
    w = hs.StoreWriter(store, append=True)
    try:
        hs.prune(store, {1}); raise AssertionError("prune ran while a backup held the lock")
    except hs.StoreLockedError:
        pass
    finally:
        w.abort()
    assert open(store, "rb").read() == data and not os.path.exists(store + ".hcs-new")


@check("a failed `pack` over an existing store leaves the old store untouched")
def _():
    store = os.path.join(TMP, "lock.hcs")
    before = open(store, "rb").read()
    w = hs.StoreWriter(store)                        # overwrite mode
    w.add_file("x.bin", os.urandom(100_000)); w.abort()
    assert open(store, "rb").read() == before and not os.path.exists(store + ".hcs-new")


# ---------------------------------------------------------------- safeguards (2026-11-15 review)

def _quiet(*argv):
    import contextlib
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = hs.main(list(argv))
    return code, out.getvalue() + err.getvalue()


def _flip(path, off):
    with open(path, "r+b") as f:
        f.seek(off); b = f.read(1); f.seek(off); f.write(bytes([b[0] ^ 0x5A]))


def _three_snapshots(name):
    src = os.path.join(TMP, name)
    store = os.path.join(TMP, name + ".hcs")
    for k in range(3):
        tree(src, {f"f{i}.txt": text(200_000, 1000 * k + i) for i in range(3 + k)})
        w = hs.StoreWriter(store, append=True); w.add_tree(src); w.close()
    return src, store


@check("damaged or missing newest footer: backup refuses instead of deleting the snapshot; repair restores it")
def _():
    src, store = _three_snapshots("footer")
    good = open(store, "rb").read()
    for how in ("flip", "missing"):
        open(store, "wb").write(good)
        if how == "flip":
            _flip(store, len(good) - 4)                 # bit rot in the magic of the newest footer
        else:
            open(store, "r+b").truncate(len(good) - hs.FOOTER.size)   # crash after the manifest's fsync
        before = open(store, "rb").read()
        with hs.StoreReader(store) as r:
            assert len(r.snapshots) == 2 and r.tail_snapshot is not None, how
        try:
            hs.StoreWriter(store, append=True)
            raise AssertionError("backup accepted a store whose newest snapshot lost its footer")
        except hs.IntegrityError as e:
            assert "repair" in str(e)
        assert open(store, "rb").read() == before, "a refused backup changed the store"
        assert _quiet("verify", store)[0] == 1
        done = hs.repair(store)
        assert len(done) == 1 and open(store, "rb").read() == good, (how, done)
        with hs.StoreReader(store) as r:
            assert len(r.snapshots) == 3 and r.verify() == 3 + 4 + 5
    # A damaged older footer: verify fails, repair rewrites it in place.
    with hs.StoreReader(store) as r:
        pos = r.snapshots[0].block_end
    _flip(store, pos + 2)
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 3
        try:
            r.verify(); raise AssertionError("damaged old footer passed verify")
        except hs.IntegrityError:
            pass
    assert hs.repair(store) and open(store, "rb").read() == good and hs.repair(store) == []
    # An interrupted write (packs, no manifest) is still discarded by the next backup.
    tree(src, {"big.bin": os.urandom(2_000_000)})
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w._flush(); w._drain(); w._shutdown()
    w.f.close(); w.lock.release()
    with hs.StoreReader(store) as r:
        assert r.tail_snapshot is None and len(r.snapshots) == 3
    w = hs.StoreWriter(store, append=True); assert w.recovered_bytes > 0; w.add_tree(src); w.close()
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 4 and r.verify() > 0


@check("`pack` refuses to replace an existing store without --force")
def _():
    src, store = _three_snapshots("packguard")
    before = open(store, "rb").read()
    code, out = _quiet("pack", src, store)
    assert code == 2 and "3 snapshot(s)" in out and open(store, "rb").read() == before, out
    other = os.path.join(TMP, "notastore.bin"); open(other, "wb").write(b"precious")
    assert _quiet("pack", src, other)[0] == 2 and open(other, "rb").read() == b"precious"
    code, _ = _quiet("pack", src, store, "--force")
    with hs.StoreReader(store) as r:
        assert code == 0 and len(r.snapshots) == 1


@check("unpack never overwrites existing files unless told to; unrelated files in the folder are fine")
def _():
    src, store = _three_snapshots("unpackguard")
    out = os.path.join(TMP, "unpackguard_out")
    tree(out, {"mine.txt": b"unrelated, untouched", "f0.txt": b"TODAY'S WORK"})
    code, msg = _quiet("unpack", store, out)
    assert code == 2 and "f0.txt" in msg, msg
    assert open(os.path.join(out, "f0.txt"), "rb").read() == b"TODAY'S WORK"
    assert not os.path.exists(os.path.join(out, "f1.txt")), "a refused restore wrote files"
    os.remove(os.path.join(out, "f0.txt"))
    assert _quiet("unpack", store, out)[0] == 0                      # only unrelated files: allowed
    assert open(os.path.join(out, "mine.txt"), "rb").read() == b"unrelated, untouched"
    open(os.path.join(out, "f0.txt"), "wb").write(b"edited")
    assert _quiet("unpack", store, out, "--force")[0] == 0
    assert open(os.path.join(out, "f0.txt"), "rb").read() == open(os.path.join(src, "f0.txt"), "rb").read()


@check("files changing while read are re-read once, then reported; small (threaded) and streamed paths")
def _():
    real_open = open

    class Grower:
        """A file handle that appends to its own file every time it is read."""
        def __init__(self, path, f, budget):
            self.path, self.f, self.budget = path, f, budget

        def read(self, *a):
            d = self.f.read(*a)
            if d and self.budget[self.path] > 0:
                self.budget[self.path] -= 1
                with real_open(self.path, "ab") as g:
                    g.write(b"+")
            return d

        def __getattr__(self, k):
            return getattr(self.f, k)

        def __enter__(self):
            return self

        def __exit__(self, *e):
            self.f.close()

    for workers in (1, 4):
        src = os.path.join(TMP, f"busy{workers}")
        tree(src, {"calm.txt": text(50_000, 5), "once.txt": text(50_000, 6), "busy.txt": text(50_000, 7),
                   "big_once.bin": os.urandom(9 << 20)})
        budget = {}
        # once.txt / big_once.bin change during their first read only; busy.txt during every read
        budget.update({os.path.join(src, "once.txt"): 1, os.path.join(src, "big_once.bin"): 1,
                       os.path.join(src, "busy.txt"): 10**9})
        budget_by_name = {os.path.basename(p): None for p in budget}
        hs.open = lambda path, mode="r", *a, **k: (
            Grower(path, real_open(path, mode, *a, **k), budget)
            if "r" in mode and os.path.basename(str(path)) in budget_by_name else real_open(path, mode, *a, **k))
        try:
            store = os.path.join(TMP, f"busy{workers}.hcs")
            w = hs.StoreWriter(store, workers=workers); w.add_tree(src); st = w.close()
        finally:
            del hs.open
        assert st.changed == ["busy.txt"], (workers, st.changed)
        assert st.files == 4, st
        with hs.StoreReader(store) as r:
            names = [e.path for e in r.snapshots[-1].files]
            assert sorted(names) == ["big_once.bin", "busy.txt", "calm.txt", "once.txt"], names
            for n in ("calm.txt", "once.txt", "big_once.bin"):   # the re-read copy is the current file
                e = next(e for e in r.snapshots[-1].files if e.path == n)
                assert r.read_file(e) == open(os.path.join(src, n), "rb").read(), (workers, n)
            e = next(e for e in r.snapshots[-1].files if e.path == "busy.txt")
            assert e.mtime_ns != os.stat(os.path.join(src, "busy.txt")).st_mtime_ns or \
                e.size != os.path.getsize(os.path.join(src, "busy.txt"))   # next backup re-reads it
            r.verify()


@check("verify lists every damaged pack and every affected file, in every snapshot")
def _():
    src = os.path.join(TMP, "scan")
    store = os.path.join(TMP, "scan.hcs")
    tree(src, {f"f{i}.bin": os.urandom(700_000) for i in range(8)})
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w.close()
    tree(src, {"extra.bin": os.urandom(500_000)})
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w.close()
    with hs.StoreReader(store) as r:
        offs = r.pack_offsets
        hit = [0, len(r.snapshots[0].packs) - 1]            # two packs of snapshot 1
        expect = {n: sorted(e.path for e in s.entries if any(p >> hs.PTR_SHIFT in hit for p in e.pointers))
                  for n, s in enumerate(r.snapshots, 1)}
    for pid in hit:
        _flip(store, offs[pid] + hs.HDR.size + 1000)
    with hs.StoreReader(store) as r:
        rep = r.scan()
        assert sorted(rep["bad_packs"]) == hit, rep["bad_packs"]
        got = {n: sorted(p for p, _ in v) for n, v in rep["damaged_files"].items()}
        assert got == {n: v for n, v in expect.items() if v}, (got, expect)
        assert expect[1] and expect[2]                      # dedup: the damage reaches snapshot 2 too
        try:
            r.verify(); raise AssertionError
        except hs.IntegrityError as e:
            assert "more problem(s)" in str(e)
    code, out = _quiet("verify", store)
    assert code == 1 and all(p in out for p in expect[1]) and "intact snapshots" in out, out


@check("a damaged manifest loses only that snapshot: the rest stays readable, backup works, prune drops it")
def _():
    src, store = _three_snapshots("mdamage")
    copies = {}
    with hs.StoreReader(store) as r:
        for n in (1, 3):
            copies[n] = {e.path: r.read_file(e) for e in r.snapshots[n - 1].files}
        moff = r.snapshots[1].offset
        newest = r.snapshots[2].offset
    good = open(store, "rb").read()
    _flip(store, moff + hs.HDR.size + 7)
    with hs.StoreReader(store) as r:
        assert r.damaged == [2] and len(r.snapshots) == 3
        for n in (1, 3):
            assert {e.path: r.read_file(e) for e in r.snapshots[n - 1].files} == copies[n]
        try:
            r.unpack(os.path.join(TMP, "md_out2"), snapshot=2); raise AssertionError
        except hs.IntegrityError:
            pass
        rep = r.scan()
        assert any("snapshot 2" in p and "manifest damaged" in p for p in rep["problems"]), rep["problems"]
        assert not rep["damaged_files"], rep["damaged_files"]
    try:
        hs.prune(store, [1]); raise AssertionError("prune kept a damaged snapshot")
    except ValueError as e:
        assert "[2]" in str(e)
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w.close()      # backups keep working
    with hs.StoreReader(store) as r:
        assert r.damaged == [2] and len(r.snapshots) == 4
    ps = hs.prune(store, [2])
    with hs.StoreReader(store) as r:
        assert ps.removed == [2] and r.damaged == [] and len(r.snapshots) == 3 and r.verify() > 0
        assert {e.path: r.read_file(e) for e in r.snapshots[0].files} == copies[1]
        assert {e.path: r.read_file(e) for e in r.snapshots[1].files} == copies[3]
    # The NEWEST manifest damaged (its footer intact): older snapshots stay readable.
    open(store, "wb").write(good)
    _flip(store, newest + hs.HDR.size + 7)
    with hs.StoreReader(store) as r:
        assert r.damaged == [3]
        assert {e.path: r.read_file(e) for e in r.snapshots[0].files} == copies[1]


# ---------------------------------------------------------------- Reed-Solomon parity

def _par_store(name, snaps=3):
    src = os.path.join(TMP, name)
    store = os.path.join(TMP, name + ".hcs")
    for k in range(snaps):
        tree(src, {f"f{i}.bin": text(400_000, 3000 + 100 * k + i) for i in range(4)})
        tree(src, {f"r{k}.bin": os.urandom(300_000)})
        w = hs.StoreWriter(store, append=True, parity=True); w.add_tree(src); w.close()
    return src, store


@check("parity: incremental updates after each backup equal a full rebuild; prune keeps it consistent")
def _():
    src, store = _par_store("par_inc")
    inc = open(store + ".hcp", "rb").read()
    hs.Parity(store).build()
    assert open(store + ".hcp", "rb").read() == inc
    c = hs.Parity(store).check()
    assert c["covered"] == c["size"] == os.path.getsize(store) and not c["bad_shards"] and not c["bad_records"]
    hs.prune(store, [2])
    c = hs.Parity(store).check()
    assert c["covered"] == os.path.getsize(store) and not c["bad_shards"] and not c["bad_records"], c
    assert not os.path.exists(store + ".hcs-new.hcp")


@check("parity: damage anywhere (packs, manifests, footers, header) is rebuilt bit-exact by repair")
def _():
    src, store = _par_store("par_fix")
    good = open(store, "rb").read()
    with hs.StoreReader(store) as r:
        hot = [8, len(good) - 3] + [s.offset + 20 for s in r.snapshots] + [s.block_end + 9 for s in r.snapshots]
    rng = random.Random(11)
    spots = hot + [rng.randrange(len(good)) for _ in range(25)]
    for i in spots:
        b = bytearray(good); b[i] ^= 1 << rng.randrange(8); open(store, "wb").write(b)
        done = hs.repair(store)
        assert open(store, "rb").read() == good, (i, done)
    # several shards at once, in different groups (2 per group is the limit)
    b = bytearray(good)
    for o in (70_000, 140_000, 1_200_000):
        b[o:o + 5000] = os.urandom(5000)
    open(store, "wb").write(b)
    hs.repair(store)
    assert open(store, "rb").read() == good
    with hs.StoreReader(store) as r:
        assert r.verify() > 0


@check("parity: damage beyond its capacity is refused and nothing is written; stale parity never writes")
def _():
    src, store = _par_store("par_lim")
    good = open(store, "rb").read()
    # Interleaved: a burst spreads over the ng groups of the (here: only) super-group, so
    # it must cover more than 2 x ng shards to put 3 damaged shards into one group.
    ng = -(-(-(-len(good) // hs.PARITY_SHARD)) // hs.PARITY_K)
    n = (2 * ng + 1) * hs.PARITY_SHARD
    assert 100_000 + n < len(good), (ng, len(good))
    b = bytearray(good); b[100_000:100_000 + n] = os.urandom(n)
    open(store, "wb").write(b)
    done = hs.repair(store)
    got = np.frombuffer(open(store, "rb").read(), np.uint8)
    g0, b0 = np.frombuffer(good, np.uint8), np.frombuffer(bytes(b), np.uint8)
    # Groups with <= 2 damaged shards are rebuilt (proven by hash); the overloaded group is left as is.
    assert ((got == g0) | (got == b0)).all(), "repair wrote bytes it could not prove"
    assert (got != g0).any() and any("could NOT" in d for d in done), done
    code, out = _quiet("verify", store)
    assert code == 1 and "beyond repair" in out, out
    # parity left over from a different store: every check fails its hash, nothing is written
    open(store, "wb").write(good)
    other_src, other = _par_store("par_other", snaps=1)
    os.replace(other + ".hcp", store + ".hcp")
    c = hs.Parity(store).check(fix=True)
    assert c["repaired_shards"] == 0 and open(store, "rb").read() == good
    done = hs.repair(store)                       # store verifies, so the parity is rebuilt for it
    assert "rebuilt the parity file from the verified store" in done, done
    c = hs.Parity(store).check()
    assert not c["bad_shards"] and c["covered"] == len(good)


@check("parity: a damaged parity file is reported and rebuilt; old damage is never baked into new parity")
def _():
    src, store = _par_store("par_side")
    _flip(store + ".hcp", 200)                     # inside the first record's hashes
    c = hs.Parity(store).check()
    assert c["bad_records"] == [0], c
    code, out = _quiet("verify", store)
    assert code == 0 and "parity record(s) damaged" in out, out
    assert "rebuilt the parity file from the verified store" in hs.repair(store)
    assert not hs.Parity(store).check()["bad_records"]
    # Damage the last (partial) group, then back up: the update must refuse rather than
    # recompute parity over the damaged bytes; repair afterwards still restores them.
    good = open(store, "rb").read()
    _flip(store, len(good) - 40_000)
    tree(src, {"later.bin": os.urandom(100_000)})
    w = hs.StoreWriter(store, append=True); w.add_tree(src); st = w.close()
    assert st.parity.startswith("warning") and "repair" in st.parity, st.parity
    hs.repair(store)
    assert open(store, "rb").read()[:len(good)] == good
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 4 and r.verify() > 0
    c = hs.Parity(store).check()
    assert c["covered"] == os.path.getsize(store) and not c["bad_shards"], c


@check("parity: on by default for new stores; --no-parity and `parity --remove` turn it off")
def _():
    src = os.path.join(TMP, "par_cli"); tree(src, {"a.txt": text(100_000, 1)})
    store = os.path.join(TMP, "par_cli.hcs")
    assert _quiet("pack", src, store)[0] == 0 and os.path.exists(store + ".hcp")
    assert _quiet("pack", src, store, "--force", "--no-parity")[0] == 0 and not os.path.exists(store + ".hcp")
    assert _quiet("parity", store)[0] == 0 and os.path.exists(store + ".hcp")
    assert _quiet("backup", src, store)[0] == 0 and not hs.Parity(store).check()["bad_shards"]
    assert _quiet("parity", store, "--remove")[0] == 0 and not os.path.exists(store + ".hcp")


@check("--pack-mb sets the pack size; unpack --fsync restores bit-exact")
def _():
    src = os.path.join(TMP, "opts"); tree(src, {f"t{i}.txt": text(900_000, 50 + i) for i in range(6)})
    small, big = os.path.join(TMP, "opts1.hcs"), os.path.join(TMP, "opts4.hcs")
    assert _quiet("pack", src, small)[0] == 0 and _quiet("pack", src, big, "--pack-mb", "4")[0] == 0
    with hs.StoreReader(small) as a, hs.StoreReader(big) as b:
        assert len(b.pack_offsets) < len(a.pack_offsets)
    out = os.path.join(TMP, "opts_out")
    assert _quiet("unpack", big, out, "--fsync")[0] == 0
    same_tree(src, out)



@check("repair rewrites damaged footers and restores a hidden newest snapshot WITHOUT parity")
def _():
    src, store = _three_snapshots("foot_np")
    if os.path.exists(store + ".hcp"):
        os.remove(store + ".hcp")
    good = open(store, "rb").read()
    with hs.StoreReader(store) as r:
        old_footer = r.snapshots[0].block_end
    _flip(store, old_footer + 3)                   # an older footer
    _flip(store, len(good) - 5)                    # the newest footer: snapshot 3 becomes hidden
    done = hs.repair(store)
    assert any("footer at byte" in d for d in done) and any("newest snapshot" in d for d in done), done
    assert open(store, "rb").read() == good
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 3 and r.verify() > 0


# ---------------------------------------------------------------- encryption

def _enc_tree(name):
    src = os.path.join(TMP, name)
    tree(src, {"secret-name-alpha.txt": b"TOP SECRET PAYLOAD " * 20_000,
               "dir/notes.txt": text(600_000, 77), "rand.bin": os.urandom(400_000)})
    return src


@check("encryption: nothing readable in the file; right password restores bit-exact; wrong/none refused")
def _():
    src = _enc_tree("enc1")
    store = os.path.join(TMP, "enc1.hcs")
    w = hs.StoreWriter(store, encrypt=True, password="correct horse"); w.add_tree(src); w.close()
    raw = open(store, "rb").read()
    for needle in (b"TOP SECRET", b"secret-name-alpha", b"notes.txt", text(600_000, 77)[:40]):
        assert needle not in raw, needle
    hs._KEYS.clear()
    for pw in (None, "wrong"):
        try:
            hs.StoreReader(store, password=pw)
            raise AssertionError("opened without the right password")
        except hs.PasswordError:
            pass
    with hs.StoreReader(store, password="correct horse") as r:
        assert r.encrypted and r.verify() == 3
        out = os.path.join(TMP, "enc1_out"); r.unpack(out)
    same_tree(src, out)
    # appending stays encrypted, needs the password (cached in-process here), and dedups
    tree(src, {"more.txt": b"TOP SECRET PAYLOAD " * 1000})
    w = hs.StoreWriter(store, append=True); w.add_tree(src); st = w.close()
    assert st.dedup_bytes > 0 and b"more.txt" not in open(store, "rb").read()
    hs.prune(store, [1])
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 1 and r.encrypted and r.verify() == 4
    # --encrypt onto an unencrypted store is refused
    plain = os.path.join(TMP, "enc_plain.hcs")
    w = hs.StoreWriter(plain); w.add_tree(src); w.close()
    try:
        hs.StoreWriter(plain, append=True, encrypt=True, password="x")
        raise AssertionError("encrypt accepted for an unencrypted store")
    except hs.IntegrityError as e:
        assert "not encrypted" in str(e)


@check("encryption: damage is told apart from a wrong key; parity repairs ciphertext and the key block")
def _():
    src = _enc_tree("enc2")
    store = os.path.join(TMP, "enc2.hcs")
    w = hs.StoreWriter(store, encrypt=True, password="pw2"); w.add_tree(src); w.close()
    good = open(store, "rb").read()
    with hs.StoreReader(store, password="pw2") as r:
        pack0 = r.pack_offsets[0]
    _flip(store, pack0 + hs.HDR.size + 40)         # inside a sealed pack
    with hs.StoreReader(store, password="pw2") as r:
        rep = r.scan()
    assert rep["problems"] and any("CRC" in p for p in rep["problems"]), rep["problems"]
    hs.repair(store)
    assert open(store, "rb").read() == good
    hs._KEYS.clear()
    _flip(store, 8 + hs.HDR.size + 30)             # inside the key block (the wrapped key)
    try:
        hs.StoreReader(store, password="pw2")
        raise AssertionError("damaged key block accepted")
    except hs.IntegrityError as e:
        assert "key block" in str(e), e
    assert hs.Parity(store).check(fix=True)["repaired_shards"] == 1    # parity needs no password
    assert open(store, "rb").read() == good
    with hs.StoreReader(store, password="pw2") as r:
        assert r.verify() == 3


@check("encryption CLI: pack --encrypt, exit 5 without password, passwd, MCP --password-file, no .sem")
def _():
    src = _enc_tree("enc3")
    store = os.path.join(TMP, "enc3.hcs")
    pw1, pw2 = os.path.join(TMP, "pw1.txt"), os.path.join(TMP, "pw2.txt")
    open(pw1, "w").write("first password\n"); open(pw2, "w").write("second password\n")
    hs.set_password(None); hs._KEYS.clear()
    assert _quiet("pack", src, store, "--encrypt", "--password-file", pw1)[0] == 0
    hs.set_password(None); hs._KEYS.clear()
    code, out = _quiet("list", store)
    assert code == 5 and "encrypted" in out, (code, out)
    assert _quiet("verify", store, "--password-file", pw1)[0] == 0
    assert _quiet("passwd", store, "--password-file", pw1, "--new-password-file", pw2)[0] == 0
    hs.set_password(None); hs._KEYS.clear()
    assert _quiet("list", store, "--password-file", pw1)[0] == 5
    hs.set_password(None); hs._KEYS.clear()
    assert _quiet("verify", store, "--password-file", pw2)[0] == 0
    assert not hs.Parity(store).check()["bad_shards"]
    hs.set_password(None); hs._KEYS.clear()
    r = subprocess.run([sys.executable, os.path.join(HERE, "hybridstore_mcp.py"), "--password-file", pw2, store,
                        "--call", "read_file", '{"path": "secret-name-alpha.txt"}'],
                       capture_output=True, timeout=120)
    assert r.returncode == 0 and b"TOP SECRET PAYLOAD" in r.stdout, r.stderr[-500:]
    sem = os.path.join(HERE, "hybridstore_semantic.py")
    r = subprocess.run([sys.executable, sem, "index", store], capture_output=True, timeout=120,
                       env={**os.environ, "HYBRIDSTORE_PASSWORD": "second password"})
    assert r.returncode != 0 and b"allow-plaintext-index" in r.stdout + r.stderr, r
    assert not os.path.exists(store + ".sem")
    hs.set_password(None); hs._KEYS.clear()


# ---------------------------------------------------------------- interleaved parity

def _big_store(name, mb=20):
    src = os.path.join(TMP, name)
    tree(src, {f"r{i}.bin": os.urandom(1 << 20) for i in range(mb)})     # incompressible: store ~= mb MiB
    store = os.path.join(TMP, name + ".hcs")
    w = hs.StoreWriter(store); w.add_tree(src); w.close()
    return src, store


@check("interleaved parity: a 2 MiB burst is rebuilt bit-exact; --m 4 survives 4 MiB; depth-1 sidecars still work")
def _():
    src, store = _big_store("burst")
    good = open(store, "rb").read()
    assert len(good) > 17 << 20
    p = hs.Parity(store).params()
    assert p["depth"] == 16 and p["m"] == 2
    S = hs.PARITY_SHARD
    tail = len(good) - 16 * 16 * S                 # bytes in the last, partial super-group
    ng_last = -(-(-(-tail // S)) // 16)
    # an unaligned burst of L bytes touches up to L/S + 1 shards; 2 per group are repairable
    for start, n in ((3_000_000, (32 - 1) * S), (len(good) - (2 * ng_last - 1) * S + 5, (2 * ng_last - 1) * S - 5)):
        b = bytearray(good); b[start:start + n] = os.urandom(n); open(store, "wb").write(b)
        done = hs.repair(store)
        assert open(store, "rb").read() == good, (start, n, done)
    # 3 MiB: more than m=2 can do in one super-group -> some groups refused, never wrong bytes
    b = bytearray(good); b[1_000_000:1_000_000 + (3 << 20)] = os.urandom(3 << 20); open(store, "wb").write(b)
    c = hs.Parity(store).check(fix=True)
    assert c["unrepairable_groups"]
    got = np.frombuffer(open(store, "rb").read(), np.uint8)
    assert ((got == np.frombuffer(good, np.uint8)) | (got == np.frombuffer(bytes(b), np.uint8))).all()
    open(store, "wb").write(good)
    assert _quiet("parity", store, "--m", "4")[0] == 0 and hs.Parity(store).params()["m"] == 4
    b = bytearray(good); b[1_000_000:1_000_000 + 63 * S] = os.urandom(63 * S)
    open(store, "wb").write(b)
    hs.repair(store)
    assert open(store, "rb").read() == good
    # a backup keeps m=4 / depth 16, and incremental == full rebuild
    tree(src, {"later.bin": os.urandom(3 << 20)})
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w.close()
    inc = open(store + ".hcp", "rb").read()
    hs.Parity(store).build(**hs.Parity(store).params())
    assert open(store + ".hcp", "rb").read() == inc
    # sidecars written before interleaving (depth 1) are still read, updated and used
    hs.Parity(store).build(depth=1)
    assert hs.Parity(store).params()["depth"] == 1
    good = open(store, "rb").read()
    _flip(store, 5_000_000)
    hs.repair(store)
    assert open(store, "rb").read() == good


# ---------------------------------------------------------------- hardening (research pass)

@check("encryption hides sizes: sealed headers carry no plaintext size; payloads padded to 4 KiB")
def _():
    src = os.path.join(TMP, "pad1")
    tree(src, {"a.txt": b"x" * 123_457, "photo.jpg": b"\xff\xd8\xff\xe0" + os.urandom(77_777),
               "tiny.txt": b"hi"})
    store = os.path.join(TMP, "pad1.hcs")
    w = hs.StoreWriter(store, encrypt=True, password="pad"); w.add_tree(src); w.close()
    raw = open(store, "rb").read()
    with hs.StoreReader(store, password="pad") as r:
        offs = list(r.pack_offsets) + [s.offset for s in r.snapshots]
        assert r.verify() > 0
        out = os.path.join(TMP, "pad1_out"); r.unpack(out)
    same_tree(src, out)
    for off in offs:
        magic, flags, olen, slen, _crc = hs.HDR.unpack_from(raw, off)
        assert flags & hs.FLAG_ENCRYPTED and olen == 0, (off, flags, olen)
        assert (slen - 28) % hs.SEAL_PAD == 0, (off, slen)
    assert hs.MAX_SEALED_BLOCKS >= 1 << 20


@check("repair --dry-run reports the plan and changes nothing; the real repair then fixes it")
def _():
    src, store = _three_snapshots("dry")
    good = open(store, "rb").read()
    with hs.StoreReader(store) as r:
        old_footer = r.snapshots[0].block_end
    _flip(store, 200)
    _flip(store, old_footer + 2)
    bad = open(store, "rb").read()
    plan = hs.repair(store, dry_run=True)
    assert plan and any("parity" in p for p in plan), plan
    assert open(store, "rb").read() == bad
    code, out = _quiet("repair", store, "--dry-run")
    assert code == 0 and "nothing was changed" in out, out
    assert open(store, "rb").read() == bad
    hs.repair(store)
    assert open(store, "rb").read() == good
    assert hs.repair(store, dry_run=True) == []


@check("cloud placeholders (offline attribute) are skipped and reported; --cloud-files includes them")
def _():
    if os.name != "nt":
        return
    import ctypes
    src = os.path.join(TMP, "cloud")
    tree(src, {"local.txt": b"here " * 1000, "online-only.docx": b"would download " * 1000})
    p = os.path.join(src, "online-only.docx")
    FILE_ATTRIBUTE_OFFLINE = 0x1000
    assert ctypes.windll.kernel32.SetFileAttributesW(p, FILE_ATTRIBUTE_OFFLINE)
    try:
        store = os.path.join(TMP, "cloud.hcs")
        w = hs.StoreWriter(store); w.add_tree(src); st = w.close()
        assert any("online-only" in s[0] and "cloud placeholder" in s[1] for s in st.skipped), st.skipped
        code, out = _quiet("list", store, "--skipped")
        assert code == 0 and "online-only" in out, out
        store2 = os.path.join(TMP, "cloud2.hcs")
        w = hs.StoreWriter(store2, cloud_files=True); w.add_tree(src); st = w.close()
        assert not st.skipped, st.skipped
        out2 = os.path.join(TMP, "cloud2_out")
        with hs.StoreReader(store2) as r:
            r.unpack(out2)
        assert open(os.path.join(out2, "online-only.docx"), "rb").read() == b"would download " * 1000
    finally:
        ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)


@check("a damaged block length is caught from the layout, without reading the rest of the store")
def _():
    src = os.path.join(TMP, "blen")
    tree(src, {f"f{i}.bin": os.urandom(300_000) for i in range(6)})
    store = os.path.join(TMP, "blen.hcs")
    w = hs.StoreWriter(store, pack_target=1 << 16, parity=False); w.add_tree(src); w.close()
    with hs.StoreReader(store) as r:
        off = r.pack_offsets[1]
    with open(store, "r+b") as f:                    # set the stored-length field of pack 1 to ~4 GB
        f.seek(off + 8); f.write(b"\xf0\xff\xff\xff")   # header: magic 3, flags 1, orig_len 4, stored_len 4, crc 4
    with hs.StoreReader(store) as r:
        rep = r.scan()
        assert 1 in rep["bad_packs"] and "does not match the store layout" in rep["bad_packs"][1], rep["bad_packs"]
        assert len(rep["bad_packs"]) == 1, rep["bad_packs"]


@check("Windows junctions are restored as junctions, directory symlinks as symlinks")
def _():
    if os.name != "nt":
        return
    import _winapi
    src, outside = os.path.join(TMP, "jsrc"), os.path.join(TMP, "joutside")
    tree(src, {"real/x.txt": b"inside"})
    tree(outside, {"y.txt": b"outside"})
    _winapi.CreateJunction(os.path.join(src, "real"), os.path.join(src, "j_in"))
    _winapi.CreateJunction(outside, os.path.join(src, "j_out"))
    try:
        os.symlink(outside, os.path.join(src, "dirsym"), target_is_directory=True); sym = True
    except OSError:
        sym = False                                  # no Developer Mode / admin
    store = os.path.join(TMP, "junc.hcs")
    w = hs.StoreWriter(store); w.add_tree(src); st = w.close()
    assert st.links == 2 + sym and st.files == 1, st     # the links' contents are not stored twice
    out = os.path.join(TMP, "junc_out")
    for k in range(2):                               # the second restore replaces the existing links
        with hs.StoreReader(store) as r:
            assert r.unpack(out, overwrite=bool(k)) == []
    for name, target in (("j_in", os.path.join(src, "real")), ("j_out", outside)):
        p = os.path.join(out, name)
        assert os.path.isjunction(p) and not os.path.islink(p), name
        assert os.path.normcase(os.readlink(p).removeprefix("\\\\?\\")) == os.path.normcase(target), os.readlink(p)
    assert open(os.path.join(out, "j_out", "y.txt"), "rb").read() == b"outside"
    if sym:
        assert os.path.islink(os.path.join(out, "dirsym")) and not os.path.isjunction(os.path.join(out, "dirsym"))
    for base in (src, out):                          # remove the links before rmtree can follow them
        for name in ("j_in", "j_out", "dirsym"):
            if os.path.lexists(os.path.join(base, name)):
                os.rmdir(os.path.join(base, name))  # removes the link only, not its target


if __name__ == "__main__":
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\nall {len(passed)} checks passed")
