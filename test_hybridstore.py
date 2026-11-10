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
    w = hs.StoreWriter(store, append=True); w.add_tree(src); w._flush()
    w.f.close()                                 # "crash": packs written, no manifest/footer
    assert os.path.getsize(store) > good
    with hs.StoreReader(store) as r:
        assert r.end == good and len(r.snapshots) == 1 and r.verify() == 4
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
    w.add_file("junk.bin", os.urandom(2_000_000)); w._flush()
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


if __name__ == "__main__":
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\nall {len(passed)} checks passed")
