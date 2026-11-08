#!/usr/bin/env python3
"""Build sample datasets, pack them with hybridstore, verify a bit-exact
round trip, check corruption detection, and compare against tar+zstd/gzip."""
import io, os, random, shutil, sys, tarfile, time, zlib, hashlib, glob
import numpy as np
import zstandard as zstd
from PIL import Image
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hybridstore as hs

WORK = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_data")
# stdlib source tree of the running interpreter (works on Linux and Windows)
import sysconfig
SRC = os.environ.get("HYBRID_BENCH_SRC", sysconfig.get_paths()["stdlib"])
rng = random.Random(42)


def stdlib_files():
    out = []
    for p in sorted(glob.glob(os.path.join(SRC, "**", "*.py"), recursive=True)):
        rel = os.path.relpath(p, SRC).replace(os.sep, "/")
        if "site-packages" in rel or rel.startswith("test") or "/test" in rel:
            continue
        out.append(p)
    return out


def copy_corpus(dst):
    for p in stdlib_files():
        d = os.path.join(dst, os.path.relpath(p, SRC))
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copyfile(p, d)


def make_code(root):
    copy_corpus(os.path.join(root, "src"))


def make_backups(root):
    """3 nightly snapshots of the same tree; each night ~3% of files get a
    small edit somewhere in the middle (shifts all later bytes)."""
    prev = None
    for night in range(3):
        snap = os.path.join(root, f"snapshot_{night}")
        if prev is None:
            copy_corpus(snap)
        else:
            shutil.copytree(prev, snap)
            files = sorted(glob.glob(snap + "/**/*.py", recursive=True))
            for p in rng.sample(files, k=max(1, len(files) * 3 // 100)):
                b = open(p, "rb").read()
                cut = rng.randrange(len(b) + 1)
                open(p, "wb").write(b[:cut] + f"\n# edit night {night}\n".encode() + b[cut:])
        prev = snap


def photo_like(w, h, seed):
    r = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w]
    base = np.stack([(x * 255 // w), (y * 255 // h), ((x + y) * 128 // (w + h))], -1)
    img = base + r.normal(0, 12, (h, w, 3))
    return Image.fromarray(np.clip(img, 0, 255).astype(np.uint8))


def make_mixed(root):
    os.makedirs(root, exist_ok=True)
    # application logs: highly repetitive text
    with open(os.path.join(root, "app.log"), "w") as f:
        t = 1_700_000_000
        for i in range(60000):
            t += rng.randint(0, 3)
            lvl = rng.choice(["INFO", "INFO", "INFO", "WARN", "DEBUG", "ERROR"])
            f.write(f"{t} {lvl} svc=api req={rng.getrandbits(32):08x} path=/v1/items/{rng.randint(1,5000)} "
                    f"status={rng.choice([200,200,200,404,500])} ms={rng.randint(1,900)}\n")
    # JSON-ish records
    with open(os.path.join(root, "records.jsonl"), "w") as f:
        for i in range(20000):
            f.write('{"id":%d,"name":"user_%d","score":%.4f,"tags":["a","b"]}\n' % (i, rng.randint(0, 9999), rng.random()))
    # photos: 6 unique JPEGs, 2 exact duplicates, 1 re-encoded near duplicate
    for i in range(6):
        photo_like(1024, 768, i).save(os.path.join(root, f"photo_{i}.jpg"), quality=90)
    shutil.copyfile(os.path.join(root, "photo_0.jpg"), os.path.join(root, "photo_0_copy.jpg"))
    shutil.copyfile(os.path.join(root, "photo_1.jpg"), os.path.join(root, "photo_1_copy.jpg"))
    photo_like(1024, 768, 2).save(os.path.join(root, "photo_2_q80.jpg"), quality=80)
    # lossless PNG screenshots (flat regions)
    for i in range(3):
        im = Image.new("RGB", (1280, 800), (240, 240, 240))
        arr = np.array(im)
        arr[100 + 50 * i:300, 100:900] = (30, 90, 200)
        Image.fromarray(arr).save(os.path.join(root, f"screen_{i}.png"))
    # incompressible data: random + already-compressed
    open(os.path.join(root, "random.bin"), "wb").write(os.urandom(2 * 1024 * 1024))
    import gzip
    open(os.path.join(root, "app.log.gz"), "wb").write(gzip.compress(open(os.path.join(root, "app.log"), "rb").read()))


def tar_bytes(root):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as t:
        t.add(root, arcname=".")
    return bio.getvalue()


def dir_bytes(root):
    return sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(root) for f in fs)


def baselines(root):
    raw = tar_bytes(root)
    res = {}
    t = time.time(); res["gzip-9 (tar)"] = len(zlib.compress(raw, 9))
    res["zstd-3 (tar)"] = len(zstd.ZstdCompressor(level=3).compress(raw))
    res["zstd-19 (tar)"] = len(zstd.ZstdCompressor(level=19).compress(raw))
    p = zstd.ZstdCompressionParameters.from_level(19, window_log=27, enable_ldm=True)
    res["zstd-19 --long (tar)"] = len(zstd.ZstdCompressor(compression_params=p).compress(raw))
    return res


def pack_and_check(root, store, **kw):
    inp = dir_bytes(root)
    t0 = time.time()
    w = hs.StoreWriter(store, **kw); w.add_tree(root); st = w.close()
    t_pack = time.time() - t0
    out = store + ".out"
    shutil.rmtree(out, ignore_errors=True)
    t0 = time.time()
    hs.StoreReader(store).unpack(out)
    t_unpack = time.time() - t0
    # independent check: compare every file byte-for-byte with the source
    mism = n = 0
    for d, _, fs in os.walk(root):
        for f in fs:
            a = os.path.join(d, f); b = os.path.join(out, os.path.relpath(a, root))
            n += 1
            if not os.path.exists(b) or open(a, "rb").read() != open(b, "rb").read():
                mism += 1
    shutil.rmtree(out)
    return st, inp / 1e6 / t_pack, inp / 1e6 / t_unpack, n, mism


def run(name, root, store):
    inp = dir_bytes(root)
    print(f"\n=== {name}  ({inp:,} bytes) ===")
    rows = []
    for label, kw in [("hybrid, 1 MiB packs", {}), ("hybrid, per-chunk + dict", {"pack_target": 0})]:
        st, mbp, mbu, n, mism = pack_and_check(root, store, **kw)
        print(f"-- {label}: pack {mbp:.1f} MB/s, unpack {mbu:.1f} MB/s, "
              f"round trip {n - mism}/{n} files bit-exact")
        print("   " + hs._fmt(st).replace("\n", "\n   "))
        rows.append((label, st.store_bytes))
    rows += list(baselines(root).items())
    for k, v in rows:
        print(f"{k:26s} {v:>12,}  {inp/v:6.2f}x")


def corruption_test(store):
    data = bytearray(open(store, "rb").read())
    caught = 0
    trials = 200
    r = random.Random(7)
    for _ in range(trials):
        bad = bytearray(data)
        i = r.randrange(8, len(bad) - hs.FOOTER.size)
        bad[i] ^= 1 << r.randrange(8)
        p = store + ".bad"
        open(p, "wb").write(bad)
        try:
            hs.StoreReader(p).verify()
        except hs.IntegrityError:
            caught += 1
        os.remove(p)
    print(f"\ncorruption test: {caught}/{trials} single-bit flips detected")


if __name__ == "__main__":
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    sets = {"code (Python stdlib, 1 copy)": make_code,
            "backups (3 snapshots, ~3% files edited/night)": make_backups,
            "mixed (logs, JSON, JPEG/PNG, random, gzip)": make_mixed}
    last = None
    for i, (name, fn) in enumerate(sets.items()):
        root = os.path.join(WORK, f"set{i}")
        fn(root)
        run(name, root, os.path.join(WORK, f"set{i}.hcs"))
    # corruption test on the default (packed) store of the mixed set
    last = os.path.join(WORK, "corrupt_test.hcs")
    w = hs.StoreWriter(last); w.add_tree(os.path.join(WORK, "set2")); w.close()
    corruption_test(last)
