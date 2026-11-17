#!/usr/bin/env python3
"""Checks for doctor.py, the error manager (run: python test_doctor.py)."""
import hashlib, io, json, os, random, shutil, sys, tempfile, threading, time
from contextlib import redirect_stdout, redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.makedirs(os.path.join(HERE, "bench_data"), exist_ok=True)
TMP = tempfile.mkdtemp(prefix="hcs-doctor-", dir=os.path.join(HERE, "bench_data"))
os.environ["HYBRIDSTORE_LOG"] = os.path.join(TMP, "events.jsonl")
os.environ.pop("HYBRIDSTORE_PASSWORD", None)
import hybridstore as hs
import doctor

ONLY = [x.strip().lower() for x in os.environ.get("HS_TEST_ONLY", "").split(",") if x.strip()]
passed = []
rng = random.Random(7)


def check(name):
    def deco(fn):
        if ONLY and not any(x in name.lower() for x in ONLY):
            return fn
        fn()
        passed.append(name)
        print(f"ok  {name}")
        return fn
    return deco


def make_src(name, n=8, size=150_000):
    src = os.path.join(TMP, name)
    for i in range(n):
        os.makedirs(os.path.join(src, "d"), exist_ok=True)
        with open(os.path.join(src, "d", f"f{i}.bin"), "wb") as f:
            f.write(os.urandom(size // 2) + bytes(rng.randrange(4) for _ in range(size // 2)))
    return src


def make_store(name, parity=True, snapshots=1, password=None):
    src = make_src(name + "_src")
    store = os.path.join(TMP, name + ".hcs")
    hs.set_password(password)
    for k in range(snapshots):
        w = hs.StoreWriter(store, pack_target=1 << 16, parity=parity, append=k > 0,
                           encrypt=password is not None and k == 0, password=password) \
            if password else hs.StoreWriter(store, pack_target=1 << 16, parity=parity, append=k > 0)
        w.add_tree(src)
        w.close()
        if k + 1 < snapshots:
            with open(os.path.join(src, "d", f"new{k}.bin"), "wb") as f:
                f.write(os.urandom(20_000))
    hs.set_password(None)
    return src, store


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def rules(fs):
    return sorted({f.rule for f in fs})


def quiet(fn, *a, **kw):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        r = fn(*a, **kw)
    return r, out.getvalue() + err.getvalue()


def flip(path, offsets):
    with open(path, "r+b") as f:
        for o in offsets:
            f.seek(o)
            b = f.read(1)
            f.seek(o)
            f.write(bytes([b[0] ^ 0x40]))


def flip_in_shards(path, shards=(2, 7), n=12):
    """n flips inside the given 64 KiB shards: within what m=2 parity can rebuild."""
    S = hs.PARITY_SHARD
    flip(path, sorted({rng.randrange(s * S, min((s + 1) * S, os.path.getsize(path))) for s in shards
                       for _ in range(n // len(shards))}))


def restored_ok(store, src, password=None):
    out = os.path.join(TMP, "restore_" + os.path.basename(store))
    shutil.rmtree(out, ignore_errors=True)
    with hs.StoreReader(store, password=password) as r:
        r.unpack(out)
    for d, _, fs in os.walk(src):
        for f in fs:
            p = os.path.join(d, f)
            q = os.path.join(out, os.path.relpath(p, src))
            assert open(p, "rb").read() == open(q, "rb").read(), q


@check("a healthy store has no findings; `check` exits 0")
def _():
    _, store = make_store("healthy")
    assert doctor.diagnose(store) == []
    rc, out = quiet(doctor.main, ["check", store])
    assert rc == 0 and "healthy" in out, out


@check("missing parity is built automatically, only over a verified store")
def _():
    _, store = make_store("nopar", parity=False)
    assert rules(doctor.diagnose(store)) == ["PARITY_MISSING"]
    res = doctor.fix(store)
    assert any("built parity" in d for d in res["done"]) and res["after"] == [], res
    assert hs.Parity(store).exists()


@check("repairable damage: --dry-run changes nothing, fix rebuilds it bit-exact")
def _():
    src, store = make_store("dmg")
    size = os.path.getsize(store)
    flip_in_shards(store, (2, 7), 25)
    assert "DAMAGE_REPAIRABLE" in rules(doctor.diagnose(store))
    before = sha(store)
    res = doctor.fix(store, dry_run=True)
    assert sha(store) == before and any("would run parity_repair" in d for d in res["done"]), res["done"]
    res = doctor.fix(store)
    assert res["after"] == [], [(f.rule, f.detail) for f in res["after"]]
    restored_ok(store, src)


@check("damage beyond repair is never written automatically; --approve with --copy-first copies first")
def _():
    _, store = make_store("dead")
    size = os.path.getsize(store)
    flip(store, range(100, size, 16 << 10))         # every shard of every group
    fs = doctor.diagnose(store)
    assert doctor.worst(fs) == doctor.SEVERITY["critical"], rules(fs)
    assert "DAMAGE_BEYOND_REPAIR" in rules(fs) or "STORE_UNOPENABLE" in rules(fs), rules(fs)
    before = sha(store)
    res = doctor.fix(store)
    assert sha(store) == before and res["done"] == [], res["done"]
    rc, out = quiet(doctor.main, ["fix", store])
    assert rc == 1 and "DAMAGE" in out or "UNOPENABLE" in out, out
    if "DAMAGE_BEYOND_REPAIR" in rules(fs):
        cp = os.path.join(TMP, "dead_copies")
        res = doctor.fix(store, approve={"DAMAGE_BEYOND_REPAIR"}, copy_first=cp)
        copies = os.listdir(cp)
        assert any(c.endswith(".hcp") for c in copies) and len(copies) == 2, copies
        assert any("copied the store" in d for d in res["done"]), res["done"]
        assert sha(os.path.join(cp, next(c for c in copies if not c.endswith(".hcp")))) == before


@check("a missing newest footer is written again; then parity is built")
def _():
    src, store = make_store("footer", parity=False, snapshots=2)
    with open(store, "r+b") as f:
        f.truncate(os.path.getsize(store) - hs.FOOTER.size)
    assert {"FOOTER_MISSING", "PARITY_MISSING"} <= set(rules(doctor.diagnose(store)))
    res = doctor.fix(store)
    assert res["after"] == [], [(f.rule, f.detail) for f in res["after"]]
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 2
    restored_ok(store, src)


@check("bytes of an interrupted write are cut off, parity then matches again")
def _():
    _, store = make_store("tail")
    good = sha(store)
    with open(store, "ab") as f:
        f.write(os.urandom(5000))
    fs = rules(doctor.diagnose(store))
    assert "INTERRUPTED_WRITE" in fs and "PARITY_STALE" in fs, fs
    assert "DAMAGE_REPAIRABLE" not in fs, fs        # appended bytes are not shard damage (was a parity bug)
    res = doctor.fix(store)
    assert res["after"] == [] and sha(store) == good, (res["done"], [f.rule for f in res["after"]])


@check("leftover temp files are reported, and deleted only with --approve")
def _():
    _, store = make_store("left")
    open(store + ".hcs-new", "wb").write(b"x" * 1000)
    assert rules(doctor.diagnose(store)) == ["LEFTOVER_TEMP"]
    doctor.fix(store)
    assert os.path.exists(store + ".hcs-new")
    res = doctor.fix(store, approve={"LEFTOVER_TEMP"})
    assert not os.path.exists(store + ".hcs-new") and res["after"] == [], res


@check("a store being written is reported as busy and not touched")
def _():
    _, store = make_store("busy")
    lock = hs._StoreLock(store)
    try:
        fs = doctor.diagnose(store)
        assert rules(fs) == ["BUSY"] and "pid" in fs[0].detail, fs
    finally:
        lock.release()


@check("encrypted store without the password: parity check and repair still work")
def _():
    src, store = make_store("enc", password="pw-doctor")
    flip_in_shards(store, (3,), 10)
    hs._KEYS.clear()                 # the writer left the unlocked key cached in this process
    assert {"NEEDS_PASSWORD", "DAMAGE_REPAIRABLE"} <= set(rules(doctor.diagnose(store)))
    res = doctor.fix(store)
    assert rules(res["after"]) == ["NEEDS_PASSWORD"], res
    assert rules(doctor.diagnose(store, password="wrong")) == ["WRONG_PASSWORD"]
    assert doctor.diagnose(store, password="pw-doctor") == []
    restored_ok(store, src, password="pw-doctor")
    hs.set_password(None)


@check("old snapshots: BACKUP_STALE when the newest snapshot is older than the limit")
def _():
    _, store = make_store("stale")
    assert rules(doctor.diagnose(store, max_age_days=1e-9)) == ["BACKUP_STALE"]
    assert doctor.diagnose(store, max_age_days=7) == []


@check("items skipped in each of the last 3 snapshots get a hint")
def _():
    if os.name != "nt":
        return
    import ctypes
    src = make_src("skip_src", n=2)
    p = os.path.join(src, "cloud.docx")
    open(p, "wb").write(b"x" * 100)
    ctypes.windll.kernel32.SetFileAttributesW(p, 0x1000)       # OFFLINE: treated as a cloud placeholder
    store = os.path.join(TMP, "skip.hcs")
    try:
        for k in range(3):
            w = hs.StoreWriter(store, append=k > 0, label=src); w.add_tree(src); w.close()
            time.sleep(0.01)
    finally:
        ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
    fs = doctor.diagnose(store)
    assert rules(fs) == ["SKIPPED_REPEATEDLY"] and "cloud" in fs[0].detail, [(f.rule, f.detail) for f in fs]
    rc, _ = quiet(doctor.main, ["check", store])
    assert rc == 0                                   # info only


@check("crashes are logged with a stable signature, grouped, reported and acknowledged")
def _():
    _, store = make_store("crash")
    real = hs._main

    def boom(a):
        raise RuntimeError("simulated bug")
    hs._main = boom
    try:
        for _ in range(2):
            try:
                quiet(hs.main, ["verify", store])
                raise AssertionError("the crash was swallowed")
            except RuntimeError:
                pass
    finally:
        hs._main = real
    ev = doctor.read_events()
    crashes = [e for e in ev if e["kind"] == "crash"]
    assert len(crashes) == 2 and crashes[0]["signature"] == crashes[1]["signature"], crashes
    sig = crashes[0]["signature"]
    assert "simulated bug" in crashes[0]["error"] and "Traceback" in crashes[0]["traceback"]
    fs = doctor.diagnose(store, events=ev)
    assert rules(fs) == ["CRASH"] and "2x" in fs[0].detail, [(f.rule, f.detail) for f in fs]
    rc, out = quiet(doctor.main, ["bugs"])
    assert rc == 1 and sig in out and "simulated bug" in out, out
    rep = os.path.join(TMP, "bug.md")
    quiet(doctor.main, ["bugs", "--report", sig, "--out", rep])
    text = open(rep, encoding="utf-8").read()
    assert "simulated bug" in text and "Traceback" in text and "no problems found" in text, text[:2000]
    quiet(doctor.main, ["bugs", "--ack", sig])
    assert doctor.diagnose(store, events=doctor.read_events()) == []
    rc, out = quiet(doctor.main, ["bugs"])
    assert rc == 0 and sig not in out.split("crash signature")[1], out


@check("failed commands are logged with their message; 3 in a week is REPEATED_FAILURES")
def _():
    _, store = make_store("fails")
    open(store, "r+b").truncate(100)                 # not a store any more
    for _ in range(3):
        rc, _ = quiet(hs.main, ["list", store])
        assert rc == 1
    ev = [e for e in doctor.read_events() if e.get("kind") == "error" and e.get("store") == os.path.abspath(store)]
    assert len(ev) == 3 and ev[0]["message"].startswith("error:") and ev[0]["exit"] == 1, ev
    fs = doctor.diagnose(store, events=doctor.read_events())
    assert "REPEATED_FAILURES" in rules(fs) and "STORE_UNOPENABLE" in rules(fs), rules(fs)


@check("known causes are recognised in error text")
def _():
    assert "full" in doctor.known_cause("OSError: [WinError 112] There is not enough space on the disk")[0]
    assert "another program" in doctor.known_cause("PermissionError: [WinError 32] being used by another process")[0]
    assert "zstandard" in doctor.known_cause("ModuleNotFoundError: No module named 'zstandard'")[1]
    assert doctor.known_cause("something new") is None
    assert doctor._store_arg(["backup", "C:/src", "D:/s.hcs", "--level", "9"]) == "D:/s.hcs"
    assert doctor._store_arg(["verify", "--password-file", "pw.txt", "D:/s.hcs"]) == "D:/s.hcs"
    assert doctor._store_arg(["prune", "D:/s.hcs", "--remove", "1", "2"]) == "D:/s.hcs"


@check("run: a locked store is waited for and the backup retried")
def _():
    src, store = make_store("runlock")
    lock = hs._StoreLock(store)
    threading.Timer(1.5, lock.release).start()
    t = time.time()
    rc, out = quiet(doctor.run, ["backup", src, store], retries=4, wait=0.5)
    assert rc == 0 and time.time() - t >= 1.4, (rc, out)
    assert "locked" in out and "retry" in out, out
    rec = [e for e in doctor.read_events() if e.get("kind") == "recovery" and e.get("store") == store]
    assert rec and rec[0]["action"] == "wait", rec


@check("run: a backup refused for a missing footer is repaired and retried")
def _():
    src, store = make_store("runfooter", snapshots=2)
    with open(store, "r+b") as f:
        f.truncate(os.path.getsize(store) - hs.FOOTER.size)
    rc, out = quiet(doctor.run, ["backup", src, store], retries=2, wait=0.1)
    assert rc == 0, out
    with hs.StoreReader(store) as r:
        assert len(r.snapshots) == 3                 # both old ones visible again, plus the new one
        assert not r.scan()["problems"]


@check("run: an unrecoverable error is not retried and its cause is named")
def _():
    rc, out = quiet(doctor.run, ["verify", os.path.join(TMP, "nope.hcs")], retries=3, wait=5)
    assert rc != 0 and "retry" not in out, out


@check("watch: config of several stores, fixes what is safe, writes report + status, exit 1 if anything is left")
def _():
    _, ok = make_store("w_ok")
    _, dmg = make_store("w_dmg")
    flip_in_shards(dmg, (4,), 5)
    _, left = make_store("w_left")
    open(left + ".hcs-new", "wb").write(b"x")
    cfg = os.path.join(TMP, "doctor.json")
    json.dump({"stores": [{"path": ok}, {"path": dmg}, {"path": left}], "max_age_days": 7}, open(cfg, "w"))
    rc, out = quiet(doctor.main, ["watch", "--config", cfg])
    st = json.load(open(os.path.join(TMP, "doctor-status.json")))
    by = {os.path.basename(s["path"]): s for s in st["stores"]}
    assert by["w_ok.hcs"]["open"] == [] and by["w_dmg.hcs"]["open"] == [] and by["w_dmg.hcs"]["fixed"]
    assert [f["rule"] for f in by["w_left.hcs"]["open"]] == ["LEFTOVER_TEMP"]
    assert rc == 1 and os.path.exists(os.path.join(TMP, "doctor-report.txt")), out


@check("schedule prints the Task Scheduler command and installs nothing without --install")
def _():
    rc, out = quiet(doctor.main, ["schedule", "--config", os.path.join(TMP, "doctor.json"), "--time", "03:17"])
    assert rc == 0 and "schtasks" in out and "watch --config" in out and "not installed" in out, out


if __name__ == "__main__":
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\n{len(passed)} checks passed")
