#!/usr/bin/env python3
"""Checks for the catalog (<store>.cat): run python test_hybridstore_catalog.py."""
import contextlib, io, os, random, re, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["HYBRIDSTORE_LOG"] = "off"
import hybridstore as hs
import hybridstore_catalog as hc
import hybridstore_mcp as mcp

os.makedirs(os.path.join(HERE, "bench_data"), exist_ok=True)
TMP = tempfile.mkdtemp(prefix="hcs-cat-", dir=os.path.join(HERE, "bench_data"))
rng = random.Random(7)
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
        with open(p, "wb") as f:
            f.write(data)


def cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = hs.main(list(argv))
    return code, out.getvalue()


WORDS = ["alpha", "Beta", "GAMMA", "delta_x", "café", "naïve", "ſome", "Straße", "İstanbul",
         "中文", "def main(", "TODO:", "x = 1", "Kelvin", "Σσς"]


def text(n_lines):
    return "\n".join(" ".join(rng.choice(WORDS) for _ in range(rng.randint(0, 8))) for _ in range(n_lines))


def files_v1():
    f = {f"src/m{i}.py": text(rng.randint(1, 300)).encode() for i in range(25)}
    f.update({
        "docs/utf16.txt": text(50).encode("utf-16"),
        "docs/bom.txt": b"\xef\xbb\xbf" + text(40).encode(),
        "docs/crlf.txt": text(30).replace("\n", "\r\n").encode(),
        "docs/long.txt": ("y" * 200_000 + " needle_long " + "z" * 200_000).encode(),
        "docs/big.txt": text(6000).encode(),                     # > 64 KB: several passages
        "bin/blob.bin": bytes(range(256)) * 40,
        "empty.txt": b"",
        "dup/a.py": b"identical content alpha\n", "dup/b.py": b"identical content alpha\n",
    })
    return f


SRC, STORE = os.path.join(TMP, "src"), os.path.join(TMP, "s.hcs")
tree(SRC, files_v1())
assert cli("backup", SRC, STORE)[0] == 0


def tools():
    return mcp.StoreTools({"s": STORE})


def search(args, use):
    real = hc.catalog_path
    if not use:
        hc.catalog_path = lambda s: s + ".none"
    try:
        out = tools().search(args)
    finally:
        hc.catalog_path = real
    lines = out.splitlines()
    return [l for l in lines if not l.startswith("(catalog")], lines[-1]


@check("case folding: strings re.IGNORECASE matches fold equal, for every character")
def _():
    import _sre
    from re import _casefix
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        low = _sre.unicode_tolower(cp)
        assert hc.fold(chr(cp)) == chr(min((low, *_casefix._EXTRA_CASES.get(low, ())))), hex(cp)
    for a in ("ſ", "İ", "K", "ς", "S", "k", "ß"):
        for b in ("s", "i", "k", "σ", "ẞ"):
            if re.fullmatch(re.escape(a), b, re.I):
                assert hc.fold(a) == hc.fold(b), (a, b)


@check("backup builds the catalog; the next backup indexes only new contents and extends versions")
def _():
    with hs.StoreReader(STORE) as r, hc.Catalog(STORE, readonly=True) as c:
        assert c.status(r) == "current" and c.covers(r, 1)
        n1 = c.stats()["contents"]
    tree(SRC, {"src/m0.py": b"changed content TODO: x = 1\n", "src/new.py": b"brand new alpha\n"})
    os.remove(os.path.join(SRC, "src", "m1.py"))
    code, out = cli("backup", SRC, STORE)
    assert code == 0 and "catalog: 1 snapshot(s) added, 2 new file content(s)" in out, out
    with hs.StoreReader(STORE) as r, hc.Catalog(STORE, readonly=True) as c:
        assert c.status(r) == "current" and c.stats()["contents"] == n1 + 2
        assert sorted(c.find("", None, 10 ** 6)) == sorted(hc.path_filter(hc.version_runs(r), "", None, 10 ** 6))
        runs = {(p, first, last) for p, _, _, _, first, last, _ in c.find("src/m", None, 1000)}
        assert ("src/m1.py", 1, 1) in runs and ("src/m2.py", 1, 2) in runs
        assert ("src/m0.py", 1, 1) in runs and ("src/m0.py", 2, 2) in runs


@check("search through the catalog returns exactly what a full scan returns (random literal patterns)")
def _():
    with hs.StoreReader(STORE) as r:
        snap = r.snapshots[-1]
        texts = []
        for e in snap.files:
            st, ps = hc._text_passages(r, e)
            texts += [t for _, _, t in ps]
    pats = ["needle_long", "zzzz needle", "xyzzy", "ſOME", "STRASSE", "straße", "istanbul", "σσ",
            "KELVIN", "ab", "e", "def main(", "\"quote", "a*b?", "[x]"]
    for _ in range(120):
        t = rng.choice(texts)
        if not t:
            continue
        i = rng.randrange(len(t))
        p = t[i:i + rng.randint(1, 14)].split("\n")[0]
        if p:
            pats.append(p if rng.random() < 0.5 else p.swapcase())
    used = 0
    for p in pats:
        for kw in ({}, {"case_sensitive": True}, {"context": 2, "max_results": 7}, {"glob": "*.txt"},
                   {"dir": "docs"}, {"snapshot": 1}):
            a, _ = search({"pattern": p, **kw}, False)
            b, note = search({"pattern": p, **kw}, True)
            assert a == b, (p, kw, a[:3], b[:3])
            used += note.startswith("(catalog:")
    assert used > len(pats) * 4, used                    # the catalog was really used


@check("a catalog that is behind is not used for the newer snapshot, and says so; `catalog` updates it")
def _():
    tree(SRC, {"src/later.py": b"added later, not cataloged yet\n"})
    assert cli("backup", "--no-catalog", SRC, STORE)[0] == 0
    out, note = search({"pattern": "not cataloged yet"}, True)
    assert "1 match(es)" in out[0] and "behind: 1 newer snapshot(s)" in note, (out, note)
    _, note = search({"pattern": "alpha", "snapshot": 1}, True)
    assert note.startswith("(catalog:"), note            # older snapshots are still covered
    code, out = cli("catalog", STORE)
    assert code == 0 and "1 snapshot(s) added" in out, out
    _, note = search({"pattern": "not cataloged yet"}, True)
    assert note.startswith("(catalog:"), note


@check("prune: the snapshot list is rebuilt, indexed contents are reused, results stay exact")
def _():
    code, out = cli("prune", STORE, "--remove", "1")
    assert code == 0 and "snapshot list rebuilt" in out and "0 new file content(s)" in out, out
    with hs.StoreReader(STORE) as r, hc.Catalog(STORE, readonly=True) as c:
        assert c.status(r) == "current"
        assert sorted(c.find("", None, 10 ** 6)) == sorted(hc.path_filter(hc.version_runs(r), "", None, 10 ** 6))
    for p in ("alpha", "TODO:", "needle_long"):
        assert search({"pattern": p}, False)[0] == search({"pattern": p}, True)[0]


@check("a damaged catalog is set aside and rebuilt; the store is never touched")
def _():
    before = open(STORE, "rb").read()
    with open(hc.catalog_path(STORE), "r+b") as f:
        f.seek(0)
        f.write(b"garbage" * 20)
    code, out = cli("catalog", STORE)
    assert code == 0 and "damaged and set aside" in out, out
    assert open(STORE, "rb").read() == before
    with hs.StoreReader(STORE) as r, hc.Catalog(STORE, readonly=True) as c:
        assert c.status(r) == "current"
    assert search({"pattern": "alpha"}, False)[0] == search({"pattern": "alpha"}, True)[0]


@check("find_files: catalog and manifests give the same answer; the catalog is used when current")
def _():
    t = tools()
    a = t.find_files({"pattern": "SRC/M", "glob": "*.py"})
    assert "(from the catalog)" in a
    real = hc.catalog_path
    hc.catalog_path = lambda s: s + ".none"
    try:
        b = t.find_files({"pattern": "SRC/M", "glob": "*.py"})
    finally:
        hc.catalog_path = real
    assert a.replace("(from the catalog)", "") == b.replace("(from the manifests)", "")
    assert "src/m0.py" in a


@check("encrypted stores get no catalog (it would hold plaintext-derived data unencrypted)")
def _():
    src, store = os.path.join(TMP, "esrc"), os.path.join(TMP, "e.hcs")
    tree(src, {"secret.txt": b"the secret is here\n"})
    pw = os.path.join(TMP, "pw.txt")
    open(pw, "w").write("pw\n")
    assert cli("pack", "--encrypt", "--password-file", pw, src, store)[0] == 0
    assert not os.path.exists(hc.catalog_path(store))
    code, out = cli("catalog", "--password-file", pw, store)
    assert code == 2 and "encrypted" in out and not os.path.exists(hc.catalog_path(store)), out


if __name__ == "__main__":
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\nall {len(passed)} checks passed")
