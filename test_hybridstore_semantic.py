#!/usr/bin/env python3
"""Checks for the semantic index (run: python test_hybridstore_semantic.py).
Uses a small fake embedding server (bag of words), so Ollama is not needed."""
import hashlib, http.server, json, os, re, shutil, subprocess, sys, tempfile, threading, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hybridstore as hs
import hybridstore_mcp as mcp
import hybridstore_semantic as sem

os.makedirs(os.path.join(HERE, "bench_data"), exist_ok=True)
TMP = tempfile.mkdtemp(prefix="hcs-sem-", dir=os.path.join(HERE, "bench_data"))
passed = []
CALLS = {"texts": 0}
DIM = 256


def fake_vector(text):
    v = [0.0] * DIM
    for w in re.findall(r"[a-z]+", text.lower()):
        v[zlib.crc32(w.encode()) % DIM] += 1.0
    return v


class FakeOllama(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path != "/api/embed" or body.get("model") not in ("fake-embed", "other-model"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error": "model not found"}')
            return
        CALLS["texts"] += len(body["input"])
        out = json.dumps({"embeddings": [fake_vector(t) for t in body["input"]]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeOllama)
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["HYBRIDSTORE_EMBED_URL"] = f"http://127.0.0.1:{srv.server_address[1]}"
os.environ["HYBRIDSTORE_EMBED_MODEL"] = "fake-embed"


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


def backup(src, store):
    w = hs.StoreWriter(store, codec=hs.BlockCodec(zstd_level=3), append=os.path.exists(store),
                       label=os.path.abspath(src))
    w.add_tree(src)
    w.close()


def filler(tag, n):
    return "".join(f"{tag} filler line number {i} with some ordinary words in it\n" for i in range(n))


SRC, STORE = os.path.join(TMP, "src"), os.path.join(TMP, "s.hcs")
AUTH = (filler("alpha", 80) + "def verify_password(user, password):\n"
        "    # compare the password hash against the stored credential\n"
        "    return bcrypt.checkpw(password, user.credential_hash)\n" + filler("beta", 80))
tree(SRC, {
    "app/auth.py": AUTH.encode(),
    "app/backup_auth.py": AUTH.encode(),                 # same content at a second path
    "app/render.py": (filler("gamma", 60) + "def draw_triangle(canvas, colour):\n"
                      "    canvas.polygon(vertices, fill=colour)\n").encode(),
    "docs/notes.md": ("# Weather\nThe forecast says rain tomorrow and sunshine on friday.\n").encode(),
    "bin/data.bin": bytes(range(256)) * 32,
    "empty.txt": b"",
})
backup(SRC, STORE)


def line_of(text, needle):
    return text.split("\n").index(next(l for l in text.split("\n") if needle in l)) + 1


@check("passages: contiguous line ranges, bounded size, content-defined cuts")
def _():
    text = "".join(f"line {i} " + "word " * (i % 23) + "\n" for i in range(3000))
    ps = sem.passages(iter(text.split("\n")[:-1]))
    assert ps[0][0] == 1 and ps[-1][1] == 3000, (ps[0], ps[-1])
    for (a, b, t), (a2, _, _) in zip(ps, ps[1:]):
        assert a2 == b + 1 and len(t) <= sem.MAX_CHARS + 200 and t.count("\n") == b - a
    assert sum(1 for _, _, t in ps if len(t) >= sem.MIN_CHARS) >= len(ps) - 1
    h1 = [hashlib.sha256(t.encode()).digest() for _, _, t in ps]
    edited = "an inserted line near the top\n" + text
    h2 = [hashlib.sha256(t.encode()).digest() for _, _, t in sem.passages(iter(edited.split("\n")[:-1]))]
    assert len(set(h1) - set(h2)) <= 2, len(set(h1) - set(h2))      # only the first passage(s) change
    long = sem.passages(iter(["x" * 7000, "short"]))
    assert [len(t) for _, _, t in long][:3] == [3000, 3000, 1000 + 1 + 5] or \
        all(len(t) <= sem.MAX_CHARS + 10 for _, _, t in long), [len(t) for _, _, t in long]


@check("index: text embedded once, binary/empty skipped, re-run does nothing")
def _():
    CALLS["texts"] = 0
    with hs.StoreReader(STORE) as r, sem.Index(STORE, create=True) as ix:
        st = ix.build(r, r.snapshots, log=None)
        assert st["files_indexed"] == 4 - 1 + 0 or st["files_indexed"] == 3, st   # auth content counted once
        assert st["binary"] == 1 and st["files_seen"] == 5, st
        first = CALLS["texts"]
        assert first == st["embedded"] > 0, (first, st)
        st = ix.build(r, r.snapshots, log=None)
        assert st["files_indexed"] == 0 and st["embedded"] == 0 and CALLS["texts"] == first, st
        s = ix.stats()
        assert s["model"] == "fake-embed" and s["dim"] == DIM and s["vectors"] == first, s


@check("search: right passage first, both paths of identical content, line numbers match read_file")
def _():
    with hs.StoreReader(STORE) as r, sem.Index(STORE, readonly=True) as ix:
        hits, cover = ix.search(r, r.snapshots[-1], "check user password hash credential", k=3)
        assert hits[0]["path"] in ("app/auth.py", "app/backup_auth.py"), hits
        assert {h["path"] for h in hits[:2]} == {"app/auth.py", "app/backup_auth.py"}, hits
        ln = line_of(AUTH, "def verify_password")
        assert hits[0]["start"] <= ln <= hits[0]["end"], (hits[0], ln)
        assert cover["files"] == 6 and cover["indexed"] == 4 and cover["not_indexed"] == 0, cover
        hits, _ = ix.search(r, r.snapshots[-1], "rain forecast friday", k=1)
        assert hits[0]["path"] == "docs/notes.md", hits
        hits, _ = ix.search(r, r.snapshots[-1], "password", k=5, d="docs")
        assert {h["path"] for h in hits} == {"docs/notes.md"}, hits
        hits, _ = ix.search(r, r.snapshots[-1], "polygon colour", k=1, glob="render.py")
        assert hits[0]["path"] == "app/render.py"
        e = next(e for e in r.snapshots[-1].files if e.path == "app/auth.py")
        snip = sem.snippet(r, e, ln, ln + 1)
    read = mcp.call_tool(mcp.StoreTools({"s": STORE}), "read_file",
                         {"path": "app/auth.py", "start_line": ln, "max_lines": 2})[0]
    assert snip.split("\n")[0] in read and "def verify_password" in snip, (snip, read)


@check("incremental: a new snapshot embeds only changed passages; coverage shows unindexed files")
def _():
    tree(SRC, {"app/render.py": (filler("gamma", 60) + "def draw_circle(canvas, radius):\n"
                                 "    canvas.ellipse(radius)\n").encode(),
               "app/new.py": b"def brand_new_feature():\n    launch rockets to the moon\n"})
    backup(SRC, STORE)
    with hs.StoreReader(STORE) as r:
        with sem.Index(STORE, readonly=True) as ix:
            _, cover = ix.search(r, r.snapshots[-1], "moon rockets", k=1)
            assert cover["not_indexed"] == 2, cover
        with sem.Index(STORE) as ix:
            CALLS["texts"] = 0
            st = ix.build(r, [r.snapshots[-1]], log=None)
            assert st["files_indexed"] == 2 and st["files_done_before"] == 4, st   # 3 text + the empty file
            assert st["reused"] >= 1 and CALLS["texts"] == st["embedded"] <= 3, (st, CALLS)
            hits, cover = ix.search(r, r.snapshots[-1], "launch rockets to the moon", k=1)
            assert hits[0]["path"] == "app/new.py" and cover["not_indexed"] == 0, (hits, cover)
            hits, _ = ix.search(r, r.snapshots[0], "launch rockets to the moon", k=3)
            assert all(h["path"] != "app/new.py" for h in hits)          # snapshot 1 never had it


@check("errors: no index, read-only open creates nothing, wrong model, server down")
def _():
    other = os.path.join(TMP, "other.hcs")
    shutil.copy(STORE, other)
    try:
        sem.Index(other, readonly=True)
        raise AssertionError("opened a missing index")
    except sem.SemanticError as e:
        assert "no semantic index" in str(e)
    assert not os.path.exists(other + ".sem")
    try:
        sem.Index(STORE, model="other-model")
        raise AssertionError("accepted another model")
    except sem.SemanticError as e:
        assert "built with 'fake-embed'" in str(e)
    try:
        sem.embed(["x"], "fake-embed", "http://127.0.0.1:9")
        raise AssertionError("no error for a dead server")
    except sem.SemanticError as e:
        assert "cannot reach" in str(e)
    try:
        sem.embed(["x"], "missing-model")
        raise AssertionError("no error for a missing model")
    except sem.SemanticError as e:
        assert "404" in str(e)


@check("MCP tool: semantic_search in-process and over stdio; store and index untouched")
def _():
    before = (open(STORE, "rb").read(), open(STORE + ".sem", "rb").read())
    t = mcp.StoreTools({"s": STORE})
    text, bad = mcp.call_tool(t, "semantic_search", {"query": "rain tomorrow", "k": 2})
    assert not bad and "docs/notes.md" in text and "similarity" in text and "rain tomorrow" in text, text
    text, bad = mcp.call_tool(t, "semantic_search", {"query": " "})
    assert bad and "query is required" in text
    text, bad = mcp.call_tool(mcp.StoreTools({"o": os.path.join(TMP, "other.hcs")}), "semantic_search",
                              {"query": "x"})
    assert bad and "no semantic index" in text, text
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "hybridstore_mcp.py"), STORE],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        def rpc(obj):
            proc.stdin.write(json.dumps(obj).encode() + b"\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())
        rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        names = [x["name"] for x in rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
        assert "semantic_search" in names, names
        r = rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "semantic_search", "arguments": {"query": "draw a circle with a radius", "k": 1}}})
        assert r["result"]["isError"] is False and "app/render.py" in r["result"]["content"][0]["text"], r
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
        proc.stdout.close()
        err = proc.stderr.read().decode(errors="replace")
        proc.stderr.close()
    assert proc.returncode == 0 and not err.strip(), err
    assert (open(STORE, "rb").read(), open(STORE + ".sem", "rb").read()) == before


@check("gc after prune drops entries no snapshot uses; command line works")
def _():
    hs.prune(STORE, [1])
    with hs.StoreReader(STORE) as r, sem.Index(STORE) as ix:
        n0 = ix.stats()["files"]
        g = ix.gc(r)
        assert g["files_removed"] == 1 and g["vectors_removed"] >= 1, g      # the old render.py
        assert ix.stats()["files"] == n0 - 1
        hits, cover = ix.search(r, r.snapshots[-1], "draw triangle polygon", k=10)
        assert cover["not_indexed"] == 0 and all(h["path"] for h in hits)
    exe = [sys.executable, os.path.join(HERE, "hybridstore_semantic.py")]
    p = subprocess.run(exe + ["search", STORE, "rockets moon", "-k", "1"], capture_output=True)
    assert p.returncode == 0 and b"app/new.py" in p.stdout, p
    p = subprocess.run(exe + ["status", STORE], capture_output=True)
    assert p.returncode == 0 and b"fake-embed" in p.stdout and b"snapshot 1:" in p.stdout, p
    p = subprocess.run(exe + ["index", STORE, "--snapshot", "9"], capture_output=True)
    assert p.returncode == 1 and b"does not exist" in p.stderr, p


if __name__ == "__main__":
    srv.shutdown()
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\n{len(passed)} checks passed")
