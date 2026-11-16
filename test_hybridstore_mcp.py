#!/usr/bin/env python3
"""Checks for the read-only MCP server (run: python test_hybridstore_mcp.py)."""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hybridstore as hs
import hybridstore_mcp as mcp

os.makedirs(os.path.join(HERE, "bench_data"), exist_ok=True)
TMP = tempfile.mkdtemp(prefix="hcs-mcp-", dir=os.path.join(HERE, "bench_data"))
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


def backup(src, store):
    w = hs.StoreWriter(store, codec=hs.BlockCodec(zstd_level=3), append=os.path.exists(store),
                       label=os.path.abspath(src))
    w.add_tree(src)
    w.close()


SRC, STORE = os.path.join(TMP, "src"), os.path.join(TMP, "s.hcs")
BIG = "".join(f"line {i} of the big file\n" for i in range(1, 20001)).encode()
V1 = {
    "README.md": b"# Demo\nThe secret word is Aardvark.\nsecond line\n",
    "src/app.py": b"import os\n\ndef main():\n    print('hello')\n\nmain()\n",
    "src/util/helpers.py": b"def helper():\n    return 42\n",
    "src/copy_of_app.py": b"import os\n\ndef main():\n    print('hello')\n\nmain()\n",
    "docs/big.txt": BIG,
    "docs/utf16.txt": "caf\u00e9 na\u00efve unicode needle\n".encode("utf-16"),
    "docs/crlf.txt": b"one\r\ntwo\r\nthree",
    "bin/blob.bin": bytes(range(256)) * 64,
    "bin/pic.png": b"\x89PNG\r\n\x1a\n" + bytes(200),
    "old/gone.txt": b"this file will be deleted\n",
    "empty.txt": b"",
    "long.txt": b"x" * 3000 + b" NEEDLE_IN_LONG_LINE " + b"y" * 3000 + b"\n",
}
tree(SRC, V1)
os.makedirs(os.path.join(SRC, "emptydir"))
backup(SRC, STORE)
tree(SRC, {"src/app.py": b"import os\n\ndef main():\n    print('goodbye')\n\nmain()\n",
           "src/new.py": b"NEW = True\n"})
os.remove(os.path.join(SRC, "old", "gone.txt"))
backup(SRC, STORE)
T = mcp.StoreTools({"s": STORE})


def call(name, **args):
    text, bad = mcp.call_tool(T, name, args)
    assert not bad, text
    return text


def fails(name, **args):
    text, bad = mcp.call_tool(T, name, args)
    assert bad, text
    return text


@check("list_snapshots shows both snapshots")
def _():
    t = call("list_snapshots")
    assert "2 snapshot(s)" in t and os.path.abspath(SRC) in t, t


@check("list_files: directory view, recursive, glob, paging, older snapshot")
def _():
    t = call("list_files")
    assert "src/" in t and "3 files" in t and "README.md" in t and "emptydir/" in t, t
    old = [l for l in t.splitlines() if l.endswith(" old/")]
    assert old and "0 files" in old[0], t                              # now an empty directory
    assert "gone.txt" in call("list_files", dir="old", snapshot=1)
    t = call("list_files", dir="src")
    assert "util/" in t and "app.py" in t and "helpers.py" not in t, t
    t = call("list_files", glob="*.py")
    assert "src/util/helpers.py" in t and "README.md" not in t, t
    t = call("list_files", recursive=True, limit=2)
    assert "showing 2 of" in t and "offset=2" in t, t
    assert "showing 2 of" in call("list_files", recursive=True, limit=2, offset=2)
    assert "no directory" in fails("list_files", dir="nope")


@check("read_file: text, paging, encodings, CRLF, empty, binary, bad path")
def _():
    t = call("read_file", path="src/app.py")
    assert "print('goodbye')" in t and "     1\timport os" in t and "(end of file, lines 1-6)" in t, t
    assert "print('hello')" in call("read_file", path="src\\app.py", snapshot=1)
    t = call("read_file", path="docs/big.txt", start_line=19990, max_lines=5)
    assert " 19990\tline 19990 of the big file" in t and "start_line=19995" in t and "19995\t" not in t, t
    t = call("read_file", path="docs/big.txt", max_lines=5000)
    assert len(t) <= mcp.MAX_OUT + 200 and "start_line=" in t, len(t)
    nxt = int(t.rsplit("start_line=", 1)[1])
    assert f"{nxt - 1:>6}\tline {nxt - 1} of" in t and f"line {nxt} of" not in t
    assert "fewer than 30000 lines" in call("read_file", path="docs/big.txt", start_line=30000)
    assert "caf\u00e9 na\u00efve unicode needle" in call("read_file", path="docs/utf16.txt")
    t = call("read_file", path="docs/crlf.txt")
    assert "\r" not in t and "     3\tthree" in t, repr(t)
    assert "(empty file)" in call("read_file", path="empty.txt")
    assert "binary file" in call("read_file", path="bin/blob.bin")
    assert "png file" in call("read_file", path="bin/pic.png")
    assert "did you mean: src/util/helpers.py" in fails("read_file", path="helpers.py")
    assert "is a directory" in fails("read_file", path="emptydir")
    assert "README.md" in call("read_file", path="readme.MD")          # unique case-insensitive match


@check("read_file cannot leave the store")
def _():
    for p in ("../../hybridstore.py", "C:/Windows/win.ini", os.path.join(HERE, "README.md"), "/etc/passwd"):
        assert "no file" in fails("read_file", path=p), p
    assert "unknown store" in fails("list_snapshots", store=os.path.join(HERE, "bench_data", "set0.hcs"))


@check("read_file pages inside a line longer than the output budget (minified / one-line files)")
def _():
    src, store = os.path.join(TMP, "oneline"), os.path.join(TMP, "oneline.hcs")
    body = "".join(f"<{i}>" for i in range(60_000))                    # ~400k characters, no newline
    tree(src, {"min.js": body.encode(), "two.txt": (body[:90_000] + "\nsecond line\n").encode()})
    backup(src, store)
    t2 = mcp.StoreTools({"o": store})
    got, line, char, calls = "", 1, 0, 0
    while True:
        text, bad = mcp.call_tool(t2, "read_file", {"path": "min.js", "start_line": line, "start_char": char})
        assert not bad, text
        calls += 1
        rows = text.split("\n")[1:]
        got += rows[0].split("\t", 1)[1]
        if "continues" not in rows[-1]:
            assert "end of file" in rows[-1], rows[-1]
            break
        nxt = rows[-1].split("start_line=")[1]
        line, char = int(nxt.split(",")[0]), int(nxt.split("start_char=")[1])
        assert calls < 100
    assert got == body and calls > 3, (len(got), calls)
    # after the long line is done, the next call moves on to line 2
    text, _ = mcp.call_tool(t2, "read_file", {"path": "two.txt", "start_line": 1, "start_char": 89_990})
    assert "second line" in text and "end of file" in text, text[-200:]


@check("search: literal, regex, case, glob, dir, context, dedup, utf-16, long lines, limits")
def _():
    t = call("search", pattern="aardvark")
    assert "README.md:2:The secret word is Aardvark." in t and "1 match(es)" in t, t
    assert "0 match(es)" in call("search", pattern="aardvark", case_sensitive=True)
    t = call("search", pattern=r"def \w+\(\)", regex=True, glob="*.py")
    assert "src/util/helpers.py:1:def helper():" in t and "src/app.py:3:" in t, t
    assert "0 match(es)" in call("search", pattern="def .+(", glob="*.py")       # literal, not regex
    assert "bad regular expression" in fails("search", pattern="(", regex=True)
    t = call("search", pattern="hello", snapshot=1)
    assert t.count(":4:") == 1 and "1 match(es)" in t, t                         # identical copy searched once
    t = call("search", pattern="return 42", context=1, dir="src")
    assert "src/util/helpers.py-1-def helper():" in t and "src/util/helpers.py:2:" in t, t
    assert "docs/utf16.txt:1:" in call("search", pattern="unicode needle")
    t = call("search", pattern="NEEDLE_IN_LONG_LINE")
    assert "NEEDLE_IN_LONG_LINE" in t and len(t) < 800, len(t)
    t = call("search", pattern="big file", max_results=7)
    assert "7 match(es)" in t and "stopped at 7 matches" in t, t[-200:]
    assert "0 match(es)" in call("search", pattern="\x00\x01\x02")               # binary files are skipped


@check("diff_snapshots: summary, one-file diff, deleted file, identical file")
def _():
    t = call("diff_snapshots")
    assert "1 added, 1 removed, 1 changed" in t and "A  src/new.py" in t, t
    assert "D  old/gone.txt" in t and "M  src/app.py" in t, t
    assert "0 added, 0 removed, 0 changed" in call("diff_snapshots", dir="docs")
    t = call("diff_snapshots", path="src/app.py")
    assert "-    print('hello')" in t and "+    print('goodbye')" in t, t
    t = call("diff_snapshots", path="old/gone.txt")
    assert "/dev/null" in t and "-this file will be deleted" in t, t
    assert "identical" in call("diff_snapshots", path="README.md")
    assert "binary file" in fails("diff_snapshots", path="bin/blob.bin", **{"from": 1, "to": 2})
    assert "does not exist" in fails("diff_snapshots", **{"from": 9})


@check("file_history: added, changed, unchanged, deleted")
def _():
    t = call("file_history", path="src/app.py")
    assert "  1  " in t and "added" in t and "changed" in t, t
    assert "deleted" in call("file_history", path="old/gone.txt")
    assert "unchanged" in call("file_history", path="README.md")
    assert "not in any snapshot" in fails("file_history", path="nope.txt")


@check("bad arguments are reported, never raised")
def _():
    assert "does not exist" in fails("read_file", path="README.md", snapshot=7)
    assert "does not exist" in fails("read_file", path="README.md", snapshot="1")
    assert "must be an integer" in fails("read_file", path="README.md", max_lines="ten")
    assert "path is required" in fails("read_file")
    assert "unknown tool" in mcp.call_tool(T, "unpack", {})[0]
    assert "unknown tool" in mcp.call_tool(T, "_open", {})[0]
    assert mcp.call_tool(T, "list_snapshots", None)[1] is False


def rpc(proc, obj):
    proc.stdin.write(json.dumps(obj).encode() + b"\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline()) if "id" in obj else None


@check("MCP stdio: initialize, tools/list, tools/call, errors; store is not held open")
def _():
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "hybridstore_mcp.py"), STORE],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        r = rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "0"}}})
        assert r["result"]["protocolVersion"] == "2025-03-26" and "tools" in r["result"]["capabilities"], r
        rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        r = rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in r["result"]["tools"]]
        assert names == ["list_snapshots", "list_files", "read_file", "search", "diff_snapshots",
                         "semantic_search", "file_history"], names
        assert all(t["inputSchema"]["type"] == "object" for t in r["result"]["tools"])
        r = rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "read_file", "arguments": {"path": "docs/utf16.txt"}}})
        assert r["result"]["isError"] is False and "caf\u00e9" in r["result"]["content"][0]["text"], r
        r = rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "read_file", "arguments": {"path": "missing"}}})
        assert r["result"]["isError"] is True, r
        r = rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "resources/list"})
        assert r["error"]["code"] == -32601, r
        proc.stdin.write(b"this is not json\n")
        proc.stdin.flush()
        assert json.loads(proc.stdout.readline())["error"]["code"] == -32700
        assert rpc(proc, {"jsonrpc": "2.0", "id": 6, "method": "ping"})["result"] == {}
        # The server is idle but still running: a prune (which replaces the
        # store file) must work, and the server must then see the new store.
        st = hs.prune(STORE, [1])
        assert st.removed == [1], st
        r = rpc(proc, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": {"name": "list_snapshots", "arguments": {}}})
        assert "1 snapshot(s)" in r["result"]["content"][0]["text"], r
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
        err = proc.stderr.read().decode(errors="replace")
        proc.stdout.close()
        proc.stderr.close()
    assert proc.returncode == 0 and not err.strip(), err


@check("command line: --call, --tools, missing store")
def _():
    exe = [sys.executable, os.path.join(HERE, "hybridstore_mcp.py")]
    p = subprocess.run(exe + [STORE, "--call", "search", json.dumps({"pattern": "Aardvark"})],
                       capture_output=True)
    assert p.returncode == 0 and b"README.md:2:" in p.stdout, p
    p = subprocess.run(exe + [STORE, "--call", "read_file", json.dumps({"path": "nope"})], capture_output=True)
    assert p.returncode == 1 and b"error:" in p.stdout, p
    p = subprocess.run(exe + ["--tools"], capture_output=True)
    assert p.returncode == 0 and len(json.loads(p.stdout)) == 7
    p = subprocess.run(exe + [os.path.join(TMP, "missing.hcs")], capture_output=True)
    assert p.returncode == 2 and b"store not found" in p.stderr, p


if __name__ == "__main__":
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\n{len(passed)} checks passed")
