#!/usr/bin/env python3
"""Semantic (meaning-based) search over a hybrid store, through a sidecar index.

    python hybridstore_semantic.py index  <store.hcs> [--snapshot N | --all] [--dir D] [--glob G]
    python hybridstore_semantic.py search <store.hcs> "how are corrupted blocks detected" [-k 10]
    python hybridstore_semantic.py status <store.hcs>
    python hybridstore_semantic.py gc     <store.hcs>      # drop entries no snapshot uses any more

The store itself is never modified: the index lives in <store>.sem (SQLite).

How it works
  * Text files are cut into passages of roughly 600-3000 characters. Cuts are
    made at line ends chosen by the content of the line (a hash), not by
    position, so an edit early in a file does not shift every later passage.
  * Each passage is keyed by the SHA-256 of its text and embedded once, with
    an embedding model served by Ollama (default bge-m3). Identical passages,
    in other files or other snapshots, reuse the same vector, so indexing a
    new snapshot only embeds what changed.
  * File content is keyed by the file's SHA-256 (from the manifest), so a
    file that is unchanged between snapshots is never re-read.
  * Search embeds the query, compares it with the vectors of the passages in
    the chosen snapshot (cosine similarity), and reads the best passages back
    from the store to show them with paths and line numbers.

Embedding server: $HYBRIDSTORE_EMBED_URL, else $OLLAMA_HOST, else
http://127.0.0.1:11434. Model: --model or $HYBRIDSTORE_EMBED_MODEL (bge-m3).
An index is tied to the model that built it.
"""
from __future__ import annotations

import argparse, fnmatch, hashlib, json, math, os, re, sqlite3, sys, time, urllib.error, urllib.request, zlib

import numpy as np

import hybridstore as hs

SCHEMA = 1
POOL, LEX_WEIGHT = 200, 0.25    # re-rank the best POOL passages: similarity + LEX_WEIGHT * word match
MIN_CHARS, TARGET_MASK, MAX_CHARS = 600, 7, 3000   # passage size: >= MIN, cut on hash & MASK == 0, <= MAX
MAX_FILE = 4 << 20                                 # default: skip text files larger than this
BATCH = 32
DEFAULT_MODEL = "bge-m3"


class SemanticError(Exception):
    pass


# ---------------------------------------------------------------- helpers

def sidecar_path(store: str) -> str:
    return store + ".sem"


def embed_url() -> str:
    url = os.environ.get("HYBRIDSTORE_EMBED_URL") or os.environ.get("OLLAMA_HOST") or "127.0.0.1:11434"
    if "://" not in url:
        url = "http://" + url
    return url.rstrip("/")


def embed(texts: list[str], model: str, url: str | None = None, timeout: int = 600,
          retries: int = 3) -> np.ndarray:
    """Unit-length float32 vectors for texts, from Ollama's /api/embed.
    Server-side failures (Ollama restarting its model runner, a busy GPU) are
    retried a few times; a missing model or an unreachable server is not."""
    body = json.dumps({"model": model, "input": texts, "keep_alive": "10m"}).encode()
    req = urllib.request.Request((url or embed_url()) + "/api/embed", body, {"Content-Type": "application/json"})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.load(r)
            break
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            if e.code == 404 or attempt == retries:
                raise SemanticError(f"embedding server error {e.code}: {detail}") from None
        except (urllib.error.URLError, OSError) as e:
            if isinstance(getattr(e, "reason", None), ConnectionRefusedError) or attempt == retries:
                raise SemanticError(f"cannot reach the embedding server at {url or embed_url()} ({e})") from None
        time.sleep(2 * 2 ** attempt)
    v = np.asarray(data.get("embeddings") or [], dtype=np.float32)
    if v.ndim != 2 or len(v) != len(texts):
        raise SemanticError("the embedding server returned an unexpected answer")
    n = np.linalg.norm(v, axis=1, keepdims=True)
    return v / np.where(n == 0, 1, n)


_WORD = re.compile(r"\w+")


def text_lines(r: hs.StoreReader, e: hs.FileEntry):
    """(encoding, line iterator) for a text file, or (None, None) for binary data.
    Line numbers match what the MCP server's read_file shows."""
    import hybridstore_mcp as m
    if e.size == 0:
        return None, None
    it = r.iter_file(e)
    first = next(it)
    enc = m._encoding(first)
    if enc is None:
        it.close()
        return None, None

    def chunks():
        yield first
        yield from it
    return enc, m._lines(chunks(), enc)


def passages(lines):
    """Split lines into content-defined passages: [(start_line, end_line, text)]."""
    out, buf, n, start = [], [], 0, 1
    for no, line in enumerate(lines, 1):
        if not buf:
            start = no
        while len(line) > MAX_CHARS:                    # one very long line: hard-split it
            if buf:
                out.append((start, no - 1 if no > start else no, "\n".join(buf)))
                buf, n, start = [], 0, no
            out.append((no, no, line[:MAX_CHARS]))
            line = line[MAX_CHARS:]
        buf.append(line)
        n += len(line) + 1
        if n >= MAX_CHARS or (n >= MIN_CHARS and zlib.crc32(line.strip().encode()) & TARGET_MASK == 0):
            out.append((start, no, "\n".join(buf)))
            buf, n = [], 0
    if buf and "".join(buf).strip():
        out.append((start, start + len(buf) - 1, "\n".join(buf)))
    return [p for p in out if p[2].strip()]


def _glob_ok(rel: str, glob: str | None) -> bool:
    return not glob or fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(rel.rsplit("/", 1)[-1], glob)


def select_files(snap: hs.Snapshot, d: str = "", glob: str | None = None) -> list[hs.FileEntry]:
    d = (d or "").replace("\\", "/").strip("/")
    pre = d + "/" if d else ""
    return [e for e in snap.files if e.path.startswith(pre) and _glob_ok(e.path[len(pre):], glob)]


# ---------------------------------------------------------------- sidecar

class Index:
    def __init__(self, store: str, create: bool = False, model: str | None = None, readonly: bool = False):
        self.path = sidecar_path(store)
        if not create and not os.path.exists(self.path):
            raise SemanticError(f"no semantic index for this store yet; build one with: "
                                f"hybridstore_semantic.py index {store}")
        if readonly:
            uri = "file:" + urllib.request.pathname2url(os.path.abspath(self.path)) + "?mode=ro"
            self.db = sqlite3.connect(uri, uri=True, timeout=30)
            meta = dict(self.db.execute("SELECT key, value FROM meta"))
            if int(meta.get("schema", 0)) != SCHEMA:
                raise SemanticError(f"{self.path} has an unknown index format")
            self.model, self.dim = meta["model"], int(meta["dim"])
            return
        self.db = sqlite3.connect(self.path, timeout=30)
        self.db.execute("PRAGMA journal_mode=DELETE")     # plain journal: read-only openers need no -shm
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS files (fsha BLOB PRIMARY KEY, status TEXT, n INTEGER);
            CREATE TABLE IF NOT EXISTS passages (fsha BLOB, idx INTEGER, start_line INTEGER,
                end_line INTEGER, phash BLOB, PRIMARY KEY (fsha, idx));
            CREATE TABLE IF NOT EXISTS vectors (phash BLOB PRIMARY KEY, vec BLOB);
            CREATE INDEX IF NOT EXISTS passages_phash ON passages (phash);
        """)
        meta = dict(self.db.execute("SELECT key, value FROM meta"))
        if not meta:
            self.model, self.dim = model or os.environ.get("HYBRIDSTORE_EMBED_MODEL") or DEFAULT_MODEL, 0
            self.db.executemany("INSERT INTO meta VALUES (?, ?)",
                                [("schema", str(SCHEMA)), ("model", self.model), ("dim", "0")])
            self.db.commit()
        else:
            if int(meta.get("schema", 0)) != SCHEMA:
                raise SemanticError(f"{self.path} has an unknown index format; delete it and index again")
            self.model, self.dim = meta["model"], int(meta["dim"])
            if model and model != self.model:
                raise SemanticError(f"this index was built with {self.model!r}, not {model!r}; "
                                    f"delete {self.path} to rebuild it with another model")

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _set_dim(self, dim: int):
        if self.dim == 0:
            self.dim = dim
            self.db.execute("UPDATE meta SET value = ? WHERE key = 'dim'", (str(dim),))
        elif dim != self.dim:
            raise SemanticError(f"the model now returns {dim}-dim vectors, the index has {self.dim}")

    def file_status(self, fshas) -> dict[bytes, str]:
        out = {}
        fshas = list(fshas)
        for i in range(0, len(fshas), 500):
            part = fshas[i:i + 500]
            q = f"SELECT fsha, status FROM files WHERE fsha IN ({','.join('?' * len(part))})"
            out.update(self.db.execute(q, part))
        return out

    # ---- building ----
    def build(self, r: hs.StoreReader, snaps: list[hs.Snapshot], d: str = "", glob: str | None = None,
              max_file: int = MAX_FILE, url: str | None = None, log=print) -> dict:
        todo, seen = [], set()
        for s in snaps:
            for e in select_files(s, d, glob):
                if e.sha256 not in seen:
                    seen.add(e.sha256)
                    todo.append(e)
        known = self.file_status(e.sha256 for e in todo)
        todo = [e for e in todo if e.sha256 not in known]
        st = {"files_seen": len(seen), "files_done_before": len(known), "files_indexed": 0, "binary": 0,
              "too_large": 0, "passages": 0, "embedded": 0, "reused": 0, "seconds": 0.0}
        t0, last = time.monotonic(), 0.0
        pending: dict[bytes, str] = {}              # phash -> text, waiting for a vector
        rows: list[tuple] = []                      # passages rows for files whose vectors are pending
        files: list[tuple] = []

        def flush():
            if pending:
                keys = list(pending)
                for i in range(0, len(keys), BATCH):
                    part = keys[i:i + BATCH]
                    vec = embed([pending[k] for k in part], self.model, url)
                    self._set_dim(vec.shape[1])
                    self.db.executemany("INSERT OR IGNORE INTO vectors VALUES (?, ?)",
                                        [(k, v.astype(np.float16).tobytes()) for k, v in zip(part, vec)])
                    st["embedded"] += len(part)
                pending.clear()
            self.db.executemany("INSERT OR REPLACE INTO passages VALUES (?, ?, ?, ?, ?)", rows)
            self.db.executemany("INSERT OR REPLACE INTO files VALUES (?, ?, ?)", files)
            self.db.commit()                        # a file counts as done only with all its vectors
            rows.clear()
            files.clear()

        for k, e in enumerate(todo, 1):
            if e.size == 0:
                files.append((e.sha256, "empty", 0))
            elif e.size > max_file:
                files.append((e.sha256, "too_large", 0))
                st["too_large"] += 1
            else:
                enc, lines = text_lines(r, e)
                if enc is None:
                    files.append((e.sha256, "binary", 0))
                    st["binary"] += 1
                else:
                    ps = passages(lines)
                    for i, (a, b, text) in enumerate(ps):
                        ph = hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()
                        rows.append((e.sha256, i, a, b, ph))
                        if ph not in pending:
                            if self.db.execute("SELECT 1 FROM vectors WHERE phash = ?", (ph,)).fetchone():
                                st["reused"] += 1
                            else:
                                pending[ph] = text
                    files.append((e.sha256, "ok", len(ps)))
                    st["files_indexed"] += 1
                    st["passages"] += len(ps)
            if len(pending) >= 256 or len(files) >= 500:
                flush()
            now = time.monotonic()
            if log and now - last > 10:
                last = now
                log(f"  {k:,}/{len(todo):,} files, {st['embedded']:,} passages embedded, "
                    f"{now - t0:.0f} s")
        flush()
        st["seconds"] = round(time.monotonic() - t0, 1)
        return st

    # ---- searching ----
    def search(self, r: hs.StoreReader, snap: hs.Snapshot, query: str, k: int = 10, d: str = "",
               glob: str | None = None, url: str | None = None, rerank: bool = True
               ) -> tuple[list[dict], dict]:
        """Best k passages. With rerank, the POOL most similar passages are read back from
        the store and re-ordered by similarity + LEX_WEIGHT * word match with the query, which
        separates near-identical passages (sibling modules, tables of numbers)."""
        files = select_files(snap, d, glob)
        by_sha: dict[bytes, list[hs.FileEntry]] = {}
        for e in files:
            by_sha.setdefault(e.sha256, []).append(e)
        status = self.file_status(by_sha)
        cover = {"files": len(files), "indexed": sum(1 for e in files if status.get(e.sha256) == "ok"),
                 "skipped": sum(1 for e in files if status.get(e.sha256) in ("binary", "too_large", "empty")),
                 "not_indexed": sum(1 for e in files if e.sha256 not in status)}
        ok = [s for s, v in status.items() if v == "ok"]
        prow: list[tuple] = []
        for i in range(0, len(ok), 500):
            part = ok[i:i + 500]
            prow += self.db.execute(
                f"SELECT p.fsha, p.start_line, p.end_line, v.vec FROM passages p JOIN vectors v "
                f"ON v.phash = p.phash WHERE p.fsha IN ({','.join('?' * len(part))})", part).fetchall()
        if not prow or not query.strip():
            return [], cover
        q = embed([query], self.model, url)[0]
        mat = np.frombuffer(b"".join(row[3] for row in prow), dtype=np.float16).reshape(len(prow), -1)
        if mat.shape[1] != q.shape[0]:
            raise SemanticError(f"query vector has {q.shape[0]} dims, the index {mat.shape[1]}; "
                                f"is the embedding server running a different model?")
        score = mat.astype(np.float32) @ q
        order = np.argsort(-score)
        lex: dict[int, float] = {}
        if rerank:
            pool = [int(i) for i in order[:max(POOL, 5 * k)]]
            lex = self._word_match(r, query, [(i, prow[i][0], prow[i][1], prow[i][2]) for i in pool], by_sha)
            pool.sort(key=lambda i: -(float(score[i]) + LEX_WEIGHT * lex[i]))
            order = pool
        hits, used = [], set()
        for i in order:
            fsha, a, b, _ = prow[i]
            for e in by_sha[fsha]:                  # one content can live at several paths
                key = (e.path, a)
                if key in used:
                    continue
                used.add(key)
                hits.append({"path": e.path, "start": a, "end": b, "score": float(score[i]),
                             "words": lex.get(i), "entry": e})
            if len(hits) >= k:
                break
        return hits[:k], cover

    @staticmethod
    def _word_match(r, query: str, cand: list[tuple], by_sha: dict) -> dict[int, float]:
        """{candidate id: 0..1}: how much of the query's words and word pairs each candidate
        passage holds; words that are rare among the candidates count for more."""
        want: dict[bytes, list[tuple]] = {}
        for cid, fsha, a, b in cand:
            want.setdefault(fsha, []).append((cid, a, b))
        text: dict[int, list[str]] = {cid: [] for cid, *_ in cand}
        for fsha, spans in want.items():
            enc, lines = text_lines(r, by_sha[fsha][0])
            if enc is None:
                continue
            last = max(b for _, _, b in spans)
            for no, line in enumerate(lines, 1):
                if no > last:
                    lines.close()
                    break
                for cid, a, b in spans:
                    if a <= no <= b:
                        text[cid].append(line)

        def terms(t: str) -> set:
            w = _WORD.findall(t.lower())
            return set(w) | set(zip(w, w[1:]))
        qt = terms(query)
        if not qt:
            return {cid: 0.0 for cid in text}
        have = {cid: terms(chr(10).join(ls)) & qt for cid, ls in text.items()}
        n = len(have)
        idf = {t: math.log(1 + n / (1 + sum(1 for h in have.values() if t in h))) for t in qt}
        total = sum(idf.values())
        return {cid: sum(idf[t] for t in h) / total for cid, h in have.items()}

    def gc(self, r: hs.StoreReader) -> dict:
        live = {e.sha256 for s in r.snapshots for e in s.files}
        dead = [f for (f,) in self.db.execute("SELECT fsha FROM files") if f not in live]
        for i in range(0, len(dead), 500):
            part = dead[i:i + 500]
            ph = ",".join("?" * len(part))
            self.db.execute(f"DELETE FROM passages WHERE fsha IN ({ph})", part)
            self.db.execute(f"DELETE FROM files WHERE fsha IN ({ph})", part)
        cur = self.db.execute("DELETE FROM vectors WHERE phash NOT IN (SELECT phash FROM passages)")
        self.db.commit()
        self.db.execute("VACUUM")
        return {"files_removed": len(dead), "vectors_removed": cur.rowcount}

    def stats(self) -> dict:
        q = lambda sql: self.db.execute(sql).fetchone()[0]
        return {"model": self.model, "dim": self.dim, "files": q("SELECT COUNT(*) FROM files"),
                "text_files": q("SELECT COUNT(*) FROM files WHERE status = 'ok'"),
                "passages": q("SELECT COUNT(*) FROM passages"), "vectors": q("SELECT COUNT(*) FROM vectors"),
                "size": os.path.getsize(self.path)}


def snippet(r: hs.StoreReader, e: hs.FileEntry, a: int, b: int, max_lines: int = 12, max_chars: int = 1200):
    enc, lines = text_lines(r, e)
    if enc is None:
        return ""
    out, n = [], 0
    for no, line in enumerate(lines, 1):
        if no < a:
            continue
        if no > b or len(out) >= max_lines or n > max_chars:
            break
        line = line if len(line) <= 300 else line[:300] + "…"
        out.append(f"{no:>6}\t{line}")
        n += len(line)
    if b - a + 1 > len(out):
        out.append(f"        … passage continues to line {b}")
    return "\n".join(out)


def format_hits(r, n, snap, query, hits, cover, model) -> str:
    out = [f"snapshot {n}: {len(hits)} passage(s) most similar in meaning to {query!r} "
           f"(model {model}; {cover['indexed']} of {cover['files']} files in scope are indexed"
           + (f", {cover['not_indexed']} not indexed yet" if cover["not_indexed"] else "") + ")"]
    for i, h in enumerate(hits, 1):
        out.append(f"\n[{i}] {h['path']}  lines {h['start']}-{h['end']}  similarity {h['score']:.3f}"
                   + (f"  word match {h['words']:.0%}" if h.get("words") is not None else ""))
        out.append(snippet(r, h["entry"], h["start"], h["end"]))
    if not hits:
        out.append("no indexed text in scope" if cover["indexed"] == 0 else "no results")
    return "\n".join(out)


# ---------------------------------------------------------------- CLI

def main(argv) -> int:
    ap = argparse.ArgumentParser(prog="hybridstore_semantic", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("index", help="embed the text of a snapshot (only what is not indexed yet)")
    p.add_argument("store")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--snapshot", type=int, default=None, help="snapshot number (default: newest)")
    g.add_argument("--all", action="store_true", help="every snapshot")
    p.add_argument("--dir", default="", help="only files under this directory")
    p.add_argument("--glob", default=None, help="only files matching, e.g. *.py")
    p.add_argument("--max-file-mb", type=float, default=MAX_FILE / (1 << 20))
    p.add_argument("--model", default=None, help=f"embedding model (default {DEFAULT_MODEL}; fixed per index)")
    p.add_argument("--allow-plaintext-index", action="store_true",
                   help="index an ENCRYPTED store anyway: the sidecar is not encrypted, and file hashes and "
                        "embedding vectors (which can be partly inverted to text) would be readable")
    p = sub.add_parser("search", help="find passages by meaning")
    p.add_argument("store"); p.add_argument("query")
    p.add_argument("-k", type=int, default=10)
    p.add_argument("--snapshot", type=int, default=None)
    p.add_argument("--dir", default=""); p.add_argument("--glob", default=None)
    p.add_argument("--no-rerank", action="store_true", help="order by similarity alone (no word match)")
    p = sub.add_parser("status", help="show what the index holds and covers")
    p.add_argument("store")
    p = sub.add_parser("gc", help="drop index entries for files no snapshot contains any more")
    p.add_argument("store")
    a = ap.parse_args(argv)
    try:
        with hs.StoreReader(a.store) as r:
            if a.cmd == "index":
                if r.encrypted and not a.allow_plaintext_index:
                    raise SemanticError(f"{a.store} is encrypted but {a.store}.sem would not be: it holds "
                                        f"file hashes and embeddings, which leak content. Pass "
                                        f"--allow-plaintext-index to index anyway")
                snaps = r.snapshots if a.all else [r.snapshots[(a.snapshot or len(r.snapshots)) - 1]] \
                    if 1 <= (a.snapshot or len(r.snapshots)) <= len(r.snapshots) else None
                if snaps is None:
                    raise SemanticError(f"snapshot {a.snapshot} does not exist (1..{len(r.snapshots)})")
                with Index(a.store, create=True, model=a.model) as ix:
                    print(f"indexing with {ix.model} at {embed_url()} into {ix.path}")
                    st = ix.build(r, snaps, a.dir, a.glob, int(a.max_file_mb * (1 << 20)))
                    print(f"done in {st['seconds']} s: {st['files_indexed']:,} text files indexed "
                          f"({st['files_done_before']:,} already done), {st['binary']:,} binary, "
                          f"{st['too_large']:,} too large; {st['passages']:,} passages, "
                          f"{st['embedded']:,} embedded, {st['reused']:,} reused from the index")
            elif a.cmd == "search":
                n = a.snapshot or len(r.snapshots)
                if not 1 <= n <= len(r.snapshots):
                    raise SemanticError(f"snapshot {n} does not exist (1..{len(r.snapshots)})")
                with Index(a.store) as ix:
                    hits, cover = ix.search(r, r.snapshots[n - 1], a.query, a.k, a.dir, a.glob,
                                            rerank=not a.no_rerank)
                    sys.stdout.buffer.write(format_hits(r, n, r.snapshots[n - 1], a.query, hits, cover,
                                                        ix.model).encode("utf-8", "replace") + b"\n")
            elif a.cmd == "status":
                with Index(a.store) as ix:
                    s = ix.stats()
                    print(f"{ix.path}: model {s['model']} ({s['dim']} dims), {s['text_files']:,} text files "
                          f"of {s['files']:,} seen, {s['passages']:,} passages, {s['vectors']:,} unique "
                          f"vectors, {s['size'] / 1e6:.1f} MB")
                    for i, snap in enumerate(r.snapshots, 1):
                        stt = ix.file_status(e.sha256 for e in snap.files)
                        todo = sum(1 for e in snap.files if e.sha256 not in stt)
                        print(f"  snapshot {i}: {len(snap.files) - todo:,} of {len(snap.files):,} files indexed")
            else:
                with Index(a.store) as ix:
                    print(ix.gc(r))
        return 0
    except (SemanticError, hs.IntegrityError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
