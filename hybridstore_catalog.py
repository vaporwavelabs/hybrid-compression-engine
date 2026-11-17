#!/usr/bin/env python3
"""Catalog: a rebuildable index next to a store (<store>.cat, SQLite) that lets
agents and tools find things without decoding the store.

    python hybridstore.py catalog <store>             # build / bring up to date
    python hybridstore.py catalog <store> --rebuild   # start again from the store

`backup`, `pack` and `prune` keep it up to date automatically.

What it holds:

* every snapshot's entries as runs: (path, content, size, mtime, kind) and the
  first..last snapshot in which that exact version is present, so "which
  snapshots have a file like X" needs no manifest;
* for every distinct text content (by SHA-256, so a file kept unchanged in 50
  snapshots is indexed once): a substring index (SQLite FTS5, trigram,
  contentless) over passages of up to 64 KB of lines.

The store stays the only source of truth. The catalog is derived data: it
records which snapshots (by manifest offset) it covers and is used for a
snapshot only when that matches the store exactly. A catalog that is behind is
brought up to date; one that no longer matches (the store was pruned or
replaced) has its snapshot list rebuilt, while indexed contents, keyed by
their SHA-256, stay valid. A damaged catalog file is set aside and rebuilt.

Exactness: the substring index only narrows which files are read. Text is
indexed after the same case folding Python's re.IGNORECASE uses, so every file
that can match a literal search is a candidate; the candidates are then
searched line by line exactly as before. Results are identical to a full scan.

Encrypted stores get no catalog: it would keep searchable data derived from
the plaintext next to the store, unencrypted.
"""
from __future__ import annotations

import _sre
import fnmatch, os, sqlite3, time
from re import _casefix

import hybridstore as hs

VERSION = 1
SUFFIX = ".cat"
MAX_FILE = 32 << 20             # larger files are not indexed (the search tool's default limit)
PASSAGE_CHARS = 64 << 10        # one index row per this many characters of whole lines
MAX_GRAMS = 48                  # trigrams used to narrow one query (more only narrows further)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS snapshots(num INTEGER PRIMARY KEY, moff INTEGER NOT NULL, created INTEGER,
                                     label TEXT, damaged INTEGER);
CREATE TABLE IF NOT EXISTS contents(fsha BLOB PRIMARY KEY, size INTEGER, status TEXT, passages INTEGER);
CREATE TABLE IF NOT EXISTS passages(id INTEGER PRIMARY KEY, fsha BLOB, start_line INTEGER, end_line INTEGER);
CREATE INDEX IF NOT EXISTS passages_fsha ON passages(fsha);
CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(text, tokenize='trigram', content='', detail='none');
CREATE TABLE IF NOT EXISTS versions(path TEXT, fsha BLOB, size INTEGER, mtime_ns INTEGER, kind INTEGER,
                                    first INTEGER, last INTEGER);
CREATE INDEX IF NOT EXISTS versions_path ON versions(path);
CREATE INDEX IF NOT EXISTS versions_last ON versions(last);
"""


class CatalogError(Exception):
    pass


def catalog_path(store: str) -> str:
    return store + SUFFIX


# ---------------------------------------------------------------- case folding

_FOLD: dict | None = None


def _fold_table() -> dict:
    """Characters that str.lower() does not map to their re.IGNORECASE class
    representative (multi-character lowercases such as U+0130, and the extra
    equivalences re knows, such as long s and s)."""
    global _FOLD
    if _FOLD is None:
        extra, t = _casefix._EXTRA_CASES, {}
        for cp in range(0x110000):
            if 0xD800 <= cp <= 0xDFFF:
                continue
            low = _sre.unicode_tolower(cp)
            rep = min((low, *extra.get(low, ())))
            if chr(cp).lower() != chr(rep):
                t[cp] = rep
        _FOLD = t
    return _FOLD


def fold(s: str) -> str:
    """Two strings that re.IGNORECASE matches character by character fold to
    the same string."""
    return s.translate(_fold_table()).lower()


def _grams(pattern: str) -> list[str] | None:
    f = fold(pattern)
    g = list(dict.fromkeys(f[i:i + 3] for i in range(len(f) - 2)))
    return g or None


# ---------------------------------------------------------------- text, as the search tool sees it

def _text_passages(r: hs.StoreReader, e: hs.FileEntry):
    """(status, [(start_line, end_line, text)]) for one file, decoded exactly
    as the MCP search tool decodes it."""
    from hybridstore_mcp import _encoding, _lines
    if e.size == 0:
        return "empty", []
    if e.size > MAX_FILE:
        return "too_large", []
    try:
        it = r.iter_file(e)
        first = next(it)
        enc = _encoding(first)
        if enc is None:
            return "binary", []

        def chunks():
            yield first
            yield from it

        out, buf, n, start, no = [], [], 0, 1, 0
        for no, line in enumerate(_lines(chunks(), enc), 1):
            buf.append(line)
            n += len(line) + 1
            if n >= PASSAGE_CHARS:
                out.append((start, no, "\n".join(buf)))
                buf, n, start = [], 0, no + 1
        if buf:
            out.append((start, no, "\n".join(buf)))
        return "text", out
    except hs.IntegrityError:
        return "unreadable", []


# ---------------------------------------------------------------- the catalog

class Catalog:
    def __init__(self, store: str, readonly: bool = False):
        self.store, self.path, self.readonly = store, catalog_path(store), readonly
        if readonly:
            if not os.path.exists(self.path):
                raise CatalogError("no catalog")
            self.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        else:
            self.db = self._open_rw()

    def _open_rw(self):
        db = None
        try:
            db = sqlite3.connect(self.path)
            db.executescript(SCHEMA)
            v = db.execute("SELECT v FROM meta WHERE k='version'").fetchone()
            if v is None:
                db.execute("INSERT INTO meta VALUES ('version', ?)", (str(VERSION),))
                db.commit()
            elif v[0] != str(VERSION):
                raise sqlite3.DatabaseError(f"catalog version {v[0]}")
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise sqlite3.DatabaseError("quick_check failed")
            return db
        except sqlite3.DatabaseError:
            if db is not None:
                db.close()
            aside = f"{self.path}.bad-{time.strftime('%Y%m%d-%H%M%S')}"
            os.replace(self.path, aside)            # derived data: set aside, start again
            self.set_aside = aside
            db = sqlite3.connect(self.path)
            db.executescript(SCHEMA)
            db.execute("INSERT INTO meta VALUES ('version', ?)", (str(VERSION),))
            db.commit()
            return db

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- state ----
    def indexed(self) -> list[int]:
        """Manifest offsets of the snapshots covered, in order."""
        return [m for (m,) in self.db.execute("SELECT moff FROM snapshots ORDER BY num")]

    def covers(self, r: hs.StoreReader, n: int) -> bool:
        """True when snapshot n of this store (1-based) is in the catalog as it is now."""
        have = self.indexed()
        if len(have) < n:
            return False
        return all(have[i] == r.snapshots[i].offset for i in range(n))

    def status(self, r: hs.StoreReader) -> str:
        have = self.indexed()
        want = [s.offset for s in r.snapshots]
        if have == want:
            return "current"
        if want[:len(have)] == have:
            return f"behind: {len(want) - len(have)} newer snapshot(s) not indexed"
        return "does not match the store (pruned or replaced since); its snapshot list will be rebuilt"

    # ---- building ----
    def update(self, r: hs.StoreReader, rebuild: bool = False, log=None) -> dict:
        if self.readonly:
            raise CatalogError("opened read-only")
        if r.encrypted:
            raise CatalogError("the store is encrypted; a catalog would keep searchable data derived from its "
                               "contents next to it, unencrypted, so none is built")
        t0 = time.monotonic()
        st = {"snapshots_added": 0, "contents_indexed": 0, "text": 0, "bytes_read": 0, "reset": False}
        have, want = self.indexed(), [s.offset for s in r.snapshots]
        if rebuild:
            self.db.executescript("DELETE FROM snapshots; DELETE FROM versions; DELETE FROM contents; "
                                  "DELETE FROM passages; DROP TABLE fts;")
            self.db.executescript(SCHEMA)
            have, st["reset"] = [], True
        elif want[:len(have)] != have:
            self.db.executescript("DELETE FROM snapshots; DELETE FROM versions;")
            have, st["reset"] = [], True
        self.db.commit()
        for num in range(len(have) + 1, len(want) + 1):
            s = r.snapshots[num - 1]
            if not s.damaged:
                self._index_contents(r, s, st, log)
            self._add_versions(num, s)
            self.db.execute("INSERT INTO snapshots VALUES (?, ?, ?, ?, ?)",
                            (num, s.offset, s.created, s.label, int(bool(s.damaged))))
            self.db.commit()                       # a snapshot counts only with all its contents and versions
            st["snapshots_added"] += 1
        st["seconds"] = time.monotonic() - t0
        return st

    def _index_contents(self, r, s, st, log):
        todo, seen = [], set()
        for e in s.files:
            if e.sha256 not in seen:
                seen.add(e.sha256)
                todo.append(e)
        known = self.status_map([e.sha256 for e in todo])
        todo = [e for e in todo if e.sha256 not in known]
        last, batch = time.monotonic(), 0
        for e in todo:
            status, ps = _text_passages(r, e)
            if status == "text":
                st["text"] += 1
                st["bytes_read"] += e.size
            for a, b, text in ps:
                cur = self.db.execute("INSERT INTO passages(fsha, start_line, end_line) VALUES (?, ?, ?)",
                                      (e.sha256, a, b))
                self.db.execute("INSERT INTO fts(rowid, text) VALUES (?, ?)", (cur.lastrowid, fold(text)))
            self.db.execute("INSERT INTO contents VALUES (?, ?, ?, ?)", (e.sha256, e.size, status, len(ps)))
            st["contents_indexed"] += 1
            batch += e.size
            if batch > 64 << 20:
                self.db.commit()                   # a content row is committed with all its passages
                batch = 0
            if log and time.monotonic() - last > 10:
                last = time.monotonic()
                log(f"  catalog: {st['contents_indexed']:,} of {len(todo):,} new file contents indexed")

    def _add_versions(self, num, s):
        prev = {p: (rid, f, sz, mt, k) for rid, p, f, sz, mt, k in self.db.execute(
            "SELECT rowid, path, fsha, size, mtime_ns, kind FROM versions WHERE last = ?", (num - 1,))}
        extend, new = [], []
        for e in s.entries:
            row = prev.get(e.path)
            if row and row[1:] == (e.sha256, e.size, e.mtime_ns, e.kind):
                extend.append((num, row[0]))
            else:
                new.append((e.path, e.sha256, e.size, e.mtime_ns, e.kind, num, num))
        self.db.executemany("UPDATE versions SET last = ? WHERE rowid = ?", extend)
        self.db.executemany("INSERT INTO versions VALUES (?, ?, ?, ?, ?, ?, ?)", new)

    # ---- queries ----
    def status_map(self, shas) -> dict[bytes, str]:
        out, shas = {}, list(shas)
        for i in range(0, len(shas), 500):
            part = shas[i:i + 500]
            out.update(self.db.execute(
                f"SELECT fsha, status FROM contents WHERE fsha IN ({','.join('?' * len(part))})", part))
        return out

    def candidates(self, pattern: str) -> set[bytes] | None:
        """Contents whose text may contain `pattern` in any letter case. None:
        the pattern is too short (under 3 characters) for the index to narrow."""
        grams = _grams(pattern)
        if grams is None:
            return None
        q = " AND ".join('"' + g.replace('"', '""') + '"' for g in grams[:MAX_GRAMS])
        return {f for (f,) in self.db.execute(
            "SELECT DISTINCT p.fsha FROM fts JOIN passages p ON p.id = fts.rowid WHERE fts MATCH ?", (q,))}

    def find(self, pattern: str = "", glob: str | None = None, limit: int = 200) -> list[tuple]:
        """Path versions across all indexed snapshots: (path, size, mtime_ns, kind, first, last, fsha).
        pattern: case-insensitive substring of the path; glob: fnmatch on the path or its name."""
        rows = self.db.execute("SELECT path, size, mtime_ns, kind, first, last, fsha FROM versions "
                               "ORDER BY path, first")
        return path_filter(rows, pattern, glob, limit)

    def stats(self) -> dict:
        q = lambda sql: self.db.execute(sql).fetchone()[0]
        return {"snapshots": q("SELECT count(*) FROM snapshots"),
                "versions": q("SELECT count(*) FROM versions"),
                "contents": q("SELECT count(*) FROM contents"),
                "text_contents": q("SELECT count(*) FROM contents WHERE status='text'"),
                "passages": q("SELECT count(*) FROM passages"),
                "bytes": os.path.getsize(self.path)}


def path_filter(rows, pattern: str, glob: str | None, limit: int) -> list[tuple]:
    """Rows whose path holds `pattern` (any case) and matches `glob` (on the path or its name)."""
    want, out = pattern.lower(), []
    for row in rows:
        p = row[0]
        if want and want not in p.lower():
            continue
        if glob and not (fnmatch.fnmatch(p, glob) or fnmatch.fnmatch(p.rsplit("/", 1)[-1], glob)):
            continue
        out.append(row)
        if len(out) >= limit:
            break
    return out


def version_runs(r: hs.StoreReader) -> list[tuple]:
    """The catalog's versions, worked out from the manifests: (path, size,
    mtime_ns, kind, first, last, fsha) sorted by path, first."""
    runs, open_ = [], {}
    for num, s in enumerate(r.snapshots, 1):
        cur = {}
        for e in s.entries:
            row = open_.get(e.path)
            if row and (row[6], row[1], row[2], row[3]) == (e.sha256, e.size, e.mtime_ns, e.kind):
                row[5] = num
            else:
                row = [e.path, e.size, e.mtime_ns, e.kind, num, num, e.sha256]
                runs.append(row)
            cur[e.path] = row
        open_ = cur
    return sorted((tuple(x) for x in runs), key=lambda x: (x[0], x[4]))


def update_store(store: str, r: hs.StoreReader | None = None, rebuild: bool = False, log=None) -> dict:
    """Bring <store>.cat up to date (creating it), under its own lock so two
    updates never interleave. Raises CatalogError for an encrypted store and
    hs.StoreLockedError when another update is running."""
    lock = hs._StoreLock(catalog_path(store))
    try:
        own = r is None
        r = r or hs.StoreReader(store)
        try:
            if r.encrypted:                      # before the catalog file is even created
                raise CatalogError("the store is encrypted; a catalog would keep searchable data derived from "
                                   "its contents next to it, unencrypted, so none is built")
            with Catalog(store) as c:
                st = c.update(r, rebuild=rebuild, log=log)
                st.update(c.stats())
                st["set_aside"] = getattr(c, "set_aside", None)
                return st
        finally:
            if own:
                r.close()
    finally:
        lock.release()


def summary(st: dict) -> str:
    s = (f"catalog: {st['snapshots_added']} snapshot(s) added, {st['contents_indexed']:,} new file content(s) indexed "
         f"({st['text']:,} text, {st['bytes_read'] / 1e6:.1f} MB read) in {st['seconds']:.1f}s; now "
         f"{st['contents']:,} contents, {st['text_contents']:,} text, {st['passages']:,} passages, "
         f"{st['bytes'] / 1e6:.1f} MB")
    if st.get("reset"):
        s += "; snapshot list rebuilt (the store had changed)"
    if st.get("set_aside"):
        s += f"; the old catalog was damaged and set aside as {st['set_aside']}"
    return s
