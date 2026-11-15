#!/usr/bin/env python3
"""Score how faithfully the LLM tools reproduce the original data.

    python llm_accuracy.py <store.hcs> [--source DIR] [--snapshot N] [--samples 100] [--json out.json]

Compares what the tools return from the compressed store ("post-compress")
with the original files on disk ("pre-compress"):

  1. bytes      every file read from the store vs. the file on disk (size + SHA-256 + bytes)
  2. read_file  every line the MCP read_file tool returns (paging through whole files)
                vs. the lines of the original file
  3. search     the MCP search tool vs. a plain grep of the original files, for
                random words and a few regular expressions (same rules: case-insensitive,
                identical files searched once)
  4. semantic   if the store has a semantic index:
                a) snippet fidelity: every line shown in a result equals the original line
                b) retrieval: a 3-line excerpt from a random indexed passage is used as the
                   query; is that passage ranked 1st / in the top 5?

Files that changed on disk after the backup (different size or mtime) are
reported separately, not counted as errors. The store is only read.
"""
from __future__ import annotations

import argparse, codecs, hashlib, json, os, random, re, sys, time

import hybridstore as hs
import hybridstore_mcp as mcp

LINE_RE = re.compile(r"^ *(\d+)\t(.*)$", re.S)


def orig_lines(data: bytes, enc: str) -> list[str]:
    """Lines of a file the way a reader expects them: split on \\n, \\r\\n stripped."""
    text = data.decode(enc, errors="replace")
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    return [p.rstrip("\r") for p in parts]


def tool(tools, name, **args):
    text, bad = mcp.call_tool(tools, name, args)
    if bad:
        raise RuntimeError(text)
    return text


def pct(a, b):
    return f"{100.0 * a / b:.3f}%" if b else "n/a"


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("store")
    ap.add_argument("--source", help="original folder (default: the snapshot's recorded source)")
    ap.add_argument("--snapshot", type=int, default=None)
    ap.add_argument("--no-rerank", action="store_true", help="semantic: similarity order only")
    ap.add_argument("--samples", type=int, default=100, help="search patterns / semantic queries")
    ap.add_argument("--max-file-mb", type=float, default=4)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--json", help="also write the results as JSON here")
    a = ap.parse_args(argv)
    rng = random.Random(a.seed)
    tools = mcp.StoreTools({"s": a.store})
    res: dict = {}

    with hs.StoreReader(a.store) as r:
        n = a.snapshot or len(r.snapshots)
        snap = r.snapshots[n - 1]
        src = a.source or snap.label
        print(f"store {a.store}, snapshot {n} ({len(snap.files):,} files), original folder {src}\n")

        # ---------------------------------------------------------- 1. bytes
        t0 = time.time()
        same = changed = missing = bad = 0
        total_bytes = 0
        text_files: list[tuple[hs.FileEntry, str, bytes]] = []
        bad_list = []
        for e in snap.files:
            p = os.path.join(src, *e.path.split("/"))
            try:
                st = os.stat(p)
                with open(p, "rb") as f:
                    disk = f.read()
            except OSError:
                missing += 1
                continue
            if st.st_size != e.size or (e.mtime_ns >= 0 and st.st_mtime_ns != e.mtime_ns):
                changed += 1
                continue
            stored = r.read_file(e)
            if stored == disk and hashlib.sha256(disk).digest() == e.sha256:
                same += 1
                total_bytes += len(disk)
                enc = mcp._encoding(disk[:mcp.SNIFF]) if disk else None
                if enc and len(disk) <= a.max_file_mb * (1 << 20):
                    text_files.append((e, enc, disk))
            else:
                bad += 1
                bad_list.append(e.path)
        compared = same + bad
        res["bytes"] = {"compared": compared, "identical": same, "different": bad, "bytes": total_bytes,
                        "changed_on_disk_since_backup": changed, "missing_on_disk": missing,
                        "score": same / compared if compared else None, "different_files": bad_list[:20]}
        print(f"1. bytes      {same:,}/{compared:,} files byte-identical ({pct(same, compared)}), "
              f"{total_bytes / 1e6:.1f} MB compared  [{time.time() - t0:.1f} s]")
        if changed or missing:
            print(f"              not compared: {changed} changed on disk since the backup, {missing} missing")
        for pth in bad_list[:5]:
            print(f"              DIFFERENT: {pth}")

        # ---------------------------------------------------------- 2. read_file
        t0 = time.time()
        lines_ok = lines_total = files_ok = calls = 0
        first_bad = []
        for e, enc, disk in text_files:
            want = orig_lines(disk, enc)
            got, start = [], 1
            while True:
                out = tool(tools, "read_file", path=e.path, start_line=start, max_lines=5000)
                calls += 1
                body = out.split("\n")[1:]
                more = None
                for ln in body:
                    m = LINE_RE.match(ln)
                    if m and int(m.group(1)) == len(got) + 1:
                        got.append(m.group(2))
                    elif ln.startswith("... more: call again with start_line="):
                        more = int(ln.rsplit("=", 1)[1])
                if more is None:
                    break
                start = more
            ok = sum(1 for x, y in zip(got, want) if x == y)
            lines_ok += ok
            lines_total += max(len(want), len(got))
            if ok == len(want) == len(got):
                files_ok += 1
            elif len(first_bad) < 5:
                i = next((i for i, (x, y) in enumerate(zip(got, want)) if x != y), min(len(got), len(want)))
                first_bad.append(f"{e.path} line {i + 1}: got {got[i] if i < len(got) else '(nothing)'!r:.80} "
                                 f"want {want[i] if i < len(want) else '(nothing)'!r:.80}")
        res["read_file"] = {"files": len(text_files), "files_exact": files_ok, "lines": lines_total,
                            "lines_exact": lines_ok, "tool_calls": calls,
                            "score": lines_ok / lines_total if lines_total else None, "examples": first_bad}
        print(f"2. read_file  {files_ok:,}/{len(text_files):,} text files exact, {lines_ok:,}/{lines_total:,} "
              f"lines exact ({pct(lines_ok, lines_total)}), {calls:,} tool calls  [{time.time() - t0:.1f} s]")
        for x in first_bad:
            print(f"              {x}")

        # ---------------------------------------------------------- 3. search
        t0 = time.time()
        uniq, seen = {}, set()
        for e, enc, disk in sorted(text_files, key=lambda t: t[0].path):
            if e.sha256 not in seen:                 # the tool searches identical content once
                seen.add(e.sha256)
                uniq[e.path] = orig_lines(disk, enc)
        words = sorted({w for ls in uniq.values() for ln in ls[:200] for w in re.findall(r"[A-Za-z_]{7,}", ln)})
        patterns = [(w, False) for w in rng.sample(words, min(len(words), a.samples))]
        patterns += [(r"def \w+_bytes\(", True), (r"^import (os|sys)$", True), (r"\bTODO\b", True),
                     (r"0x[0-9a-f]{8}", True), (r"raise ValueError\(f?\"", True)]
        tp = fp = fn = exact = used = 0
        notes = []
        for pat, is_rx in patterns:
            rx = re.compile(pat if is_rx else re.escape(pat), re.IGNORECASE)
            want = {(pth, i) for pth, ls in uniq.items() for i, ln in enumerate(ls, 1) if rx.search(ln)}
            if not want or len(want) > 400:
                continue                             # keep each pattern within one tool call
            used += 1
            out = tool(tools, "search", pattern=pat, regex=is_rx, max_results=500, max_file_mb=int(a.max_file_mb),
                       seconds=120)
            got = set()
            for ln in out.split("\n")[1:]:
                m = re.match(r"^(.+?):(\d+):", ln)
                if m and not ln.startswith("... "):
                    got.add((m.group(1), int(m.group(2))))
            tp += len(want & got)
            fp += len(got - want)
            fn += len(want - got)
            exact += want == got
            if want != got and len(notes) < 5:
                notes.append(f"{pat!r}: missed {sorted(want - got)[:2]}, extra {sorted(got - want)[:2]}")
        prec = tp / (tp + fp) if tp + fp else None
        rec = tp / (tp + fn) if tp + fn else None
        res["search"] = {"patterns": used, "patterns_exact": exact, "matches_expected": tp + fn,
                         "true_positive": tp, "false_positive": fp, "false_negative": fn,
                         "precision": prec, "recall": rec, "examples": notes}
        print(f"3. search     {exact}/{used} patterns returned exactly the grep result; "
              f"{tp:,} of {tp + fn:,} matching lines found, {fp} wrong "
              f"(precision {pct(tp, tp + fp)}, recall {pct(tp, tp + fn)})  [{time.time() - t0:.1f} s]")
        for x in notes:
            print(f"              {x}")

        # ---------------------------------------------------------- 4. semantic
        if not os.path.exists(a.store + ".sem"):
            print("4. semantic   skipped: the store has no semantic index")
        else:
            import hybridstore_semantic as sem
            t0 = time.time()
            with sem.Index(a.store, readonly=True) as ix:
                by_path = {e.path: (e, enc, disk) for e, enc, disk in text_files}
                rows = []
                for pth, (e, enc, disk) in by_path.items():
                    for (st_, en_) in ix.db.execute("SELECT start_line, end_line FROM passages WHERE fsha = ?",
                                                    (e.sha256,)):
                        if en_ - st_ >= 4:
                            rows.append((pth, st_, en_))
                picks = rng.sample(rows, min(len(rows), a.samples))
                top1 = top5 = has1 = has5 = snip_ok = snip_total = 0
                miss = []
                for pth, s0, e0 in picks:
                    e, enc, disk = by_path[pth]
                    ls = orig_lines(disk, enc)
                    mid = rng.randint(s0, max(s0, e0 - 2))
                    query = "\n".join(ls[mid - 1:mid + 2])
                    hits, _ = ix.search(r, snap, query, k=5, rerank=not a.no_rerank)
                    rank = next((i for i, h in enumerate(hits, 1)
                                 if h["start"] <= mid <= h["end"] and
                                 by_path.get(h["path"], (None,))[0] is not None and
                                 by_path[h["path"]][0].sha256 == e.sha256), None)
                    top1 += rank == 1
                    top5 += rank is not None
                    # Looser: does a returned passage contain the queried lines verbatim?
                    # (repetitive files hold the same text in several places)
                    def holds(h):
                        he = by_path.get(h["path"])
                        if he is None:
                            return False
                        hl = orig_lines(he[2], he[1])[h["start"] - 1:h["end"]]
                        return query in chr(10).join(hl)
                    has1 += bool(hits) and holds(hits[0])
                    has5 += any(holds(h) for h in hits)
                    if rank is None and len(miss) < 5:
                        miss.append(f"{pth}:{mid} -> got {hits[0]['path']}:{hits[0]['start']}" if hits else pth)
                    for h in hits[:2]:                # snippet fidelity
                        he, henc, hdisk = by_path.get(h["path"], (None, None, None))
                        if he is None:
                            continue
                        hl = orig_lines(hdisk, henc)
                        for ln in sem.snippet(r, h["entry"], h["start"], h["end"]).split("\n"):
                            m = LINE_RE.match(ln)
                            if m:
                                i = int(m.group(1))
                                shown = m.group(2)
                                real = hl[i - 1] if i <= len(hl) else None
                                snip_total += 1
                                snip_ok += real is not None and (shown == real or (
                                    shown.endswith("…") and real.startswith(shown[:-1])))
                st = ix.stats()
            res["semantic"] = {"model": st["model"], "indexed_text_files": st["text_files"],
                               "queries": len(picks), "top1": top1, "top5": top5, "text_top1": has1, "text_top5": has5,
                               "snippet_lines": snip_total, "snippet_lines_exact": snip_ok, "misses": miss}
            print(f"4. semantic   retrieval: right passage ranked 1st for {top1}/{len(picks)} "
                  f"({pct(top1, len(picks))}), in top 5 for {top5}/{len(picks)} ({pct(top5, len(picks))})")
            print(f"              a passage containing the query text ranked 1st for {has1}/{len(picks)} "
                  f"({pct(has1, len(picks))}), in top 5 for {has5}/{len(picks)} ({pct(has5, len(picks))})")
            print(f"              snippets: {snip_ok:,}/{snip_total:,} lines identical to the original "
                  f"({pct(snip_ok, snip_total)}); model {st['model']}, {st['text_files']:,} text files indexed  "
                  f"[{time.time() - t0:.1f} s]")
            for x in miss:
                print(f"              missed: {x}")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
