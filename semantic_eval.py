#!/usr/bin/env python3
"""Score semantic_search on questions phrased in other words than the text.

A chat model (Ollama) reads sampled passages and writes one plain-language question
each; the questions are cached next to the store as <store>.questions.json. Then every
question is searched and the rank of its source passage is reported, for similarity
alone and for each word-match weight given.

  python semantic_eval.py <store.hcs> [--samples 100] [--chat-model gemma3:12b]
                                      [--weights 0,0.25,0.5,1] [--glob *.py] [--seed 7]
"""
from __future__ import annotations

import argparse, json, math, os, random, sys, urllib.request

import hybridstore as hs
import hybridstore_semantic as sem

NL = chr(10)
PROMPT = ("Below is a passage from a file in a software project. Write ONE short question, in plain "
          "everyday English, that this passage answers. Describe what it does or says; do not copy "
          "function names, variable names or whole phrases from it. Reply with the question only." + NL + NL)


def ask(model: str, text: str, timeout: int = 300) -> str:
    base = sem.embed_url().split("/api/")[0]
    body = json.dumps({"model": model, "prompt": PROMPT + text, "stream": False,
                       "options": {"temperature": 0}}).encode()
    req = urllib.request.Request(base + "/api/generate", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as f:
        return json.load(f)["response"].strip().split(NL)[0].strip()


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion (Wilson score)."""
    if not n:
        return 0.0, 0.0
    p = hits / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def fmt(hits: int, n: int) -> str:
    lo, hi = wilson(hits, n)
    return f"{hits}/{n} ({100 * hits / n:.0f}%, 95% CI {100 * lo:.0f}-{100 * hi:.0f}%)" if n else "0/0"


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split(NL + NL)[0])
    ap.add_argument("store")
    ap.add_argument("--samples", type=int, default=100)
    ap.add_argument("--chat-model", default="gemma3:12b")
    ap.add_argument("--weights", default="0,0.25,0.5,1", help="word-match weights to compare")
    ap.add_argument("--glob", default="*.py", help="files to draw passages from")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("-k", type=int, default=5)
    ap.add_argument("--min-words", type=int, default=4,
                    help="drop generated questions shorter than this (empty or too vague to score)")
    ap.add_argument("--json", default=None, help="write every query, its rank and the top hit here")
    a = ap.parse_args(argv)
    cache = a.store + ".questions.json"
    with hs.StoreReader(a.store) as r, sem.Index(a.store, readonly=True) as ix:
        snap = r.snapshots[-1]
        qs = json.load(open(cache, encoding="utf-8")) if os.path.exists(cache) else []
        if len(qs) < a.samples:
            rows = []
            for e in {e.sha256: e for e in sem.select_files(snap, "", a.glob)}.values():
                for s0, e0 in ix.db.execute("SELECT start_line, end_line FROM passages WHERE fsha = ?",
                                            (e.sha256,)):
                    if e0 - s0 >= 8:
                        rows.append((e, s0, e0))
            rows.sort(key=lambda t: (t[0].path, t[1]))
            have = {(q["path"], q["start"]) for q in qs}
            for e, s0, e0 in random.Random(a.seed).sample(rows, min(len(rows), a.samples)):
                if (e.path, s0) in have:
                    continue
                _, lines = sem.text_lines(r, e)
                text = NL.join(l for no, l in enumerate(lines, 1) if s0 <= no <= e0)
                qs.append({"path": e.path, "start": s0, "end": e0, "question": ask(a.chat_model, text)})
                json.dump(qs, open(cache, "w", encoding="utf-8"), indent=1)
                print(f"  question {len(qs)}/{a.samples}", end=chr(13), file=sys.stderr)
        qs = qs[:a.samples]
        dropped = [q for q in qs if len(q["question"].split()) < a.min_words]
        qs = [q for q in qs if len(q["question"].split()) >= a.min_words]
        sha = {e.path: e.sha256 for e in snap.files}
        print(f"{len(qs)} questions written by {a.chat_model}, cached in {cache}; "
              f"{len(dropped)} dropped as empty or under {a.min_words} words")
        print(f"e.g. {qs[0]['path']}:{qs[0]['start']}  ->  {qs[0]['question']}")
        out, detail = {}, {}
        for w in [None] + [float(x) for x in a.weights.split(",")]:
            if w is not None:
                sem.LEX_WEIGHT = w
            top1 = topk = file1 = filek = 0
            rows = []
            for q in qs:
                hits, _ = ix.search(r, snap, q["question"], k=a.k, rerank=w is not None)
                rank = next((i for i, h in enumerate(hits, 1) if sha.get(h["path"]) == sha.get(q["path"])
                             and h["start"] == q["start"]), None)
                top1 += rank == 1
                topk += rank is not None
                same = [sha.get(h["path"]) == sha.get(q["path"]) for h in hits]
                file1 += bool(same) and same[0]
                filek += any(same)
                rows.append({"path": q["path"], "start": q["start"], "question": q["question"], "rank": rank,
                             "top": f"{hits[0]['path']}:{hits[0]['start']}" if hits else None})
            name = "similarity only" if w is None else f"word-match weight {w:g}"
            out[name] = {"passage_top1": top1, "passage_topk": topk, "file_top1": file1, "file_topk": filek,
                         "n": len(qs)}
            detail[name] = rows
            print(f"  {name}")
            print(f"    passage ranked 1st {fmt(top1, len(qs))}, top {a.k} {fmt(topk, len(qs))}")
            print(f"    right file  1st    {fmt(file1, len(qs))}, top {a.k} {fmt(filek, len(qs))}")
        if a.json:
            with open(a.json, "w", encoding="utf-8") as f:
                json.dump({"k": a.k, "chat_model": a.chat_model, "dropped": dropped, "summary": out,
                           "queries": detail}, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
