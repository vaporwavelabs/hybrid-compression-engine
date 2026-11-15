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

import argparse, json, os, random, sys, urllib.request

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


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split(NL + NL)[0])
    ap.add_argument("store")
    ap.add_argument("--samples", type=int, default=100)
    ap.add_argument("--chat-model", default="gemma3:12b")
    ap.add_argument("--weights", default="0,0.25,0.5,1", help="word-match weights to compare")
    ap.add_argument("--glob", default="*.py", help="files to draw passages from")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("-k", type=int, default=5)
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
        sha = {e.path: e.sha256 for e in snap.files}
        print(f"{len(qs)} questions written by {a.chat_model}, cached in {cache}")
        print(f"e.g. {qs[0]['path']}:{qs[0]['start']}  ->  {qs[0]['question']}")
        out = {}
        for w in [None] + [float(x) for x in a.weights.split(",")]:
            if w is not None:
                sem.LEX_WEIGHT = w
            top1 = topk = file1 = filek = 0
            for q in qs:
                hits, _ = ix.search(r, snap, q["question"], k=a.k, rerank=w is not None)
                rank = next((i for i, h in enumerate(hits, 1) if sha.get(h["path"]) == sha.get(q["path"])
                             and h["start"] == q["start"]), None)
                top1 += rank == 1
                topk += rank is not None
                same = [sha.get(h["path"]) == sha.get(q["path"]) for h in hits]
                file1 += bool(same) and same[0]
                filek += any(same)
            name = "similarity only" if w is None else f"word-match weight {w:g}"
            out[name] = (top1, topk)
            print(f"  {name:<24} passage 1st {top1}/{len(qs)}, top {a.k} {topk}/{len(qs)};  "
                  f"right file 1st {file1}/{len(qs)}, top {a.k} {filek}/{len(qs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
