"""Fake rdc4.py for the window flood test: copy it as rdc4.py next to a copy of rdc_gui.py."""
# Fake rdc4 that floods the GUI: unthrottled progress lines plus plain warning lines, then a result.
import json, sys
if '--help' in sys.argv:
    print('usage: pack ... --progress --password-stdin'); sys.exit(0)
N = 200_000; W = 20_000
total = N * 1000
w = sys.stderr.write
for i in range(N):
    w('{"event": "progress", "stage": "verify", "done": %d, "total": %d}\n' % ((i + 1) * 1000, total))
    if i % (N // W) == 0:
        w('warning line %d: something noisy\n' % i)
sys.stderr.flush()
print(json.dumps(dict(ok=True, files=1, bad_shards=[], bad_packs=[], bad_chunks=[], parity_repairs_used=0, needs_repair=False, warnings=[])))
