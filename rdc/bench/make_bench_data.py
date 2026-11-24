"""Make ~164 MB of mixed research-style test data (logs, edited versions, random, floats, small files).
Usage: python bench/make_bench_data.py bench_data"""
import os, random, struct
random.seed(42)
import sys
root = sys.argv[1] if len(sys.argv) > 1 else 'bench_data'
os.makedirs(root, exist_ok=True)
words = 'sample sensor reading error warn info value calibrate start stop node queue retry ok fail'.split()
# logs ~60 MB
for i in range(6):
    with open(f'{root}/log_{i}.txt', 'w') as f:
        n = 0
        while n < 10_000_000:
            line = '2026-11-%02d %02d:%02d:%02d %s %s=%d\n' % (random.randint(1,28), random.randint(0,23), random.randint(0,59), random.randint(0,59), random.choice(words).upper(), random.choice(words), random.randint(0, 99999))
            f.write(line); n += len(line)
# versioned: 8 snapshots of a 6 MB document with small edits
base = bytearray(os.urandom(3_000_000)) + bytearray(b''.join(random.choice(words).encode()+b' ' for _ in range(500_000)))
for v in range(8):
    for _ in range(20):
        p = random.randrange(len(base) - 100); base[p:p+50] = os.urandom(50)
    os.makedirs(f'{root}/versions/v{v}', exist_ok=True)
    open(f'{root}/versions/v{v}/doc.bin', 'wb').write(base)
# random binary 30 MB
open(f'{root}/random.bin', 'wb').write(os.urandom(30_000_000))
# float measurements 24 MB
with open(f'{root}/measure.f64', 'wb') as f:
    x = 0.0
    buf = bytearray()
    for i in range(3_000_000):
        x += random.gauss(0, 0.01); buf += struct.pack('<d', round(x, 4))
    f.write(buf)
# many small files
for i in range(2000):
    os.makedirs(f'{root}/small/{i % 20}', exist_ok=True)
    open(f'{root}/small/{i % 20}/f{i}.json', 'w').write('{"id": %d, "name": "%s", "v": %f}\n' % (i, random.choice(words), random.random()) * random.randint(1, 40))
tot = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(root) for f in fs)
print('total MB', tot / 1e6)
