"""RDCv004 (v3.1) acceptance tests: solid packs + all RDCv003 safety properties + RDCv003 compatibility."""
import collections
import hashlib
import json
import os
import random
import tracemalloc
from pathlib import Path

import numpy as np
import pytest
import zstandard as zstd

import rdc3
import rdc4
from rdc3 import IntegrityError, LimitError, PublicationError

PW = 'test-only-password'
FAST = dict(kdf_log2n=10)
SMALLPACK = dict(pack_size=64 * 1024, level=3)   # many packs, quick
HERE = Path(__file__).resolve().parent


def tree_hashes(root):
    out = {}
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if not d.startswith(rdc3.STAGING_PREFIX)]
        for d in dn:
            out[Path(os.path.relpath(os.path.join(dp, d), root)).as_posix() + '/'] = 'dir'   # 3.1.6: '/' on Windows
        for f in fn:
            p = os.path.join(dp, f)
            out[Path(os.path.relpath(p, root)).as_posix()] = hashlib.sha256(Path(p).read_bytes()).hexdigest()
    return out


def make_tree(root, spec):
    root.mkdir(parents=True, exist_ok=True)
    for rel, data in spec.items():
        p = root / rel
        if data is None:
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
    return root


RNG = random.Random(20261109)
REDUNDANT = b'2026-11-09T21:00:00Z INFO request ok path=/api/v1/items status=200\n' * 40000
BASIC = {'empty.txt': b'', 'tiny': b'x', 'text.txt': b'lossless round trip\n' * 5000,
         'random.bin': RNG.randbytes(300_000), 'sub/deeper/redundant.log': REDUNDANT,
         'sub/dup.log': REDUNDANT, 'emptydir': None}
MULTI = {f'd{i % 3}/f{i:02d}.bin': random.Random(i).randbytes(40_000) + (b'text %d ' % i) * 6000 for i in range(12)}


def roundtrip(tmp, spec, password=None, **kw):
    src = make_tree(tmp / 'src', spec)
    ar = tmp / 'a.rdc4'
    stats = rdc4.pack(src, ar, password=password, **kw)
    out = tmp / 'out'
    r = rdc4.restore(ar, out, password)
    assert r['format'] == 'RDCv004'
    assert tree_hashes(out) == tree_hashes(src)
    assert rdc4.verify(ar, password)['ok']
    return stats, ar


def simple(tmp, spec=None, **kw):
    src = make_tree(tmp / 'src', spec or {'document.txt': b'original sample data' * 2000,
                                          'other.txt': b'other file ' * 3000})
    ar = tmp / 'a.rdc4'
    kw.setdefault('parity', None)    # most tests exercise the no-parity paths; 3.1.2 default tested below
    rdc4.pack(src, ar, **kw)
    return src, ar


def read_manifest(ar):
    raw = Path(ar).read_bytes()
    f = rdc3.HDR.unpack(raw[:rdc3.HDR.size])
    return json.loads(zstd.ZstdDecompressor().decompress(raw[rdc3.HDR.size:rdc3.HDR.size + f[7]])), raw, f


def forge(src, dst, manifest_fn=None, payload_fn=None, retag=False, manifest_bytes_fn=None, fix_root=True,
          header_fn=None):
    """Rewrite an UNKEYED v4 archive as an attacker can (recompute every SHA-256)."""
    m, raw, f = read_manifest(src)
    f = list(f)
    payload = bytearray(raw[rdc3.HDR.size + f[7]:])
    if payload_fn:
        payload = bytearray(payload_fn(payload, m))
    if manifest_fn:
        manifest_fn(m)
    if retag:
        off = 0
        for p in m['packs']:
            p[3] = hashlib.sha256(bytes(payload[off:off + p[2]])).hexdigest()
            off += p[2]
    if fix_root:
        f[10] = hashlib.sha256(b'rdc3-root\0' + rdc3.canonical(dict(files=[x[:3] for x in m['files']],
                                                                      dirs=m['dirs']))).digest()
    mraw = rdc3.canonical(m)
    if manifest_bytes_fn:
        mraw = manifest_bytes_fn(mraw)
    mc = zstd.ZstdCompressor(level=3, write_content_size=True).compress(mraw)
    f[7], f[8], f[9] = len(mc), len(mraw), len(payload)
    if header_fn:
        header_fn(f)
    prefix = rdc3.HDR.pack(*f[:11], b'\0' * 32)[:rdc3.HDR_PREFIX]
    Path(dst).write_bytes(prefix + hashlib.sha256(prefix + mc).digest() + mc + bytes(payload))
    return m


def pack_offset(m, i):
    return sum(p[2] for p in m['packs'][:i])


def rejected(ar, password=None):
    with pytest.raises(IntegrityError):
        with rdc4.open_archive(ar, password) as a:
            a.verify()


def corrupt_pack(tmp, ar, pack=0, name='c.rdc4', n=1, password=PW):
    with rdc4.open_archive(ar, password if rdc3.HDR.unpack(Path(ar).read_bytes()[:rdc3.HDR.size])[2] else None) as a:
        _, _, stored, _, off = a.packs[pack]
        pos = a.base + off + stored // 2
    raw = bytearray(Path(ar).read_bytes())
    for i in range(n):
        raw[pos + i] ^= 0x55
    out = tmp / name
    out.write_bytes(bytes(raw))
    return out


# ---------------------------------------------------------------- round trips
@pytest.mark.parametrize('variant', [
    {}, dict(level=3), dict(level=9, pack_size=64 * 1024), dict(pack_size=4 << 20), dict(threads=4),
    dict(threads=3, **SMALLPACK), dict(parity=(4, 2, 4096)), dict(parity=(10, 2, 65536)),
    dict(password=PW, gear='keyed', **FAST), dict(password=PW, gear='keyed', parity=(5, 2, 8192), threads=2, **FAST),
    pytest.param(dict(hash_name='blake3'), marks=pytest.mark.skipif(rdc3._blake3 is None, reason='blake3 not installed'),
                 id='blake3'),
    dict(gear='seeded', seed='00ff11'), dict(min_size=64, avg_size=256, max_size=1024, **SMALLPACK),
    dict(zstd_overrides={})])
def test_roundtrip_variants(tmp_path, variant):
    pw = variant.pop('password', None)
    stats, _ = roundtrip(tmp_path, BASIC, password=pw, **variant)
    assert stats['dedup_saved_bytes'] >= len(REDUNDANT) - 200_000


def test_threads_do_not_change_bytes(tmp_path):
    src = make_tree(tmp_path / 'src', MULTI)
    a1, a4 = tmp_path / '1.rdc4', tmp_path / '4.rdc4'
    rdc4.pack(src, a1, threads=1, **SMALLPACK)
    rdc4.pack(src, a4, threads=4, **SMALLPACK)
    assert a1.read_bytes() == a4.read_bytes()   # deterministic, order-preserving parallel compression


def test_empty_tree_and_files(tmp_path):
    stats, ar = roundtrip(tmp_path, {'d': None, 'e1': b'', 'e2': b''})
    assert stats['packs'] == 0 and stats['unique_chunks'] == 0


def test_single_file_source(tmp_path):
    (tmp_path / 'f').write_bytes(b'abc' * 1000)
    rdc4.pack(tmp_path / 'f', tmp_path / 'a.rdc4')
    rdc4.restore(tmp_path / 'a.rdc4', tmp_path / 'out')
    assert (tmp_path / 'out' / 'f').read_bytes() == b'abc' * 1000


def test_random_data_stored_raw_packs(tmp_path):
    data = random.Random(3).randbytes(3_000_000)
    stats, _ = roundtrip(tmp_path, {'r': data})
    assert stats['raw_packs'] == stats['packs'] and stats['data_bytes'] == len(data)


def test_highly_redundant(tmp_path):
    stats, _ = roundtrip(tmp_path, {'r.log': REDUNDANT * 4})
    assert stats['savings'] > 0.99


def test_large_file_spans_many_packs_chunks_never_split(tmp_path):
    data = random.Random(7).randbytes(5 * 1024 * 1024)
    stats, ar = roundtrip(tmp_path, {'big.bin': data, 'small.txt': b'tail' * 100}, pack_size=256 * 1024)
    assert stats['packs'] >= 15
    with rdc4.open_archive(ar) as a:
        fill = collections.Counter()
        for p, raw, cid, off in a.chunks:
            assert off + raw <= a.packs[p][1]
            fill[p] += raw
        assert all(fill[i] == a.packs[i][1] for i in range(len(a.packs)))


# ---------------------------------------------------------------- pack-specific safety
def test_pack_corruption_refused_nothing_published(tmp_path):
    _, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    bad = corrupt_pack(tmp_path, ar, pack=1)
    with pytest.raises(IntegrityError, match='authentication'):
        rdc4.verify(bad)
    out = tmp_path / 'out'
    with pytest.raises(IntegrityError):
        rdc4.restore(bad, out)
    assert not out.exists()


def test_pack_authenticated_before_decode(tmp_path, monkeypatch):
    _, ar = simple(tmp_path, spec=MULTI, password=PW, gear='keyed', **FAST, **SMALLPACK)
    bad = corrupt_pack(tmp_path, ar, pack=0)
    calls = []
    orig = rdc4.Archive4._zstd_decode
    def spy(self, body, raw_len, d, want=0):
        calls.append(raw_len)
        return orig(self, body, raw_len, d, want)
    with rdc4.open_archive(bad, PW) as a:
        monkeypatch.setattr(rdc4.Archive4, '_zstd_decode', spy)
        with pytest.raises(IntegrityError, match='authentication'):
            a.pack_bytes(0)
        assert calls == [] and a.pack_decodes == 0


def test_chunk_hash_verified_after_unpacking_pack(tmp_path):
    _, ar = simple(tmp_path, spec={'a': b'alpha ' * 20000})
    def mf(m):
        m['chunks'][0][2] = hashlib.sha256(b'not this chunk').hexdigest()
    forge(ar, tmp_path / 'id.rdc4', manifest_fn=mf)
    with pytest.raises(IntegrityError, match='chunk 0 content hash'):
        rdc4.restore(tmp_path / 'id.rdc4', tmp_path / 'out')


def test_truncated_pack_refused(tmp_path):
    _, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    def pf(p, m):  # cut the last 20 bytes of pack 1 and shrink its declared stored length
        off, n = pack_offset(m, 1), m['packs'][1][2]
        m['packs'][1][2] = n - 20
        return p[:off + n - 20] + p[off + n:]
    forge(ar, tmp_path / 't.rdc4', payload_fn=pf, retag=True)
    with pytest.raises(IntegrityError):
        rdc4.restore(tmp_path / 't.rdc4', tmp_path / 'out')
    assert not (tmp_path / 'out').exists()
    raw = ar.read_bytes()
    (tmp_path / 'cut.rdc4').write_bytes(raw[:-100])
    rejected(tmp_path / 'cut.rdc4')


def test_oversized_declared_pack_refused(tmp_path):
    _, ar = simple(tmp_path)
    forge(ar, tmp_path / 'big.rdc4', manifest_fn=lambda m: m['packs'][0].__setitem__(1, rdc4.Limits4.max_pack + 1))
    with pytest.raises(IntegrityError, match='declared pack size'):
        rdc4.open_archive(tmp_path / 'big.rdc4')


@pytest.mark.parametrize('content_size', [True, False])
def test_pack_frame_larger_than_declared_refused_bounded(tmp_path, content_size):
    _, ar = simple(tmp_path, spec={'a': b'q' * 50_000})
    frame = zstd.ZstdCompressor(level=3, write_content_size=content_size).compress(b'\0' * (64 << 20))
    def pf(p, m):
        n = m['packs'][0][2]
        m['packs'][0][2] = len(frame)
        return frame + p[n:]
    forge(ar, tmp_path / 'bomb.rdc4', payload_fn=pf, retag=True)
    tracemalloc.start()
    with pytest.raises(IntegrityError):
        rdc4.restore(tmp_path / 'bomb.rdc4', tmp_path / 'out')
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 8 << 20 and not (tmp_path / 'out').exists()


@pytest.mark.parametrize('case', ['span_past_pack', 'gap_between_packs', 'pack_index_backwards',
                                  'unaccounted_pack_bytes', 'skip_pack'])
def test_chunk_spanning_and_tiling_forgeries_refused(tmp_path, case):
    _, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    def mf(m):
        ch = m['chunks']
        first1 = next(i for i, c in enumerate(ch) if c[0] == 1)
        if case == 'span_past_pack':      # last chunk of pack 0 claims bytes of pack 1
            ch[first1 - 1][1] += 10
        elif case == 'gap_between_packs':  # move last chunk of pack 0 into pack 1 => pack 0 underfilled
            ch[first1 - 1][0] = 1
        elif case == 'pack_index_backwards':
            ch[first1 + 1][0] = 0
        elif case == 'unaccounted_pack_bytes':
            m['packs'][-1][1] += 5
        elif case == 'skip_pack':
            for c in ch[first1:]:
                c[0] += 1
            m['packs'].insert(1, list(m['packs'][1]))
    forge(ar, tmp_path / 'f.rdc4', manifest_fn=mf)
    with pytest.raises(IntegrityError):
        rdc4.open_archive(tmp_path / 'f.rdc4')


def test_random_access_single_file_decodes_only_needed_packs(tmp_path):
    src, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    with rdc4.open_archive(ar) as a:
        target = a.files[5]
        needed = {a.chunks[r][0] for r in target[3]}
        total_packs = len(a.packs)
    assert total_packs >= 6 * len(needed)
    r = rdc4.restore(ar, tmp_path / 'one', paths=[target[0]])
    assert r['files'] == 1 and r['pack_decodes'] == len(needed)
    assert tree_hashes(tmp_path / 'one') == {
        os.path.dirname(target[0]) + '/': 'dir',
        target[0]: hashlib.sha256((src / target[0]).read_bytes()).hexdigest()}
    # damage a pack the file does not use: single-file restore still succeeds, full restore refuses
    other = next(i for i in range(total_packs) if i not in needed)
    bad = corrupt_pack(tmp_path, ar, pack=other)
    rdc4.restore(bad, tmp_path / 'one-bad', paths=[target[0]])
    with pytest.raises(IntegrityError):
        rdc4.restore(bad, tmp_path / 'all-bad')
    with pytest.raises(KeyError):
        rdc4.restore(ar, tmp_path / 'missing', paths=['no/such/file'])
    assert not (tmp_path / 'missing').exists()
    assert rdc4.main(['unpack', str(ar), str(tmp_path / 'cli1'), '--only', target[0]]) == 0
    assert os.listdir(tmp_path / 'cli1') == [target[0].split('/')[0]]


def test_restore_memory_bounded_one_pack_at_a_time(tmp_path):
    rng = np.random.default_rng(5)
    make_tree(tmp_path / 'src', {'big': rng.integers(0, 256, 48 << 20, dtype=np.uint8).tobytes()})
    rdc4.pack(tmp_path / 'src', tmp_path / 'a.rdc4', pack_size=4 << 20, level=1)
    tracemalloc.start()
    r = rdc4.restore(tmp_path / 'a.rdc4', tmp_path / 'out')
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert r['pack_decodes'] >= 12 and peak < 32 << 20, peak


def test_pack_memory_independent_of_input_size(tmp_path):
    peaks = []
    for mib in (8, 48):
        d = tmp_path / str(mib)
        rng = np.random.default_rng(mib)
        make_tree(d / 'src', {'big': rng.integers(0, 256, mib << 20, dtype=np.uint8).tobytes()})
        tracemalloc.start()
        rdc4.pack(d / 'src', d / 'a.rdc4', level=3)
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    # Growth with input size is the property under test. The fixed part of the peak differs by
    # interpreter (40.6 MiB on 3.13, 42.4 MiB on 3.14 with the same code), so the absolute cap
    # has headroom for that and only catches a gross regression.
    assert peaks[1] < 48 << 20 and peaks[1] - peaks[0] < 8 << 20, peaks


# ---------------------------------------------------------------- framing / parser safety
def test_trailing_and_truncation(tmp_path):
    _, ar = simple(tmp_path)
    raw = ar.read_bytes()
    for i, data in enumerate([raw + b'J', raw[:-1], raw[:rdc3.HDR.size], raw[:7], b'']):
        (tmp_path / f't{i}').write_bytes(data)
        with pytest.raises(IntegrityError):
            rdc4.restore(tmp_path / f't{i}', tmp_path / f'o{i}')
        assert not (tmp_path / f'o{i}').exists()


@pytest.mark.parametrize('variant', [{}, dict(password=PW, gear='keyed', **FAST)])
def test_bitflip_fuzz_never_wrong_output(tmp_path, variant):
    src, ar = simple(tmp_path, spec=MULTI, **SMALLPACK, **variant)
    pw = variant.get('password')
    raw = ar.read_bytes()
    rng = random.Random(4321)
    for n in range(50):
        b = bytearray(raw)
        pos = rng.randrange(len(raw))
        b[pos] ^= 1 << rng.randrange(8)
        t = tmp_path / f'f{n}.rdc4'
        t.write_bytes(bytes(b))
        with pytest.raises(IntegrityError):
            rdc4.restore(t, tmp_path / f'o{n}', pw)
        assert not (tmp_path / f'o{n}').exists()


def test_header_bits_and_manifest_strictness(tmp_path):
    _, ar = simple(tmp_path)
    for idx, val in ((1, 1), (2, 8), (3, 1), (6, b'\0\0\1')):
        def hf(f, idx=idx, val=val):
            f[idx] = val
        forge(ar, tmp_path / 'h', header_fn=hf)
        rejected(tmp_path / 'h')
    for fn in (lambda b: b[:-1] + b',"v":4}', lambda b: b.replace(b',', b', ', 1), lambda b: b + b'JUNK'):
        forge(ar, tmp_path / 'm', manifest_bytes_fn=fn)
        rejected(tmp_path / 'm')


@pytest.mark.parametrize('bad', ['../outside.txt', '/etc/passwd', 'a/../../x', 'a\\b', 'C:x', 'a//b', '',
                                 '.rdc3-staging-evil/x', 'nul\x00byte'])
def test_unsafe_paths_refused(tmp_path, bad):
    _, ar = simple(tmp_path)
    forge(ar, tmp_path / 'p', manifest_fn=lambda m: m['files'][0].__setitem__(0, bad))
    with pytest.raises(IntegrityError):
        rdc4.restore(tmp_path / 'p', tmp_path / 'out')
    assert not (tmp_path / 'outside.txt').exists() and not (tmp_path / 'out').exists()


def test_bad_fields_refused(tmp_path):
    _, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    cases = {
        'pack_codec': lambda m: m['packs'][0].__setitem__(0, 9),
        'pack_raw_noncanonical': lambda m: m['packs'][0].__setitem__(0, 0),
        'pack_stored_len': lambda m: m['packs'][0].__setitem__(2, m['packs'][0][2] + 1),
        'chunk_pack_oob': lambda m: m['chunks'][-1].__setitem__(0, 999),
        'chunk_raw_over_max': lambda m: m['chunks'][0].__setitem__(1, rdc4.Limits4.max_chunk + 1),
        'bool_as_int': lambda m: m['chunks'][0].__setitem__(0, False),
        'dup_chunk_id': lambda m: m['chunks'][1].__setitem__(2, m['chunks'][0][2]),
        'ref_oob': lambda m: m['files'][0][3].append(99999),
        'v3_version_in_v4': lambda m: m.__setitem__('v', 3),
        'extra_key': lambda m: m.__setitem__('x', 1),
        'dup_path': lambda m: m['files'][1].__setitem__(0, m['files'][0][0]),
        'file_as_dir': lambda m: m['files'][1].__setitem__(0, m['files'][0][0] + '/x'),
    }
    for name, fn in cases.items():
        forge(ar, tmp_path / name, manifest_fn=fn)
        rejected(tmp_path / name)
    def unused(m):
        m['files'][0][3], m['files'][0][1] = [], 0
        m['files'][0][2] = hashlib.sha256(b'').hexdigest()
    forge(ar, tmp_path / 'unused', manifest_fn=unused)
    with pytest.raises(IntegrityError, match='unreferenced'):
        rdc4.open_archive(tmp_path / 'unused')
    forge(ar, tmp_path / 'pl', payload_fn=lambda p, m: p + b'\0')
    rejected(tmp_path / 'pl')
    forge(ar, tmp_path / 'root', manifest_fn=lambda m: m['files'][0].__setitem__(2, 'f' * 64), fix_root=False)
    with pytest.raises(IntegrityError, match='root'):
        rdc4.open_archive(tmp_path / 'root')


def test_keyed_password_and_forgery(tmp_path):
    _, ar = simple(tmp_path, password=PW, gear='keyed', **FAST)
    for pw in (None, 'wrong'):
        with pytest.raises(IntegrityError):
            rdc4.open_archive(ar, pw)
    raw = bytearray(ar.read_bytes())
    raw[-5] ^= 0xFF
    (tmp_path / 't').write_bytes(bytes(raw))
    with pytest.raises(IntegrityError, match='authentication'):
        rdc4.restore(tmp_path / 't', tmp_path / 'out', PW)
    assert b'original sample data' not in ar.read_bytes()


# ---------------------------------------------------------------- 3.0.1/3.0.2 limits carried over
def _zeros(tmp_path, mib):
    src = tmp_path / 'z'
    src.mkdir()
    with open(src / 'zeros.img', 'wb') as f:
        for _ in range(mib):
            f.write(b'\0' * (1 << 20))
    return src


def test_expansion_cap_unkeyed_refused_keyed_skipped_explicit_enforced(tmp_path):
    src = _zeros(tmp_path, 96)
    rdc4.pack(src, tmp_path / 'u.rdc4')
    with pytest.raises(LimitError) as e:
        rdc4.restore(tmp_path / 'u.rdc4', tmp_path / 'uo')
    assert '--max-expansion 0' in str(e.value) and 'max_expansion=0' in str(e.value)
    assert not (tmp_path / 'uo').exists()
    rdc4.restore(tmp_path / 'u.rdc4', tmp_path / 'uo', max_expansion=0)
    rdc4.pack(src, tmp_path / 'k.rdc4', password=PW, gear='keyed', **FAST)
    rdc4.restore(tmp_path / 'k.rdc4', tmp_path / 'ko', PW)
    assert (tmp_path / 'ko' / 'zeros.img').stat().st_size == 96 << 20
    with pytest.raises(LimitError):
        rdc4.restore(tmp_path / 'k.rdc4', tmp_path / 'ke', PW, max_expansion=1000)
    assert not (tmp_path / 'ke').exists()


def test_free_space_check(tmp_path, monkeypatch):
    _, ar = simple(tmp_path)
    usage = collections.namedtuple('usage', 'total used free')
    monkeypatch.setattr(rdc3.shutil, 'disk_usage', lambda p: usage(10**9, 10**9 - 1000, 1000))
    with pytest.raises(LimitError, match='free space'):
        rdc4.restore(ar, tmp_path / 'new')
    assert not (tmp_path / 'new').exists()


def test_failed_restore_removes_created_destination_only(tmp_path):
    _, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    bad = corrupt_pack(tmp_path, ar, pack=2)
    with pytest.raises(IntegrityError):
        rdc4.restore(bad, tmp_path / 'new')
    assert not (tmp_path / 'new').exists()
    (tmp_path / 'pre').mkdir()
    with pytest.raises(IntegrityError):
        rdc4.restore(bad, tmp_path / 'pre')
    assert (tmp_path / 'pre').is_dir() and os.listdir(tmp_path / 'pre') == []


# ---------------------------------------------------------------- writer safety
def test_writer_self_ingestion_overwrite_symlinks(tmp_path, need_links):
    need_links('symlink')
    src = make_tree(tmp_path / 'src', {'a': b'data'})
    for dest in (src / 'in.rdc4', src / 'sub' / 'in.rdc4'):
        with pytest.raises(ValueError):
            rdc4.pack(src, dest)
    with pytest.raises(FileExistsError):
        rdc4.pack(src, src / 'a')
    (tmp_path / 'exists').write_bytes(b'keep')
    with pytest.raises(FileExistsError):
        rdc4.pack(src, tmp_path / 'exists')
    assert (tmp_path / 'exists').read_bytes() == b'keep'
    os.symlink('/etc/hostname', src / 'link')
    with pytest.raises(ValueError, match='symlink'):
        rdc4.pack(src, tmp_path / 'o.rdc4')


def test_pack_failpoints(tmp_path):
    src = make_tree(tmp_path / 'src', {'a': b'data' * 100})
    with pytest.raises(RuntimeError):
        rdc4.pack(src, tmp_path / 'o.rdc4', failpoint='before_commit')
    assert not (tmp_path / 'o.rdc4').exists() and not list(tmp_path.glob('.rdc3-*'))
    with pytest.raises(PublicationError):
        rdc4.pack(src, tmp_path / 'p.rdc4', failpoint='after_publish')
    assert rdc4.verify(tmp_path / 'p.rdc4')['ok']


def test_invalid_pack_parameters(tmp_path):
    src = make_tree(tmp_path / 'src', {'a': b'x'})
    for kw in (dict(pack_size=1000), dict(pack_size=64 << 20), dict(threads=0), dict(level=30),
               dict(avg_size=8192)):
        with pytest.raises(ValueError):
            rdc4.pack(src, tmp_path / 'x.rdc4', **kw)


# ---------------------------------------------------------------- restore safety
def test_restore_never_overwrites_and_symlinks_refused(tmp_path, need_links):
    need_links('symlink')
    src, ar = simple(tmp_path, spec={'a/b.txt': b'payload' * 100, 'c.txt': b'c'})
    out = tmp_path / 'out'
    (out / 'a').mkdir(parents=True)
    (out / 'c.txt').write_bytes(b'KEEP')
    with pytest.raises(FileExistsError):
        rdc4.restore(ar, out)
    assert (out / 'c.txt').read_bytes() == b'KEEP' and sorted(os.listdir(out)) == ['a', 'c.txt']
    outside = tmp_path / 'outside'
    outside.mkdir()
    o2 = tmp_path / 'o2'
    o2.mkdir()
    os.symlink(outside, o2 / 'a')
    with pytest.raises(IntegrityError):
        rdc4.restore(ar, o2)
    assert os.listdir(outside) == []


def test_recover_mode_skips_files_in_damaged_pack(tmp_path):
    spec = {'a_bad.bin': random.Random(1).randbytes(200_000), 'b_good.txt': b'good data ' * 30000}
    src, ar = simple(tmp_path, spec=spec, pack_size=64 * 1024, level=3)
    with rdc4.open_archive(ar) as a:
        bad_pack = a.chunks[a.files[0][3][0]][0]
        good_packs = {a.chunks[r][0] for r in a.files[1][3]}
    assert bad_pack not in good_packs
    bad = corrupt_pack(tmp_path, ar, pack=bad_pack)
    r = rdc4.restore(bad, tmp_path / 'rec', recover=True)
    assert [d['path'] for d in r['damaged']] == ['a_bad.bin']
    assert os.listdir(tmp_path / 'rec') == ['b_good.txt']
    assert (tmp_path / 'rec' / 'b_good.txt').read_bytes() == spec['b_good.txt']


def test_publication_error_distinct(tmp_path):
    _, ar = simple(tmp_path)
    with pytest.raises(PublicationError) as e:
        rdc4.restore(ar, tmp_path / 'out', failpoint='after_first_publish')
    assert e.value.published == ['document.txt']


# ---------------------------------------------------------------- parity drills
def _damage_shards(ar, dst, group, idxs, password=None):
    with rdc4.open_archive(ar, password) as a:
        k, m, groups = a.parity
        gs, gl, s, poff, _ = groups[group]
        base = a.base
    raw = bytearray(Path(ar).read_bytes())
    for i in idxs:
        st = base + (gs + i * s if i < k else poff + (i - k) * s)
        en = st + (min(s, gl - i * s) if i < k else s)
        raw[st:en] = b'\0' * (en - st)
    Path(dst).write_bytes(bytes(raw))


def test_parity_flip_repair_byte_identical(tmp_path):
    src, ar = simple(tmp_path, spec=MULTI, parity=(4, 2, 4096), **SMALLPACK)
    bad = corrupt_pack(tmp_path, ar, pack=3, n=40)
    rep = rdc4.verify(bad)
    assert rep['needs_repair'] and rep['bad_packs'] == [3]
    r = rdc4.repair(bad, tmp_path / 'fixed.rdc4')
    assert r['reverify']['ok'] and (tmp_path / 'fixed.rdc4').read_bytes() == ar.read_bytes()
    rdc4.restore(bad, tmp_path / 'out')
    assert tree_hashes(tmp_path / 'out') == tree_hashes(src)


@pytest.mark.parametrize('k,m', [(4, 2), (10, 2), (5, 3)])
def test_parity_drop_m_repairs_m_plus_1_refused(tmp_path, k, m):
    src, ar = simple(tmp_path, spec=MULTI, parity=(k, m, 4096), **SMALLPACK)
    rng = random.Random(k * 7 + m)
    _damage_shards(ar, tmp_path / 'm.rdc4', 0, rng.sample(range(k + m), m))
    rdc4.repair(tmp_path / 'm.rdc4', tmp_path / 'mf.rdc4')
    assert (tmp_path / 'mf.rdc4').read_bytes() == ar.read_bytes()
    _damage_shards(ar, tmp_path / 'm1.rdc4', 0, list(range(m + 1)))
    with pytest.raises(IntegrityError):
        rdc4.repair(tmp_path / 'm1.rdc4', tmp_path / 'm1f.rdc4')
    assert not (tmp_path / 'm1f.rdc4').exists()
    with pytest.raises(IntegrityError):
        rdc4.restore(tmp_path / 'm1.rdc4', tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_encrypted_parity_repair(tmp_path):
    src, ar = simple(tmp_path, spec=MULTI, password=PW, gear='keyed', parity=(4, 2, 4096), **FAST, **SMALLPACK)
    bad = corrupt_pack(tmp_path, ar, pack=2, n=10)
    rdc4.restore(bad, tmp_path / 'out', PW)
    assert tree_hashes(tmp_path / 'out') == tree_hashes(src)


# ---------------------------------------------------------------- peer regressions adapted to RDCv004
def test_web_existing_destination_survives_validation_failure(tmp_path):
    _, ar = simple(tmp_path, spec={'important.txt': b'new content ' * 1000})
    bad = corrupt_pack(tmp_path, ar)
    out = tmp_path / 'd'
    out.mkdir()
    (out / 'important.txt').write_bytes(b'ORIGINAL MUST SURVIVE')
    with pytest.raises((IntegrityError, FileExistsError)):
        rdc4.restore(bad, out)
    assert (out / 'important.txt').read_bytes() == b'ORIGINAL MUST SURVIVE'


def test_web_validation_failure_leaves_no_new_destination(tmp_path):
    _, ar = simple(tmp_path, spec={'new.txt': b'new ' * 5000})
    with pytest.raises(IntegrityError):
        rdc4.restore(corrupt_pack(tmp_path, ar), tmp_path / 'd')
    assert not (tmp_path / 'd' / 'new.txt').exists()


def test_web_manifest_rejects_trailing_bytes(tmp_path):
    _, ar = simple(tmp_path)
    forge(ar, tmp_path / 't', manifest_bytes_fn=lambda b: b + b'UNACCOUNTED')
    rejected(tmp_path / 't')


def test_web_codec_block_rejects_trailing_bytes(tmp_path):
    _, ar = simple(tmp_path, spec={'s': b'sample' * 5000})
    def pf(p, m):
        n = m['packs'][0][2]
        m['packs'][0][2] = n + 11
        return p[:n] + b'UNACCOUNTED' + p[n:]
    forge(ar, tmp_path / 't', payload_fn=pf, retag=True)
    with pytest.raises(IntegrityError, match='trailing|decode'):
        rdc4.restore(tmp_path / 't', tmp_path / 'out')


def test_web_verify_rejects_unsafe_manifest_path(tmp_path):
    _, ar = simple(tmp_path)
    forge(ar, tmp_path / 't', manifest_fn=lambda m: m['files'][0].__setitem__(0, '../outside.txt'))
    with pytest.raises(IntegrityError):
        rdc4.verify(tmp_path / 't')


def test_web_basic_roundtrip(tmp_path):
    roundtrip(tmp_path, {'empty': b'', 'a': b'abc' * 10000, 'b': bytes(range(256)) * 40})


def test_seeker_restore_never_overwrites_existing_file(tmp_path):
    _, ar = simple(tmp_path, spec={'document.txt': b'original sample data' * 20})
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'document.txt').write_bytes(b'KEEP EXISTING')
    with pytest.raises((FileExistsError, IntegrityError)):
        rdc4.restore(ar, out)
    assert (out / 'document.txt').read_bytes() == b'KEEP EXISTING'


def test_seeker_integrity_failure_preserves_existing_file(tmp_path):
    _, ar = simple(tmp_path, spec={'document.txt': b'original sample data' * 20})
    forge(ar, tmp_path / 'f', manifest_fn=lambda m: m['files'][0].__setitem__(2, '0' * 64))
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(IntegrityError, match='digest'):
        rdc4.restore(tmp_path / 'f', out)
    assert os.listdir(out) == []


def test_seeker_codec_block_rejects_trailing_payload(tmp_path):
    _, ar = simple(tmp_path, spec={'c': b'compressed text' * 100})
    def pf(p, m):
        n = m['packs'][0][2]
        m['packs'][0][2] = n + 4
        return p[:n] + b'JUNK' + p[n:]
    forge(ar, tmp_path / 't', payload_fn=pf, retag=True)
    rejected(tmp_path / 't')


def test_seeker_manifest_rejects_unconsumed_bytes(tmp_path):
    _, ar = simple(tmp_path)
    forge(ar, tmp_path / 't', manifest_bytes_fn=lambda b: b + b'JUNK')
    rejected(tmp_path / 't')


# ---------------------------------------------------------------- RDCv003 compatibility
COMPAT = HERE / 'compat_fixtures'


@pytest.mark.parametrize('name', ['v302-plain.rdc3', 'v302-dict-delta.rdc3', 'v302-keyed-parity.rdc3'])
def test_v302_archives_still_restore(tmp_path, name):
    exp = json.loads((COMPAT / 'expected.json').read_text())
    pw = exp['password'] if 'keyed' in name else None
    r = rdc4.restore(COMPAT / name, tmp_path / 'out', pw)
    assert r['format'] == 'RDCv003'
    got = tree_hashes(tmp_path / 'out')
    assert {k: v for k, v in got.items() if v != 'dir'} == exp['files']
    assert 'emptydir/' in got
    assert rdc4.verify(COMPAT / name, pw)['ok']
    assert rdc4.list_archive(COMPAT / name, pw)['format'] == 'RDCv003'


def test_v302_keyed_parity_fixture_repairs_via_rdc4(tmp_path):
    exp = json.loads((COMPAT / 'expected.json').read_text())
    src = COMPAT / 'v302-keyed-parity.rdc3'
    with rdc3.Archive(src, exp['password']) as a:
        off = a.base + a.data_len // 2
    raw = bytearray(src.read_bytes())
    raw[off] ^= 0x10
    (tmp_path / 'bad.rdc3').write_bytes(bytes(raw))
    rdc4.repair(tmp_path / 'bad.rdc3', tmp_path / 'fixed.rdc3', exp['password'])
    assert (tmp_path / 'fixed.rdc3').read_bytes() == src.read_bytes()


def test_format3_still_writable_and_v4_not_readable_by_v3(tmp_path):
    src = make_tree(tmp_path / 'src', BASIC)
    assert rdc4.main(['pack', str(src), str(tmp_path / 'a.rdc3'), '--format', '3', '--delta']) == 0
    assert rdc4.archive_format(tmp_path / 'a.rdc3') == 3
    rdc4.restore(tmp_path / 'a.rdc3', tmp_path / 'o3')
    assert tree_hashes(tmp_path / 'o3') == tree_hashes(src)
    rdc4.pack(src, tmp_path / 'b.rdc4')
    with pytest.raises(IntegrityError, match='magic'):
        rdc3.Archive(tmp_path / 'b.rdc4')
    (tmp_path / 'junk').write_bytes(b'NOTANARCHIVE' * 20)
    with pytest.raises(IntegrityError, match='magic'):
        rdc4.restore(tmp_path / 'junk', tmp_path / 'oj')


def test_cli_roundtrip_and_exit_codes(tmp_path, monkeypatch):
    src = make_tree(tmp_path / 'src', BASIC)
    monkeypatch.setenv('RDC_PASSWORD', PW)
    assert rdc4.main(['pack', str(src), str(tmp_path / 'a.rdc4'), '--encrypt', '--parity', '4,2,4096',
                      '--threads', '2']) == 0
    assert rdc4.main(['verify', str(tmp_path / 'a.rdc4')]) == 0
    assert rdc4.main(['ls', str(tmp_path / 'a.rdc4')]) == 0
    assert rdc4.main(['unpack', str(tmp_path / 'a.rdc4'), str(tmp_path / 'o')]) == 0
    assert tree_hashes(tmp_path / 'o') == tree_hashes(src)
    assert rdc4.main(['unpack', str(tmp_path / 'a.rdc4'), str(tmp_path / 'o')]) == 1
    assert rdc4.main(['pack', str(src), str(tmp_path / 'b.rdc4'), '--dict']) == 1


def test_seeker_amplification_forged_v4_refused_limit(tmp_path):
    """RDCv004 version of SEEKER's forge: one 1 MiB zero chunk in one pack referenced 2048x (2 GiB)."""
    _, ar = simple(tmp_path, spec={'a': b'x' * 100})
    raw = b'\0' * rdc4.Limits4.max_chunk
    body = zstd.ZstdCompressor(level=19, write_content_size=True).compress(raw)
    N = 2048
    def mf(m):
        m['chunker']['max'] = len(raw)
        m['parity'] = None
        m['packs'] = [[1, len(raw), len(body), hashlib.sha256(body).hexdigest()]]
        m['chunks'] = [[0, len(raw), hashlib.sha256(raw).hexdigest()]]
        h = hashlib.sha256()
        for _ in range(N):
            h.update(raw)
        m['files'] = [['bomb.bin', len(raw) * N, h.hexdigest(), [0] * N]]
        m['dirs'] = []
    forge(ar, tmp_path / 'bomb.rdc4', manifest_fn=mf, payload_fn=lambda p, m: body)
    assert (tmp_path / 'bomb.rdc4').stat().st_size < 20_000
    with pytest.raises(LimitError, match='--max-expansion 0'):
        rdc4.restore(tmp_path / 'bomb.rdc4', tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


# ---------------------------------------------------------------- v3.1.1: decode amplification
# SEEKER (v3.1 review): unkeyed archives are forgeable, and a file whose pieces cycle through more
# packs than the restore cache holds forced a full pack decode per piece (4.5 KB -> ~94 GiB decoded).
MiB = 1 << 20


def build_unkeyed(path, pack_chunks, files):
    """Write a valid unkeyed RDCv004 archive from explicit packs (lists of chunk bytes) and files
    [(name, [chunk indices])]. Mirrors SEEKER's v4_forge.py builder."""
    ctx = rdc3.Ctx(None, b'\0' * 16, 0, False, 'sha256')
    packs, data, chunks, flat = [], b'', [], []
    for pi, cl in enumerate(pack_chunks):
        raw = b''.join(cl)
        body = zstd.ZstdCompressor(level=3, write_content_size=True, write_checksum=False).compress(raw)
        if len(body) >= len(raw):            # incompressible: stored raw, as the packer does
            body, codec = raw, 0
        else:
            codec = 1
        packs.append([codec, len(raw), len(body), ctx.tag(body).hex()])
        data += body
        for c in cl:
            chunks.append([pi, len(c), ctx.chunk_id(c)])
            flat.append(c)
    mf = []
    for name, refs in files:
        content = b''.join(flat[r] for r in refs)
        mf.append([name, len(content), hashlib.sha256(content).hexdigest(), refs])
    root = ctx.tag(b'rdc3-root\0' + rdc3.canonical(dict(files=[f[:3] for f in mf], dirs=[])))
    m = dict(v=4, hash='sha256', level=19, pack_size=16 * MiB,
             chunker=dict(min=1, avg=8192, max=MiB, gear='public', seed=None),
             packs=packs, chunks=chunks, files=mf, dirs=[], parity=None)
    mraw = rdc3.canonical(m)
    mcomp = zstd.ZstdCompressor(level=19, write_content_size=True).compress(mraw)
    prefix = rdc3.HDR.pack(rdc4.MAGIC4, 0, 0, 0, b'\0' * 16, 0, b'\0\0\0', len(mcomp), len(mraw), len(data),
                           root, b'\0' * 32)[:rdc3.HDR_PREFIX]
    Path(path).write_bytes(prefix + ctx.tag(prefix + mcomp) + mcomp + data)
    return {f[0]: b''.join(flat[r] for r in refs) for f, (_, refs) in zip(mf, files)}


def thrash_archive(path, cycles, npacks=3):
    """SEEKER's attack: 16 MiB packs, each ending in a 1-byte chunk; tiny.bin cycles those bytes."""
    packs, refs_big, tiny, base = [], [], [], 0
    for p in range(npacks):
        cl = [bytes([p, j]) + b'\0' * (MiB - 2) for j in range(15)] + [bytes([p, 99]) + b'\0' * (MiB - 3),
                                                                       bytes([200 + p])]
        packs.append(cl)
        refs_big += list(range(base, base + 16))
        tiny.append(base + 16)
        base += 17
    return build_unkeyed(path, packs, [('big.bin', refs_big), ('tiny.bin', tiny * cycles)])


def test_thrash_archive_restore_decodes_each_pack_once(tmp_path):
    import time
    want = thrash_archive(tmp_path / 't.rdc4', cycles=2000)          # SEEKER's 94 GiB case
    assert os.path.getsize(tmp_path / 't.rdc4') < 16 * 1024
    with rdc4.open_archive(tmp_path / 't.rdc4') as a:
        assert a.decode_cost([e for e in a.files if e[0] == 'tiny.bin']) >= 6000 * 16 * MiB
    t = time.time()
    r = rdc4.restore(tmp_path / 't.rdc4', tmp_path / 'one', paths=['tiny.bin'])
    assert r['pack_decodes'] == 3 and r['files'] == 1
    r = rdc4.restore(tmp_path / 't.rdc4', tmp_path / 'all')
    assert r['pack_decodes'] == 3 and r['files'] == 2
    assert time.time() - t < 20
    assert (tmp_path / 'one' / 'tiny.bin').read_bytes() == want['tiny.bin']
    assert (tmp_path / 'all' / 'big.bin').read_bytes() == want['big.bin']
    assert rdc4.main(['unpack', str(tmp_path / 't.rdc4'), str(tmp_path / 'cli'), '--only', 'tiny.bin']) == 0


def test_thrash_archive_verify_switches_to_pack_order(tmp_path):
    thrash_archive(tmp_path / 't.rdc4', cycles=2000)
    with rdc4.open_archive(tmp_path / 't.rdc4') as a:
        rep = a.verify()
        assert rep['ok'] and rep['verify_mode'] == 'pack_order' and a.pack_decodes == 3
    assert not [n for n in os.listdir(tempfile_dir()) if n.startswith('.rdc-verify-')]
    # max_decode=0 restores the old sequential behaviour (opt-in for callers who want no temp disk)
    thrash_archive(tmp_path / 's.rdc4', cycles=20)
    rep = rdc4.verify(tmp_path / 's.rdc4', max_decode=0)
    assert rep['ok'] and rep['verify_mode'] == 'sequential' and rep['pack_decodes'] >= 60


def tempfile_dir():
    import tempfile
    return tempfile.gettempdir()


def test_shuffled_dedup_archive_restores_and_verifies(tmp_path):
    """Legitimate worst case for piece order: a snapshot that reuses 8 KiB pieces from many packs in
    shuffled order. A '4 x declared output' style cap would refuse it; pack order handles it."""
    rng = random.Random(7)
    packs = [[rng.randbytes(8192) for _ in range(256)] for _ in range(4)]   # 4 x 2 MiB packs
    n = sum(len(p) for p in packs)
    order = list(range(n))
    rng.shuffle(order)
    want = build_unkeyed(tmp_path / 'd.rdc4', packs, [('a.bin', list(range(n))), ('b.bin', order)])
    with rdc4.open_archive(tmp_path / 'd.rdc4') as a:
        b = next(e for e in a.files if e[0] == 'b.bin')
        assert a.decode_cost([b]) > 4 * b[1]
    r = rdc4.restore(tmp_path / 'd.rdc4', tmp_path / 'out')
    assert r['pack_decodes'] == 4
    assert (tmp_path / 'out' / 'b.bin').read_bytes() == want['b.bin']
    rep = rdc4.verify(tmp_path / 'd.rdc4')
    assert rep['ok'] and rep['verify_mode'] == 'pack_order' and rep['pack_decodes'] == 4


def test_pack_order_restore_detects_bad_digest_and_recovers_others(tmp_path):
    """A forged file digest still fails closed; --recover publishes the good file only."""
    rng = random.Random(3)
    packs = [[rng.randbytes(4096) for _ in range(8)] for _ in range(3)]
    build_unkeyed(tmp_path / 'g.rdc4', packs, [('good.bin', [0, 9, 17]), ('bad.bin', [1, 2]),
                                                ('rest.bin', list(range(24)))])
    def mf(m):
        m['files'][1][2] = '0' * 64
    forge(tmp_path / 'g.rdc4', tmp_path / 'f.rdc4', manifest_fn=mf)
    with pytest.raises(IntegrityError, match='digest mismatch'):
        rdc4.restore(tmp_path / 'f.rdc4', tmp_path / 'strict')
    assert not (tmp_path / 'strict').exists()
    r = rdc4.restore(tmp_path / 'f.rdc4', tmp_path / 'rec', recover=True)
    assert r['files'] == 2 and [d['path'] for d in r['damaged']] == ['bad.bin']
    assert sorted(os.listdir(tmp_path / 'rec')) == ['good.bin', 'rest.bin']


def test_normal_archive_verifies_sequentially(tmp_path):
    _, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    rep = rdc4.verify(ar)
    assert rep['ok'] and rep['verify_mode'] == 'sequential'


def test_cli_max_decode(tmp_path, capsys):
    thrash_archive(tmp_path / 't.rdc4', cycles=20)
    assert rdc4.main(['verify', str(tmp_path / 't.rdc4')]) == 0
    assert json.loads(capsys.readouterr().out)['verify_mode'] == 'pack_order'
    assert rdc4.main(['verify', str(tmp_path / 't.rdc4'), '--max-decode', '0']) == 0
    assert json.loads(capsys.readouterr().out)['verify_mode'] == 'sequential'


# ---------------------------------------------------------------- v3.1.2: parity on by default
def test_default_pack_has_parity_and_repairs_a_flipped_byte(tmp_path):
    src = make_tree(tmp_path / 'src', MULTI)
    ar = tmp_path / 'd.rdc4'
    rdc4.pack(src, ar, **SMALLPACK)                      # no parity argument at all
    assert rdc4.list_archive(ar)['parity'] == (10, 2)
    bad = corrupt_pack(tmp_path, ar, pack=1)
    rep = rdc4.verify(bad)
    assert rep['needs_repair'] and rep['bad_shards']
    r = rdc4.restore(bad, tmp_path / 'out')               # repaired in flight, nothing damaged
    assert not r['damaged'] and tree_hashes(tmp_path / 'out') == tree_hashes(src)
    rdc4.repair(bad, tmp_path / 'fixed.rdc4')
    assert rdc4.verify(tmp_path / 'fixed.rdc4')['ok']


def test_cli_parity_default_no_parity_and_conflict(tmp_path):
    src = make_tree(tmp_path / 'src', MULTI)
    assert rdc4.main(['pack', str(src), str(tmp_path / 'p.rdc4')]) == 0
    assert rdc4.main(['pack', str(src), str(tmp_path / 'n.rdc4'), '--no-parity']) == 0
    assert rdc4.main(['pack', str(src), str(tmp_path / 'k.rdc4'), '--parity', '4,2,4096']) == 0
    assert rdc4.list_archive(tmp_path / 'p.rdc4')['parity'] == (10, 2)
    assert rdc4.list_archive(tmp_path / 'n.rdc4')['parity'] is None
    assert rdc4.list_archive(tmp_path / 'k.rdc4')['parity'] == (4, 2)
    assert os.path.getsize(tmp_path / 'n.rdc4') < os.path.getsize(tmp_path / 'p.rdc4')
    assert rdc4.main(['pack', str(src), str(tmp_path / 'x.rdc4'), '--parity', '4,2', '--no-parity']) != 0
    assert not (tmp_path / 'x.rdc4').exists()


def test_forced_sequential_warns_only_when_costly(tmp_path, capsys):
    thrash_archive(tmp_path / 't.rdc4', cycles=20)
    with pytest.warns(RuntimeWarning, match='crafted to waste CPU'):
        rep = rdc4.verify(tmp_path / 't.rdc4', max_decode=0)
    assert rep['verify_mode'] == 'sequential' and rep['warnings']
    with pytest.warns(RuntimeWarning):
        assert rdc4.main(['verify', str(tmp_path / 't.rdc4'), '--force-sequential']) == 0
    assert json.loads(capsys.readouterr().out)['verify_mode'] == 'sequential'
    _, ar = simple(tmp_path, spec=MULTI, **SMALLPACK)
    import warnings as w
    with w.catch_warnings():
        w.simplefilter('error')
        rep = rdc4.verify(ar, max_decode=0)
    assert rep['verify_mode'] == 'sequential' and rep['warnings'] == []


# ---------------------------------------------------------------- v3.1.3: Windows path, temp space, memory
# `sim_nt` (conftest.py) removes O_DIRECTORY, O_NOFOLLOW, pwrite/pread, fchmod and dir_fd support, as on
# Windows Python, so these run the portable restore. RDC_SIM_NT=1 runs the WHOLE suite that way.
def test_portable_restore_roundtrip_thrash_and_recover(tmp_path, sim_nt):
    src = make_tree(tmp_path / 'src', BASIC)
    rdc4.pack(src, tmp_path / 'b.rdc4', **SMALLPACK)
    r = rdc4.restore(tmp_path / 'b.rdc4', tmp_path / 'out')
    assert r['mode'] == 'portable' and tree_hashes(tmp_path / 'out') == tree_hashes(src)
    want = thrash_archive(tmp_path / 't.rdc4', cycles=2000)
    r = rdc4.restore(tmp_path / 't.rdc4', tmp_path / 'thr')
    assert r['mode'] == 'portable' and r['pack_decodes'] == 3
    assert (tmp_path / 'thr' / 'tiny.bin').read_bytes() == want['tiny.bin']
    rep = rdc4.verify(tmp_path / 't.rdc4')
    assert rep['ok'] and rep['verify_mode'] == 'pack_order' and rep['pack_decodes'] == 3
    rng = random.Random(3)
    packs = [[rng.randbytes(4096) for _ in range(8)] for _ in range(3)]
    build_unkeyed(tmp_path / 'g.rdc4', packs, [('good.bin', [0, 9, 17]), ('bad.bin', [1, 2]),
                                                ('rest.bin', list(range(24)))])
    forge(tmp_path / 'g.rdc4', tmp_path / 'f.rdc4', manifest_fn=lambda m: m['files'][1].__setitem__(2, '0' * 64))
    with pytest.raises(IntegrityError, match='digest mismatch'):
        rdc4.restore(tmp_path / 'f.rdc4', tmp_path / 'strict')
    assert not (tmp_path / 'strict').exists()
    r = rdc4.restore(tmp_path / 'f.rdc4', tmp_path / 'rec', recover=True)
    assert [d['path'] for d in r['damaged']] == ['bad.bin'] and sorted(os.listdir(tmp_path / 'rec')) == ['good.bin', 'rest.bin']


def test_portable_restore_refuses_symlinks_and_overwrite(tmp_path, sim_nt, need_links):
    need_links('symlink')
    _, ar = simple(tmp_path, spec={'d/x.txt': b'new' * 100, 'y.txt': b'y'})
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'y.txt').write_bytes(b'KEEP')
    with pytest.raises(FileExistsError):
        rdc4.restore(ar, out)
    assert (out / 'y.txt').read_bytes() == b'KEEP' and sorted(os.listdir(out)) == ['y.txt']
    out2, elsewhere = tmp_path / 'out2', tmp_path / 'elsewhere'
    out2.mkdir()
    elsewhere.mkdir()
    os.symlink(elsewhere, out2 / 'd')
    with pytest.raises(IntegrityError, match='symlink'):
        rdc4.restore(ar, out2)
    assert os.listdir(elsewhere) == []
    os.symlink(tmp_path / 'out', tmp_path / 'link')
    with pytest.raises(IntegrityError, match='symlink'):
        rdc4.restore(ar, tmp_path / 'link')


@pytest.mark.parametrize('names', [['CON.txt'], ['sub/nul'], ['a.'], ['b '], ['q?.txt'], ['A.txt', 'a.txt'],
                                   ['Dir/x', 'dir/y']])
def test_portable_restore_refuses_windows_unsafe_names(tmp_path, sim_nt, names):
    try:
        src, ar = simple(tmp_path, spec={n: b'data ' + n.encode() for n in names})
    except OSError as exc:      # 3.1.6: e.g. 'q?.txt' cannot even be created on Windows
        pytest.skip(f'this OS cannot create {names}: {exc}')
    made = sorted(p.relative_to(src).as_posix() for p in src.rglob('*') if p.is_file())
    if made != sorted(names):   # 3.1.6: real Windows renames/drops these at creation, so the archive cannot hold them
        pytest.skip(f'this OS cannot create {names} in the source tree (got {made})')
    with pytest.raises(IntegrityError, match='Windows|case-insensitively'):
        rdc4.restore(ar, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_portable_restore_of_v3_archive(tmp_path, sim_nt):
    src = make_tree(tmp_path / 'src', BASIC)
    rdc3.pack(src, tmp_path / 'a.rdc3', parity=(4, 2, 4096))
    r = rdc3.restore(tmp_path / 'a.rdc3', tmp_path / 'out')        # rdc3 hands off to the portable path
    assert r['mode'] == 'portable' and tree_hashes(tmp_path / 'out') == tree_hashes(src)


def test_portable_pack_and_repair_publish(tmp_path, sim_nt):
    src = make_tree(tmp_path / 'src', MULTI)
    rdc4.pack(src, tmp_path / 'p.rdc4', **SMALLPACK)
    bad = corrupt_pack(tmp_path, tmp_path / 'p.rdc4', pack=1)
    rdc4.repair(bad, tmp_path / 'fixed.rdc4')
    assert rdc4.verify(tmp_path / 'fixed.rdc4')['ok']


def test_pack_order_verify_needs_no_output_sized_temp(tmp_path, monkeypatch):
    """Gap 2: 3.1.2 staged the whole output in system temp. 3.1.3 keeps only unique pieces, in RAM
    up to spill_memory, so a verify on a full drive works when the unique data fits in RAM."""
    rng = random.Random(7)
    packs = [[rng.randbytes(8192) for _ in range(256)] for _ in range(4)]
    order = list(range(1024))
    rng.shuffle(order)
    build_unkeyed(tmp_path / 'd.rdc4', packs, [(f'snap{i}.bin', order[i:] + order[:i]) for i in range(8)])
    real = rdc3.shutil.disk_usage
    monkeypatch.setattr(rdc3.shutil, 'disk_usage', lambda p: real(p)._replace(free=0))
    rep = rdc4.verify(tmp_path / 'd.rdc4')
    assert rep['ok'] and rep['verify_mode'] == 'pack_order' and rep['pack_decodes'] == 4
    assert rep['spill'] == dict(bytes=8 * MiB, on_disk=False)          # output is 64 MiB; nothing on disk
    monkeypatch.setattr(rdc4.Limits4, 'spill_memory', 1 * MiB)
    with pytest.raises(LimitError, match='--temp-dir'):
        rdc4.verify(tmp_path / 'd.rdc4')                                 # clear message, before decoding
    monkeypatch.setattr(rdc3.shutil, 'disk_usage', real)
    td = tmp_path / 'scratch'
    td.mkdir()
    rep = rdc4.verify(tmp_path / 'd.rdc4', temp_dir=str(td))
    assert rep['ok'] and rep['spill'] == dict(bytes=8 * MiB, on_disk=True) and os.listdir(td) == []
    assert rdc4.main(['verify', str(tmp_path / 'd.rdc4'), '--temp-dir', str(td)]) == 0


def test_restore_plan_memory_is_per_chunk_not_per_reference(tmp_path, monkeypatch):
    """Gap 3: 3.1.2 kept a (file, offset, chunk) tuple per reference (~1.6 GiB RSS at 12M refs).
    3.1.3 stores references as 4-byte arrays and indexes by chunk."""
    rng = random.Random(1)
    packs = [[bytes([p, j, 7]) for j in range(200)] for p in range(4)]
    refs = [rng.randrange(800) for _ in range(400_000)]
    build_unkeyed(tmp_path / 'm.rdc4', packs, [('many.bin', refs)])
    monkeypatch.setattr(rdc4.Limits4, 'decode_floor', 1)
    monkeypatch.setattr(rdc4.Limits4, 'decode_factor', 0)            # force the pack-order path
    with rdc4.open_archive(tmp_path / 'm.rdc4') as a:
        assert a.files[0][3].itemsize == 4 and a.manifest['files'][0][3] is a.files[0][3]
        tracemalloc.start()
        os.mkdir(tmp_path / 'st')
        a.stage_all(str(tmp_path / 'st'), False, durable=False, spill_dir=str(tmp_path / 'st'))
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    assert a.pack_decodes == 4
    assert peak < 3 * MiB, peak                                         # 3.1.2: ~43 MiB staging peak here


def test_version_strings_agree():
    assert rdc4.__version__ == '3.1.6' and 'v3.1.6' in rdc4.__doc__.splitlines()[0]


# ---------------------------------------------------------------- 3.1.4: Windows hardening, temp dir, AEAD
def _winerr(code):
    e = OSError(13, 'simulated lock')
    e.winerror = code
    return e


def test_win_retry_transient_lock_then_success():
    calls, slept = [], []
    def fn():
        calls.append(1)
        if len(calls) < 4:
            raise _winerr(32)
        return 'ok'
    assert rdc4._win_retry(fn, sleep=slept.append) == 'ok'
    assert len(calls) == 4 and sum(slept) <= rdc4._WIN_RETRY_BUDGET


def test_win_retry_persistent_lock_raises_within_budget():
    slept = []
    def fn():
        raise _winerr(33)
    with pytest.raises(OSError):
        rdc4._win_retry(fn, sleep=slept.append)
    assert abs(sum(slept) - rdc4._WIN_RETRY_BUDGET) < 1e-9


def test_win_retry_never_retries_exists_or_other_errors():
    for exc in (FileExistsError(17, 'exists'), _winerr(2), OSError(5, 'posix eacces')):
        n = []
        def fn():
            n.append(1)
            raise exc
        with pytest.raises(type(exc)):
            rdc4._win_retry(fn, sleep=lambda d: None)
        assert len(n) == 1


def test_link_noclobber_no_rename_after_lock(tmp_path, monkeypatch):
    src, dst = tmp_path / 's', tmp_path / 'd'
    src.write_bytes(b'x')
    monkeypatch.setattr(rdc4.os, 'name', 'nt')
    monkeypatch.setattr(rdc4, '_WIN_RETRY_BUDGET', 0.0)
    def locked(*a):
        raise _winerr(32)
    renamed = []
    monkeypatch.setattr(rdc4.os, 'link', locked)
    monkeypatch.setattr(rdc4.os, 'rename', lambda *a: renamed.append(a))
    with pytest.raises(OSError):
        rdc4._link_noclobber(str(src), str(dst))
    assert not renamed


def test_link_noclobber_keeps_no_clobber(tmp_path, need_links):
    need_links('hardlink')
    src, dst = tmp_path / 's', tmp_path / 'd'
    src.write_bytes(b'new')
    dst.write_bytes(b'OLD')
    with pytest.raises(FileExistsError):
        rdc4._link_noclobber(str(src), str(dst))
    assert dst.read_bytes() == b'OLD'


def test_open_nofollow_refuses_symlink_and_identity_mismatch(tmp_path, need_links):
    need_links('symlink')
    real, other, link = tmp_path / 'real', tmp_path / 'other', tmp_path / 'link'
    real.write_bytes(b'a')
    other.write_bytes(b'b')
    link.symlink_to(real)
    with pytest.raises((IntegrityError, OSError)):
        rdc4._open_nofollow_read(str(link))
    with pytest.raises(IntegrityError):
        rdc4._open_nofollow_read(str(real), expect=os.lstat(other))
    os.close(rdc4._open_nofollow_read(str(real), expect=os.lstat(real)))


def test_open_nofollow_refuses_inode_zero(tmp_path):
    f = tmp_path / 'f'
    f.write_bytes(b'a')
    fake = os.stat_result((0o100644, 0, os.lstat(f).st_dev, 1, 0, 0, 1, 0, 0, 0))
    with pytest.raises(IntegrityError, match='inode 0'):
        rdc4._open_nofollow_read(str(f), expect=fake)


def test_missing_temp_dir_is_clean_limit_error(tmp_path):
    sp = rdc4._Spill(memory=10, dir=str(tmp_path / 'nope'))
    with pytest.raises(LimitError, match='does not exist'):
        sp.prepare(1000)


def test_no_chunk_metadata_outside_aead(tmp_path):
    """Encrypted archive: header is fixed-size sizes/salt/tags only; manifest (pack table, chunk list,
    parity layout) and every pack are ciphertext, so no chunk offsets or lengths are visible."""
    src, ar = simple(tmp_path, spec=MULTI, password=PW, gear='keyed', parity=(4, 2, 4096), **FAST, **SMALLPACK)
    raw = Path(ar).read_bytes()
    with open(ar, 'rb') as f:
        hdr = f.read(rdc3.HDR.size)
    fields = rdc3.HDR.unpack(hdr)
    mlen, plen = fields[7], fields[9]
    assert len(raw) == rdc3.HDR.size + mlen + plen          # nothing outside header + sealed blobs
    body = raw[rdc3.HDR.size:]
    for needle in (b'"chunks"', b'"packs"', b'"parity"', b'"files"', b'\x28\xb5\x2f\xfd'):
        assert needle not in body, needle                   # no plaintext JSON keys, no zstd frames
    for name in MULTI:
        assert name.encode() not in raw


# ================================================================ 3.1.5
import subprocess
import sys
import unicodedata
import warnings


def _env(**kw):
    env = dict(os.environ, PYTHONPATH=str(HERE), **kw)
    env.pop('PYTHONSAFEPATH', None)
    return env


# ---------------------------------------------------------------- 1. sys.path[0] hijack (security)
@pytest.mark.parametrize('module', ['rdc4', 'rdc3'])
def test_python_m_from_restore_destination_does_not_run_restored_module(tmp_path, module):
    marker = tmp_path / 'PWNED_argparse'
    evil = f'open({str(marker)!r}, "w").write("ran")\n'.encode()
    _, ar = simple(tmp_path, spec={'argparse.py': evil, 'json.py': evil, 'notes.txt': b'n' * 100})
    dest = tmp_path / 'dest'
    rdc4.restore(ar, dest)                                   # the restored tree now holds argparse.py
    assert (dest / 'argparse.py').read_bytes() == evil
    # control: the planted module really runs when cwd is first on sys.path
    subprocess.run([sys.executable, '-c', 'import argparse'], cwd=dest, env=_env(), check=True)
    assert marker.exists()
    marker.unlink()
    archive = ar if module == 'rdc4' else tmp_path / 'v3.rdc3'
    if module == 'rdc3':
        rdc3.pack(make_tree(tmp_path / 'src3', {'x': b'x' * 10}), archive)
    p = subprocess.run([sys.executable, '-m', module, 'verify', str(archive)], cwd=dest, env=_env(),
                       capture_output=True, text=True, timeout=120)
    assert not marker.exists(), p.stderr
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)['ok']


def test_python_m_from_own_folder_still_works(tmp_path):
    _, ar = simple(tmp_path)
    p = subprocess.run([sys.executable, '-m', 'rdc4', 'verify', str(ar)], cwd=HERE, env=_env(),
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and json.loads(p.stdout)['ok'], p.stderr


# ---------------------------------------------------------------- 2. Windows handle-based publish (mocked)
def _werr(code):
    e = OSError(None, f'simulated winerror {code}')
    e.winerror = code
    return e


class FakeNt:
    def __init__(self, **fail):
        self.calls, self.fail = [], {k: list(v) for k, v in fail.items()}

    def _hit(self, name, *a):
        self.calls.append((name,) + a)
        seq = self.fail.get(name)
        if seq:
            exc = seq.pop(0)
            if exc is not None:
                raise exc

    def open_dir(self, p):
        self._hit('open_dir', p)
        return 'DIRH'

    def open_file(self, p):
        self._hit('open_file', p)
        return 'FH'

    def flush(self, h):
        self._hit('flush', h)

    def rename_by_handle(self, fh, dh, name):
        self._hit('rename', fh, dh, name)

    def move_file_ex(self, s, d, flags):
        self._hit('move', s, d, flags)

    def close(self, h):
        self.calls.append(('close', h))

    def names(self):
        return [c[0] for c in self.calls]


DST = os.path.join('C:', 'out', 'sub', 'file.txt')


def test_nt_publish_handle_path():
    api = FakeNt()
    assert rdc4._nt_publish('S', DST, api) == 'handle_rename'
    assert api.names() == ['open_dir', 'open_file', 'flush', 'rename', 'close', 'close']
    assert api.calls[0] == ('open_dir', os.path.dirname(DST))
    assert api.calls[3] == ('rename', 'FH', 'DIRH', 'file.txt')          # leaf name relative to the dir handle
    assert ('close', 'DIRH') in api.calls and ('close', 'FH') in api.calls


@pytest.mark.parametrize('code', [1, 50, 87, 123])
@pytest.mark.parametrize('where', ['rename', 'open_file', 'flush'])
def test_nt_publish_falls_back_to_movefile_write_through_only_on_unsupported(code, where):
    api = FakeNt(**{where: [_werr(code)]})
    assert rdc4._nt_publish('S', DST, api) == 'movefile_write_through'
    move = [c for c in api.calls if c[0] == 'move']
    assert move == [('move', 'S', DST, 0x8)]
    assert not move[0][3] & 0x1                                           # never MOVEFILE_REPLACE_EXISTING
    assert api.calls[-1] == ('close', 'DIRH')


@pytest.mark.parametrize('code', [80, 183])
def test_nt_publish_exists_is_file_exists_error_without_fallback(code):
    api = FakeNt(rename=[_werr(code)])
    with pytest.raises(FileExistsError):
        rdc4._nt_publish('S', DST, api)
    assert 'move' not in api.names() and api.calls[-1] == ('close', 'DIRH')
    api = FakeNt(rename=[_werr(87)], move=[_werr(code)])                 # fallback also refuses existing names
    with pytest.raises(FileExistsError):
        rdc4._nt_publish('S', DST, api)


@pytest.mark.parametrize('code', [2, 3, 1392])
def test_nt_publish_other_errors_raise_without_fallback(code):
    api = FakeNt(rename=[_werr(code)])
    with pytest.raises(OSError) as ei:
        rdc4._nt_publish('S', DST, api)
    assert not isinstance(ei.value, FileExistsError) and 'move' not in api.names()


def test_nt_publish_retries_transient_locks(monkeypatch):
    monkeypatch.setattr(rdc4, '_WIN_RETRY_BUDGET', 0.2)
    import time
    monkeypatch.setattr(time, 'sleep', lambda d: None)
    api = FakeNt(open_file=[_werr(32)], rename=[_werr(5), _werr(33)])
    assert rdc4._nt_publish('S', DST, api) == 'handle_rename'
    assert api.names().count('open_file') == 2 and api.names().count('rename') == 3
    api = FakeNt(rename=[_werr(32)] * 1000)                              # persistent lock: raised, no fallback
    with pytest.raises(OSError):
        rdc4._nt_publish('S', DST, api)
    assert 'move' not in api.names()


def test_nt_publish_refuses_reparse_folder():
    api = FakeNt(open_dir=[IntegrityError('publish folder is a reparse point')])
    with pytest.raises(IntegrityError):
        rdc4._nt_publish('S', DST, api)
    assert api.names() == ['open_dir']


def test_windows_code_imports_cleanly_elsewhere(tmp_path):
    if sys.platform == 'win32':
        pytest.skip('real Windows')
    with pytest.raises(NotImplementedError):
        rdc4._NtApi()
    src, dst = tmp_path / 's', tmp_path / 'd'
    src.write_bytes(b'x')
    assert rdc4._publish_noclobber(str(src), str(dst)) == 'link' and dst.read_bytes() == b'x'
    with pytest.raises(FileExistsError):
        rdc4._publish_noclobber(str(src), str(dst))
    assert rdc3._WIN_PUBLISH is None


def test_atomic_publish_uses_windows_hook_and_reports_honestly(tmp_path, monkeypatch):
    used = []

    def hook(temp, dest):
        used.append((temp, dest))
        os.rename(temp, dest)
        return 'handle_rename'
    monkeypatch.setattr(rdc3, '_WIN_PUBLISH', hook)
    r = rdc3.atomic_publish_file(tmp_path / 'out.bin', lambda f: f.write(b'data'))
    monkeypatch.undo()
    assert used and r['publish'] == 'handle_rename' and (tmp_path / 'out.bin').read_bytes() == b'data'
    assert [n for n in os.listdir(tmp_path) if n != 'out.bin'] == []
    r = rdc3.atomic_publish_file(tmp_path / 'out2.bin', lambda f: f.write(b'x'))
    if sys.platform == 'win32':   # 3.1.6: real Windows installs the handle-rename hook by default; no dir fsync
        assert r['publish'] == 'handle_rename' and r['directories_fsynced'] is False
    else:
        assert r == dict(sync_mode='fsync', directories_fsynced=True, publish='link')


# ---------------------------------------------------------------- 3. zstd backend fallback
def _backend(name):
    try:
        return rdc3.load_zstd_backend(name)
    except rdc3.BackendUnavailable:
        pytest.skip(f'{name} not installed here')


def _raw_block_frame(payload, wd):
    """zstd frame: no content size, window descriptor wd, one raw last block."""
    return b'\x28\xb5\x2f\xfd' + bytes([0x00, wd]) + ((len(payload) << 3) | 1).to_bytes(3, 'little') + payload


def test_backend_order_and_env_hook():
    assert rdc3.ZSTD_BACKENDS == ('zstandard', 'compression.zstd', 'backports.zstd')
    code = 'import rdc3; print(rdc3.ZB.name)'
    for name in rdc3.ZSTD_BACKENDS:
        p = subprocess.run([sys.executable, '-c', code], cwd=HERE, env=_env(RDC_ZSTD_BACKEND=name),
                           capture_output=True, text=True, timeout=60)
        try:
            rdc3.load_zstd_backend(name)
        except rdc3.BackendUnavailable:
            assert p.returncode != 0 and 'not installed' in p.stderr
            continue
        assert p.returncode == 0 and p.stdout.strip() == name, p.stderr
    p = subprocess.run([sys.executable, '-c', code], cwd=HERE, env=_env(RDC_ZSTD_BACKEND='nope'),
                       capture_output=True, text=True, timeout=60)
    assert p.returncode != 0 and 'unknown zstd backend' in p.stderr
    with pytest.raises(rdc3.BackendUnavailable):
        rdc3.load_zstd_backend('nope')


def test_frame_header_parser_matches_zstandard():
    rng = random.Random(5)
    d = zstd.train_dictionary(4096, [b'sample %d ' % i * rng.randint(2, 30) for i in range(600)])
    for n in (1, 255, 256, 257, 65535, 65536 + 300, 3 << 20):
        data = rng.randbytes(n // 2) + b'\0' * (n - n // 2)
        frames = [zstd.ZstdCompressor(level=1).compress(data),
                  zstd.ZstdCompressor(level=3, write_content_size=False).compress(data),
                  zstd.ZstdCompressor(level=3, dict_data=d).compress(data),
                  zstd.ZstdCompressor(compression_params=zstd.ZstdCompressionParameters(
                      window_log=22, write_content_size=1)).compress(data)]
        c = zstd.ZstdCompressor(level=3)
        frames.append(b''.join(c.read_to_iter(__import__('io').BytesIO(data))))   # streamed: window descriptor
        for fr in frames:
            p = zstd.get_frame_parameters(fr)
            cs, ws, did = rdc3.parse_zstd_frame_header(fr)
            assert (cs if cs >= 0 else -1, ws, did) == (p.content_size if p.content_size < 2**63 else -1,
                                                        p.window_size, p.dict_id), (n, fr[:8].hex())
    for bad in (b'', b'\x28\xb5\x2f', b'\x28\xb5\x2f\xfd\x08', b'\x50\x2a\x4d\x18' + b'\0' * 8):
        with pytest.raises(ValueError):
            rdc3.parse_zstd_frame_header(bad)


@pytest.mark.parametrize('name', list(rdc3.ZSTD_BACKENDS))
def test_backend_window_log_max_24(name):
    be = _backend(name)
    payload = b'abc' * 100
    ok = _raw_block_frame(payload, 0x70)              # window 2**24: accepted
    big = _raw_block_frame(payload, 0x78)             # window 2**25: refused even if the caller allows more
    assert be.decompress(ok, len(payload), None, 1 << 26) == payload
    with pytest.raises(Exception):
        be.decompress(big, len(payload), None, 1 << 26)
    with pytest.raises(Exception):                    # trailing bytes refused
        be.decompress(ok + b'\0', len(payload), None, 1 << 24)


@pytest.mark.parametrize('name', list(rdc3.ZSTD_BACKENDS))
@pytest.mark.parametrize('wlog', [25, 26])
def test_backend_window_cap_with_content_size(name, wlog):   # 3.1.6 (SEEKER): content-size frames too
    be = _backend(name)
    payload = b'xyz' * 1000
    wd = (wlog - 10) << 3                                            # window descriptor, mantissa 0
    fr = (b'\x28\xb5\x2f\xfd' + bytes([0x80, wd]) + len(payload).to_bytes(4, 'little')   # FCS 4 bytes, not single-segment
          + ((len(payload) << 3) | 1).to_bytes(3, 'little') + payload)
    assert rdc3.parse_zstd_frame_header(fr)[:2] == (len(payload), 1 << wlog)
    with pytest.raises(Exception):
        be.decompress(fr, len(payload), None, 1 << 30)
    with pytest.raises(Exception):
        be.decompress(fr, len(payload), None, 1 << 20)
    ok = fr[:5] + bytes([0x70]) + fr[6:]                             # same frame at 2**24 still decodes
    assert be.decompress(ok, len(payload), None, 1 << 24) == payload


def test_cryptography_floor_warns(monkeypatch):
    import cryptography
    monkeypatch.setattr(cryptography, '__version__', '43.0.0')
    monkeypatch.setattr(rdc3, '_crypto_floor_checked', False)
    with pytest.warns(RuntimeWarning, match='floor'):
        rdc3._check_cryptography_floor()
    monkeypatch.setattr(cryptography, '__version__', '46.0.7')
    monkeypatch.setattr(rdc3, '_crypto_floor_checked', False)
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        rdc3._check_cryptography_floor()


@pytest.mark.parametrize('name', list(rdc3.ZSTD_BACKENDS))
def test_backend_roundtrip_cross_decode_and_v302_fixtures(tmp_path, monkeypatch, name):
    be = _backend(name)
    zs = rdc3.load_zstd_backend('zstandard')
    monkeypatch.setattr(rdc3, 'ZB', be)
    stats, ar = roundtrip(tmp_path, BASIC, parity=(4, 2, 4096), **SMALLPACK)
    assert stats['zstd_backend'] == name
    monkeypatch.setattr(rdc3, 'ZB', zs)                       # written by `name`, read by zstandard
    assert rdc4.verify(ar)['ok']
    ar2 = tmp_path / 'z.rdc4'
    rdc4.pack(tmp_path / 'src', ar2, **SMALLPACK)
    monkeypatch.setattr(rdc3, 'ZB', be)                       # written by zstandard, read by `name`
    assert rdc4.verify(ar2)['ok'] and rdc4.verify(ar2, max_decode=0)['ok']
    exp = json.loads((COMPAT / 'expected.json').read_text())
    for fx in ('v302-plain.rdc3', 'v302-dict-delta.rdc3', 'v302-keyed-parity.rdc3'):
        out = tmp_path / ('fx-' + fx)
        rdc4.restore(COMPAT / fx, out, exp['password'] if 'keyed' in fx else None)
        assert {k: v for k, v in tree_hashes(out).items() if v != 'dir'} == exp['files']
    v3ar = tmp_path / 'delta.rdc3'                            # RDCv003 delta writing works on every backend
    rdc3.pack(make_tree(tmp_path / 'src3', BASIC), v3ar, delta=True)
    rdc4.restore(v3ar, tmp_path / 'o3')
    assert tree_hashes(tmp_path / 'o3') == tree_hashes(tmp_path / 'src3')


def test_dictionary_training_is_zstandard_only(tmp_path, monkeypatch):
    fake = rdc3._StdlibBackend(None, 'compression.zstd')
    with pytest.raises(rdc3.BackendUnavailable, match='needs the zstandard package'):
        fake.train(1024, [b'x'], 3)
    monkeypatch.setattr(rdc3, 'ZB', fake)
    with pytest.raises(rdc3.BackendUnavailable, match='pack without --dict'):
        rdc3.pack(make_tree(tmp_path / 'src', BASIC), tmp_path / 'd.rdc3', use_dict=True)
    assert not (tmp_path / 'd.rdc3').exists()
    assert rdc4.main(['pack', str(tmp_path / 'src'), str(tmp_path / 'e.rdc3'), '--format', '3', '--dict']) == 1


# ---------------------------------------------------------------- 4. requirements
def test_requirements_floor():
    req = (HERE / 'requirements-v3.txt').read_text()
    assert 'cryptography>=46.0.7' in req


# ---------------------------------------------------------------- 5. verify --packs n/t
def _packs_archive(tmp_path, **kw):
    spec = {f'f{i}.bin': random.Random(i).randbytes(50_000) + b'z' * 30_000 for i in range(8)}
    kw.setdefault('parity', (4, 2, 4096))
    return simple(tmp_path, spec=spec, **SMALLPACK, **kw)


def test_verify_packs_rotation_covers_everything_without_decoding(tmp_path, monkeypatch):
    _, ar = _packs_archive(tmp_path)
    monkeypatch.setattr(rdc4.Archive4, '_decode_pack', lambda *a: pytest.fail('partial verify decoded a pack'))
    with rdc4.open_archive(ar) as a:
        npacks, ngroups = len(a.packs), len(a.parity[2])
        assert npacks >= 6
        seen_packs, seen_groups = set(), set()
        for n in range(3):
            r = a.verify_packs(n, 3)
            assert r['ok'] and not r['needs_repair'] and r['verify_mode'] == 'partial' and r['pack_decodes'] == 0
            assert r['packs_checked'] == len(range(n, npacks, 3))
            seen_packs |= set(range(n, npacks, 3))
            seen_groups.add(r['groups_checked'])
        assert seen_packs == set(range(npacks))
    total = sum(rdc4.verify(ar, packs=f'{n}/3')['groups_checked'] for n in range(3))
    assert total >= ngroups
    assert rdc4.verify(ar, packs=(0, 1))['groups_checked'] == ngroups   # 0/1 = every pack and shard
    assert rdc4.verify(ar, packs='999/1000')['packs_checked'] == 0          # empty slice is fine


def test_verify_packs_finds_damage_only_in_its_slice(tmp_path):
    _, ar = _packs_archive(tmp_path, parity=None)
    bad = corrupt_pack(tmp_path, ar, pack=4, password=None)
    hits = {n: rdc4.verify(bad, packs=(n, 3))['bad_packs'] for n in range(3)}
    assert hits == {0: [], 1: [4], 2: []}
    assert rdc4.main(['verify', str(bad), '--packs', '1/3']) == 4
    assert rdc4.main(['verify', str(bad), '--packs', '0/3']) == 0


def test_verify_packs_checks_parity_shards_and_encrypted_aead(tmp_path):
    _, ar = _packs_archive(tmp_path, password=PW, gear='keyed', **FAST)
    with rdc4.open_archive(ar, PW) as a:
        k, m, groups = a.parity
        gs, gl, s, poff, _ = groups[-1]
        pos = a.base + poff + 5                                   # a parity shard of the last group
    raw = bytearray(Path(ar).read_bytes())
    raw[pos] ^= 1
    bad = tmp_path / 'p.rdc4'
    bad.write_bytes(bytes(raw))
    found = [rdc4.verify(bad, PW, packs=(n, 2))['bad_shards'] for n in range(2)]
    assert any(found) and all(b[0][1] >= k for b in found if b)
    assert all(rdc4.verify(ar, PW, packs=(n, 2))['ok'] for n in range(2))


def test_verify_packs_aead_checked_when_encrypted(tmp_path, monkeypatch):
    _, ar = _packs_archive(tmp_path, password=PW, gear='keyed', parity=None, **FAST)
    opened = []
    real = rdc3.Ctx.open
    monkeypatch.setattr(rdc3.Ctx, 'open', lambda self, d, i, b: opened.append(i) or real(self, d, i, b))
    r = rdc4.verify(ar, PW, packs=(1, 2))
    assert r['ok'] and opened == list(range(1, r['packs_total'], 2))


def test_verify_packs_bad_arguments(tmp_path):
    _, ar = _packs_archive(tmp_path)
    for bad in ('3/3', '1', 'a/b', '-1/2', '0/0'):
        with pytest.raises(ValueError):
            rdc4.verify(ar, packs=bad)
        assert rdc4.main(['verify', str(ar), '--packs=' + bad]) == 1
    with pytest.raises(ValueError, match='RDCv004-only'):
        rdc4.verify(COMPAT / 'v302-plain.rdc3', packs='0/2')


# ---------------------------------------------------------------- 6. --sparse
def _fs_supports_holes(d):
    p = d / '.holetest'
    with open(p, 'wb') as f:
        f.truncate(8 << 20)
    ok = os.stat(p).st_blocks * 512 < (1 << 20)
    p.unlink()
    return ok


SPARSE = {'disk.img': RNG.randbytes(100_000) + bytes(6 << 20) + RNG.randbytes(70_000) + bytes(3 << 20),
          'tail_hole.bin': b'head' * 1000 + bytes(2 << 20), 'all_zero.bin': bytes(1 << 20), 'plain.txt': b'hello'}


@pytest.mark.parametrize('variant', ['v4', 'v4-pack-order', 'v3', 'v4-portable'])
def test_sparse_restore_identical_bytes_fewer_blocks(tmp_path, monkeypatch, variant):
    src = make_tree(tmp_path / 'src', SPARSE)
    ar = tmp_path / 'a.rdc'
    if variant == 'v3':
        rdc3.pack(src, ar)
    else:
        rdc4.pack(src, ar, **SMALLPACK)
    if variant == 'v4-pack-order':
        monkeypatch.setattr(rdc4.Archive4, '_sequential_ok', lambda self, files: False)
    kw = dict(portable=True) if variant == 'v4-portable' else {}
    dense = rdc4.restore(ar, tmp_path / 'dense', **kw)
    sparse = rdc4.restore(ar, tmp_path / 'sparse', sparse=True, **kw)
    assert sparse['sparse'] and not dense['sparse']
    assert tree_hashes(tmp_path / 'sparse') == tree_hashes(src) == tree_hashes(tmp_path / 'dense')
    for name in SPARSE:
        assert os.path.getsize(tmp_path / 'sparse' / name) == len(SPARSE[name])
    if sys.platform.startswith('linux') and _fs_supports_holes(tmp_path):
        blocks = lambda d: sum(os.stat(tmp_path / d / n).st_blocks for n in SPARSE)
        assert blocks('sparse') * 512 < blocks('dense') * 512 - (8 << 20), (blocks('sparse'), blocks('dense'))
        assert os.stat(tmp_path / 'sparse' / 'all_zero.bin').st_blocks == 0


def test_sparse_cli_and_damage_still_refused(tmp_path):
    src = make_tree(tmp_path / 'src', SPARSE)
    ar = tmp_path / 'a.rdc4'
    rdc4.pack(src, ar, parity=None, **SMALLPACK)
    assert rdc4.main(['unpack', str(ar), str(tmp_path / 'o'), '--sparse']) == 0
    assert tree_hashes(tmp_path / 'o') == tree_hashes(src)
    bad = corrupt_pack(tmp_path, ar, pack=0, password=None)
    with pytest.raises(IntegrityError):
        rdc4.restore(bad, tmp_path / 'o2', sparse=True)
    assert not (tmp_path / 'o2').exists()


def test_sparse_hashes_zero_pieces(tmp_path, monkeypatch):
    """A forged archive whose zero piece hashes are right but whose file digest is wrong is refused
    in sparse mode too (the zero pieces are hashed, not just skipped)."""
    src = make_tree(tmp_path / 'src', {'z.bin': bytes(300_000) + b'end'})
    ar, bad = tmp_path / 'a.rdc4', tmp_path / 'f.rdc4'
    rdc4.pack(src, ar, parity=None, **SMALLPACK)

    def fn(m):
        m['files'][0][2] = hashlib.sha256(b'end').hexdigest()
    forge(ar, bad, manifest_fn=fn)
    with pytest.raises(IntegrityError, match='digest'):
        rdc4.restore(bad, tmp_path / 'o', sparse=True)


# ---------------------------------------------------------------- 7. name collisions
NFC, NFD = unicodedata.normalize('NFC', 'café.txt'), unicodedata.normalize('NFD', 'café.txt')


def test_collision_keys():
    k = rdc4.collision_key
    assert k('Readme.md') == k('README.md') and k('Readme.md', True, True) == k('README.md', True, True)
    assert k('straße') != k('strasse')                                   # NTFS: 1:1 upcase, distinct names
    assert k(NFC) != k(NFD)                                              # NTFS does not normalize
    assert k(NFC, True, True) == k(NFD, True, True)                      # APFS/HFS+: NFD + casefold
    assert k(NFC, False, True) == k(NFD, False, True) and k('A', False, True) != k('a', False, True)
    assert k('Readme.md', False, False) != k('README.md', False, False)
    assert rdc4.find_name_collisions(['Docs/a', 'docs/b'], []) == [('Docs', 'docs')]
    rdc4.check_portable_tree(['straße', 'strasse'], [])                  # 3.1.4 refused this for nothing


def test_probe_on_this_filesystem_leaves_nothing(tmp_path):
    sem = rdc4.probe_name_semantics(str(tmp_path))
    assert set(sem) == {'case_insensitive', 'normalization_insensitive'}
    assert os.listdir(tmp_path) == []
    if sys.platform.startswith('linux'):
        assert sem == dict(case_insensitive=False, normalization_insensitive=False)


@pytest.mark.parametrize('pair', [['Readme.md', 'README.md'], [NFC, NFD]], ids=['case', 'nfc-nfd'])
def test_posix_collision_warns_by_default_strict_refuses(tmp_path, pair):
    if not sys.platform.startswith('linux'):
        pytest.skip('needs a case/normalization-sensitive filesystem')
    if _portable_in_use():
        pytest.skip('portable (Windows-rules) mode refuses case pairs; covered by the portable tests')
    _, ar = simple(tmp_path, spec={p: p.encode() for p in pair})
    with pytest.warns(RuntimeWarning, match='collision'):
        r = rdc4.restore(ar, tmp_path / 'out')
    assert r['name_warnings'] and sorted(os.listdir(tmp_path / 'out')) == sorted(pair)
    with pytest.raises(IntegrityError, match='strict-names'):
        rdc4.restore(ar, tmp_path / 'out2', strict_names=True)
    assert not (tmp_path / 'out2').exists()
    assert rdc4.main(['unpack', str(ar), str(tmp_path / 'out3'), '--strict-names']) == 1


def _portable_in_use():   # 3.1.6: the mode restore() will actually use (RDC_PORTABLE=1 forces portable)
    return os.environ.get('RDC_PORTABLE') == '1' or not rdc4.posix_fd_restore_supported()


@pytest.mark.parametrize('sem,pair,refused', [
    (dict(case_insensitive=True, normalization_insensitive=True), ['Readme.md', 'README.md'], True),   # macOS
    (dict(case_insensitive=True, normalization_insensitive=True), [NFC, NFD], True),
    (dict(case_insensitive=True, normalization_insensitive=False), ['Readme.md', 'README.md'], True),  # NTFS
    (dict(case_insensitive=True, normalization_insensitive=False), [NFC, NFD], False),
    (dict(case_insensitive=True, normalization_insensitive=False), ['straße', 'strasse'], False),
    (dict(case_insensitive=False, normalization_insensitive=True), [NFC, NFD], True),
])
def test_insensitive_destination_refuses_before_staging(tmp_path, monkeypatch, sem, pair, refused):
    if not sys.platform.startswith('linux'):
        pytest.skip('pair must be creatable in the source tree')
    _, ar = simple(tmp_path, spec={p: p.encode() for p in pair})
    monkeypatch.setattr(rdc4, 'probe_name_semantics', lambda d: dict(sem))
    if refused:
        monkeypatch.setattr(rdc4, '_stage_create', lambda *a: pytest.fail('staged before collision check'))
        with pytest.raises(IntegrityError, match='collide on this destination' if not _portable_in_use()
                           else 'collide'):            # portable mode: Windows rules refuse case pairs first
            rdc4.restore(ar, tmp_path / 'out')
        assert not (tmp_path / 'out').exists()
    else:
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            r = rdc4.restore(ar, tmp_path / 'out')
        assert r['name_semantics'] == sem and r['name_warnings'] == []


def test_collision_check_also_runs_in_portable_mode(tmp_path, monkeypatch, sim_nt):
    _, ar = simple(tmp_path, spec={NFC: b'1', NFD: b'2'})
    monkeypatch.setattr(rdc4, 'probe_name_semantics',
                        lambda d: dict(case_insensitive=True, normalization_insensitive=True))
    with pytest.raises(IntegrityError, match='collide'):
        rdc4.restore(ar, tmp_path / 'out')


# ---------------------------------------------------------------- 8. durable sync
class FakeFcntl:
    F_FULLFSYNC = 51

    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def fcntl(self, fd, op):
        self.calls.append(op)
        if self.fail:
            raise OSError(errno.ENOTSUP, 'F_FULLFSYNC not supported')


import errno


@pytest.mark.parametrize('fail', [False, True])
def test_durable_sync_full_fsync_on_darwin(tmp_path, monkeypatch, fail):
    fake = FakeFcntl(fail)
    synced = []
    real_fsync = os.fsync
    monkeypatch.setattr(rdc3, '_IS_DARWIN', True)
    monkeypatch.setattr(rdc3, 'fcntl', fake)
    monkeypatch.setattr(rdc3.os, 'fsync', lambda fd: synced.append(fd) or real_fsync(fd))
    log = rdc3.SyncLog()
    with open(tmp_path / 'f', 'wb') as f:
        mode = rdc3._durable_sync(f.fileno(), log)
    assert fake.calls == [FakeFcntl.F_FULLFSYNC] and len(synced) == 1
    assert mode == log.mode == ('fsync' if fail else 'full_fsync')       # never claims full_fsync after failure


def test_durable_sync_reported_by_restore_and_pack(tmp_path, monkeypatch):
    src = make_tree(tmp_path / 'src', {'a/b.txt': b'b' * 1000, 'c.txt': b'c'})
    st = rdc4.pack(src, tmp_path / 'a.rdc4')
    can_dir = hasattr(os, 'O_DIRECTORY')                                  # False under RDC_SIM_NT (like Windows)
    assert st['sync_mode'] == 'fsync' and st['directories_fsynced'] is can_dir
    r = rdc4.restore(tmp_path / 'a.rdc4', tmp_path / 'o1')
    assert r['sync_mode'] == 'fsync' and r['directories_fsynced'] is can_dir
    fake = FakeFcntl()
    monkeypatch.setattr(rdc3, '_IS_DARWIN', True)
    monkeypatch.setattr(rdc3, 'fcntl', fake)
    r = rdc4.restore(tmp_path / 'a.rdc4', tmp_path / 'o2')
    assert r['sync_mode'] == 'full_fsync' and len(fake.calls) >= (4 if can_dir else 2)   # 2 files (+ root, a/)
    st = rdc4.pack(src, tmp_path / 'b.rdc4')
    assert st['sync_mode'] == 'full_fsync'                                # archive temp file + its folder
    fake.fail = True
    r = rdc4.restore(tmp_path / 'a.rdc4', tmp_path / 'o3')
    assert r['sync_mode'] == 'fsync'


def test_portable_restore_reports_no_directory_fsync_when_impossible(tmp_path, sim_nt):
    _, ar = simple(tmp_path)
    r = rdc4.restore(ar, tmp_path / 'out')
    assert r['mode'] == 'portable' and r['directories_fsynced'] is False and r['sync_mode'] == 'fsync'
    assert r['publish'] == (['handle_rename'] if sys.platform == 'win32' else ['link'])   # 3.1.6


# ---------------------------------------------------------------- 9. tampered RDCv003 dictionary
def _v3_dict_archive(tmp_path):
    src = tmp_path / 'src'
    src.mkdir()
    rng = random.Random(8)
    for i in range(40):
        (src / f'f{i}.txt').write_bytes(b''.join((b'record %06d alpha beta gamma delta %d ' % (j, i)) * 3 +
                                                 rng.randbytes(4) for j in range(400)))
    ar = tmp_path / 'd.rdc3'
    active, rdc3.ZB = rdc3.ZB, rdc3.load_zstd_backend('zstandard')   # training is zstandard-only;
    try:                                                              # reading below uses the active backend
        st = rdc3.pack(src, ar, use_dict=True, min_size=1024, avg_size=4096, max_size=16384)
    finally:
        rdc3.ZB = active
    assert st['dict_trained'] and st['codec_counts']['zstd-dict'] > 0
    return src, ar


def _swap_dictionary(ar, dst):
    """Unkeyed RDCv003: replace the stored dictionary with a fuzzed one (same magic, id and entropy
    tables, content bytes scrambled), then recompute its tag, the manifest, root and header tag."""
    raw = Path(ar).read_bytes()
    f = list(rdc3.HDR.unpack(raw[:rdc3.HDR.size]))
    m = json.loads(zstd.ZstdDecompressor().decompress(raw[rdc3.HDR.size:rdc3.HDR.size + f[7]]))
    payload = bytearray(raw[rdc3.HDR.size + f[7]:])
    dlen = m['dict'][0]
    d = bytearray(payload[:dlen])
    for i in range(dlen // 2, dlen):
        d[i] ^= 0x5A
    payload[:dlen] = d
    m['dict'][2] = hashlib.sha256(bytes(d)).hexdigest()
    f[10] = hashlib.sha256(b'rdc3-root\0' + rdc3.canonical(dict(files=[x[:3] for x in m['files']],
                                                                  dirs=m['dirs']))).digest()
    mraw = rdc3.canonical(m)
    mc = zstd.ZstdCompressor(level=3, write_content_size=True).compress(mraw)
    f[7], f[8], f[9] = len(mc), len(mraw), len(payload)
    prefix = rdc3.HDR.pack(*f[:11], b'\0' * 32)[:rdc3.HDR_PREFIX]
    Path(dst).write_bytes(prefix + hashlib.sha256(prefix + mc).digest() + mc + bytes(payload))


def test_tampered_v003_dictionary_refused_and_post_decode_check_is_what_stops_it(tmp_path, monkeypatch):
    src, ar = _v3_dict_archive(tmp_path)
    bad = tmp_path / 'bad.rdc3'
    _swap_dictionary(ar, bad)
    with rdc3.Archive(bad) as a:                              # header, manifest, dict tag, root: all consistent
        assert a.dict_rec is not None
    with pytest.raises(IntegrityError):
        rdc4.restore(bad, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()
    with pytest.raises(IntegrityError):
        rdc4.verify(bad)
    with rdc3.Archive(ar) as a:
        good = {i: a.chunk(i) for i, c in enumerate(a.chunks) if c[0] == rdc3.CODEC_DICT}

    class NoChunkCheck:                                      # disable ONLY the post-decode chunk-id comparison
        compare_digest = staticmethod(lambda x, y: True if isinstance(x, str) else hmac.compare_digest(x, y))
    import hmac
    monkeypatch.setattr(rdc3, 'hmac', NoChunkCheck)
    wrong = 0
    with rdc3.Archive(bad) as a:
        for i, raw in good.items():
            try:
                out = a.chunk(i)
            except IntegrityError:
                continue                                      # some mutations make libzstd error instead
            wrong += out != raw
    assert wrong > 0                                          # without the check, bad bytes get through


# ---------------------------------------------------------------- 10. manifest: HMAC before decrypt
@pytest.mark.parametrize('fmt', [3, 4])
def test_manifest_authenticated_before_decrypt(tmp_path, monkeypatch, fmt):
    src = make_tree(tmp_path / 'src', BASIC)
    ar = tmp_path / 'e.rdc'
    (rdc3.pack if fmt == 3 else rdc4.pack)(src, ar, password=PW, gear='keyed', **FAST)
    events = []
    real_tag, Real = rdc3.Ctx.tag, rdc3.ChaCha20Poly1305

    class Spy:
        def __init__(self, key):
            self._c = Real(key)

        def encrypt(self, *a):
            return self._c.encrypt(*a)

        def decrypt(self, nonce, data, aad):
            events.append(('decrypt', nonce))
            return self._c.decrypt(nonce, data, aad)
    monkeypatch.setattr(rdc3, 'ChaCha20Poly1305', Spy)
    monkeypatch.setattr(rdc3.Ctx, 'tag', lambda self, data: events.append(('tag', len(data))) or real_tag(self, data))
    f = rdc3.HDR.unpack(Path(ar).read_bytes()[:rdc3.HDR.size])
    manifest_nonce = struct.pack('>IQ', 1, 0)
    with rdc4.open_archive(ar, PW):
        pass
    first = next(i for i, e in enumerate(events) if e == ('decrypt', manifest_nonce))
    assert ('tag', rdc3.HDR_PREFIX + f[7]) in events[:first]                     # header+manifest MAC first
    raw = bytearray(Path(ar).read_bytes())
    raw[rdc3.HDR.size + f[7] // 2] ^= 1                                          # flip a manifest ciphertext bit
    (tmp_path / 't.rdc').write_bytes(bytes(raw))
    events.clear()
    with pytest.raises(IntegrityError, match='authentication failed'):
        rdc4.open_archive(tmp_path / 't.rdc', PW)
    assert not [e for e in events if e[0] == 'decrypt']                          # never decrypted


import struct


# ---------------------------------------------------------------- 11. ELOOP -> IntegrityError
def test_nofollow_open_eloop_is_integrity_error(tmp_path, need_links):
    need_links('symlink')
    if not hasattr(os, 'O_NOFOLLOW'):
        pytest.skip('POSIX only')
    real, link = tmp_path / 'real', tmp_path / 'link'
    real.write_bytes(b'a')
    link.symlink_to(real)
    with pytest.raises(IntegrityError, match='symlink'):
        rdc4._open_nofollow_read(str(link))
    with pytest.raises(FileNotFoundError):                                       # other errors unchanged
        rdc4._open_nofollow_read(str(tmp_path / 'missing'))


# ---------------------------------------------------------------- 12. '..' entries and planted symlinks
@pytest.mark.parametrize('bad', ['..', 'a/..', '../up', 'a/../b', '.', 'x/./y'])
def test_dotdot_directory_entries_refused(tmp_path, bad):
    _, ar = simple(tmp_path, spec={'a/f.txt': b'f'})
    forged = tmp_path / 'f.rdc4'
    forge(ar, forged, manifest_fn=lambda m: m['dirs'].append(bad))
    with pytest.raises(IntegrityError, match='unsafe path'):
        rdc4.restore(forged, tmp_path / 'out')
    assert not (tmp_path / 'out').exists() and sorted(os.listdir(tmp_path)) == ['a.rdc4', 'f.rdc4', 'src']


@pytest.mark.parametrize('portable', [False, True])
@pytest.mark.parametrize('dangling', [False, True])
def test_symlink_planted_at_file_path_never_followed(tmp_path, portable, dangling, need_links):
    need_links('symlink')
    if not portable and not rdc4.posix_fd_restore_supported():
        pytest.skip('descriptor-relative mode unavailable on this platform (no dir_fd/O_NOFOLLOW; e.g. Windows or RDC_SIM_NT=1)')
    _, ar = simple(tmp_path, spec={'d/x.txt': b'NEW' * 10, 'y.txt': b'NEW'})
    target = tmp_path / 'target.txt'
    if not dangling:
        target.write_bytes(b'KEEP')
    out = tmp_path / 'out'
    (out / 'd').mkdir(parents=True)
    os.symlink(target, out / 'd' / 'x.txt')
    with pytest.raises(FileExistsError):
        rdc4.restore(ar, out, portable=portable)
    assert (target.read_bytes() == b'KEEP') if not dangling else not target.exists()
    assert sorted(os.listdir(out)) == ['d'] and os.listdir(out / 'd') == ['x.txt']


@pytest.mark.parametrize('portable', [False, True])
@pytest.mark.parametrize('when', ['before', 'during_staging'])
def test_symlink_planted_as_folder_never_followed(tmp_path, monkeypatch, portable, when, need_links):
    need_links('symlink')
    if not portable and not rdc4.posix_fd_restore_supported():
        pytest.skip('descriptor-relative mode unavailable on this platform (no dir_fd/O_NOFOLLOW; e.g. Windows or RDC_SIM_NT=1)')
    _, ar = simple(tmp_path, spec={'d/sub/x.txt': b'NEW' * 10, 'y.txt': b'NEW'})
    outside = tmp_path / 'outside'
    outside.mkdir()
    out = tmp_path / 'out'
    out.mkdir()
    if when == 'before':
        os.symlink(outside, out / 'd')
    else:
        real = rdc4._write_staged

        def plant(*a, **kw):
            if not os.path.lexists(out / 'd'):
                os.symlink(outside, out / 'd')                                  # swapped in after the pre-check
            return real(*a, **kw)
        monkeypatch.setattr(rdc4, '_write_staged', plant)
    with pytest.raises(IntegrityError, match='symlink'):
        rdc4.restore(ar, out, portable=portable)
    assert os.listdir(outside) == []
    assert not (out / 'y.txt').exists()                                          # nothing published


# ---------------------------------------------------------------- 13. README notes / version
def test_readme_documents_315_caveats():
    readme = (HERE / 'README.md').read_text()
    for needle in ('python -P -m rdc4', 'does not cover the manifest', '192 KiB', '64-bit Python',
                   'not a full crash guarantee', 'F_FULLFSYNC', '--packs', '--sparse', '--strict-names'):
        assert needle in readme, needle
    changelog = (HERE / 'CHANGELOG.md').read_text()
    assert '3.1.5' in changelog and 'RDCv005' in changelog
