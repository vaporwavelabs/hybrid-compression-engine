"""RDCv003 acceptance tests: round trips, safety, peer (WEB/SEEKER) regressions, parity drills, fuzz."""
import hashlib
import json
import os
import random
import struct
import tracemalloc
from pathlib import Path

import numpy as np
import pytest
import zstandard as zstd

import rdc3
from rdc3 import IntegrityError, PublicationError

PW = 'test-only-password'   # throwaway test credential
FAST = dict(kdf_log2n=10)


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


def roundtrip(tmp, spec, password=None, **kw):
    src = make_tree(tmp / 'src', spec)
    ar = tmp / 'a.rdc3'
    stats = rdc3.pack(src, ar, password=password, **kw)
    out = tmp / 'out'
    rdc3.restore(ar, out, password)
    assert tree_hashes(out) == tree_hashes(src)
    assert rdc3.verify(ar, password)['ok']
    return stats, ar


RNG = random.Random(20261109)
REDUNDANT = b'2026-11-09T21:00:00Z INFO request ok path=/api/v1/items status=200\n' * 40000
BASIC = {'empty.txt': b'', 'tiny': b'x', 'text.txt': b'lossless round trip\n' * 5000,
         'random.bin': RNG.randbytes(300_000), 'sub/deeper/redundant.log': REDUNDANT,
         'sub/dup.log': REDUNDANT, 'emptydir': None}


# ---------------------------------------------------------------- forging helper (unkeyed archives)
def forge(src, dst, manifest_fn=None, payload_fn=None, retag_chunks=False, manifest_bytes_fn=None,
          fix_root=False, header_fn=None):
    """Rewrite an UNKEYED archive the way an attacker can (SHA-256 is detection, not auth):
    mutate manifest/payload, then recompute every unkeyed hash so the parser itself is tested."""
    raw = Path(src).read_bytes()
    f = list(rdc3.HDR.unpack(raw[:rdc3.HDR.size]))
    mlen = f[7]
    m = json.loads(zstd.ZstdDecompressor().decompress(raw[rdc3.HDR.size:rdc3.HDR.size + mlen]))
    payload = bytearray(raw[rdc3.HDR.size + mlen:])
    if payload_fn:
        payload = bytearray(payload_fn(payload, m))
    if manifest_fn:
        manifest_fn(m)
    if retag_chunks:
        off = m['dict'][1] if m['dict'] else 0
        for c in m['chunks']:
            c[4] = hashlib.sha256(bytes(payload[off:off + c[2]])).hexdigest()
            off += c[2]
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


def chunk_offset(m, i):
    off = m['dict'][1] if m['dict'] else 0
    return off + sum(c[2] for c in m['chunks'][:i])


def simple_archive(tmp, spec=None, **kw):
    src = make_tree(tmp / 'src', spec or {'document.txt': b'original sample data' * 2000,
                                          'other.txt': b'other file ' * 3000})
    ar = tmp / 'a.rdc3'
    rdc3.pack(src, ar, **kw)
    return src, ar


def assert_rejected(ar, password=None):
    with pytest.raises(IntegrityError):
        with rdc3.Archive(ar, password) as a:
            a.verify()


# ---------------------------------------------------------------- round trips
@pytest.mark.parametrize('variant', [
    {}, dict(level=19), dict(use_dict=True), dict(delta=True), dict(parity=(4, 2, 4096)),
    dict(parity=(10, 2, 65536)), dict(password=PW, gear='keyed', **FAST),
    dict(password=PW, gear='keyed', use_dict=True, delta=True, parity=(5, 2, 8192), **FAST),
    pytest.param(dict(hash_name='blake3'), marks=pytest.mark.skipif(rdc3._blake3 is None, reason='blake3 not installed'),
                 id='blake3'),
    dict(gear='seeded', seed='00ff11'),
    dict(min_size=64, avg_size=256, max_size=1024)])
def test_roundtrip_variants(tmp_path, variant):
    if variant.get('use_dict') and rdc3.ZB.name != 'zstandard':   # 3.1.5: training is zstandard-only
        with pytest.raises(rdc3.BackendUnavailable):
            rdc3.pack(make_tree(tmp_path / 'src', BASIC), tmp_path / 'a.rdc3', **variant)
        return
    pw = variant.pop('password', None)
    stats, _ = roundtrip(tmp_path, BASIC, password=pw, **variant)
    assert stats['dedup_saved_bytes'] >= len(REDUNDANT) - 200_000  # duplicate file deduped


def test_empty_tree(tmp_path):
    stats, ar = roundtrip(tmp_path, {'d': None})
    assert stats['original_bytes'] == 0 and stats['unique_chunks'] == 0


def test_single_empty_file_and_single_file_source(tmp_path):
    for name, data in (('e', b''), ('one', b'abc' * 1000)):
        d = tmp_path / name
        d.mkdir()
        (d / 'f').write_bytes(data)
        rdc3.pack(d / 'f', d / 'a.rdc3')
        rdc3.restore(d / 'a.rdc3', d / 'out')
        assert (d / 'out' / 'f').read_bytes() == data


def test_large_file_spans_read_blocks(tmp_path):
    data = random.Random(7).randbytes(3 * rdc3.READ_BLOCK + 12345)
    data = data + data[: rdc3.READ_BLOCK]  # duplicated region across block boundary
    stats, _ = roundtrip(tmp_path, {'big.bin': data})
    assert stats['dedup_saved_bytes'] > rdc3.READ_BLOCK // 2


def test_highly_redundant_compresses(tmp_path):
    stats, _ = roundtrip(tmp_path, {'r.log': REDUNDANT * 4})
    assert stats['savings'] > 0.95


def test_random_raw_fallback_never_expands_payload(tmp_path):
    data = random.Random(3).randbytes(2_000_000)
    stats, _ = roundtrip(tmp_path, {'r': data})
    assert stats['data_bytes'] == len(data)  # all raw, no per-chunk expansion
    assert stats['codec_counts']['raw'] == stats['unique_chunks']


# ---------------------------------------------------------------- chunker
def test_vectorized_gear_matches_rolling_reference():
    ctx = rdc3.Ctx()
    g = rdc3.gear_table('public', ctx)
    c = rdc3.Chunker(g, 64, 256, 1024)
    buf = random.Random(1).randbytes(5000)
    h = c.hashes(buf)
    ref, mask = 0, 2**64 - 1
    for i, b in enumerate(buf):
        ref = ((ref << 1) + int(g[b])) & mask
        if i >= 63:
            assert int(h[i]) == ref
    # windowed: hash depends only on last 64 bytes
    assert int(c.hashes(b'Z' * 100 + buf[:200])[299]) == int(h[199])


def test_cdc_insert_resilience_and_stream_determinism(tmp_path):
    base = random.Random(5).randbytes(2_000_000)
    ctx = rdc3.Ctx()
    ch = rdc3.Chunker(rdc3.gear_table('public', ctx))
    def ids(data):
        p = tmp_path / 'x'
        p.write_bytes(data)
        with open(p, 'rb') as f:
            return [hashlib.sha256(c).hexdigest() for c, _ in ch.iter_file(f)]
    a, b = ids(base), ids(b'INSERTED' + base)
    assert len(set(a) & set(b)) >= len(a) - 2
    lens, _ = ch.split(base, True)
    assert sum(lens) == len(base) and all(ch.min <= x <= ch.max for x in lens[:-1])
    assert [hashlib.sha256(base[sum(lens[:i]):sum(lens[:i + 1])]).hexdigest() for i in range(len(lens))] == a


def test_keyed_gear_changes_boundaries():
    data = random.Random(9).randbytes(1_000_000)
    pub = rdc3.Chunker(rdc3.gear_table('public', rdc3.Ctx())).split(data, True)[0]
    k1 = rdc3.Chunker(rdc3.gear_table('keyed', rdc3.Ctx(b'k1', b'1' * 16, 10))).split(data, True)[0]
    k2 = rdc3.Chunker(rdc3.gear_table('keyed', rdc3.Ctx(b'k2', b'1' * 16, 10))).split(data, True)[0]
    assert pub != k1 and k1 != k2


# ---------------------------------------------------------------- Reed-Solomon
def test_rs_recovers_any_m_erasures():
    rng = random.Random(11)
    for k, m in ((1, 1), (4, 2), (10, 2), (5, 3), (20, 4)):
        shards = [rng.randbytes(257) for _ in range(k)]
        allsh = shards + rdc3.rs_encode(shards, m)
        for _ in range(20):
            lost = rng.sample(range(k + m), m)
            got = [None if i in lost else s for i, s in enumerate(allsh)]
            assert rdc3.rs_reconstruct(got, k, m) == shards
        with pytest.raises(IntegrityError):
            rdc3.rs_reconstruct([None] * (m + 1) + allsh[m + 1:], k, m)


# ---------------------------------------------------------------- archive framing / parser safety
def test_trailing_bytes_rejected(tmp_path):
    _, ar = simple_archive(tmp_path)
    with open(ar, 'ab') as f:
        f.write(b'JUNK')
    assert_rejected(ar)


def test_truncation_everywhere_rejected(tmp_path):
    _, ar = simple_archive(tmp_path)
    raw = ar.read_bytes()
    for cut in sorted({0, 1, 7, 8, rdc3.HDR.size - 1, rdc3.HDR.size, rdc3.HDR.size + 5, len(raw) // 2, len(raw) - 1}):
        t = tmp_path / f't{cut}'
        t.write_bytes(raw[:cut])
        assert_rejected(t)


@pytest.mark.parametrize('variant', [{}, dict(password=PW, **FAST)])
def test_bitflip_fuzz_never_yields_wrong_output(tmp_path, variant):
    src, ar = simple_archive(tmp_path, **variant)
    pw = variant.get('password')
    raw = ar.read_bytes()
    rng = random.Random(1234)
    positions = sorted(set(rng.randrange(len(raw)) for _ in range(60)) | set(range(0, rdc3.HDR.size, 7)))
    for n, pos in enumerate(positions):
        bad = bytearray(raw)
        bad[pos] ^= 1 << rng.randrange(8)
        t = tmp_path / f'f{n}.rdc3'
        t.write_bytes(bytes(bad))
        out = tmp_path / f'o{n}'
        with pytest.raises(IntegrityError):
            rdc3.restore(t, out, pw)
        assert not out.exists() or tree_hashes(out) == {}


def test_header_reserved_and_flag_bits_rejected(tmp_path):
    _, ar = simple_archive(tmp_path)
    for idx, val in ((1, 1), (2, 8), (3, 1), (6, b'\0\0\1'), (2, 2)):
        t = tmp_path / f'h{idx}_{bytes(val).hex() if isinstance(val, bytes) else val}.rdc3'   # 3.1.6: Windows-safe name
        def hf(f, idx=idx, val=val):
            f[idx] = val
        forge(ar, t, header_fn=hf)
        assert_rejected(t)


def test_manifest_duplicate_key_and_noncanonical_rejected(tmp_path):
    _, ar = simple_archive(tmp_path)
    forge(ar, tmp_path / 'dk', manifest_bytes_fn=lambda b: b[:-1] + b',"v":3}')
    assert_rejected(tmp_path / 'dk')
    forge(ar, tmp_path / 'nc', manifest_bytes_fn=lambda b: b.replace(b',', b', ', 1))
    assert_rejected(tmp_path / 'nc')


@pytest.mark.parametrize('bad', ['../outside.txt', '/etc/passwd', 'a/../../x', 'a\\b', 'C:x', 'a//b',
                                 './a', 'a/./b', '', '.rdc3-staging-evil/x', 'nul\x00byte', 'tab\tok'])
def test_unsafe_manifest_paths_rejected(tmp_path, bad):
    _, ar = simple_archive(tmp_path)
    t = tmp_path / 'p.rdc3'
    def mf(m):
        m['files'][0][0] = bad
    forge(ar, t, manifest_fn=mf, fix_root=True)
    assert_rejected(t)
    with pytest.raises(IntegrityError):
        rdc3.restore(t, tmp_path / 'out')
    assert not (tmp_path / 'outside.txt').exists()


def test_duplicate_and_conflicting_paths_rejected(tmp_path):
    _, ar = simple_archive(tmp_path)
    for name, fn in (('dup', lambda m: m['files'].__setitem__(1, [m['files'][0][0]] + m['files'][1][1:])),
                     ('filedir', lambda m: m['files'].__setitem__(1, [m['files'][0][0] + '/x'] + m['files'][1][1:])),
                     ('dirfile', lambda m: m['dirs'].append(m['files'][0][0]))):
        forge(ar, tmp_path / name, manifest_fn=fn, fix_root=True)
        assert_rejected(tmp_path / name)


def test_bad_lengths_offsets_codecs_rejected(tmp_path):
    _, ar = simple_archive(tmp_path)
    cases = {
        'stored_len': lambda m: m['chunks'][0].__setitem__(2, m['chunks'][0][2] + 1),
        'raw_len': lambda m: m['chunks'][0].__setitem__(1, m['chunks'][0][1] + 1),
        'codec': lambda m: m['chunks'][0].__setitem__(0, 9),
        'raw_noncanonical': lambda m: m['chunks'][0].__setitem__(0, 0),
        'bool_int': lambda m: m['chunks'][0].__setitem__(5, False),
        'ref_oob': lambda m: m['files'][0][3].append(999),
        'neg_ref': lambda m: m['files'][0][3].__setitem__(0, -1),
        'unused_chunk': lambda m: m['files'][0].__setitem__(3, []) or m['files'][0].__setitem__(1, 0)
                                  or m['files'][0].__setitem__(2, hashlib.sha256(b'').hexdigest()),
        'dict_codec_no_dict': lambda m: m['chunks'][0].__setitem__(0, 2),
        'delta_forward_base': lambda m: m['chunks'][0].__setitem__(0, 3) or m['chunks'][0].__setitem__(5, 0),
        'huge_raw': lambda m: m['chunks'][0].__setitem__(1, 1 << 40),
        'version': lambda m: m.__setitem__('v', 4),
        'extra_key': lambda m: m.__setitem__('x', 1),
    }
    for name, fn in cases.items():
        t = tmp_path / name
        forge(ar, t, manifest_fn=fn, fix_root=True)
        assert_rejected(t)


def test_payload_length_mismatch_rejected(tmp_path):
    _, ar = simple_archive(tmp_path)
    forge(ar, tmp_path / 'pl', payload_fn=lambda p, m: p + b'\0' * 10)
    assert_rejected(tmp_path / 'pl')


def test_decompression_bomb_bounded(tmp_path):
    """A forged frame whose real content is far larger than the advertised raw length."""
    _, ar = simple_archive(tmp_path, spec={'a': b'q' * 50_000})
    bomb = zstd.ZstdCompressor(level=3, write_content_size=False).compress(b'\0' * 64 * 1024 * 1024)
    def pf(p, m):
        off = chunk_offset(m, 0)
        c = m['chunks'][0]
        new = p[:off] + bomb + p[off + c[2]:]
        c[2] = len(bomb)
        return new
    forge(ar, tmp_path / 'bomb', payload_fn=pf, retag_chunks=True)
    tracemalloc.start()
    with pytest.raises(IntegrityError):
        rdc3.restore(tmp_path / 'bomb', tmp_path / 'out')
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 16 * 1024 * 1024


def test_repeated_pointer_amplification_capped(tmp_path):
    _, ar = simple_archive(tmp_path, spec={'a': b'z' * 40_000})
    class Small(rdc3.Limits):
        max_output = 10_000_000
    def mf(m):
        m['files'][0][3] = m['files'][0][3] * 1000
        m['files'][0][1] *= 1000
    forge(ar, tmp_path / 'amp', manifest_fn=mf, fix_root=True)
    with pytest.raises(IntegrityError):
        rdc3.Archive(tmp_path / 'amp', limits=Small)


def test_root_hash_verified(tmp_path):
    _, ar = simple_archive(tmp_path)
    def mf(m):
        m['files'][0][2] = 'f' * 64
    forge(ar, tmp_path / 'r', manifest_fn=mf, fix_root=False)
    with pytest.raises(IntegrityError, match='root'):
        rdc3.Archive(tmp_path / 'r')


def test_keyed_archive_requires_correct_password_and_detects_forgery(tmp_path):
    _, ar = simple_archive(tmp_path, password=PW, **FAST)
    with pytest.raises(IntegrityError):
        rdc3.Archive(ar)
    with pytest.raises(IntegrityError):
        rdc3.Archive(ar, 'wrong')
    raw = bytearray(ar.read_bytes())
    raw[-5] ^= 0xFF  # payload byte; attacker cannot recompute HMAC
    (tmp_path / 't').write_bytes(bytes(raw))
    with pytest.raises(IntegrityError, match='authentication'):
        rdc3.restore(tmp_path / 't', tmp_path / 'out', PW)
    assert b'original sample data' not in ar.read_bytes()  # encrypted at rest


# ---------------------------------------------------------------- writer safety
def test_writer_refuses_self_ingestion_and_overwrite(tmp_path):
    src = make_tree(tmp_path / 'src', {'a': b'data'})
    with pytest.raises(ValueError):
        rdc3.pack(src, src / 'inside.rdc3')
    with pytest.raises(ValueError):
        rdc3.pack(src, src / 'sub' / 'inside.rdc3')
    assert not (src / 'inside.rdc3').exists()
    with pytest.raises(FileExistsError):
        rdc3.pack(src, src / 'a')
    assert (src / 'a').read_bytes() == b'data'
    (tmp_path / 'exists').write_bytes(b'keep')
    with pytest.raises(FileExistsError):
        rdc3.pack(src, tmp_path / 'exists')
    assert (tmp_path / 'exists').read_bytes() == b'keep'


def test_writer_refuses_symlinks_in_source(tmp_path, need_links):
    need_links('symlink')
    src = make_tree(tmp_path / 'src', {'a': b'data'})
    os.symlink('/etc/hostname', src / 'link')
    with pytest.raises(ValueError, match='symlink'):
        rdc3.pack(src, tmp_path / 'o.rdc3')
    os.symlink(src, tmp_path / 'srclink')
    with pytest.raises(ValueError, match='symlink'):
        rdc3.pack(tmp_path / 'srclink', tmp_path / 'o2.rdc3')


def test_pack_failpoints(tmp_path):
    src = make_tree(tmp_path / 'src', {'a': b'data' * 100})
    with pytest.raises(RuntimeError):
        rdc3.pack(src, tmp_path / 'o.rdc3', failpoint='before_commit')
    assert not (tmp_path / 'o.rdc3').exists() and not list(tmp_path.glob('.rdc3-*'))
    with pytest.raises(PublicationError) as e:
        rdc3.pack(src, tmp_path / 'p.rdc3', failpoint='after_publish')
    assert e.value.published and not e.value.durability_confirmed
    assert rdc3.verify(tmp_path / 'p.rdc3')['ok']  # published output is complete and valid


def test_bounded_memory_pack_independent_of_input_size(tmp_path):
    peaks = []
    for mib in (8, 48):
        d = tmp_path / str(mib)
        rng = np.random.default_rng(mib)
        make_tree(d / 'src', {'big': rng.integers(0, 256, mib << 20, dtype=np.uint8).tobytes()})
        tracemalloc.start()
        rdc3.pack(d / 'src', d / 'a.rdc3')
        rdc3.restore(d / 'a.rdc3', d / 'out')
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    assert peaks[1] < 48 << 20 and peaks[1] - peaks[0] < 8 << 20, peaks


# ---------------------------------------------------------------- restore safety
def corrupt_chunk(tmp_path, ar, chunk=0, name='c.rdc3', delta=1):
    raw = bytearray(ar.read_bytes())
    m = json.loads(zstd.ZstdDecompressor().decompress(raw[rdc3.HDR.size:rdc3.HDR.size + rdc3.HDR.unpack(raw[:rdc3.HDR.size])[7]]))
    base = len(raw) - rdc3.HDR.unpack(raw[:rdc3.HDR.size])[9]
    off = base + chunk_offset(m, chunk)
    for i in range(delta):
        raw[off + i] ^= 0x55
    out = tmp_path / name
    out.write_bytes(bytes(raw))
    return out, m


def test_restore_refuses_existing_file_before_writing(tmp_path):
    _, ar = simple_archive(tmp_path)
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'other.txt').write_bytes(b'KEEP')
    with pytest.raises(FileExistsError):
        rdc3.restore(ar, out)
    assert (out / 'other.txt').read_bytes() == b'KEEP'
    assert sorted(os.listdir(out)) == ['other.txt']  # nothing else published, staging cleaned


def test_restore_corruption_publishes_nothing(tmp_path):
    _, ar = simple_archive(tmp_path)
    bad, _ = corrupt_chunk(tmp_path, ar, chunk=1)
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'sentinel').write_bytes(b'S')
    with pytest.raises(IntegrityError):
        rdc3.restore(bad, out)
    assert sorted(os.listdir(out)) == ['sentinel']


def test_restore_refuses_symlinked_destination_components(tmp_path, need_links):
    need_links('symlink')
    src = make_tree(tmp_path / 'src', {'a/b.txt': b'payload'})
    ar = tmp_path / 'a.rdc3'
    rdc3.pack(src, ar)
    outside = tmp_path / 'outside'
    outside.mkdir()
    out = tmp_path / 'out'
    out.mkdir()
    os.symlink(outside, out / 'a')
    with pytest.raises(IntegrityError):
        rdc3.restore(ar, out)
    assert os.listdir(outside) == []
    os.symlink(out, tmp_path / 'outlink')
    with pytest.raises(IntegrityError):
        rdc3.restore(ar, tmp_path / 'outlink')


def test_recover_mode_skip_and_warn(tmp_path):
    spec = {'good.txt': b'good data ' * 5000, 'bad.bin': random.Random(4).randbytes(100_000)}
    src = make_tree(tmp_path / 'src', spec)
    ar = tmp_path / 'a.rdc3'
    rdc3.pack(src, ar)
    m = rdc3.list_archive(ar)
    # chunk 0 belongs to the first file in sorted order ('bad.bin')
    bad, _ = corrupt_chunk(tmp_path, ar, chunk=0)
    with pytest.raises(IntegrityError):
        rdc3.restore(bad, tmp_path / 'strict')
    r = rdc3.restore(bad, tmp_path / 'rec', recover=True)
    assert [d['path'] for d in r['damaged']] == ['bad.bin']
    assert os.listdir(tmp_path / 'rec') == ['good.txt']
    assert (tmp_path / 'rec' / 'good.txt').read_bytes() == spec['good.txt']


def test_restore_publication_error_is_distinct(tmp_path):
    _, ar = simple_archive(tmp_path)
    with pytest.raises(PublicationError) as e:
        rdc3.restore(ar, tmp_path / 'out', failpoint='after_first_publish')
    assert e.value.published == ['document.txt'] and not e.value.durability_confirmed
    assert (tmp_path / 'out' / 'document.txt').read_bytes() == b'original sample data' * 2000
    with pytest.raises(IntegrityError):
        rdc3.restore(ar, tmp_path / 'out2', failpoint='before_publish')
    assert not (tmp_path / 'out2').exists()  # v3.0.1: created destination removed on failure


# ---------------------------------------------------------------- parity drills
DRILL = {'f%d.bin' % i: random.Random(i).randbytes(40_000) + b'text ' * 4000 for i in range(6)}


def test_drill_bitflip_detect_repair_reverify(tmp_path):
    src, ar = simple_archive(tmp_path, spec=DRILL, parity=(4, 2, 4096))
    bad, _ = corrupt_chunk(tmp_path, ar, chunk=2, delta=50)
    rep = rdc3.verify(bad)
    assert rep['needs_repair'] and rep['bad_chunks'] == [2] and rep['bad_shards']
    r = rdc3.repair(bad, tmp_path / 'fixed.rdc3')
    assert r['reverify']['ok']
    assert (tmp_path / 'fixed.rdc3').read_bytes() == ar.read_bytes()  # bit-identical archive
    rdc3.restore(bad, tmp_path / 'out')  # restore also repairs transparently from parity
    assert tree_hashes(tmp_path / 'out') == tree_hashes(src)


def _damage_shards(ar, dst, group, shard_idxs):
    with rdc3.Archive(ar) as a:
        k, m, groups = a.parity
        gs, gl, s, poff, _ = groups[group]
        base = a.base
    raw = bytearray(ar.read_bytes())
    for i in shard_idxs:
        start = base + (gs + i * s if i < k else poff + (i - k) * s)
        end = start + (min(s, gl - i * s) if i < k else s)
        raw[start:end] = b'\0' * (end - start)   # "drop" shard (zero-fill)
    Path(dst).write_bytes(bytes(raw))


@pytest.mark.parametrize('k,m', [(4, 2), (10, 2), (5, 3)])
def test_drill_drop_m_shards_repairs_and_m_plus_1_fails(tmp_path, k, m):
    src, ar = simple_archive(tmp_path, spec=DRILL, parity=(k, m, 4096))
    rng = random.Random(k * 10 + m)
    lost = rng.sample(range(k + m), m)
    _damage_shards(ar, tmp_path / 'm.rdc3', 0, lost)
    assert rdc3.verify(tmp_path / 'm.rdc3')['needs_repair']
    rdc3.repair(tmp_path / 'm.rdc3', tmp_path / 'm-fixed.rdc3')
    assert (tmp_path / 'm-fixed.rdc3').read_bytes() == ar.read_bytes()
    lost = rng.sample(range(k), min(k, m + 1)) if m + 1 <= k else list(range(k))
    lost = (lost + [k + i for i in range(m + 1)])[:m + 1]
    _damage_shards(ar, tmp_path / 'm1.rdc3', 0, lost)
    with pytest.raises(IntegrityError):
        rdc3.repair(tmp_path / 'm1.rdc3', tmp_path / 'm1-fixed.rdc3')
    assert not (tmp_path / 'm1-fixed.rdc3').exists()
    with pytest.raises(IntegrityError):
        rdc3.restore(tmp_path / 'm1.rdc3', tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_repair_without_parity_refused(tmp_path):
    _, ar = simple_archive(tmp_path)
    with pytest.raises(IntegrityError):
        rdc3.repair(ar, tmp_path / 'x')


# ---------------------------------------------------------------- peer regressions (WEB)
def test_web_existing_destination_survives_validation_failure(tmp_path):
    _, ar = simple_archive(tmp_path, spec={'important.txt': b'new content ' * 1000})
    bad, _ = corrupt_chunk(tmp_path, ar)
    out = tmp_path / 'd'
    out.mkdir()
    (out / 'important.txt').write_bytes(b'ORIGINAL MUST SURVIVE')
    with pytest.raises((IntegrityError, FileExistsError)):
        rdc3.restore(bad, out)
    assert (out / 'important.txt').read_bytes() == b'ORIGINAL MUST SURVIVE'


def test_web_validation_failure_leaves_no_new_destination(tmp_path):
    _, ar = simple_archive(tmp_path, spec={'new.txt': b'new ' * 5000})
    bad, _ = corrupt_chunk(tmp_path, ar)
    with pytest.raises(IntegrityError):
        rdc3.restore(bad, tmp_path / 'd')
    assert not (tmp_path / 'd' / 'new.txt').exists()


def test_web_manifest_rejects_trailing_bytes(tmp_path):
    _, ar = simple_archive(tmp_path)
    forge(ar, tmp_path / 't', manifest_bytes_fn=lambda b: b + b'UNACCOUNTED')
    assert_rejected(tmp_path / 't')


def test_web_codec_block_rejects_trailing_bytes(tmp_path):
    _, ar = simple_archive(tmp_path, spec={'s': b'sample' * 5000})
    def pf(p, m):
        off = chunk_offset(m, 0)
        c = m['chunks'][0]
        assert c[0] == rdc3.CODEC_ZSTD
        new = p[:off + c[2]] + b'UNACCOUNTED' + p[off + c[2]:]
        c[2] += 11
        return new
    forge(ar, tmp_path / 't', payload_fn=pf, retag_chunks=True)
    with pytest.raises(IntegrityError, match='trailing|decode'):
        rdc3.restore(tmp_path / 't', tmp_path / 'out')


def test_web_verify_rejects_unsafe_manifest_path(tmp_path):
    _, ar = simple_archive(tmp_path)
    forge(ar, tmp_path / 't', manifest_fn=lambda m: m['files'][0].__setitem__(0, '../outside.txt'), fix_root=True)
    with pytest.raises(IntegrityError):
        rdc3.verify(tmp_path / 't')


def test_web_basic_roundtrip(tmp_path):
    cases = {'empty': b'', 'a': b'abc' * 10000, 'b': bytes(range(256)) * 40}
    roundtrip(tmp_path, cases)


# ---------------------------------------------------------------- peer regressions (SEEKER)
def test_seeker_restore_never_overwrites_existing_file(tmp_path):
    _, ar = simple_archive(tmp_path, spec={'document.txt': b'original sample data' * 20})
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'document.txt').write_bytes(b'KEEP EXISTING')
    with pytest.raises((FileExistsError, IntegrityError)):
        rdc3.restore(ar, out)
    assert (out / 'document.txt').read_bytes() == b'KEEP EXISTING'


def test_seeker_integrity_failure_preserves_existing_file(tmp_path):
    """Whole-file digest forged (root re-forged too, as an unkeyed attacker could)."""
    _, ar = simple_archive(tmp_path, spec={'document.txt': b'original sample data' * 20})
    forge(ar, tmp_path / 'f', manifest_fn=lambda m: m['files'][0].__setitem__(2, '0' * 64), fix_root=True)
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(IntegrityError, match='digest'):
        rdc3.restore(tmp_path / 'f', out)
    assert os.listdir(out) == []
    (out / 'document.txt').write_bytes(b'KEEP EXISTING')
    with pytest.raises((FileExistsError, IntegrityError)):
        rdc3.restore(tmp_path / 'f', out)
    assert (out / 'document.txt').read_bytes() == b'KEEP EXISTING'


def test_seeker_codec_block_rejects_trailing_payload(tmp_path):
    """SEEKER's zlib case adapted: v3 has no zlib; a zstd frame + JUNK must fail, even re-tagged."""
    _, ar = simple_archive(tmp_path, spec={'c': b'compressed text' * 100})
    def pf(p, m):
        off = chunk_offset(m, 0)
        c = m['chunks'][0]
        new = p[:off + c[2]] + b'JUNK' + p[off + c[2]:]
        c[2] += 4
        return new
    forge(ar, tmp_path / 't', payload_fn=pf, retag_chunks=True)
    assert_rejected(tmp_path / 't')


def test_seeker_manifest_rejects_unconsumed_bytes(tmp_path):
    _, ar = simple_archive(tmp_path)
    forge(ar, tmp_path / 't', manifest_bytes_fn=lambda b: b + b'JUNK')
    assert_rejected(tmp_path / 't')
    # and bytes after the compressed manifest frame inside the manifest region
    raw = ar.read_bytes()
    f = list(rdc3.HDR.unpack(raw[:rdc3.HDR.size]))
    mc = raw[rdc3.HDR.size:rdc3.HDR.size + f[7]] + b'JUNK'
    f[7] += 4
    prefix = rdc3.HDR.pack(*f[:11], b'\0' * 32)[:rdc3.HDR_PREFIX]
    (tmp_path / 'u').write_bytes(prefix + hashlib.sha256(prefix + mc).digest() + mc + raw[rdc3.HDR.size + f[7] - 4:])
    assert_rejected(tmp_path / 'u')


def test_cli_roundtrip_and_exit_codes(tmp_path, monkeypatch):
    src = make_tree(tmp_path / 'src', BASIC)
    monkeypatch.setenv('RDC_PASSWORD', PW)
    assert rdc3.main(['pack', str(src), str(tmp_path / 'a.rdc3'), '--encrypt', '--parity', '4,2,4096']) == 0
    assert rdc3.main(['verify', str(tmp_path / 'a.rdc3')]) == 0
    assert rdc3.main(['unpack', str(tmp_path / 'a.rdc3'), str(tmp_path / 'o')]) == 0
    assert tree_hashes(tmp_path / 'o') == tree_hashes(src)
    assert rdc3.main(['unpack', str(tmp_path / 'a.rdc3'), str(tmp_path / 'o')]) == 1  # refuses overwrite


# ---------------------------------------------------------------- v3.0.1 regressions (SEEKER v3 review)
def _amplification_archive(tmp_path, n=2048):
    """SEEKER's probe: one 1 MiB zero chunk referenced n times (2 GiB declared) in a ~500-byte archive."""
    _, ar = simple_archive(tmp_path)
    raw = b'\0' * rdc3.Limits.max_chunk
    body = zstd.ZstdCompressor(level=19, write_content_size=True).compress(raw)
    h = hashlib.sha256()
    for _ in range(n):
        h.update(raw)
    def mf(m):
        m['chunker']['max'] = len(raw)
        m['chunks'] = [[1, len(raw), len(body), hashlib.sha256(raw).hexdigest(), hashlib.sha256(body).hexdigest(), -1]]
        m['files'] = [['bomb.bin', len(raw) * n, h.hexdigest(), [0] * n]]
        m['dirs'] = []
    bomb = tmp_path / 'bomb.rdc3'
    forge(ar, bomb, manifest_fn=mf, payload_fn=lambda p, m: body, fix_root=True)
    return bomb


def test_v301_expansion_ratio_cap_refuses_amplification(tmp_path):
    bomb = _amplification_archive(tmp_path)
    assert bomb.stat().st_size < 1000
    with pytest.raises(rdc3.LimitError, match='archive'):
        rdc3.Archive(bomb)
    with pytest.raises(rdc3.LimitError):
        rdc3.verify(bomb)
    out = tmp_path / 'out'
    with pytest.raises(rdc3.LimitError):
        rdc3.restore(bomb, out)
    assert not out.exists()
    assert rdc3.main(['unpack', str(bomb), str(out)]) == 1 and not out.exists()
    # explicit override opens it (validation only; no 2 GiB restore performed)
    with rdc3.Archive(bomb, max_expansion=0) as a:
        assert a.total == 2048 * rdc3.Limits.max_chunk


def test_v301_expansion_cap_allows_legit_redundant_and_override(tmp_path):
    class Tight(rdc3.Limits):
        expansion_floor = 0
        max_expansion = 10
    src = make_tree(tmp_path / 'src', {'r.log': REDUNDANT})  # ~2.7 MB, compresses >100x
    ar = tmp_path / 'a.rdc3'
    rdc3.pack(src, ar)
    rdc3.restore(ar, tmp_path / 'ok')  # default cap + floor: accepted
    with pytest.raises(rdc3.LimitError):
        rdc3.Archive(ar, limits=Tight)
    with rdc3.Archive(ar, limits=Tight, max_expansion=0) as a:
        assert a.verify()['ok']
    with rdc3.Archive(ar, limits=Tight, max_expansion=100000) as a:
        assert a.verify()['ok']


def test_v301_free_space_check_before_staging(tmp_path, monkeypatch):
    _, ar = simple_archive(tmp_path)
    import collections
    usage = collections.namedtuple('usage', 'total used free')
    monkeypatch.setattr(rdc3.shutil, 'disk_usage', lambda p: usage(10**9, 10**9 - 1000, 1000))
    out = tmp_path / 'new'
    with pytest.raises(rdc3.LimitError, match='free space'):
        rdc3.restore(ar, out)
    assert not out.exists()
    existing = tmp_path / 'existing'
    existing.mkdir()
    (existing / 'keep').write_bytes(b'k')
    with pytest.raises(rdc3.LimitError):
        rdc3.restore(ar, existing)
    assert os.listdir(existing) == ['keep']
    monkeypatch.undo()
    rdc3.restore(ar, tmp_path / 'fine')


def test_v301_chunk_decode_bounded_by_declared_length(tmp_path):
    """A frame whose real content exceeds the declared chunk raw length is refused (frame header and output cap)."""
    _, ar = simple_archive(tmp_path, spec={'a': b'q' * 50_000})
    big = zstd.ZstdCompressor(level=3, write_content_size=True).compress(b'q' * 200_000)
    nosize = zstd.ZstdCompressor(level=3, write_content_size=False).compress(b'q' * 200_000)
    for name, frame in (('declared', big), ('undeclared', nosize)):
        def pf(p, m, frame=frame):
            off = chunk_offset(m, 0)
            c = m['chunks'][0]
            new = p[:off] + frame + p[off + c[2]:]
            c[2] = len(frame)
            return new
        forge(ar, tmp_path / name, payload_fn=pf, retag_chunks=True)
        tracemalloc.start()
        with pytest.raises(IntegrityError):
            rdc3.restore(tmp_path / name, tmp_path / ('out-' + name))
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert peak < 4 * 1024 * 1024 and not (tmp_path / ('out-' + name)).exists()


def test_v301_failed_restore_removes_created_destination(tmp_path):
    _, ar = simple_archive(tmp_path)
    bad, _ = corrupt_chunk(tmp_path, ar)
    out = tmp_path / 'never-existed'
    with pytest.raises(IntegrityError):
        rdc3.restore(bad, out)
    assert not out.exists()
    # pre-existing destination is never removed, even when empty
    pre = tmp_path / 'pre'
    pre.mkdir()
    with pytest.raises(IntegrityError):
        rdc3.restore(bad, pre)
    assert pre.is_dir() and os.listdir(pre) == []
    # a PublicationError keeps the created destination and its published files
    with pytest.raises(PublicationError):
        rdc3.restore(ar, tmp_path / 'pub', failpoint='after_first_publish')
    assert (tmp_path / 'pub' / 'document.txt').exists()


def test_v301_blake3_variant_skips_cleanly_without_module(monkeypatch):
    monkeypatch.setattr(rdc3, '_blake3', None)
    with pytest.raises(ValueError, match='hash unavailable'):
        rdc3.Ctx(hash_name='blake3')


# ---------------------------------------------------------------- v3.0.2: keyed archives skip the default ratio cap
def _zero_tree(tmp_path, mib=256):
    src = tmp_path / 'zsrc'
    src.mkdir()
    with open(src / 'zeros.img', 'wb') as f:
        block = b'\0' * (1 << 20)
        for _ in range(mib):
            f.write(block)
    return src


def test_v302_keyed_256mib_zero_file_restores_under_defaults(tmp_path):
    src = _zero_tree(tmp_path)
    ar = tmp_path / 'k.rdc3'
    rdc3.pack(src, ar, password=PW, gear='keyed', **FAST)
    assert (256 << 20) / ar.stat().st_size > 1000  # well beyond the unkeyed default cap
    r = rdc3.restore(ar, tmp_path / 'out', PW)
    assert r['bytes'] == 256 << 20
    out = tmp_path / 'out' / 'zeros.img'
    assert out.stat().st_size == 256 << 20
    h = hashlib.sha256()
    with open(out, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    assert h.hexdigest() == hashlib.sha256(b'\0' * (256 << 20)).hexdigest()


def test_v302_unkeyed_256mib_zero_file_refused_with_flag_hint(tmp_path):
    src = _zero_tree(tmp_path)
    ar = tmp_path / 'u.rdc3'
    rdc3.pack(src, ar)
    out = tmp_path / 'out'
    with pytest.raises(rdc3.LimitError) as e:
        rdc3.restore(ar, out)
    msg = str(e.value)
    assert '--max-expansion 0' in msg and 'max_expansion=0' in msg
    assert not out.exists()
    assert rdc3.main(['unpack', str(ar), str(out)]) == 1 and not out.exists()
    assert rdc3.main(['unpack', str(ar), str(out), '--max-expansion', '0']) == 0
    assert (out / 'zeros.img').stat().st_size == 256 << 20


@pytest.mark.parametrize('password', [None, PW])
def test_v302_versioned_multi_snapshot_restores_under_defaults(tmp_path, password):
    rng = random.Random(302)
    files = {f'proj/m{i}.py': (b'def f%d():\n    return %d\n' % (i, i)) * rng.randint(500, 3000) for i in range(30)}
    files['proj/blob.bin'] = rng.randbytes(512 * 1024)
    spec = {}
    for snap in range(1, 21):
        if snap > 1:
            for name in rng.sample(sorted(files), 3):
                d = bytearray(files[name])
                p = rng.randrange(len(d))
                d[p:p] = b'# edit %d\n' % snap
                files[name] = bytes(d)
        for name, data in files.items():
            spec[f'snap{snap:02d}/{name}'] = data
    kw = dict(password=password, gear='keyed', **FAST) if password else {}
    stats, _ = roundtrip(tmp_path, spec, **kw)
    assert stats['dedup_saved_bytes'] > stats['original_bytes'] * 0.8


def test_v302_keyed_archive_explicit_cap_still_refused(tmp_path):
    src = _zero_tree(tmp_path, mib=96)
    ar = tmp_path / 'k.rdc3'
    rdc3.pack(src, ar, password=PW, gear='keyed', **FAST)
    out = tmp_path / 'out'
    with pytest.raises(rdc3.LimitError) as e:
        rdc3.restore(ar, out, PW, max_expansion=1000)
    assert 'keyed' in str(e.value) and not out.exists()
    with pytest.raises(rdc3.LimitError):
        rdc3.verify(ar, PW, max_expansion=50)
    os.environ['RDC_PASSWORD'] = PW
    try:
        assert rdc3.main(['unpack', str(ar), str(out), '--max-expansion', '1000']) == 1 and not out.exists()
    finally:
        del os.environ['RDC_PASSWORD']


def test_v302_keyed_bomb_without_password_never_reaches_cap(tmp_path):
    """Skipping the cap requires a verified MAC: a keyed archive with a wrong password fails auth first."""
    src = _zero_tree(tmp_path, mib=96)
    ar = tmp_path / 'k.rdc3'
    rdc3.pack(src, ar, password=PW, gear='keyed', **FAST)
    with pytest.raises(IntegrityError, match='authentication'):
        rdc3.Archive(ar, 'wrong')
