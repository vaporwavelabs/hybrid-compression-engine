"""RDCv004 research container (prototype v3.1.6, not production).

RDCv003 pipeline (FastCDC chunking, per-chunk dedup, authenticated stored bytes, optional
ChaCha20-Poly1305, optional RS(k+m,k) parity, fail-closed validate-before-publish restore) with
one change: unique chunks are grouped, in creation order, into solid *packs* (default target
see DEFAULTS) that are compressed as one zstd frame each, optionally in parallel threads.
A pack's stored bytes are authenticated before decryption/decoding; every chunk sliced from a
decoded pack is then checked against its chunk id. Restore decodes one pack at a time (small
LRU), bounded by the declared pack size. Reads RDCv003 archives through rdc3.py (v3.0.2 code).
Restore and verify run on POSIX (descriptor-relative, symlink-safe) and on Windows (path-based
portable mode, see README: Windows).
"""
# 3.1.5 SECURITY: with `python -m rdc4` Python puts the current directory first on sys.path, so a restored
# argparse.py/json.py/... in that directory would run on the next start. Drop it before any import that
# could be shadowed (os/sys are already loaded by the interpreter), unless cwd is rdc4's own folder.
import os as _os, sys as _sys
if __name__ == '__main__' and _sys.path and \
        _os.path.normcase(_os.path.realpath(_sys.path[0] or '.')) == _os.path.normcase(_os.path.realpath(_os.getcwd())) and \
        _os.path.normcase(_os.path.realpath(_os.path.dirname(_os.path.abspath(__file__)))) != \
        _os.path.normcase(_os.path.realpath(_os.getcwd())):
    del _sys.path[0]
import argparse
import errno
import hashlib
import warnings
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import struct
import sys
import tempfile
import threading
import unicodedata
from array import array
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor

if sys.platform == 'win32':          # pragma: no cover - Windows only; loaded up front, never mid-publish
    import ctypes
    import msvcrt
    from ctypes import wintypes

import rdc3 as v3
from rdc3 import (AEAD_TAG, F_ENCRYPTED, F_KEYED, HDR, HDR_PREFIX, Chunker, Ctx, IntegrityError,
                  LimitError, PublicationError, _hex, _int, _keys, _unique_pairs, atomic_publish_file,
                  canonical, cauchy, check_free_space, gear_table, parity_layout, rs_encode,
                  _inside, _restore_into)
# scan_source / check_tree are used late-bound as v3.<name> so one path-policy implementation is shared

__version__ = '3.1.6'
_O_BINARY = getattr(os, 'O_BINARY', 0)   # Windows: os.open is text mode without it
MAGIC4 = b'RDCv004\n'
PACK_RAW, PACK_ZSTD = 0, 1
DOMAIN_PACK = 2
# Chosen from sweep-v3.1.json (see BENCHMARKS.md): zstd-19 on 2 MiB packs with hash/chain logs capped at 20
# keeps encoder RSS near v3's (~80-110 MiB single-threaded) at <1% ratio cost; 8 KiB average chunks
# give the best cross-snapshot dedup. threads=1 by default for memory; --threads N for speed.
DEFAULTS = dict(level=19, pack_size=2 * 1024 * 1024, threads=1, min_size=2048, avg_size=8192, max_size=32768,
                zstd_overrides=dict(hash_log=20, chain_log=20))

# GUI add-on (opt-in, see `--progress`): a progress reporter. None = off, which is the default and costs one
# global lookup per piece. It only observes byte counts; it never changes what is read, written or stored.
_progress = None   # object with .start(stage, total) and .add(n)


class Limits4(v3.Limits):
    max_pack = 16 * 1024 * 1024        # hard cap on declared pack raw length
    max_window = 16 * 1024 * 1024      # zstd window accepted when decoding packs/manifest
    max_packs = 1_000_000
    pack_cache = 2                     # decoded packs kept in memory for sequential (streaming) reads
    decode_floor = 256 * 1024 * 1024   # sequential verify allowed to decode at least this much ...
    decode_factor = 4                  # ... or this many times the raw bytes of the packs it uses;
                                       # above that, verify switches to pack-order (each pack decoded once)
    spill_memory = 64 * 1024 * 1024    # pack-order: unique verified pieces kept in RAM up to this, then a temp file
    max_threads = 32


# ---------------------------------------------------------------- pack (write)
DEFAULT_PARITY = (10, 2, 65536)   # 3.1.2: RS(12,10), 64 KiB shards; parity=None turns it off


def pack(source, dest, *, level=None, pack_size=None, threads=None, parity='default', password=None,
         gear='public', seed=None, min_size=None, avg_size=None, max_size=None, hash_name='sha256',
         kdf_log2n=15, failpoint=None, zstd_overrides=None):
    level = DEFAULTS['level'] if level is None else level
    pack_size = DEFAULTS['pack_size'] if pack_size is None else pack_size
    threads = DEFAULTS['threads'] if threads is None else threads
    if (min_size, avg_size, max_size) == (None, None, None):
        min_size, avg_size, max_size = DEFAULTS['min_size'], DEFAULTS['avg_size'], DEFAULTS['max_size']
    elif None in (min_size, avg_size, max_size):
        raise ValueError('give all of min_size/avg_size/max_size or none')
    zstd_overrides = DEFAULTS['zstd_overrides'] if zstd_overrides is None else zstd_overrides
    source, dest = os.path.abspath(source), os.path.abspath(dest)
    if os.path.lexists(dest):
        raise FileExistsError(dest)
    if os.path.isdir(source) and _inside(os.path.dirname(dest), source):
        raise ValueError('output inside source tree refused (self-ingestion)')
    if os.path.realpath(dest) == os.path.realpath(source):
        raise ValueError('output equals input')
    if type(level) is not int or not 1 <= level <= 22:
        raise ValueError('zstd level')
    if type(pack_size) is not int or not 64 * 1024 <= pack_size <= Limits4.max_pack - Limits4.max_chunk:
        raise ValueError('pack_size must be 64 KiB .. 15 MiB')
    if type(threads) is not int or not 1 <= threads <= Limits4.max_threads:
        raise ValueError('threads')
    if isinstance(password, str):
        password = password.encode()
    encrypt = password is not None
    salt = secrets.token_bytes(16) if encrypt else b'\0' * 16
    log2n = kdf_log2n if encrypt else 0
    ctx = Ctx(password, salt, log2n, encrypt, hash_name)
    if gear == 'keyed' and not ctx.keyed:
        raise ValueError('keyed gear requires password')
    if gear == 'seeded':
        seed = seed or secrets.token_hex(16)
        if not re.fullmatch(r'[0-9a-f]{2,64}', seed):
            raise ValueError('seed must be hex')
    else:
        seed = None
    chunker = Chunker(gear_table(gear, ctx, seed), min_size, avg_size, max_size)
    if parity == 'default':
        parity = DEFAULT_PARITY
    if parity is not None:
        k, m, shard = parity
        cauchy(k, m)
        if not 512 <= shard <= Limits4.max_shard:
            raise ValueError('shard size')
    files, dirs = v3.scan_source(source)
    prog = _progress
    if prog is not None:
        prog.start('pack', sum(os.stat(path).st_size for _rel, path in files))

    tls = threading.local()

    def compress(idx, raw):
        c = getattr(tls, 'c', None)
        if c is None:
            # parameters adapted to the pack size (bounds context memory); optional hash/chain overrides
            c = tls.c = v3.ZB.compressor(level, source_size=pack_size + Limits4.max_chunk,
                                         overrides=zstd_overrides or {})
        body = c.compress(raw)
        codec = PACK_ZSTD
        if len(body) >= len(raw):
            body, codec = raw, PACK_RAW
        stored = ctx.seal(DOMAIN_PACK, idx, body)
        return codec, len(raw), stored, ctx.tag(stored)

    pool = ThreadPoolExecutor(threads) if threads > 1 else None
    packs, chunks, index, manifest_files = [], [], {}, []
    pending = deque()
    logical = unique_raw = 0
    with tempfile.TemporaryFile() as raw_spool, tempfile.TemporaryFile() as data_spool, \
            tempfile.TemporaryFile() as parity_spool:
        data_len = raw_off = 0
        cur = bytearray()
        n_submitted = 0

        def drain_one():
            nonlocal data_len
            codec, rlen, stored, tag = pending.popleft()
            if pool is not None:
                codec, rlen, stored, tag = codec.result()
            data_spool.write(stored)
            packs.append([codec, rlen, len(stored), tag.hex()])
            data_len += len(stored)

        def flush():
            nonlocal cur, n_submitted
            if not cur:
                return
            raw = bytes(cur)
            cur = bytearray()
            if pool is not None:
                pending.append((pool.submit(compress, n_submitted, raw), None, None, None))
            else:
                pending.append(compress(n_submitted, raw))
            n_submitted += 1
            while len(pending) > threads:   # bounded in-flight packs (memory)
                drain_one()

        try:
            for rel, path in files:
                fh = hashlib.sha256()
                refs, size = [], 0
                fd = _open_nofollow_read(path)
                before = os.fstat(fd)
                with os.fdopen(fd, 'rb') as f:
                    for raw, _h in chunker.iter_file(f):
                        fh.update(raw)
                        size += len(raw)
                        if prog is not None:
                            prog.add(len(raw))
                        cid = ctx.chunk_id(raw)
                        if cid in index:
                            ci, off = index[cid]
                            raw_spool.seek(off)
                            if raw_spool.read(len(raw)) != raw:
                                raise ValueError('chunk hash collision; refusing dedup')
                            raw_spool.seek(0, 2)
                            refs.append(ci)
                            continue
                        if len(chunks) >= Limits4.max_chunks:
                            raise ValueError('chunk count limit')
                        ci = len(chunks)
                        chunks.append([n_submitted, len(raw), cid])
                        cur += raw
                        raw_spool.write(raw)
                        index[cid] = (ci, raw_off)
                        raw_off += len(raw)
                        unique_raw += len(raw)
                        refs.append(ci)
                        if len(cur) >= pack_size:
                            flush()
                    after = os.fstat(f.fileno())
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or size != after.st_size:
                    raise ValueError(f'source changed while reading: {rel}')
                logical += size
                manifest_files.append([rel, size, fh.hexdigest(), refs])
            flush()
            while pending:
                drain_one()
        finally:
            if pool is not None:
                pool.shutdown(wait=True, cancel_futures=True)
        par, parity_len = None, 0
        if parity is not None:
            k, m, shard = parity
            groups = []
            data_spool.flush()
            if prog is not None:
                prog.start('parity', data_len)
            for gstart, glen, s in parity_layout(data_len, k, shard):
                if prog is not None:
                    prog.add(glen)
                data_spool.seek(gstart)
                buf = data_spool.read(glen).ljust(k * s, b'\0')
                shards = [buf[i * s:(i + 1) * s] for i in range(k)]
                pshards = rs_encode(shards, m)
                for p in pshards:
                    parity_spool.write(p)
                parity_len += m * s
                groups.append([ctx.tag(x).hex() for x in shards + pshards])
            par = dict(k=k, m=m, shard=shard, groups=groups)
        root = ctx.tag(b'rdc3-root\0' + canonical(dict(files=[f[:3] for f in manifest_files], dirs=dirs)))
        manifest = dict(v=4, hash=hash_name, level=level, pack_size=pack_size,
                        chunker=dict(min=min_size, avg=avg_size, max=max_size, gear=gear, seed=seed),
                        packs=packs, chunks=chunks, files=manifest_files, dirs=dirs, parity=par)
        mraw = canonical(manifest)
        if len(mraw) > Limits4.max_manifest:
            raise ValueError('manifest too large')
        mcomp = v3.ZB.compressor(19).compress(mraw)
        mstored_len = len(mcomp) + (AEAD_TAG if encrypt else 0)
        flags = (F_KEYED if ctx.keyed else 0) | (F_ENCRYPTED if encrypt else 0)
        payload_len = data_len + parity_len
        prefix = HDR.pack(MAGIC4, 0, flags, 0, salt, log2n, b'\0\0\0', mstored_len, len(mraw),
                          payload_len, root, b'\0' * 32)[:HDR_PREFIX]
        mstored = ctx.aead.encrypt(struct.pack('>IQ', 1, 0), mcomp, prefix) if encrypt else mcomp
        header = prefix + ctx.tag(prefix + mstored)

        def writer(out):
            out.write(header)
            out.write(mstored)
            for sp in (data_spool, parity_spool):
                sp.flush()
                sp.seek(0)
                shutil.copyfileobj(sp, out, 1024 * 1024)
        pub = atomic_publish_file(dest, writer, failpoint)
    stored_total = HDR.size + mstored_len + payload_len
    return dict(format='RDCv004', original_bytes=logical, stored_bytes=stored_total, header_bytes=HDR.size,
                manifest_bytes=mstored_len, manifest_raw_bytes=len(mraw), data_bytes=data_len,
                parity_bytes=parity_len, packs=len(packs), raw_packs=sum(p[0] == PACK_RAW for p in packs),
                level=level, pack_size=pack_size, threads=threads, files=len(files), dirs=len(dirs),
                unique_chunks=len(chunks), logical_chunks=sum(len(f[3]) for f in manifest_files),
                unique_raw_bytes=unique_raw, dedup_saved_bytes=logical - unique_raw,
                keyed=ctx.keyed, encrypted=encrypt, gear=gear, hash=hash_name,
                savings=(1 - stored_total / logical) if logical else None,
                sync_mode=pub['sync_mode'], directories_fsynced=pub['directories_fsynced'],
                zstd_backend=v3.ZB.name)


# ---------------------------------------------------------------- read
class Archive4(v3.Archive):
    """RDCv004 reader. Reuses v3 parity/stored-byte authentication; packs replace per-chunk frames."""
    def __init__(self, path, password=None, limits=Limits4, max_expansion=None, max_decode=None):
        self.pack_decodes = 0
        self.max_decode = max_decode
        self.on_warning = None
        self._packs_cache = OrderedDict()
        super().__init__(path, password, limits, max_expansion)

    def _load(self, password):
        L = self.limits
        st = os.fstat(self.f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise IntegrityError('archive must be a regular file')
        hdr = self.f.read(HDR.size)
        if len(hdr) != HDR.size:
            raise IntegrityError('truncated header')
        (magic, minor, flags, res16, salt, log2n, res3, mlen, mraw, plen, root, tag) = HDR.unpack(hdr)
        if magic != MAGIC4 or minor != 0 or res16 != 0 or res3 != b'\0\0\0' or flags & ~3:
            raise IntegrityError('bad magic/version/reserved/flags')
        keyed, enc = bool(flags & F_KEYED), bool(flags & F_ENCRYPTED)
        if enc and not keyed or (not keyed and (log2n or salt != b'\0' * 16)):
            raise IntegrityError('inconsistent flags')
        if not 0 < mraw <= L.max_manifest or not 0 < mlen <= L.max_manifest + 64:
            raise IntegrityError('manifest size limits')
        if st.st_size != HDR.size + mlen + plen:
            raise IntegrityError('archive length mismatch (truncated or trailing bytes)')
        if keyed and password is None:
            raise IntegrityError('archive is keyed; password required')
        if isinstance(password, str):
            password = password.encode()
        self.ctx = Ctx(password if keyed else None, salt, log2n, enc, 'sha256')
        mstored = self.f.read(mlen)
        if len(mstored) != mlen:
            raise IntegrityError('truncated manifest')
        prefix = hdr[:HDR_PREFIX]
        if not hmac.compare_digest(self.ctx.tag(prefix + mstored), tag):
            raise IntegrityError('header/manifest authentication failed (wrong password or tampered)')
        if enc:
            try:
                mcomp = self.ctx.aead.decrypt(struct.pack('>IQ', 1, 0), mstored, prefix)
            except Exception as exc:
                raise IntegrityError('manifest AEAD failed') from exc
        else:
            mcomp = mstored
        mbytes = self._zstd_decode(mcomp, mraw, None)
        try:
            m = json.loads(mbytes, object_pairs_hook=_unique_pairs)
        except IntegrityError:
            raise
        except Exception as exc:
            raise IntegrityError('manifest JSON invalid or has trailing bytes') from exc
        if canonical(m) != mbytes:
            raise IntegrityError('manifest not canonical')
        self.header = dict(flags=flags, keyed=keyed, encrypted=enc, manifest_len=mlen, payload_len=plen)
        self.base = HDR.size + mlen
        self._validate(m, plen, root)

    def _validate(self, m, plen, root):
        L = self.limits
        _keys(m, ['v', 'hash', 'level', 'pack_size', 'chunker', 'packs', 'chunks', 'files', 'dirs', 'parity'],
              'manifest')
        if type(m['v']) is not int or m['v'] != 4:
            raise IntegrityError('unsupported version')
        if m['hash'] not in ('sha256', 'blake3') or (m['hash'] == 'blake3' and v3._blake3 is None):
            raise IntegrityError('hash unsupported')
        self.ctx.hash_name = m['hash']
        _int(m['level'], 1, 22, 'level')
        _int(m['pack_size'], 1, L.max_pack, 'pack_size')
        ch = m['chunker']
        _keys(ch, ['min', 'avg', 'max', 'gear', 'seed'], 'chunker')
        _int(ch['max'], 1, L.max_chunk, 'chunk max')
        if ch['gear'] not in ('public', 'seeded', 'keyed'):
            raise IntegrityError('gear')
        aead = AEAD_TAG if self.ctx.encrypted else 0
        packs = m['packs']
        if not isinstance(packs, list) or len(packs) > L.max_packs:
            raise IntegrityError('pack list')
        self.packs, offset = [], 0
        for p in packs:
            if not isinstance(p, list) or len(p) != 4:
                raise IntegrityError('pack schema')
            codec, raw, stored, tag = p
            _int(codec, 0, 1, 'pack codec')
            _int(raw, 1, L.max_pack, 'declared pack size')
            _int(stored, 1, L.max_pack + 64, 'pack stored length')
            _hex(tag, 'pack tag')
            body = stored - aead
            if codec == PACK_RAW and body != raw or codec == PACK_ZSTD and not 0 < body < raw:
                raise IntegrityError('pack codec/length noncanonical')
            self.packs.append((codec, raw, stored, bytes.fromhex(tag), offset))
            offset += stored
        self.data_len = offset
        chunks = m['chunks']
        if not isinstance(chunks, list) or len(chunks) > L.max_chunks:
            raise IntegrityError('chunk list')
        self.chunks, ids = [], set()
        cur_pack, fill = 0, 0
        for c in chunks:
            if not isinstance(c, list) or len(c) != 3:
                raise IntegrityError('chunk schema')
            p, raw, cid = c
            _int(p, 0, len(self.packs) - 1, 'chunk pack index')
            _int(raw, 1, ch['max'], 'chunk raw length')
            _hex(cid, 'chunk id')
            if cid in ids:
                raise IntegrityError('duplicate chunk id')
            ids.add(cid)
            if p != cur_pack:
                if p != cur_pack + 1 or fill != self.packs[cur_pack][1]:
                    raise IntegrityError('chunks do not exactly tile packs (gap, overlap or spanning)')
                cur_pack, fill = p, 0
            if fill + raw > self.packs[p][1]:
                raise IntegrityError('chunk spans past its pack')
            self.chunks.append((p, raw, cid, fill))
            fill += raw
        if self.packs and (cur_pack != len(self.packs) - 1 or fill != self.packs[-1][1] or not self.chunks):
            raise IntegrityError('chunks do not exactly tile packs (unaccounted pack bytes)')
        if not self.packs and self.chunks:
            raise IntegrityError('chunks without packs')
        used = [False] * len(self.chunks)
        files = m['files']
        if not isinstance(files, list) or len(files) > L.max_files or not isinstance(m['dirs'], list):
            raise IntegrityError('file list')
        self.files, total = [], 0
        for e in files:
            if not isinstance(e, list) or len(e) != 4 or not isinstance(e[3], list):
                raise IntegrityError('file schema')
            path, size, sha, refs = e
            _int(size, 0, L.max_output, 'file size')
            _hex(sha, 'file sha256')
            s = 0
            for r in refs:
                _int(r, 0, len(self.chunks) - 1, 'chunk reference')
                used[r] = True
                s += self.chunks[r][1]
            if s != size:
                raise IntegrityError('file size does not match chunk references')
            total += size
            if total > L.max_output:
                raise IntegrityError('restored output exceeds limit')
            self.files.append((path, size, sha, array('I', refs)))   # 4 B/ref (3.1.3)
        v3.check_tree([f[0] for f in self.files], m['dirs'], L)
        self.dirs = m['dirs']
        if not all(used):
            raise IntegrityError('unreferenced chunk (unaccounted bytes)')
        self.total = total
        archive_size = HDR.size + self.header['manifest_len'] + plen
        if self._max_expansion_arg is not None:
            self.max_expansion = self._max_expansion_arg
        else:
            self.max_expansion = L.max_expansion_keyed if self.ctx.keyed else L.max_expansion
        if self.max_expansion and total > max(L.expansion_floor, self.max_expansion * archive_size):
            hint = ('An explicit cap was set on this keyed archive; pass --max-expansion 0 (API: max_expansion=0) '
                    'to remove it.' if self.ctx.keyed else
                    'Unkeyed archives are unauthenticated. If you trust this archive (e.g. zero-filled/sparse files '
                    'or disk images), rerun with --max-expansion 0 to disable the cap (API: max_expansion=0) or '
                    '--max-expansion N to raise it.')
            raise LimitError(f'declared output {total:,} bytes is {total / archive_size:,.0f}x the {archive_size:,}-byte '
                             f'archive (cap {self.max_expansion}x above {L.expansion_floor:,} bytes); refusing. ' + hint)
        self.parity, parity_len = None, 0
        if m['parity'] is not None:
            p = m['parity']
            _keys(p, ['k', 'm', 'shard', 'groups'], 'parity')
            k, mm = _int(p['k'], 1, 128, 'k'), _int(p['m'], 1, 64, 'm')
            _int(p['shard'], 512, L.max_shard, 'shard')
            layout = parity_layout(self.data_len, k, p['shard'])
            if not isinstance(p['groups'], list) or len(p['groups']) != len(layout):
                raise IntegrityError('parity group count')
            groups = []
            for (gs, gl, s), hs in zip(layout, p['groups']):
                if not isinstance(hs, list) or len(hs) != k + mm:
                    raise IntegrityError('parity hashes')
                groups.append((gs, gl, s, self.data_len + parity_len, [bytes.fromhex(_hex(h)) for h in hs]))
                parity_len += mm * s
            self.parity = (k, mm, groups)
        if self.data_len + parity_len != plen:
            raise IntegrityError('payload length mismatch')
        expect = self.ctx.tag(b'rdc3-root\0' + canonical(dict(files=[list(f[:3]) for f in self.files],
                                                                 dirs=self.dirs)))
        if not hmac.compare_digest(expect, root):
            raise IntegrityError('root hash mismatch')
        self.root = root
        for fe, me in zip(self.files, m['files']):   # 3.1.3: share the compact arrays, free the int lists
            me[3] = fe[3]
        self.manifest = m

    def _decode_pack(self, p):
        """Authenticate (parity-repair if needed) -> decrypt -> bounded decode one pack (no caching)."""
        codec, raw_len, n, tag, off = self.packs[p]
        body = self.ctx.open(DOMAIN_PACK, p, self.stored(off, n, tag))
        raw = body if codec == PACK_RAW else self._zstd_decode(body, raw_len, None)
        if len(raw) != raw_len:
            raise IntegrityError('decoded pack length mismatch')
        self.pack_decodes += 1
        return raw

    def pack_bytes(self, p):
        """Cached pack access for sequential reads (iter_file / chunk)."""
        if p in self._packs_cache:
            self._packs_cache.move_to_end(p)
            return self._packs_cache[p]
        raw = self._decode_pack(p)
        self._packs_cache[p] = raw
        while len(self._packs_cache) > self.limits.pack_cache:
            self._packs_cache.popitem(last=False)
        return raw

    def chunk(self, i):
        p, raw_len, cid, off = self.chunks[i]
        raw = self.pack_bytes(p)[off:off + raw_len]
        if len(raw) != raw_len or not hmac.compare_digest(self.ctx.chunk_id(raw), cid):
            raise IntegrityError(f'chunk {i} content hash mismatch')
        return raw

    # -- decode-cost control (SEEKER v3.1 finding: piece order cycling >2 packs forced a full pack
    #    decode per piece, e.g. 4.5 KB archive -> ~94 GiB decompressed). Restore and verify no longer
    #    depend on piece order: each pack is decoded at most once when sequential reading would cost more.
    def decode_cost(self, files):
        """Raw bytes a sequential read of `files` would decode with the pack_cache-sized LRU."""
        cache, cost, size = OrderedDict(), 0, self.limits.pack_cache
        for e in files:
            for r in e[3]:
                p = self.chunks[r][0]
                if p in cache:
                    cache.move_to_end(p)
                    continue
                cost += self.packs[p][1]
                cache[p] = None
                if len(cache) > size:
                    cache.popitem(last=False)
        return cost

    def decode_budget(self, files, default=False):
        L = self.limits
        if self.max_decode is not None and not default:
            return self.max_decode
        used = {self.chunks[r][0] for e in files for r in e[3]}
        return max(L.decode_floor, L.decode_factor * sum(self.packs[p][1] for p in used))

    def _sequential_ok(self, files):
        budget = self.decode_budget(files)
        return not budget or self.decode_cost(files) <= budget

    def _collect(self, files, recover, spill):
        """Pack-order pass: decode each needed pack once, check every needed chunk against its id once,
        append it to `spill`. Memory is O(chunks) (no per-reference plan). Returns (where, bad):
        where[r] = spill offset of chunk r, bad = {chunk: error} (recover mode only)."""
        n = len(self.chunks)
        need = bytearray(n)
        for e in files:
            for r in e[3]:
                need[r] = 1
        by_pack, unique = {}, 0
        for r in range(n):
            if need[r]:
                c = self.chunks[r]
                by_pack.setdefault(c[0], array('I')).append(r)
                unique += c[1]
        del need
        spill.prepare(unique)
        where, bad = array('q', bytes(8 * n)), {}
        for p in sorted(by_pack):
            try:
                raw = self._decode_pack(p)
            except IntegrityError as exc:
                if not recover:
                    raise
                for r in by_pack[p]:
                    bad[r] = str(exc)
                continue
            for r in by_pack[p]:
                _, rl, cid, coff = self.chunks[r]
                seg = raw[coff:coff + rl]
                if len(seg) != rl or not hmac.compare_digest(self.ctx.chunk_id(seg), cid):
                    exc = IntegrityError(f'chunk {r} content hash mismatch')
                    if not recover:
                        raise exc
                    bad[r] = str(exc)
                    continue
                where[r] = spill.append(seg)
            del raw
        spill.done()
        return where, bad

    def _iter_spilled(self, e, spill, where, granular=False):
        chunks, buf, n = self.chunks, [], 0
        for r in e[3]:
            b = spill.read(where[r], chunks[r][1])
            if granular:          # --sparse: one piece at a time so all-zero pieces can become holes
                yield b
                continue
            buf.append(b)
            n += len(b)
            if n >= 1 << 20 or len(buf) >= 4096:
                yield b''.join(buf)
                buf, n = [], 0
        if buf:
            yield b''.join(buf)

    def stage_all(self, stage, recover, files=None, durable=True, spill_dir=None, pending=0, sparse=False,
                  sync_log=None):
        """Write `files` into staging dir `stage` (a POSIX dir fd or a path) as 00000000, 00000001, ...
        Within the decode budget files are read in piece order (2-pack cache). Above it (crafted or
        shuffled-dedup archives) every needed pack is decoded once, in pack order, and the unique
        verified pieces are spilled to RAM (up to Limits4.spill_memory) then to an unnamed temp file
        in `spill_dir`; files are then written sequentially from the spill. Decode work stays
        <= used pack bytes, extra disk <= unique piece bytes, no positional writes, one open file.
        Each staged file is checked against its SHA-256. sparse: all-zero pieces are skipped with a
        seek (holes) and the file is truncated to its full size. Returns (staged, damaged, digests)."""
        files = self.files if files is None else files
        spill = where = None
        bad = {}
        if not self._sequential_ok(files):
            spill = _Spill(self.limits.spill_memory, spill_dir, self.limits, pending)
            where, bad = self._collect(files, recover, spill)
        staged, damaged, digests = [], [], []
        try:
            for fi, e in enumerate(files):
                name = f'{fi:08d}'
                err = next((bad[r] for r in e[3] if r in bad), None) if bad else None
                if err is not None:
                    damaged.append(dict(path=e[0], error=err))
                    continue
                f = _stage_create(stage, name)
                try:
                    pieces = (self.iter_file(e) if spill is None
                              else self._iter_spilled(e, spill, where, granular=sparse))
                    _write_staged(f, pieces, e, sparse, durable, sync_log)
                except IntegrityError as exc:
                    _stage_unlink(stage, name)
                    if not recover:
                        raise
                    damaged.append(dict(path=e[0], error=str(exc)))
                    continue
                staged.append((name, e))
                digests.append([e[0], e[1], e[2]])
        finally:
            if spill is not None:
                spill.close()
        return staged, damaged, digests

    def _scan_group(self, gi):
        k, m, groups = self.parity
        gs, gl, s, poff, hashes = groups[gi]
        raw = self._read_at(gs, gl).ljust(k * s, b'\0')
        bad = []
        for i in range(k + m):
            sh = raw[i * s:(i + 1) * s] if i < k else self._read_at(poff + (i - k) * s, s)
            if not hmac.compare_digest(self.ctx.tag(sh), hashes[i]):
                bad.append((gi, i))
        return bad

    def verify_packs(self, n, t):
        """Rotating partial verify (3.1.5, `verify --packs n/t`). Selected packs: index i with i % t == n.
        For each selected pack: its stored-bytes tag (HMAC-SHA256 keyed / SHA-256 unkeyed) and, when
        encrypted, its ChaCha20-Poly1305 tag (decrypt-only). For every parity group whose data range
        overlaps a selected pack: all k+m shard hashes. No zstd decode, no file digests; the manifest
        and root were authenticated when the archive was opened. Running n = 0..t-1 covers every pack
        and every parity shard at least once."""
        if type(n) is not int or type(t) is not int or not 1 <= t <= Limits4.max_packs or not 0 <= n < t:
            raise ValueError(f'--packs n/t needs integers with 0 <= n < t <= {Limits4.max_packs}')
        sel = set(range(n, len(self.packs), t))
        bad_packs = []
        for i in sorted(sel):
            codec, raw_len, stored_len, tag, off = self.packs[i]
            b = self._read_at(off, stored_len)
            if not hmac.compare_digest(self.ctx.tag(b), tag):
                bad_packs.append(i)
                continue
            if self.ctx.encrypted:
                try:
                    self.ctx.open(DOMAIN_PACK, i, b)
                except IntegrityError:
                    bad_packs.append(i)
        bad_shards, groups_checked = [], 0
        if self.parity is not None:
            import bisect
            offs = [p[4] for p in self.packs]
            for gi, (gs, gl, s, poff, hashes) in enumerate(self.parity[2]):
                j = max(0, bisect.bisect_right(offs, gs) - 1)
                hit = False
                while j < len(self.packs) and self.packs[j][4] < gs + gl:
                    if j in sel and self.packs[j][4] + self.packs[j][2] > gs:
                        hit = True
                        break
                    j += 1
                if hit:
                    groups_checked += 1
                    bad_shards += self._scan_group(gi)
        return dict(ok=not bad_shards and not bad_packs, format='RDCv004', verify_mode='partial',
                    slice=f'{n}/{t}', packs_checked=len(sel), packs_total=len(self.packs),
                    groups_checked=groups_checked, groups_total=len(self.parity[2]) if self.parity else 0,
                    bad_packs=bad_packs, bad_shards=bad_shards, needs_repair=bool(bad_shards or bad_packs),
                    files=len(self.files), pack_decodes=self.pack_decodes, file_digests_checked=False)

    def verify(self, temp_dir=None):
        bad_shards = self.scan_shards()
        bad_packs = [i for i, p in enumerate(self.packs)
                     if not hmac.compare_digest(self.ctx.tag(self._read_at(p[4], p[2])), p[3])]
        cost, budget = self.decode_cost(self.files), self.decode_budget(self.files)
        warns = []
        if not budget and cost > self.decode_budget(self.files, default=True):
            # max_decode=0 / --force-sequential re-enables piece-order decoding: say so before paying for it
            warns.append(f'forced sequential verify will decode {cost} bytes of packs '
                         f'(default budget {self.decode_budget(self.files, default=True)}); '
                         'this archive may be crafted to waste CPU. Drop --max-decode 0 to check in pack order.')
            warnings.warn(warns[-1], RuntimeWarning, stacklevel=2)
            if self.on_warning:
                self.on_warning(warns[-1])
        spill_info = None
        prog = _progress
        if prog is not None:
            prog.start('verify', sum(e[1] for e in self.files))
        if not budget or cost <= budget:
            mode, digests = 'sequential', []
            for e in self.files:
                h = hashlib.sha256()
                for b in self.iter_file(e):
                    h.update(b)
                    if prog is not None:
                        prog.add(len(b))
                if h.hexdigest() != e[2]:
                    raise IntegrityError(f'file digest mismatch: {e[0]}')
                digests.append([e[0], e[1], h.hexdigest()])
        else:
            # 3.1.3: no staged copy of the output. Unique verified pieces only (<= used pack bytes),
            # RAM first, then an unnamed temp file in temp_dir (default: system temp).
            mode, digests = 'pack_order', []
            spill = _Spill(self.limits.spill_memory, temp_dir, self.limits)
            try:
                where, _ = self._collect(self.files, False, spill)
                for e in self.files:
                    h = hashlib.sha256()
                    for b in self._iter_spilled(e, spill, where):
                        h.update(b)
                        if prog is not None:
                            prog.add(len(b))
                    if h.hexdigest() != e[2]:
                        raise IntegrityError(f'file digest mismatch: {e[0]}')
                    digests.append([e[0], e[1], e[2]])
                spill_info = dict(bytes=spill.size, on_disk=spill.f is not None)
            finally:
                spill.close()
        root = self.ctx.tag(b'rdc3-root\0' + canonical(dict(files=digests, dirs=self.dirs)))
        if not hmac.compare_digest(root, self.root):
            raise IntegrityError('root hash mismatch on verify')
        return dict(ok=not bad_shards and not bad_packs, files=len(self.files), bad_shards=bad_shards,
                    bad_packs=bad_packs, bad_chunks=bad_packs, parity_repairs_used=self.repairs,
                    needs_repair=bool(bad_shards or bad_packs), format='RDCv004', verify_mode=mode,
                    sequential_decode_bytes=cost, pack_decodes=self.pack_decodes, warnings=warns,
                    spill=spill_info)


class _Spill:
    """Append-only store of unique verified piece bytes: RAM up to `memory`, then an unnamed temp file
    (deleted on close on every OS) in `dir`. Free space for the on-disk part (+ `pending` bytes the
    caller will still write to the same filesystem) is checked before anything is decoded."""
    def __init__(self, memory, dir=None, limits=Limits4, pending=0):
        self.memory, self.dir, self.limits, self.pending = memory, dir, limits, pending
        self.buf, self.f, self.size = bytearray(), None, 0

    def prepare(self, total):
        if total > self.memory:
            path = self.dir or tempfile.gettempdir()
            if not os.path.isdir(path):
                raise LimitError(f'--temp-dir {path!r} does not exist or is not a folder; pack-order '
                                 f'checking needs {total:,} bytes of temp space there')
            try:
                check_free_space(path, total + self.pending, self.limits)
            except LimitError as exc:
                raise LimitError(f'{exc}. Pack-order checking needs {total:,} bytes of unique pieces; '
                                 'point --temp-dir at a drive with room, or use --force-sequential '
                                 '(no temp disk, slower on crafted archives)') from None

    def append(self, b):
        off = self.size
        if self.f is None and off + len(b) > self.memory:
            self.f = tempfile.TemporaryFile(dir=self.dir)
            self.f.write(self.buf)
            self.buf = None
        if self.f is None:
            self.buf += b
        else:
            self.f.write(b)
        self.size += len(b)
        return off

    def done(self):
        if self.f is not None:
            self.f.flush()

    def read(self, off, n):
        if self.f is None:
            return self.buf[off:off + n]
        self.f.seek(off)
        b = self.f.read(n)
        if len(b) != n:
            raise IntegrityError('spill file truncated')
        return b

    def close(self):
        if self.f is not None:
            self.f.close()
        self.buf = None


def _write_staged(f, pieces, e, sparse, durable, sync_log):
    """Write verified pieces to staged file f, check the whole-file SHA-256, then durable-sync.
    sparse: every piece is still hashed; all-zero pieces are seeked over (a hole on filesystems that
    support them) and the file is truncated to its full size before the sync, so a trailing hole
    still yields the right length."""
    prog = _progress
    with f:
        h = hashlib.sha256()
        for b in pieces:
            h.update(b)
            if prog is not None:
                prog.add(len(b))
            if sparse and b and b.count(0) == len(b):
                f.seek(len(b), 1)
            else:
                f.write(b)
        if h.hexdigest() != e[2]:
            raise IntegrityError(f'file digest mismatch: {e[0]}')
        if sparse:
            f.truncate(e[1])
        if durable:
            f.flush()
            if hasattr(os, 'fchmod'):
                os.fchmod(f.fileno(), 0o644)
            v3._durable_sync(f.fileno(), sync_log)


def _stage_sequential(a, stage, recover, files=None, durable=True, spill_dir=None, pending=0, sparse=False,
                      sync_log=None):
    """Piece-order stager for RDCv003 readers (same contract and return value as Archive4.stage_all)."""
    files = a.files if files is None else files
    staged, damaged, digests = [], [], []
    for fi, e in enumerate(files):
        name = f'{fi:08d}'
        f = _stage_create(stage, name)
        try:
            _write_staged(f, a.iter_file(e), e, sparse, durable, sync_log)
        except IntegrityError as exc:
            _stage_unlink(stage, name)
            if not recover:
                raise
            damaged.append(dict(path=e[0], error=str(exc)))
            continue
        staged.append((name, e))
        digests.append([e[0], e[1], e[2]])
    return staged, damaged, digests


class _StageView:
    """Archive view whose stage_all carries the restore options (sparse, sync log) to any reader."""
    def __init__(self, inner, stage_all):
        self._inner = inner
        self.stage_all = stage_all

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _stage_create(stage, name):
    if isinstance(stage, int):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _O_BINARY, 0o600, dir_fd=stage)
    else:
        fd = os.open(os.path.join(stage, name),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | _O_BINARY, 0o600)
        # O_EXCL never opens an existing name (a planted link fails with FileExistsError); on Windows
        # also confirm the new handle and the staged path are the same file and not a reparse point.
        if not hasattr(os, 'O_NOFOLLOW'):
            ls, fs = os.lstat(os.path.join(stage, name)), os.fstat(fd)
            if _is_link_like(ls) or (ls.st_ino and (ls.st_dev, ls.st_ino) != (fs.st_dev, fs.st_ino)):
                os.close(fd)
                raise IntegrityError(f'staging file replaced during create: {name}')
    return os.fdopen(fd, 'wb')


def _stage_unlink(stage, name):
    if isinstance(stage, int):
        os.unlink(name, dir_fd=stage)
    else:
        os.unlink(os.path.join(stage, name))


def archive_format(path):
    with open(path, 'rb') as f:
        magic = f.read(8)
    if magic == MAGIC4:
        return 4
    if magic == v3.MAGIC:
        return 3
    raise IntegrityError('not an RDCv003/RDCv004 archive (bad magic)')


def open_archive(path, password=None, max_expansion=None, limits=None, max_decode=None):
    if archive_format(path) == 4:
        return Archive4(path, password, limits or Limits4, max_expansion, max_decode)
    return v3.Archive(path, password, limits or v3.Limits, max_expansion)


class _Subset:
    """View restoring only selected files. The full manifest (and its root) was already authenticated;
    the subset root is recomputed from those authenticated entries and checked against restored bytes."""
    def __init__(self, a, paths):
        want = list(dict.fromkeys(paths))
        by_path = {e[0]: e for e in a.files}
        missing = [p for p in want if p not in by_path]
        if missing:
            raise KeyError(f'not in archive: {missing[:5]}')
        self._a = a
        self.files = [by_path[p] for p in want]
        if hasattr(a, 'stage_all'):   # RDCv004: pack-order staging of just these files
            self.stage_all = lambda stage, recover, **kw: a.stage_all(stage, recover, self.files, **kw)
        self.dirs = []
        self.ctx, self.limits = a.ctx, a.limits
        self.total = sum(e[1] for e in self.files)
        self.root = a.ctx.tag(b'rdc3-root\0' + canonical(dict(files=[list(e[:3]) for e in self.files], dirs=[])))

    def iter_file(self, e):
        return self._a.iter_file(e)

    @property
    def repairs(self):
        return self._a.repairs


def posix_fd_restore_supported():
    return (hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY') and os.link in os.supports_dir_fd
            and os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd)


def restore(archive, dest_dir, password=None, recover=False, failpoint=None, max_expansion=None, paths=None,
            portable=None, sparse=False, strict_names=False):
    """Restore an RDCv004 or RDCv003 archive (fail closed, no clobber; see rdc3.restore).
    paths: restore only these archive paths (random access; only their packs are decoded).
    portable: None = descriptor-relative POSIX restore where the OS supports it, else the path-based
    portable restore (Windows); True/False forces one (env RDC_PORTABLE=1 also forces portable).
    sparse: leave holes for all-zero pieces (opt-in). strict_names: refuse names that would collide on
    a case- or normalization-insensitive filesystem even when this destination is not one (see
    check_name_collisions; on such a destination they are always refused)."""
    if portable is None:
        portable = os.environ.get('RDC_PORTABLE') == '1' or not posix_fd_restore_supported()
    elif not portable and not posix_fd_restore_supported():
        raise NotImplementedError('descriptor-relative restore requires POSIX dir_fd support')
    with open_archive(archive, password, max_expansion) as a:
        view = _Subset(a, paths) if paths is not None else a
        if os.path.islink(dest_dir) or (os.path.lexists(dest_dir) and _is_link_like(os.lstat(dest_dir))):
            raise IntegrityError('destination is a symlink')
        created = not os.path.exists(dest_dir)
        check_free_space(dest_dir if not created else os.path.dirname(os.path.abspath(dest_dir)) or '.',
                         view.total, a.limits)
        if created:
            os.mkdir(dest_dir, 0o755)
        if _progress is not None:
            _progress.start('unpack', view.total)
        log = v3.SyncLog()
        inner_stage = getattr(view, 'stage_all', None)
        if inner_stage is None:          # RDCv003 reader: piece-order stager with the same options
            v3view = view
            inner_stage = lambda stage, recover, **kw: _stage_sequential(v3view, stage, recover, **kw)
        sview = _StageView(view, lambda stage, recover, **kw: inner_stage(stage, recover, sparse=sparse,
                                                                         sync_log=log, **kw))
        try:
            if portable:   # Windows rules first (reserved names, NTFS case key), then the probe-driven check
                check_portable_tree([e[0] for e in view.files], view.dirs)
            names = check_name_collisions([e[0] for e in view.files], view.dirs, dest_dir, strict_names)
            r = (_restore_into_portable if portable else _restore_into)(sview, dest_dir, recover, failpoint, log)
        except PublicationError:
            raise
        except BaseException:
            if created:
                try:
                    os.rmdir(dest_dir)
                except OSError:
                    pass
            raise
        r['pack_decodes'] = getattr(a, 'pack_decodes', None)
        r['format'] = 'RDCv004' if isinstance(a, Archive4) else 'RDCv003'
        r['mode'] = 'portable' if portable else 'posix_fd'
        r['sparse'] = bool(sparse)
        r['name_semantics'] = names['semantics']
        r['name_warnings'] = names['warnings']
        return r   # directories_fsynced / sync_mode come from the restore that actually ran


# ---------------------------------------------------------------- portable (Windows) restore
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_WIN_RESERVED = ({'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} | {f'COM{c}' for c in '0123456789\u00b9\u00b2\u00b3'}
                 | {f'LPT{c}' for c in '0123456789\u00b9\u00b2\u00b3'})


def _is_link_like(st):
    """Symlink, or any Windows reparse point (junction, mount point, cloud placeholder)."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, 'st_file_attributes', 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def check_portable_tree(files, dirs):
    """Names Windows would reinterpret: reserved devices, <>"|?*, trailing dot/space, and paths that
    collide under the NTFS case key (collision_key, 1:1 per character, so straße/strasse are distinct).
    rdc3.check_rel_path already refuses \\ : and control chars."""
    for p in list(dirs) + list(files):
        for part in p.split('/'):
            if part[-1] in '. ' or any(c in '<>"|?*' for c in part) or \
                    part.split('.')[0].rstrip(' ').upper() in _WIN_RESERVED:
                raise IntegrityError(f'path not representable on Windows: {p!r}')
    hits = find_name_collisions(files, dirs, case_insensitive=True, normalization_insensitive=False)
    if hits:
        raise IntegrityError(f'paths collide case-insensitively: {hits[0][0]!r} / {hits[0][1]!r}')


# ---------------------------------------------------------------- name collisions (3.1.5)
def collision_key(p, case_insensitive=True, normalization_insensitive=False):
    """The one collision key used before staging on every platform.
    normalization- and case-insensitive (macOS APFS/HFS+ default): NFD + casefold (+ NFD again).
    case-insensitive only (NTFS default): per-character upper(), kept only if it stays one character
    (NTFS $UpCase is 1:1, so 'ß' stays 'ß' and straße/strasse do not collide).
    normalization-insensitive only: NFD. Neither: the name itself.
    Best effort: Python's Unicode tables approximate a volume's own case table."""
    if normalization_insensitive:
        p = unicodedata.normalize('NFD', p)
        return unicodedata.normalize('NFD', p.casefold()) if case_insensitive else p
    if case_insensitive:
        return ''.join(u if len(u := c.upper()) == 1 else c for c in p)
    return p


def find_name_collisions(files, dirs, case_insensitive=True, normalization_insensitive=False):
    """[(first, second)] pairs of distinct archive paths (files, dirs and every parent directory)
    that share a collision_key."""
    names = set(dirs) | set(files)
    for p in list(files) + list(dirs):
        parts = p.split('/')
        names.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    seen, hits = {}, []
    for p in sorted(names):
        k = collision_key(p, case_insensitive, normalization_insensitive)
        if k in seen and seen[k] != p:
            hits.append((seen[k], p))
        else:
            seen[k] = p
    return hits


_PROBE_NAME = 'rdc-probe-\u00e9'     # lowercase, NFC


def probe_name_semantics(dest_dir):
    """Create a test name in a fresh staging-prefixed folder inside dest_dir and look it up in upper
    case and in NFD. Returns dict(case_insensitive=bool, normalization_insensitive=bool). Leaves nothing."""
    d = tempfile.mkdtemp(prefix=v3.STAGING_PREFIX, dir=dest_dir)
    try:
        p = os.path.join(d, _PROBE_NAME)
        os.close(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600))
        try:
            ci = os.path.lexists(os.path.join(d, _PROBE_NAME.upper()))
            ni = os.path.lexists(os.path.join(d, unicodedata.normalize('NFD', _PROBE_NAME)))
        finally:
            for n in os.listdir(d):
                os.unlink(os.path.join(d, n))
    finally:
        os.rmdir(d)
    return dict(case_insensitive=ci, normalization_insensitive=ni)


def check_name_collisions(files, dirs, dest_dir, strict=False, semantics=None):
    """Run before staging on every platform. If the destination probe shows case- or normalization-
    insensitive lookup, names colliding under that key are refused (IntegrityError, nothing written).
    Otherwise (e.g. Linux ext4) collisions under the NTFS and macOS keys are only warnings, unless
    strict (--strict-names), which refuses them. Returns dict(semantics, warnings)."""
    sem = semantics if semantics is not None else probe_name_semantics(dest_dir)
    ci, ni = sem['case_insensitive'], sem['normalization_insensitive']
    if ci or ni:
        hits = find_name_collisions(files, dirs, ci, ni)
        if hits:
            kind = ' and '.join(x for x, on in (('case', ci), ('Unicode normalization', ni)) if on)
            raise IntegrityError(f'paths collide on this destination ({kind}-insensitive): {hits[0][0]!r} / '
                                 f'{hits[0][1]!r} ({len(hits)} collision(s)); nothing written')
        return dict(semantics=sem, warnings=[])
    hits = list(dict.fromkeys(find_name_collisions(files, dirs, True, False) +
                              find_name_collisions(files, dirs, True, True)))
    if hits and strict:
        raise IntegrityError(f'--strict-names: paths would collide on Windows/macOS: {hits[0][0]!r} / '
                             f'{hits[0][1]!r} ({len(hits)} collision(s)); nothing written')
    msgs = [f'paths would collide on a case/normalization-insensitive filesystem (Windows/macOS): {a!r} / {b!r}'
            for a, b in hits[:20]]
    if msgs:
        warnings.warn(f'{len(hits)} name collision(s) for Windows/macOS, e.g. {hits[0][0]!r} / {hits[0][1]!r}; '
                      'restored here, but copying this tree to such a filesystem would merge them '
                      '(--strict-names refuses)', RuntimeWarning, stacklevel=3)
    return dict(semantics=sem, warnings=msgs)


def _safe_parent(root, parts, create):
    """Path of the parent of parts under root, refusing any component that is a symlink, junction or
    non-directory (lstat per component; no following). None if absent and not create."""
    cur = root
    for name in parts[:-1]:
        nxt = os.path.join(cur, name)
        try:
            st = os.lstat(nxt)
        except FileNotFoundError:
            if not create:
                return None
            try:
                os.mkdir(nxt, 0o755)
            except FileExistsError:
                pass
            st = os.lstat(nxt)
        if _is_link_like(st) or not stat.S_ISDIR(st.st_mode):
            raise IntegrityError(f'path component is a symlink/junction or not a directory: {name}')
        cur = nxt
    return cur


_WIN_RETRY_ERRS = (5, 32, 33)          # access denied / sharing violation / lock violation
_WIN_RETRY_BUDGET = 3.0                # seconds of bounded backoff for transient AV/indexer locks


def _win_retry(fn, *args, budget=None, sleep=None):
    """Call fn(*args); on Windows retry only winerror 5/32/33 with bounded backoff. Anything else
    (including FileExistsError) is raised at once. Non-Windows: single call."""
    import time
    sleep = sleep or time.sleep
    budget = _WIN_RETRY_BUDGET if budget is None else budget
    delay, waited = 0.05, 0.0
    while True:
        try:
            return fn(*args)
        except FileExistsError:
            raise
        except OSError as exc:
            if getattr(exc, 'winerror', None) not in _WIN_RETRY_ERRS or waited >= budget:
                raise
            d = min(delay, budget - waited)
            sleep(d)
            waited += d
            delay = min(delay * 2, 0.5)


def _open_nofollow_read(path, expect=None):
    """Open a regular file for reading without following a final symlink/junction.
    POSIX: O_NOFOLLOW. Windows: CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT and refuse any reparse
    point. Both: if `expect` (the walk-time lstat) is given, dev/ino must match the opened handle;
    ino 0 (FAT/exFAT/some SMB) cannot prove identity and is refused."""
    if hasattr(os, 'O_NOFOLLOW'):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | _O_BINARY)
        except OSError as exc:   # 3.1.5: final symlink -> ELOOP (FreeBSD: EMLINK) is an integrity refusal
            if exc.errno == errno.ELOOP or ('bsd' in sys.platform and exc.errno == errno.EMLINK):
                raise IntegrityError(f'refusing symlink: {path}') from exc
            raise
    elif os.name == 'nt':
        fd = _nt_open_reparse_safe(path)
    else:   # no O_NOFOLLOW and not Windows (e.g. the RDC_SIM_NT test run): lstat-then-compare
        ls = os.lstat(path)
        if _is_link_like(ls):
            raise IntegrityError(f'refusing symlink/reparse point: {path}')
        fd = os.open(path, os.O_RDONLY | _O_BINARY)
        fs = os.fstat(fd)
        if (fs.st_dev, fs.st_ino) != (ls.st_dev, ls.st_ino):
            os.close(fd)
            raise IntegrityError(f'file swapped during open: {path}')
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IntegrityError(f'not a regular file: {path}')
        if expect is not None:
            if not st.st_ino or not expect.st_ino:
                raise IntegrityError(f'cannot prove file identity (inode 0) for {path}')
            if (st.st_dev, st.st_ino) != (expect.st_dev, expect.st_ino):
                raise IntegrityError(f'file changed between scan and read: {path}')
    except BaseException:
        os.close(fd)
        raise
    return fd


def _nt_open_reparse_safe(path):                      # pragma: no cover - Windows only
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    GENERIC_READ, SHARE_RW = 0x80000000, 0x1 | 0x2
    OPEN_EXISTING, FLAG_REPARSE, ATTR_REPARSE = 3, 0x00200000, 0x400
    INVALID = wintypes.HANDLE(-1).value
    h = _win_retry(lambda: _nt_create(k32, path, GENERIC_READ, SHARE_RW, OPEN_EXISTING, FLAG_REPARSE, INVALID))

    class BHFI(ctypes.Structure):
        _fields_ = [('attr', wintypes.DWORD), ('c', wintypes.FILETIME), ('a', wintypes.FILETIME),
                    ('w', wintypes.FILETIME), ('vol', wintypes.DWORD), ('szh', wintypes.DWORD),
                    ('szl', wintypes.DWORD), ('links', wintypes.DWORD), ('ih', wintypes.DWORD),
                    ('il', wintypes.DWORD)]
    info = BHFI()
    if not k32.GetFileInformationByHandle(h, ctypes.byref(info)) or info.attr & ATTR_REPARSE:
        k32.CloseHandle(h)
        raise IntegrityError(f'refusing reparse point (symlink/junction): {path}')
    return msvcrt.open_osfhandle(h, os.O_RDONLY | _O_BINARY)


def _nt_create(k32, path, access, share, disp, flags, invalid):  # pragma: no cover - Windows only
    h = k32.CreateFileW(path, access, share, None, disp, flags, None)
    if h == invalid or h is None:
        err = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(err), path, err)
    return h


def _link_noclobber(src, dst):
    """Non-Windows publish without overwriting: hard link (refuses an existing name). 3.1.5: no rename
    fallback here at all; Windows uses _nt_publish (handle-based, never replaces)."""
    _win_retry(os.link, src, dst)


# ---------------------------------------------------------------- Windows publish (3.1.5)
_NT_FALLBACK_ERRS = (1, 50, 87, 123)   # INVALID_FUNCTION / NOT_SUPPORTED / INVALID_PARAMETER / INVALID_NAME (3.1.6) -> MoveFileExW
_NT_EXISTS_ERRS = (80, 183)       # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS -> FileExistsError
_MOVEFILE_WRITE_THROUGH = 0x8     # never MOVEFILE_REPLACE_EXISTING (0x1)


def _nt_exists(exc, dst):
    return FileExistsError(errno.EEXIST, f'destination exists, refusing to overwrite (winerror '
                                         f'{getattr(exc, "winerror", None)})', dst)


def _nt_publish(src, dst, api=None):
    """Windows no-clobber publish of staged file src as dst, one handle-based path:
    1. open dst's folder with FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT and no
       FILE_SHARE_DELETE (it cannot be renamed/replaced by a junction while held); refuse a reparse point;
    2. open src, FlushFileBuffers on that handle;
    3. NtSetInformationFile(FileRenameInformation, ReplaceIfExists=FALSE (3.1.6; kernel32's wrapper refuses this), RootDirectory=folder handle,
       FileName=leaf name).
    Only if step 2/3 fails with winerror 1/50/87/123 (call unsupported, e.g. some network/FAT drivers):
    MoveFileExW(src, dst, MOVEFILE_WRITE_THROUGH), never REPLACE_EXISTING. winerror 183/80 ->
    FileExistsError. 5/32/33 are retried (_win_retry). Returns 'handle_rename' or 'movefile_write_through'.
    `api` is injectable for tests (see _NtApi for the real calls)."""
    api = api or _NtApi()
    parent, name = os.path.split(dst)
    dirh = _win_retry(api.open_dir, parent)
    try:
        try:
            fh = _win_retry(api.open_file, src)
            try:
                api.flush(fh)
                _win_retry(api.rename_by_handle, fh, dirh, name)
            finally:
                api.close(fh)
            return 'handle_rename'
        except FileExistsError:
            raise
        except OSError as exc:
            w = getattr(exc, 'winerror', None)
            if w in _NT_EXISTS_ERRS:
                raise _nt_exists(exc, dst) from exc
            if w not in _NT_FALLBACK_ERRS:
                raise
        try:
            _win_retry(api.move_file_ex, src, dst, _MOVEFILE_WRITE_THROUGH)
        except FileExistsError:
            raise
        except OSError as exc:
            if getattr(exc, 'winerror', None) in _NT_EXISTS_ERRS:
                raise _nt_exists(exc, dst) from exc
            raise
        return 'movefile_write_through'
    finally:
        api.close(dirh)


class _NtApi:                                          # pragma: no cover - Windows only
    """The real Win32 calls behind _nt_publish (ctypes; constructed only on Windows)."""
    GENERIC_WRITE, DELETE, SYNCHRONIZE = 0x40000000, 0x00010000, 0x00100000
    FILE_LIST_DIRECTORY, FILE_TRAVERSE = 0x1, 0x20
    SHARE_READ, SHARE_WRITE = 0x1, 0x2
    OPEN_EXISTING = 3
    BACKUP_SEMANTICS, OPEN_REPARSE_POINT = 0x02000000, 0x00200000
    ATTR_DIRECTORY, ATTR_REPARSE = 0x10, 0x400
    FILE_RENAME_INFORMATION = 10   # NtSetInformationFile class (3.1.6)

    def __init__(self):
        if sys.platform != 'win32':
            raise NotImplementedError('Windows publish API requested on a non-Windows OS')
        k = self.k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        k.CreateFileW.restype = wintypes.HANDLE
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        k.FlushFileBuffers.restype = wintypes.BOOL
        k.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        k.SetFileInformationByHandle.restype = wintypes.BOOL
        nt = self.nt = ctypes.WinDLL('ntdll')
        nt.NtSetInformationFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG,
                                            ctypes.c_int]
        nt.NtSetInformationFile.restype = ctypes.c_long
        nt.RtlNtStatusToDosError.argtypes = [wintypes.ULONG]
        nt.RtlNtStatusToDosError.restype = wintypes.ULONG
        k.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        k.MoveFileExW.restype = wintypes.BOOL
        k.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k.GetFileInformationByHandle.restype = wintypes.BOOL
        self.invalid = wintypes.HANDLE(-1).value

    def _fail(self, what, path):
        err = ctypes.get_last_error()
        return OSError(None, f'{what}: {ctypes.FormatError(err)}', path, err)

    def _attrs(self, h):
        class BHFI(ctypes.Structure):
            _fields_ = [('attr', wintypes.DWORD), ('c', wintypes.FILETIME), ('a', wintypes.FILETIME),
                        ('w', wintypes.FILETIME), ('vol', wintypes.DWORD), ('szh', wintypes.DWORD),
                        ('szl', wintypes.DWORD), ('links', wintypes.DWORD), ('ih', wintypes.DWORD),
                        ('il', wintypes.DWORD)]
        info = BHFI()
        if not self.k32.GetFileInformationByHandle(h, ctypes.byref(info)):
            return None
        return info.attr

    def _open(self, path, access, share, flags):
        h = self.k32.CreateFileW(path, access, share, None, self.OPEN_EXISTING, flags, None)
        if h == self.invalid or h is None:
            raise self._fail('CreateFileW', path)
        return h

    def open_dir(self, path):
        h = self._open(path, self.FILE_LIST_DIRECTORY | self.FILE_TRAVERSE | self.SYNCHRONIZE,
                       self.SHARE_READ | self.SHARE_WRITE, self.BACKUP_SEMANTICS | self.OPEN_REPARSE_POINT)
        a = self._attrs(h)
        if a is None or a & self.ATTR_REPARSE or not a & self.ATTR_DIRECTORY:
            self.k32.CloseHandle(h)
            raise IntegrityError(f'publish folder is a reparse point (junction/symlink) or not a folder: {path}')
        return h

    def open_file(self, path):
        h = self._open(path, self.GENERIC_WRITE | self.DELETE | self.SYNCHRONIZE, self.SHARE_READ,
                       self.OPEN_REPARSE_POINT)
        a = self._attrs(h)
        if a is None or a & (self.ATTR_REPARSE | self.ATTR_DIRECTORY):
            self.k32.CloseHandle(h)
            raise IntegrityError(f'staged file is a reparse point or folder: {path}')
        return h

    def flush(self, h):
        if not self.k32.FlushFileBuffers(h):
            raise self._fail('FlushFileBuffers', None)

    def rename_by_handle(self, fh, dirh, name):
        # 3.1.6: kernel32 SetFileInformationByHandle(FileRenameInfo) rejects a RootDirectory-relative name on
        # real Windows (winerror 123, found on the 3090), so call NtSetInformationFile(FileRenameInformation=10)
        # directly; same FILE_RENAME_INFORMATION layout, ReplaceIfExists=FALSE, NTSTATUS mapped to winerror.
        n16 = len(name.encode('utf-16-le')) // 2

        class FILE_RENAME_INFO(ctypes.Structure):
            _fields_ = [('ReplaceIfExists', wintypes.DWORD), ('RootDirectory', wintypes.HANDLE),
                        ('FileNameLength', wintypes.DWORD), ('FileName', ctypes.c_wchar * (n16 + 1))]

        class IO_STATUS_BLOCK(ctypes.Structure):
            _fields_ = [('Status', ctypes.c_void_p), ('Information', ctypes.c_void_p)]
        info = FILE_RENAME_INFO(0, dirh, n16 * 2, name)
        iosb = IO_STATUS_BLOCK()
        st = self.nt.NtSetInformationFile(fh, ctypes.byref(iosb), ctypes.byref(info), ctypes.sizeof(info),
                                          self.FILE_RENAME_INFORMATION) & 0xFFFFFFFF
        if st >= 0x80000000:   # NT_ERROR / NT_WARNING
            err = self.nt.RtlNtStatusToDosError(st)
            raise OSError(None, f'NtSetInformationFile(FileRenameInformation) NTSTATUS 0x{st:08x}: '
                                f'{ctypes.FormatError(err).strip()}', name, err)

    def move_file_ex(self, src, dst, flags):
        if not self.k32.MoveFileExW(src, dst, flags):
            raise self._fail('MoveFileExW', dst)

    def close(self, h):
        self.k32.CloseHandle(h)


def _publish_noclobber(src, dst):
    """The one no-clobber publish used for restored files and archive outputs.
    Windows: _nt_publish (moves src). Elsewhere: hard link (src stays, caller unlinks)."""
    if sys.platform == 'win32':
        return _nt_publish(src, dst)
    _link_noclobber(src, dst)
    return 'link'


if sys.platform == 'win32':                            # pragma: no cover - Windows only
    v3._WIN_PUBLISH = _publish_noclobber


def _restore_into_portable(a, dest_dir, recover, failpoint, sync_log=None):
    """Same contract as rdc3._restore_into (stage + verify everything, root check, no-clobber publish,
    PublicationError once anything is published) using paths instead of directory descriptors.
    Residual risk vs POSIX: a local process racing to swap a checked directory for a junction between
    the check and the link (documented in README: Windows)."""
    log = sync_log if sync_log is not None else v3.SyncLog()
    dsynced = False
    publish_modes = set()
    root = os.path.abspath(dest_dir)
    st = os.lstat(root)
    if _is_link_like(st) or not stat.S_ISDIR(st.st_mode):
        raise IntegrityError('destination is a symlink/junction or not a directory')
    check_portable_tree([e[0] for e in a.files], a.dirs)
    for e in a.files:                                    # 1. conflict pre-check
        parts = e[0].split('/')
        parent = _safe_parent(root, parts, create=False)
        if parent is not None and os.path.lexists(os.path.join(parent, parts[-1])):
            raise FileExistsError(f'destination exists, refusing to overwrite: {e[0]}')
    staging = tempfile.mkdtemp(prefix=v3.STAGING_PREFIX, dir=root)
    published = []
    try:
        stage_all = getattr(a, 'stage_all', None)       # 2. stage + verify
        if stage_all is not None:
            staged, damaged, digests = stage_all(staging, recover, spill_dir=staging)
        else:                                           # RDCv003 reader called directly: piece order
            staged, damaged, digests = _stage_sequential(a, staging, recover, sync_log=log)
        if not recover:
            r = a.ctx.tag(b'rdc3-root\0' + canonical(dict(files=digests, dirs=a.dirs)))
            if not hmac.compare_digest(r, a.root):
                raise IntegrityError('root hash mismatch on restore')
        if failpoint == 'before_publish':
            raise IntegrityError('injected before_publish')
        for d in a.dirs:                                # 3. publish (no clobber)
            _safe_parent(root, d.split('/') + ['x'], create=True)
        stage = 'publish'
        try:
            for name, e in staged:
                parts = e[0].split('/')
                parent = _safe_parent(root, parts, create=True)
                publish_modes.add(_publish_noclobber(os.path.join(staging, name), os.path.join(parent, parts[-1])))
                published.append(e[0])
                if failpoint == 'after_first_publish':
                    raise OSError('injected after_first_publish')
            stage = 'directory_fsync'
            if os.name != 'nt' and hasattr(os, 'O_DIRECTORY'):
                for d in sorted({''} | {'/'.join(e[0].split('/')[:-1]) for _, e in staged}):
                    v3._fsync_dir(os.path.join(root, *d.split('/')) if d else root, log)
                dsynced = True                           # Windows: no directory fsync exists (README)
        except Exception as exc:
            if published:
                raise PublicationError(published, stage, exc) from exc
            raise
    finally:
        for name in os.listdir(staging):
            try:
                os.unlink(os.path.join(staging, name))
            except OSError:
                pass
        try:
            os.rmdir(staging)
        except OSError:
            pass
    return dict(files=len(published), bytes=sum(e[1] for _, e in staged), damaged=damaged,
                parity_repairs_used=a.repairs, recover=recover, directories_fsynced=dsynced,
                sync_mode=log.mode, publish=sorted(publish_modes))


def parse_packs_slice(s):
    m = re.fullmatch(r'\s*(\d+)\s*/\s*(\d+)\s*', s or '')
    if not m:
        raise ValueError('--packs wants n/t, e.g. 0/7 (packs whose index % t == n)')
    return int(m.group(1)), int(m.group(2))


def verify(path, password=None, max_expansion=None, max_decode=None, temp_dir=None, packs=None):
    """max_decode: bytes a sequential verify may decode before switching to pack order
    (default max(256 MiB, 4x the used pack bytes); 0 = always sequential). RDCv004 only.
    temp_dir: where pack order spills unique pieces beyond Limits4.spill_memory (default system temp).
    packs: (n, t) or 'n/t' -> rotating partial verify (Archive4.verify_packs; RDCv004 only)."""
    if isinstance(packs, str):
        packs = parse_packs_slice(packs)
    with open_archive(path, password, max_expansion, max_decode=max_decode) as a:
        if packs is not None:
            if not isinstance(a, Archive4):
                raise ValueError('--packs (partial verify) is RDCv004-only')
            return a.verify_packs(*packs)
        return a.verify(temp_dir) if isinstance(a, Archive4) else a.verify()


def repair(src, dest, password=None, max_expansion=None, max_decode=None):
    """Parity rebuild into a NEW file (no overwrite), then re-verify. Works for v3 and v4."""
    with open_archive(src, password, max_expansion) as a:
        if a.parity is None:
            raise IntegrityError('archive has no parity; cannot repair')
        bad = a.scan_shards()
        badg = sorted({g for g, _ in bad})
        k, m, groups = a.parity
        fixed = {}
        for gi in badg:
            data = a._group_data(gi)
            gs, gl, s, poff, hashes = groups[gi]
            buf = data.ljust(k * s, b'\0')
            fixed[gi] = (data, b''.join(rs_encode([buf[i * s:(i + 1) * s] for i in range(k)], m)))

        def writer(out):
            a.f.seek(0)
            out.write(a.f.read(a.base))
            for gi, (gs, gl, s, poff, hashes) in enumerate(groups):
                out.write(fixed[gi][0] if gi in fixed else a._read_at(gs, gl))
            for gi, (gs, gl, s, poff, hashes) in enumerate(groups):
                out.write(fixed[gi][1] if gi in fixed else a._read_at(poff, m * s))
        pub = atomic_publish_file(dest, writer)
    report = verify(dest, password, max_expansion, max_decode=max_decode, temp_dir=os.path.dirname(os.path.abspath(dest)))
    if report['needs_repair']:
        raise IntegrityError('re-verify after repair failed')
    return dict(repaired_groups=badg, bad_shards_before=bad, reverify=report, sync_mode=pub['sync_mode'],
                directories_fsynced=pub['directories_fsynced'])


def list_archive(path, password=None, max_expansion=None):
    with open_archive(path, password, max_expansion) as a:
        out = dict(format='RDCv004' if isinstance(a, Archive4) else 'RDCv003',
                   files=[dict(path=f[0], size=f[1], sha256=f[2]) for f in a.files], dirs=a.dirs,
                   chunks=len(a.chunks), parity=a.parity[:2] if a.parity else None,
                   encrypted=a.ctx.encrypted, keyed=a.ctx.keyed, total=a.total)
        if isinstance(a, Archive4):
            out['packs'] = len(a.packs)
        return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    pk = sub.add_parser('pack')
    pk.add_argument('source')
    pk.add_argument('archive')
    pk.add_argument('--format', type=int, choices=[3, 4], default=4)
    pk.add_argument('--level', type=int, default=None)
    pk.add_argument('--pack-size', type=int, default=None, help='bytes (v4), default %d' % DEFAULTS['pack_size'])
    pk.add_argument('--threads', type=int, default=None)
    pk.add_argument('--dict', action='store_true', help='v3 only')
    pk.add_argument('--delta', action='store_true', help='v3 only')
    pk.add_argument('--parity', help='K,M[,SHARD] (default 10,2,65536)')
    pk.add_argument('--no-parity', action='store_true', help='write no Reed-Solomon parity (smaller, not repairable)')
    pk.add_argument('--encrypt', action='store_true', help='password from env RDC_PASSWORD')
    pk.add_argument('--gear', choices=['public', 'seeded', 'keyed'], default=None)
    pk.add_argument('--seed')
    pk.add_argument('--hash', choices=['sha256', 'blake3'], default='sha256')
    pk.add_argument('--min', type=int, default=None)
    pk.add_argument('--avg', type=int, default=None)
    pk.add_argument('--max', type=int, default=None)
    _add_gui_options(pk)
    for name in ('unpack', 'verify', 'repair', 'ls'):
        s = sub.add_parser(name)
        s.add_argument('archive')
        _add_gui_options(s)
        if name in ('unpack', 'repair'):
            s.add_argument('destination')
        if name == 'unpack':
            s.add_argument('--recover', action='store_true')
            s.add_argument('--only', action='append', help='restore only this archive path (repeatable)')
            s.add_argument('--sparse', action='store_true',
                           help='leave holes for all-zero pieces (output bytes identical; less disk on '
                                'filesystems with sparse files; Windows NTFS zero-fills)')
            s.add_argument('--strict-names', action='store_true',
                           help='refuse names that would collide on Windows/macOS even on a case-sensitive '
                                'destination (default there: warn)')
        s.add_argument('--max-expansion', type=int, default=None)
        if name in ('verify', 'repair'):
            s.add_argument('--max-decode', type=int, default=None,
                           help='bytes of sequential pack decoding verify may spend before switching to '
                                'pack-order checking (default max(256 MiB, 4x pack bytes); 0 = always '
                                'sequential, warns when that is costly)')
            s.add_argument('--force-sequential', dest='max_decode', action='store_const', const=0,
                           help='same as --max-decode 0')
        if name == 'verify':
            s.add_argument('--temp-dir', default=None,
                           help='folder for pack-order spill beyond 64 MiB of unique pieces (default system temp)')
            s.add_argument('--packs', default=None, metavar='N/T',
                           help='partial verify: only packs with index %% T == N (stored tags, AEAD tags and '
                                'parity shard hashes; no decode). Run N=0..T-1 over T days to cover all')
    a = p.parse_args(argv)
    pw = os.environ.get('RDC_PASSWORD')
    if a.password_stdin:
        pw = _read_password_stdin()
        if not pw:
            print(json.dumps(dict(error='ValueError', message='--password-stdin: no password on standard input')),
                  file=sys.stderr)
            return 1
    global _progress
    if a.progress:
        _progress = _JsonProgress(sys.stderr)
    try:
        if a.cmd == 'pack':
            if a.parity and a.no_parity:
                raise ValueError('--parity and --no-parity conflict')
            par = None if a.no_parity else DEFAULT_PARITY
            if a.parity:
                v = [int(x) for x in a.parity.split(',')]
                par = (v[0], v[1], v[2] if len(v) > 2 else 65536)
            if a.encrypt and not pw:
                raise ValueError('--encrypt needs RDC_PASSWORD in the environment (or --password-stdin)')
            gear = a.gear or ('keyed' if a.encrypt else 'public')
            common = dict(parity=par, password=pw if a.encrypt else None, gear=gear, seed=a.seed, hash_name=a.hash)
            if a.format == 3:
                sizes = {k: v for k, v in (('min_size', a.min), ('avg_size', a.avg), ('max_size', a.max)) if v}
                r = v3.pack(a.source, a.archive, level=a.level or 3, use_dict=a.dict, delta=a.delta, **common, **sizes)
            else:
                if a.dict or a.delta:
                    raise ValueError('--dict/--delta are RDCv003-only (use --format 3)')
                r = pack(a.source, a.archive, level=a.level, pack_size=a.pack_size, threads=a.threads,
                         min_size=a.min, avg_size=a.avg, max_size=a.max, **common)
        elif a.cmd == 'unpack':
            r = restore(a.archive, a.destination, pw, recover=a.recover, max_expansion=a.max_expansion, paths=a.only,
                        sparse=a.sparse, strict_names=a.strict_names)
            if r['damaged']:
                print(json.dumps(r), file=sys.stderr)
                return 3
        elif a.cmd == 'verify':
            r = verify(a.archive, pw, a.max_expansion, max_decode=a.max_decode, temp_dir=a.temp_dir, packs=a.packs)
            if r['needs_repair']:
                print(json.dumps(r))
                return 4
        elif a.cmd == 'repair':
            r = repair(a.archive, a.destination, pw, a.max_expansion, max_decode=a.max_decode)
        else:
            r = list_archive(a.archive, pw, a.max_expansion)
    except PublicationError as exc:
        print(json.dumps(dict(error='PublicationError', published=exc.published, stage=exc.stage,
                              durability_confirmed=False, message=str(exc))), file=sys.stderr)
        return 2
    except (IntegrityError, FileExistsError, ValueError, KeyError) as exc:
        print(json.dumps(dict(error=type(exc).__name__, message=str(exc))), file=sys.stderr)
        return 1
    finally:
        prog_done, _progress = _progress, None
    if prog_done is not None:          # success only: errors keep their JSON as the last stderr line
        prog_done.finish()
    print(json.dumps(r, default=str))
    return 0


# ---------------------------------------------------------------- GUI add-on CLI options (opt-in)
def _add_gui_options(sp):
    sp.add_argument('--progress', action='store_true',
                    help='print progress as JSON lines on stderr, e.g. {"event": "progress", "stage": "pack", '
                         '"done": N, "total": T} (at most ~5 per second); the result line is unchanged')
    sp.add_argument('--password-stdin', action='store_true',
                    help='read the password from the first line of standard input instead of RDC_PASSWORD')


def _read_password_stdin():
    return sys.stdin.readline().rstrip('\r\n')


class _JsonProgress:
    """Throttled JSON-lines progress on a text stream. Only counts bytes; never touches archive data."""
    def __init__(self, out, interval=0.2):
        import time
        self._time = time.monotonic
        self.out, self.interval = out, interval
        self.stage, self.done, self.total, self._last = None, 0, 0, 0.0

    def _emit(self):
        try:
            self.out.write(json.dumps(dict(event='progress', stage=self.stage, done=self.done,
                                           total=self.total)) + '\n')
            self.out.flush()
        except (OSError, ValueError):
            pass   # a closed pipe must never break the actual work

    def start(self, stage, total):
        if self.stage is not None:      # close the previous stage at 100%
            self.done = max(self.done, self.total)
            self._emit()
        self.stage, self.done, self.total = stage, 0, int(total)
        self._last = self._time()
        self._emit()

    def add(self, n):
        self.done += n
        now = self._time()
        if now - self._last >= self.interval:
            self._last = now
            self._emit()

    def finish(self):
        if self.stage is not None:
            self.done = max(self.done, self.total)
            self._emit()
            self.stage = None


if __name__ == '__main__':
    sys.exit(main())
