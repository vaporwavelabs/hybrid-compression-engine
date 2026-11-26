"""RDCv003 research container (prototype, not production).

Content-defined (FastCDC-style) chunking with whole-archive dedup, per-chunk codec
selection (raw / zstd / zstd+trained dictionary / experimental delta+zstd), optional
ChaCha20-Poly1305 encryption, authentication of every stored byte (HMAC-SHA256 when a
key is given, plain SHA-256 detection otherwise), optional Reed-Solomon RS(k+m,k) parity
over the stored data region, and fail-closed, validate-before-publish restore.
Lossless only. See README.md for the format and its limitations.
"""
import os as _os, sys as _sys
if __name__ == '__main__' and _sys.path and \
        _os.path.normcase(_os.path.realpath(_sys.path[0] or '.')) == _os.path.normcase(_os.path.realpath(_os.getcwd())) and \
        _os.path.normcase(_os.path.realpath(_os.path.dirname(_os.path.abspath(__file__)))) != \
        _os.path.normcase(_os.path.realpath(_os.getcwd())):
    del _sys.path[0]   # 3.1.5: `python -m rdc3` from a restore destination must not import stdlib shadows from cwd
import argparse
import hashlib
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
import warnings
from collections import OrderedDict
from pathlib import Path

import numpy as np

try:
    import zstandard as zstd
except ImportError:   # 3.1.5: stdlib compression.zstd (3.14+) or backports.zstd can stand in (see ZB below)
    zstd = None
try:
    import fcntl
except ImportError:   # Windows
    fcntl = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:  # encryption/keyed mode then unavailable (documented)
    ChaCha20Poly1305 = Scrypt = None
CRYPTOGRAPHY_FLOOR = (46, 0, 7)   # 3.1.6: requirements floor also checked at run time (warning, once)
_crypto_floor_checked = False


def _check_cryptography_floor():
    global _crypto_floor_checked
    if _crypto_floor_checked:
        return
    _crypto_floor_checked = True
    try:
        import cryptography
        v = tuple(int(x) for x in re.findall(r'\d+', cryptography.__version__)[:3])
    except Exception:
        return
    if v < CRYPTOGRAPHY_FLOOR:
        warnings.warn(f'cryptography {cryptography.__version__} is below the tested floor '
                      f'{".".join(map(str, CRYPTOGRAPHY_FLOOR))} (security fixes); upgrade it', RuntimeWarning,
                      stacklevel=3)


try:
    import blake3 as _blake3
except ImportError:
    _blake3 = None

__version__ = '3.1.6'   # code version of the bundle; RDCv003 format unchanged since 3.0.2
MAGIC = b'RDCv003\n'
# magic, minor, flags, reserved16, salt, kdf_log2n, reserved3, manifest_stored,
# manifest_raw, payload_len, root, tag
HDR = struct.Struct('>8sBBH16sB3sQQQ32s32s')
HDR_PREFIX = HDR.size - 32
F_KEYED, F_ENCRYPTED = 1, 2
CODEC_RAW, CODEC_ZSTD, CODEC_DICT, CODEC_DELTA = 0, 1, 2, 3
CODEC_NAMES = {0: 'raw', 1: 'zstd', 2: 'zstd-dict', 3: 'delta-zstd'}
AEAD_TAG = 16
HEX = re.compile(r'[0-9a-f]{64}\Z')
STAGING_PREFIX = '.rdc3-staging-'
READ_BLOCK = 1024 * 1024


class Limits:
    max_chunk = 1024 * 1024            # hard cap on any chunk's raw length
    max_window = 8 * 1024 * 1024       # zstd window accepted on decode
    max_manifest = 64 * 1024 * 1024    # raw (decompressed) manifest bytes
    max_files = 1_000_000
    max_chunks = 4_000_000
    max_output = 64 * 1024**3          # total restored bytes (repeated-pointer amplification cap)
    max_expansion = 1000               # unkeyed default: declared output / archive bytes (0 disables)
    max_expansion_keyed = 0            # keyed (MAC-verified) default: no ratio cap (3.0.2)
    expansion_floor = 64 * 1024 * 1024 # outputs up to this size are never refused by the ratio cap
    free_space_headroom = 64 * 1024 * 1024  # plus 5% of declared output, kept free after staging
    max_path = 4096
    max_dict = 1024 * 1024
    max_shard = 16 * 1024 * 1024
    delta_cache = 32 * 1024 * 1024


class IntegrityError(ValueError):
    """Archive is malformed, tampered, corrupt, or outside limits. Nothing was published."""


class LimitError(IntegrityError):
    """Archive is well-formed but exceeds a resource limit (expansion ratio, free space). Nothing written."""


class PublicationError(OSError):
    """Some validated output IS published, but a later step failed. Durability unconfirmed."""
    def __init__(self, published, stage, cause):
        super().__init__(getattr(cause, 'errno', None),
                         f'{len(published)} validated file(s) published; {stage} failed: {cause}; '
                         'durability unconfirmed; do not delete as rollback')
        self.published = list(published)
        self.stage = stage
        self.durability_confirmed = False


# ---------------------------------------------------------------- zstd backend (3.1.5)
# Order: zstandard -> compression.zstd (Python 3.14+) -> backports.zstd. Env RDC_ZSTD_BACKEND=<name> forces one.
# All backends decode with a hard window cap of 2**ZSTD_WINDOW_LOG_MAX (16 MiB); the per-format limit
# (Limits.max_window) is checked from the frame header before any decoding.
ZSTD_WINDOW_LOG_MAX = 24
ZSTD_BACKENDS = ('zstandard', 'compression.zstd', 'backports.zstd')


class BackendUnavailable(ValueError):
    """The requested zstd backend (or a feature only one backend has) is not available."""


def parse_zstd_frame_header(b):
    """(content_size or -1 if absent, window_size, dict_id) from a zstd frame header (RFC 8878 3.1.1.1).
    Needed because the stdlib get_frame_info() does not report the window size."""
    b = bytes(b[:18])
    if len(b) < 5 or b[:4] != b'\x28\xb5\x2f\xfd':
        raise ValueError('not a zstd frame')
    fhd = b[4]
    fcs_flag, single, reserved, did_flag = fhd >> 6, (fhd >> 5) & 1, (fhd >> 3) & 1, fhd & 3
    if reserved:
        raise ValueError('reserved frame header bit set')
    pos = 5
    window = None
    if not single:
        if len(b) < pos + 1:
            raise ValueError('truncated frame header')
        wd = b[pos]
        pos += 1
        wlog = 10 + (wd >> 3)
        window = (1 << wlog) + ((1 << wlog) >> 3) * (wd & 7)
    dsz = (0, 1, 2, 4)[did_flag]
    fsz = (1 if single else 0, 2, 4, 8)[fcs_flag]
    if len(b) < pos + dsz + fsz:
        raise ValueError('truncated frame header')
    dict_id = int.from_bytes(b[pos:pos + dsz], 'little')
    pos += dsz
    if fsz:
        size = int.from_bytes(b[pos:pos + fsz], 'little') + (256 if fsz == 2 else 0)
    else:
        size = -1
    if single:
        window = size
    return size, window, dict_id


class _ZstandardBackend:
    name = 'zstandard'

    def __init__(self, mod):
        self.z = mod

    def compressor(self, level, dict_obj=None, write_dict_id=True, source_size=None, overrides=None):
        z = self.z
        if source_size is not None:
            params = z.ZstdCompressionParameters.from_level(
                level, source_size=source_size, write_content_size=1, write_checksum=0, **(overrides or {}))
            return z.ZstdCompressor(compression_params=params)
        if dict_obj is not None:
            return z.ZstdCompressor(level=level, dict_data=dict_obj, write_content_size=True, write_checksum=False,
                                    write_dict_id=write_dict_id)
        return z.ZstdCompressor(level=level, write_content_size=True, write_checksum=False)

    def make_dict(self, data, raw=False):
        if raw:
            return self.z.ZstdCompressionDict(data, dict_type=self.z.DICT_TYPE_RAWCONTENT)
        return self.z.ZstdCompressionDict(data)

    def dict_id(self, d):
        return d.dict_id()

    def train(self, size, samples, level):
        d = self.z.train_dictionary(size, samples, level=level)
        return d, d.as_bytes()

    def frame_info(self, body):
        p = self.z.get_frame_parameters(body)
        return p.content_size, p.window_size, p.dict_id

    def decompress(self, body, raw_len, dict_obj, max_window):
        max_window = min(max_window, 1 << ZSTD_WINDOW_LOG_MAX)
        ws = self.z.get_frame_parameters(body).window_size   # 3.1.6: one-shot decode ignores max_window_size
        if ws > max_window:                                    # when the frame records its content size
            raise ValueError(f'zstd frame window {ws} exceeds cap {max_window}')
        d = (self.z.ZstdDecompressor(dict_data=dict_obj, max_window_size=max_window) if dict_obj is not None
             else self.z.ZstdDecompressor(max_window_size=max_window))
        return d.decompress(body, max_output_size=raw_len, allow_extra_data=False)


class _StdlibCompressor:
    def __init__(self, mod, options, zdict):
        self._c = mod.ZstdCompressor(options=options, zstd_dict=zdict)

    def compress(self, data):
        return self._c.compress(data, mode=self._c.FLUSH_FRAME)


class _StdlibBackend:
    """compression.zstd (3.14+) and backports.zstd share one API (PEP 784)."""
    def __init__(self, mod, name):
        self.z, self.name = mod, name

    def compressor(self, level, dict_obj=None, write_dict_id=True, source_size=None, overrides=None):
        P = self.z.CompressionParameter
        opts = {P.compression_level: level, P.content_size_flag: 1, P.checksum_flag: 0,
                P.dict_id_flag: 1 if write_dict_id else 0}
        for k, v in (overrides or {}).items():
            opts[getattr(P, k)] = v
        return _StdlibCompressor(self.z, opts, dict_obj)

    def make_dict(self, data, raw=False):
        return self.z.ZstdDict(bytes(data), is_raw=raw)

    def dict_id(self, d):
        return d.dict_id

    def train(self, size, samples, level):
        raise BackendUnavailable(f'zstd dictionary training (RDCv003 --dict) needs the zstandard package; the active '
                                 f'zstd backend is {self.name}. Install zstandard or pack without --dict.')

    def frame_info(self, body):
        return parse_zstd_frame_header(body)

    def decompress(self, body, raw_len, dict_obj, max_window):
        ws = parse_zstd_frame_header(body)[1]   # 3.1.6: libzstd sizes content-size frames by FCS, so the
        cap = min(max_window, 1 << ZSTD_WINDOW_LOG_MAX)   # window_log_max option alone is not a hard cap
        if ws > cap:
            raise ValueError(f'zstd frame window {ws} exceeds cap {cap}')
        wlog = min(ZSTD_WINDOW_LOG_MAX, max(10, max_window.bit_length() - 1))
        d = self.z.ZstdDecompressor(zstd_dict=dict_obj, options={self.z.DecompressionParameter.window_log_max: wlog})
        out = d.decompress(body, max_length=raw_len + 1)
        if not d.eof or d.unused_data or len(out) != raw_len:
            raise ValueError('zstd frame incomplete, oversized or followed by trailing data')
        return out


def load_zstd_backend(name=None):
    """Return the first available backend in ZSTD_BACKENDS order, or exactly `name`."""
    if name is not None and name not in ZSTD_BACKENDS:
        raise BackendUnavailable(f'unknown zstd backend {name!r}; choose one of {", ".join(ZSTD_BACKENDS)}')
    for n in ([name] if name else ZSTD_BACKENDS):
        try:
            if n == 'zstandard':
                import zstandard as mod
                return _ZstandardBackend(mod)
            if n == 'compression.zstd':
                import compression.zstd as mod
                return _StdlibBackend(mod, n)
            from backports import zstd as mod
            return _StdlibBackend(mod, n)
        except ImportError:
            if name:
                raise BackendUnavailable(f'zstd backend {name!r} is not installed') from None
    raise ImportError('no zstd backend: pip install zstandard (or use Python 3.14+, or pip install backports.zstd)')


ZB = load_zstd_backend(os.environ.get('RDC_ZSTD_BACKEND') or None)
_IS_DARWIN = sys.platform == 'darwin'


# ---------------------------------------------------------------- durable sync (3.1.5)
class SyncLog:
    """Records which sync primitive actually succeeded for each fd (honest reporting)."""
    def __init__(self):
        self.modes = []

    @property
    def mode(self):
        if not self.modes:
            return 'none'
        return 'full_fsync' if all(m == 'full_fsync' for m in self.modes) else 'fsync'


def _durable_sync(fd, log=None):
    """os.fsync, plus fcntl(F_FULLFSYNC) on macOS (plain fsync there does not flush the drive cache).
    If F_FULLFSYNC is refused (some network/FUSE/external volumes) the result is recorded as 'fsync',
    never as 'full_fsync'. Returns the mode achieved."""
    os.fsync(fd)
    mode = 'fsync'
    if _IS_DARWIN and fcntl is not None and hasattr(fcntl, 'F_FULLFSYNC'):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            mode = 'full_fsync'
        except OSError:
            mode = 'fsync'
    if log is not None:
        log.modes.append(mode)
    return mode


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


# ---------------------------------------------------------------- keys / hashing
class Ctx:
    """Hashing, authentication and optional AEAD for one archive."""
    def __init__(self, password=None, salt=b'\0' * 16, log2n=0, encrypt=False, hash_name='sha256'):
        if hash_name not in ('sha256', 'blake3') or (hash_name == 'blake3' and _blake3 is None):
            raise ValueError('hash unavailable: ' + str(hash_name))
        self.hash_name = hash_name
        self.keyed = password is not None
        self.encrypted = bool(encrypt)
        if self.encrypted and not self.keyed:
            raise ValueError('encryption requires a password')
        if self.keyed:
            if Scrypt is None:
                raise RuntimeError('cryptography package not installed; keyed mode unavailable')
            _check_cryptography_floor()
            if not 10 <= log2n <= 20:
                raise IntegrityError('kdf cost out of bounds')
            master = Scrypt(salt=salt, length=32, n=2 ** log2n, r=8, p=1).derive(password)
            sub = lambda label: hmac.new(master, b'rdc3/' + label, hashlib.sha256).digest()
            self.mac_key, self.id_key, self.gear_key = sub(b'mac'), sub(b'id'), sub(b'gear')
            self.aead = ChaCha20Poly1305(sub(b'enc')) if self.encrypted else None
        else:
            self.aead = None

    def chunk_id(self, raw):
        if self.hash_name == 'blake3':
            h = _blake3.blake3(raw, key=self.id_key) if self.keyed else _blake3.blake3(raw)
            return h.hexdigest()
        if self.keyed:
            return hmac.new(self.id_key, raw, hashlib.sha256).hexdigest()
        return hashlib.sha256(raw).hexdigest()

    def tag(self, data):
        if self.keyed:
            return hmac.new(self.mac_key, data, hashlib.sha256).digest()
        return hashlib.sha256(data).digest()

    def seal(self, domain, index, body):
        if not self.aead:
            return body
        return self.aead.encrypt(struct.pack('>IQ', domain, index), body, b'rdc3')

    def open(self, domain, index, stored):
        if not self.aead:
            return stored
        try:
            return self.aead.decrypt(struct.pack('>IQ', domain, index), stored, b'rdc3')
        except Exception as exc:
            raise IntegrityError('AEAD authentication failed') from exc


def gear_table(mode, ctx, seed=None):
    if mode == 'public':
        src = lambda i: hashlib.sha256(b'rdc3-gear-public' + i.to_bytes(2, 'big')).digest()
    elif mode == 'seeded':
        s = bytes.fromhex(seed)
        src = lambda i: hashlib.sha256(b'rdc3-gear-seed' + s + i.to_bytes(2, 'big')).digest()
    elif mode == 'keyed':
        if not ctx.keyed:
            raise ValueError('keyed gear table requires a password')
        src = lambda i: hmac.new(ctx.gear_key, i.to_bytes(2, 'big'), hashlib.sha256).digest()
    else:
        raise ValueError('gear mode')
    return np.array([int.from_bytes(src(i)[:8], 'big') for i in range(256)], dtype=np.uint64)


# ---------------------------------------------------------------- FastCDC
class Chunker:
    """FastCDC-style normalized chunking; vectorized 64-byte gear window, top-bit masks."""
    def __init__(self, gear, min_size=8192, avg_size=32768, max_size=131072):
        if not (64 <= min_size < avg_size < max_size <= Limits.max_chunk) or avg_size & (avg_size - 1):
            raise ValueError('chunk sizes: need 64<=min<avg<max<=1MiB and avg a power of two')
        bits = avg_size.bit_length() - 1
        self.gear, self.min, self.avg, self.max = gear, min_size, avg_size, max_size
        self.shift_s = np.uint64(64 - (bits + 2))   # stricter before avg
        self.shift_l = np.uint64(64 - (bits - 2))   # looser after avg

    def hashes(self, buf):
        h = self.gear[np.frombuffer(buf, dtype=np.uint8)]
        w = 1
        while w < 64:  # h_2w[i] = h_w[i] + (h_w[i-w] << w)  ==  sum_{j<64} G[b[i-j]] << j
            nh = h.copy()
            nh[w:] += h[:-w] << np.uint64(w)
            h, w = nh, w * 2
        return h

    def split(self, buf, final):
        """Return (chunk lengths, hashes). Non-final: trailing undecided bytes are left over."""
        n = len(buf)
        if n == 0:
            return [], None
        h = self.hashes(buf)
        cs = np.flatnonzero((h >> self.shift_s) == 0)
        cl = np.flatnonzero((h >> self.shift_l) == 0)
        out, start = [], 0
        while start < n:
            cut = None
            i = np.searchsorted(cs, start + self.min)
            if i < len(cs) and cs[i] < min(start + self.avg, n):
                cut = int(cs[i]) + 1
            elif start + self.avg <= n or final:
                j = np.searchsorted(cl, start + self.avg)
                if j < len(cl) and cl[j] < min(start + self.max, n):
                    cut = int(cl[j]) + 1
                elif start + self.max <= n:
                    cut = start + self.max
                elif final:
                    cut = n
            if cut is None:
                break
            out.append(cut - start)
            start = cut
        return out, h

    def iter_file(self, f):
        """Yield (chunk bytes, gear hashes of chunk) from an open binary file."""
        left = b''
        while True:
            data = f.read(READ_BLOCK)
            final = not data
            buf = left + data
            lens, h = self.split(buf, final)
            pos = 0
            for length in lens:
                yield buf[pos:pos + length], h[pos:pos + length]
                pos += length
            left = buf[pos:]
            if final:
                return


_FEAT = [(np.uint64(0x9E3779B97F4A7C15 + 2 * k + 1), np.uint64(0xD6E8FEB86659FD93 * (k + 1) & (2**64 - 1)))
         for k in range(3)]


def features(h):
    """Resemblance sketch (Finesse/N-transform style) for delta base selection."""
    if h is None or len(h) <= 64:
        return []
    v = h[63:]
    return [int((v * a + b).max()) for a, b in _FEAT]


# ---------------------------------------------------------------- GF(256) Reed-Solomon (own code)
def _gf():
    exp, log, x = [0] * 512, [0] * 256, 1
    for i in range(255):
        exp[i], log[x] = x, i
        x <<= 1
        if x & 0x100:
            x ^= 0x11d
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    mul = np.zeros((256, 256), dtype=np.uint8)
    for a in range(1, 256):
        for b in range(1, 256):
            mul[a, b] = exp[log[a] + log[b]]
    return exp, log, mul


GF_EXP, GF_LOG, GF_MUL = _gf()


def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError
    return GF_EXP[255 - GF_LOG[a]]


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else GF_EXP[GF_LOG[a] + GF_LOG[b]]


def cauchy(k, m):
    """Systematic generator: rows 0..k-1 identity, rows k.. Cauchy 1/(x_i ^ y_j); any k rows invertible."""
    if not (1 <= k and 1 <= m and k + m <= 256):
        raise ValueError('RS parameters')
    return [[gf_inv(i ^ (m + j)) for j in range(k)] for i in range(m)]


def rs_encode(shards, m):
    k = len(shards)
    C = cauchy(k, m)
    arrs = [np.frombuffer(s, dtype=np.uint8) for s in shards]
    out = []
    for i in range(m):
        acc = np.zeros_like(arrs[0])
        for j in range(k):
            acc ^= GF_MUL[C[i][j]][arrs[j]]
        out.append(acc.tobytes())
    return out


def _gf_invert(mat):
    n = len(mat)
    a = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(mat)]
    for col in range(n):
        piv = next(r for r in range(col, n) if a[r][col])
        a[col], a[piv] = a[piv], a[col]
        inv = gf_inv(a[col][col])
        a[col] = [gf_mul(v, inv) for v in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                f = a[r][col]
                a[r] = [v ^ gf_mul(f, w) for v, w in zip(a[r], a[col])]
    return [row[n:] for row in a]


def rs_reconstruct(shards, k, m):
    """shards: list of k+m bytes-or-None. Returns the k data shards. Up to m erasures."""
    avail = [i for i, s in enumerate(shards) if s is not None]
    if len(avail) < k:
        raise IntegrityError(f'{k + m - len(avail)} bad shards exceed parity m={m}')
    if all(shards[j] is not None for j in range(k)):
        return list(shards[:k])
    C = cauchy(k, m)
    use = avail[:k]
    rows = [[1 if c == i else 0 for c in range(k)] if i < k else C[i - k] for i in use]
    inv = _gf_invert(rows)
    arrs = [np.frombuffer(shards[i], dtype=np.uint8) for i in use]
    data = []
    for j in range(k):
        if shards[j] is not None:
            data.append(shards[j])
            continue
        acc = np.zeros_like(arrs[0])
        for t in range(k):
            if inv[j][t]:
                acc ^= GF_MUL[inv[j][t]][arrs[t]]
        data.append(acc.tobytes())
    return data


def parity_layout(data_len, k, shard):
    """[(group_start, group_len, shard_size)] covering the data region; last group shrinks."""
    out, pos = [], 0
    while pos < data_len:
        glen = min(k * shard, data_len - pos)
        out.append((pos, glen, -(-glen // k)))
        pos += glen
    return out


# ---------------------------------------------------------------- paths
def check_rel_path(p, limits=Limits):
    if not isinstance(p, str) or not p or len(p.encode('utf-8', 'surrogatepass')) > limits.max_path:
        raise IntegrityError('invalid path')
    try:
        p.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise IntegrityError('path not UTF-8') from exc
    if p.startswith('/') or '\\' in p or ':' in p or any(ord(c) < 32 or ord(c) == 127 for c in p):
        raise IntegrityError(f'unsafe path {p!r}')
    parts = p.split('/')
    if any(x in ('', '.', '..') for x in parts) or parts[0].startswith(STAGING_PREFIX):
        raise IntegrityError(f'unsafe path {p!r}')
    return parts


def check_tree(files, dirs, limits=Limits):
    seen_files, seen_dirs = set(), set()
    for p in dirs:
        check_rel_path(p, limits)
        if p in seen_dirs:
            raise IntegrityError(f'duplicate directory {p!r}')
        seen_dirs.add(p)
    for p in files:
        check_rel_path(p, limits)
        if p in seen_files:
            raise IntegrityError(f'duplicate path {p!r}')
        if p in seen_dirs:
            raise IntegrityError(f'path is both file and directory {p!r}')
        seen_files.add(p)
    for p in list(seen_files) + list(seen_dirs):
        parts = p.split('/')
        for i in range(1, len(parts)):
            if '/'.join(parts[:i]) in seen_files:
                raise IntegrityError(f'file used as directory in {p!r}')


def _inside(child, parent):
    child, parent = os.path.realpath(child), os.path.realpath(parent)
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def scan_source(source):
    """Return (files [(rel, abs)], dirs [rel]) without following symlinks; refuse specials."""
    st = os.lstat(source)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError('source is a symlink; refused')
    if stat.S_ISREG(st.st_mode):
        name = os.path.basename(os.path.abspath(source))
        check_rel_path(name)
        return [(name, os.path.abspath(source))], []
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError('source must be a regular file or directory')
    files, dirs = [], []

    def walk(abs_dir, rel):
        with os.scandir(abs_dir) as it:
            entries = sorted(it, key=lambda e: e.name)
        for e in entries:
            r = f'{rel}/{e.name}' if rel else e.name
            if e.is_symlink() or getattr(e, 'is_junction', lambda: False)():
                raise ValueError(f'symlink in source refused: {r}')
            if e.is_dir(follow_symlinks=False):
                check_rel_path(r)
                dirs.append(r)
                walk(e.path, r)
            elif e.is_file(follow_symlinks=False):
                check_rel_path(r)
                files.append((r, e.path))
            else:
                raise ValueError(f'special file refused: {r}')
    walk(os.path.abspath(source), '')
    check_tree([f for f, _ in files], dirs)
    return files, dirs


# ---------------------------------------------------------------- publication
def _fsync_dir(path_or_fd, log=None):
    """True when the directory was actually synced; False where the OS cannot (Windows)."""
    if not isinstance(path_or_fd, int) and not hasattr(os, 'O_DIRECTORY'):
        return False  # Windows: directories cannot be opened/fsynced; NTFS journals the metadata
    fd = path_or_fd if isinstance(path_or_fd, int) else os.open(path_or_fd, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _durable_sync(fd, log)
    finally:
        if not isinstance(path_or_fd, int):
            os.close(fd)
    return True


# 3.1.5: rdc4 installs its handle-based no-clobber publish here on Windows (one publish path for all writes)
_WIN_PUBLISH = None


def atomic_publish_file(dest, writer, failpoint=None):
    """Write temp beside dest, durable sync, no-clobber publish (os.link; Windows: rdc4's handle-based
    rename), unlink temp, fsync dir. Returns dict(sync_mode, directories_fsynced, publish)."""
    log = SyncLog()
    dest = Path(os.path.abspath(dest))
    if os.path.lexists(dest):
        raise FileExistsError(dest)
    if not dest.parent.is_dir() or dest.parent.is_symlink():
        raise ValueError('output parent must be an existing non-symlink directory')
    fd, temp = tempfile.mkstemp(prefix='.rdc3-', suffix='.part', dir=dest.parent)
    published, stage = False, 'write'
    try:
        with os.fdopen(fd, 'wb') as f:
            writer(f)
            f.flush()
            _durable_sync(f.fileno(), log)
        if failpoint == 'before_commit':
            raise RuntimeError('injected before_commit')
        if _WIN_PUBLISH is not None:              # set by rdc4 on Windows only
            how = _WIN_PUBLISH(temp, str(dest))   # moves temp (no clobber, write-through)
            linked = False
        else:
            try:
                os.link(temp, dest)
                linked, how = True, 'link'
            except FileExistsError:
                raise
            except OSError:
                if os.name != 'nt':
                    raise
                os.rename(temp, dest)   # FAT/exFAT: no hard links; rename refuses an existing dest on Windows
                linked, how = False, 'rename'
        published, stage = True, 'temporary_unlink'
        if linked:
            os.unlink(temp)
        stage = 'directory_fsync'
        if failpoint == 'after_publish':
            raise OSError('injected after_publish')
        dsynced = _fsync_dir(str(dest.parent), log)
    except Exception as exc:
        if published:
            raise PublicationError([str(dest)], stage, exc) from exc
        raise
    finally:
        if os.path.exists(temp):
            try:
                os.unlink(temp)
            except OSError:
                pass
    return dict(sync_mode=log.mode, directories_fsynced=dsynced, publish=how)


# ---------------------------------------------------------------- pack
def pack(source, dest, *, level=3, use_dict=False, delta=False, parity=None, password=None,
         gear='public', seed=None, min_size=8192, avg_size=32768, max_size=131072,
         hash_name='sha256', kdf_log2n=15, dict_size=112 * 1024, failpoint=None):
    """Create an RDCv003 archive. parity=(k, m, shard_bytes) or None. Returns stats dict."""
    source, dest = os.path.abspath(source), os.path.abspath(dest)
    if os.path.lexists(dest):
        raise FileExistsError(dest)
    if os.path.isdir(source) and _inside(os.path.dirname(dest), source):
        raise ValueError('output inside source tree refused (self-ingestion)')
    if os.path.realpath(dest) == os.path.realpath(source):
        raise ValueError('output equals input')
    if type(level) is not int or not 1 <= level <= 22:
        raise ValueError('zstd level')
    if password is not None and isinstance(password, str):
        password = password.encode()
    encrypt = password is not None
    salt = secrets.token_bytes(16) if password is not None else b'\0' * 16
    log2n = kdf_log2n if password is not None else 0
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
    if parity is not None:
        k, m, shard = parity
        cauchy(k, m)
        if not 512 <= shard <= Limits.max_shard:
            raise ValueError('shard size')
    files, dirs = scan_source(source)

    dict_obj, dict_raw = None, None
    if use_dict:
        samples, budget = [], 0
        for _, path in files:
            with open(path, 'rb') as f:
                for raw, _h in chunker.iter_file(f):
                    samples.append(raw)
                    budget += len(raw)
                    if budget >= 8 * 1024 * 1024:
                        break
            if budget >= 8 * 1024 * 1024:
                break
        try:
            dict_obj, dict_raw = ZB.train(dict_size, samples, level)
        except BackendUnavailable:
            raise   # 3.1.5: training is zstandard-only; say so instead of silently packing without
        except Exception:
            dict_obj = None  # too few samples; recorded in stats
    plain = ZB.compressor(level)
    dictc = ZB.compressor(level, dict_obj=dict_obj, write_dict_id=True) if dict_obj else None

    chunks, index, feat_index = [], {}, [dict(), dict(), dict()]
    manifest_files = []
    codec_counts = {n: 0 for n in CODEC_NAMES.values()}
    logical = unique_raw = 0
    with tempfile.TemporaryFile() as raw_spool, tempfile.TemporaryFile() as data_spool, \
            tempfile.TemporaryFile() as parity_spool:
        data_len = raw_off = 0
        dict_rec = None
        if dict_raw is not None:
            stored = ctx.seal(0, 0, dict_raw)
            data_spool.write(stored)
            data_len += len(stored)
            dict_rec = [len(dict_raw), len(stored), ctx.tag(stored).hex()]
        for rel, path in files:
            fh = hashlib.sha256()
            refs, size = [], 0
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
            before = os.fstat(fd)
            with os.fdopen(fd, 'rb') as f:
                for raw, h in chunker.iter_file(f):
                    fh.update(raw)
                    size += len(raw)
                    cid = ctx.chunk_id(raw)
                    if cid in index:
                        ci, off = index[cid]
                        raw_spool.seek(off)
                        if raw_spool.read(len(raw)) != raw:
                            raise ValueError('chunk hash collision; refusing dedup')
                        raw_spool.seek(0, 2)
                        refs.append(ci)
                        continue
                    if len(chunks) >= Limits.max_chunks:
                        raise ValueError('chunk count limit')
                    ci = len(chunks)
                    best, codec, base = plain.compress(raw), CODEC_ZSTD, -1
                    if dictc is not None:
                        cand = dictc.compress(raw)
                        if len(cand) < len(best):
                            best, codec = cand, CODEC_DICT
                    feats = features(h) if delta else []
                    if feats:
                        b = next((fi[v] for fi, v in zip(feat_index, feats) if v in fi), None)
                        if b is not None:
                            boff, blen = chunks[b][6], chunks[b][1]
                            raw_spool.seek(boff)
                            braw = raw_spool.read(blen)
                            raw_spool.seek(0, 2)
                            dc = ZB.compressor(level, dict_obj=ZB.make_dict(braw, raw=True), write_dict_id=False)
                            cand = dc.compress(raw)
                            if len(cand) < len(best):
                                best, codec, base = cand, CODEC_DELTA, b
                    if len(best) >= len(raw):
                        best, codec, base = raw, CODEC_RAW, -1
                    stored = ctx.seal(0, ci + 1, best)
                    raw_spool.write(raw)
                    data_spool.write(stored)
                    chunks.append([codec, len(raw), len(stored), cid, ctx.tag(stored).hex(), base, raw_off])
                    index[cid] = (ci, raw_off)
                    if codec != CODEC_DELTA:
                        for fi, v in zip(feat_index, feats):
                            fi.setdefault(v, ci)
                    raw_off += len(raw)
                    data_len += len(stored)
                    unique_raw += len(raw)
                    codec_counts[CODEC_NAMES[codec]] += 1
                    refs.append(ci)
                after = os.fstat(f.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or size != after.st_size:
                raise ValueError(f'source changed while reading: {rel}')
            logical += size
            manifest_files.append([rel, size, fh.hexdigest(), refs])
        par = None
        parity_len = 0
        if parity is not None:
            k, m, shard = parity
            groups = []
            data_spool.flush()
            for gstart, glen, s in parity_layout(data_len, k, shard):
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
        manifest = dict(v=3, hash=hash_name, level=level,
                        chunker=dict(min=min_size, avg=avg_size, max=max_size, gear=gear, seed=seed),
                        dict=dict_rec, chunks=[c[:6] for c in chunks], files=manifest_files, dirs=dirs,
                        parity=par)
        mraw = canonical(manifest)
        if len(mraw) > Limits.max_manifest:
            raise ValueError('manifest too large')
        mcomp = ZB.compressor(19).compress(mraw)
        mstored_len = len(mcomp) + (AEAD_TAG if encrypt else 0)
        flags = (F_KEYED if ctx.keyed else 0) | (F_ENCRYPTED if encrypt else 0)
        payload_len = data_len + parity_len
        prefix = HDR.pack(MAGIC, 0, flags, 0, salt, log2n, b'\0\0\0', mstored_len, len(mraw),
                          payload_len, root, b'\0' * 32)[:HDR_PREFIX]
        mstored = ctx.aead.encrypt(struct.pack('>IQ', 1, 0), mcomp, prefix) if encrypt else mcomp
        assert len(mstored) == mstored_len
        header = prefix + ctx.tag(prefix + mstored)

        def writer(out):
            out.write(header)
            out.write(mstored)
            for sp in (data_spool, parity_spool):
                sp.flush()
                sp.seek(0)
                shutil.copyfileobj(sp, out, 1024 * 1024)
        atomic_publish_file(dest, writer, failpoint)
    stored_total = HDR.size + mstored_len + payload_len
    return dict(format='RDCv003', original_bytes=logical, stored_bytes=stored_total, header_bytes=HDR.size,
                manifest_bytes=mstored_len, manifest_raw_bytes=len(mraw), data_bytes=data_len,
                parity_bytes=parity_len, dict_bytes=dict_rec[1] if dict_rec else 0,
                dict_requested=bool(use_dict), dict_trained=dict_rec is not None,
                files=len(files), dirs=len(dirs), unique_chunks=len(chunks),
                logical_chunks=sum(len(f[3]) for f in manifest_files), unique_raw_bytes=unique_raw,
                dedup_saved_bytes=logical - unique_raw, codec_counts=codec_counts,
                keyed=ctx.keyed, encrypted=encrypt, gear=gear, hash=hash_name,
                savings=(1 - stored_total / logical) if logical else None)


# ---------------------------------------------------------------- read side
def _unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise IntegrityError('duplicate JSON key')
        out[k] = v
    return out


def _int(v, lo, hi, what):
    if type(v) is not int or not lo <= v <= hi:
        raise IntegrityError(f'{what} out of bounds')
    return v


def _hex(v, what='digest'):
    if not isinstance(v, str) or not HEX.fullmatch(v):
        raise IntegrityError(f'invalid {what}')
    return v


def _keys(obj, expected, what):
    if not isinstance(obj, dict) or set(obj) != set(expected):
        raise IntegrityError(f'{what} schema')


class Archive:
    """Open + fully validate header and manifest before any payload byte is trusted."""
    def __init__(self, path, password=None, limits=Limits, max_expansion=None):
        self.limits = limits
        self._max_expansion_arg = max_expansion  # None = default by keyed/unkeyed (resolved after MAC check)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        self.f = os.fdopen(fd, 'rb')
        try:
            self._load(password)
        except Exception:
            self.f.close()
            raise
        self.repairs = 0
        self._group_cache = None
        self._raw_cache = OrderedDict()
        self._raw_cache_bytes = 0

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _load(self, password):
        L = self.limits
        st = os.fstat(self.f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise IntegrityError('archive must be a regular file')
        hdr = self.f.read(HDR.size)
        if len(hdr) != HDR.size:
            raise IntegrityError('truncated header')
        (magic, minor, flags, res16, salt, log2n, res3, mlen, mraw, plen, root, tag) = HDR.unpack(hdr)
        if magic != MAGIC or minor != 0 or res16 != 0 or res3 != b'\0\0\0' or flags & ~3:
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
        except Exception as exc:  # includes trailing bytes after the JSON value
            raise IntegrityError('manifest JSON invalid or has trailing bytes') from exc
        if canonical(m) != mbytes:
            raise IntegrityError('manifest not canonical')
        self.header = dict(flags=flags, keyed=keyed, encrypted=enc, manifest_len=mlen, payload_len=plen)
        self.base = HDR.size + mlen
        self._validate(m, plen, root)

    def _validate(self, m, plen, root):
        L = self.limits
        _keys(m, ['v', 'hash', 'level', 'chunker', 'dict', 'chunks', 'files', 'dirs', 'parity'], 'manifest')
        if m['v'] != 3 or type(m['v']) is not int:
            raise IntegrityError('unsupported version')
        if m['hash'] not in ('sha256', 'blake3') or (m['hash'] == 'blake3' and _blake3 is None):
            raise IntegrityError('hash unsupported')
        self.ctx.hash_name = m['hash']
        _int(m['level'], 1, 22, 'level')
        ch = m['chunker']
        _keys(ch, ['min', 'avg', 'max', 'gear', 'seed'], 'chunker')
        _int(ch['max'], 1, L.max_chunk, 'chunk max')
        if ch['gear'] not in ('public', 'seeded', 'keyed'):
            raise IntegrityError('gear')
        aead = AEAD_TAG if self.ctx.encrypted else 0
        offset = 0
        self.dict_rec = None
        if m['dict'] is not None:
            d = m['dict']
            if not isinstance(d, list) or len(d) != 3:
                raise IntegrityError('dict schema')
            _int(d[0], 1, L.max_dict, 'dict length')
            if d[1] != d[0] + aead:
                raise IntegrityError('dict stored length')
            _hex(d[2])
            self.dict_rec = (offset, d[0], d[1], bytes.fromhex(d[2]))
            offset += d[1]
        chunks = m['chunks']
        if not isinstance(chunks, list) or len(chunks) > L.max_chunks:
            raise IntegrityError('chunk list')
        self.chunks, ids, used = [], set(), [False] * len(chunks)
        for i, c in enumerate(chunks):
            if not isinstance(c, list) or len(c) != 6:
                raise IntegrityError('chunk schema')
            codec, raw, stored, cid, sh, base = c
            _int(codec, 0, 3, 'codec')
            _int(raw, 1, ch['max'], 'chunk raw length')
            _int(stored, 1, L.max_chunk + 64, 'chunk stored length')
            _hex(cid, 'chunk id')
            _hex(sh, 'chunk tag')
            if cid in ids:
                raise IntegrityError('duplicate chunk id')
            ids.add(cid)
            body = stored - aead
            if codec == CODEC_RAW and body != raw or codec != CODEC_RAW and not 0 < body < raw:
                raise IntegrityError('codec/length noncanonical')
            if codec == CODEC_DICT and self.dict_rec is None:
                raise IntegrityError('dictionary codec without dictionary')
            if codec == CODEC_DELTA:
                _int(base, 0, i - 1, 'delta base')
                if chunks[base][0] == CODEC_DELTA:
                    raise IntegrityError('delta chain depth > 1')
                used[base] = True
            elif base != -1:
                raise IntegrityError('base on non-delta chunk')
            self.chunks.append((codec, raw, stored, cid, bytes.fromhex(sh), base, offset))
            offset += stored
        self.data_len = offset
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
            self.files.append((path, size, sha, refs))
        check_tree([f[0] for f in self.files], m['dirs'], L)
        self.dirs = m['dirs']
        if not all(used):
            raise IntegrityError('unreferenced chunk (unaccounted bytes)')
        self.total = total
        archive_size = HDR.size + self.header['manifest_len'] + plen
        # Reached only after the header/manifest tag verified. Keyed archives were authenticated with
        # the password, so their declared size is the writer's, not a forger's: no default ratio cap.
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
        self.manifest = m

    # -- low level
    def _read_at(self, off, n):
        self.f.seek(self.base + off)
        b = self.f.read(n)
        if len(b) != n:
            raise IntegrityError('truncated payload')
        return b

    def _zstd_decode(self, body, raw_len, dict_data, want_dict_id=0):
        try:
            content_size, window_size, dict_id = ZB.frame_info(body)
        except Exception as exc:
            raise IntegrityError('bad zstd frame') from exc
        if content_size != raw_len or window_size > self.limits.max_window or dict_id != want_dict_id:
            raise IntegrityError('zstd frame size/window/dictionary limits')
        try:
            out = ZB.decompress(body, raw_len, dict_data, self.limits.max_window)
        except Exception as exc:
            raise IntegrityError('zstd decode failed or trailing data') from exc
        if len(out) != raw_len:
            raise IntegrityError('decoded length mismatch')
        return out

    def _group_data(self, gi):
        """Return repaired data-region bytes of parity group gi (raises if > m bad shards)."""
        if self._group_cache and self._group_cache[0] == gi:
            return self._group_cache[1]
        k, m, groups = self.parity
        gs, gl, s, poff, hashes = groups[gi]
        raw = self._read_at(gs, gl).ljust(k * s, b'\0')
        shards = [raw[i * s:(i + 1) * s] for i in range(k)] + \
                 [self._read_at(poff + i * s, s) for i in range(m)]
        good = [sh if hmac.compare_digest(self.ctx.tag(sh), hashes[i]) else None for i, sh in enumerate(shards)]
        bad = sum(x is None for x in good)
        data = b''.join(rs_reconstruct(good, k, m))[:gl]
        self._group_cache = (gi, data, bad)
        return data

    def _repaired_range(self, off, n):
        k, m, groups = self.parity
        out = []
        for gi, (gs, gl, s, _p, _h) in enumerate(groups):
            if gs + gl <= off or gs >= off + n:
                continue
            g = self._group_data(gi)
            lo, hi = max(off, gs) - gs, min(off + n, gs + gl) - gs
            out.append(g[lo:hi])
        return b''.join(out)

    def stored(self, off, n, tag):
        b = self._read_at(off, n)
        if hmac.compare_digest(self.ctx.tag(b), tag):
            return b
        if self.parity is None:
            raise IntegrityError('stored chunk authentication failed (no parity)')
        b = self._repaired_range(off, n)
        if not hmac.compare_digest(self.ctx.tag(b), tag):
            raise IntegrityError('parity repair did not reproduce authenticated bytes')
        self.repairs += 1
        return b

    def dictionary(self):
        if self.dict_rec is None:
            return None
        if not hasattr(self, '_dict'):
            off, raw, n, tag = self.dict_rec
            d = self.ctx.open(0, 0, self.stored(off, n, tag))
            try:
                self._dict = ZB.make_dict(d)
                self._dict_id = ZB.dict_id(self._dict)
            except Exception as exc:
                raise IntegrityError('stored dictionary unusable') from exc
        return self._dict

    def chunk(self, i):
        if i in self._raw_cache:
            self._raw_cache.move_to_end(i)
            return self._raw_cache[i]
        codec, raw_len, n, cid, tag, base, off = self.chunks[i]
        body = self.ctx.open(0, i + 1, self.stored(off, n, tag))  # verify BEFORE decrypt/decode
        if codec == CODEC_RAW:
            raw = body
        elif codec == CODEC_ZSTD:
            raw = self._zstd_decode(body, raw_len, None)
        elif codec == CODEC_DICT:
            d = self.dictionary()
            raw = self._zstd_decode(body, raw_len, d, self._dict_id)
        else:
            braw = self.chunk(base)
            raw = self._zstd_decode(body, raw_len, ZB.make_dict(braw, raw=True))
        if len(raw) != raw_len or not hmac.compare_digest(self.ctx.chunk_id(raw), cid):
            raise IntegrityError(f'chunk {i} content hash mismatch')
        if self.is_base(i):
            self._raw_cache[i] = raw
            self._raw_cache_bytes += len(raw)
            while self._raw_cache_bytes > self.limits.delta_cache:
                _, v = self._raw_cache.popitem(last=False)
                self._raw_cache_bytes -= len(v)
        return raw

    def is_base(self, i):
        if not hasattr(self, '_bases'):
            self._bases = {c[5] for c in self.chunks if c[0] == CODEC_DELTA}
        return i in self._bases

    def iter_file(self, entry):
        for r in entry[3]:
            yield self.chunk(r)

    # -- verification
    def scan_shards(self):
        """Return list of (group, shard_index) whose stored hash fails."""
        if self.parity is None:
            return []
        k, m, groups = self.parity
        bad = []
        for gi, (gs, gl, s, poff, hashes) in enumerate(groups):
            raw = self._read_at(gs, gl).ljust(k * s, b'\0')
            for i in range(k + m):
                sh = raw[i * s:(i + 1) * s] if i < k else self._read_at(poff + (i - k) * s, s)
                if not hmac.compare_digest(self.ctx.tag(sh), hashes[i]):
                    bad.append((gi, i))
        return bad

    def verify(self):
        """Full check without writing. Returns report; raises IntegrityError if unrecoverable."""
        bad_shards = self.scan_shards()
        bad_chunks = []
        for i, c in enumerate(self.chunks):
            if not hmac.compare_digest(self.ctx.tag(self._read_at(c[6], c[2])), c[4]):
                bad_chunks.append(i)
        digests = []
        for e in self.files:
            h = hashlib.sha256()
            for b in self.iter_file(e):
                h.update(b)
            if h.hexdigest() != e[2]:
                raise IntegrityError(f'file digest mismatch: {e[0]}')
            digests.append([e[0], e[1], h.hexdigest()])
        root = self.ctx.tag(b'rdc3-root\0' + canonical(dict(files=digests, dirs=self.dirs)))
        if not hmac.compare_digest(root, self.root):
            raise IntegrityError('root hash mismatch on verify')
        return dict(ok=not bad_shards and not bad_chunks, files=len(self.files), bad_shards=bad_shards,
                    bad_chunks=bad_chunks, parity_repairs_used=self.repairs,
                    needs_repair=bool(bad_shards or bad_chunks))


def verify(path, password=None, max_expansion=None):
    with Archive(path, password, max_expansion=max_expansion) as a:
        return a.verify()


def repair(src, dest, password=None, max_expansion=None):
    """Rewrite a damaged archive using parity into a NEW file (no overwrite); re-verify."""
    with Archive(src, password, max_expansion=max_expansion) as a:
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
        atomic_publish_file(dest, writer)
    report = verify(dest, password, max_expansion)
    if report['needs_repair']:
        raise IntegrityError('re-verify after repair failed')
    return dict(repaired_groups=badg, bad_shards_before=bad, reverify=report)


# ---------------------------------------------------------------- restore
def _open_dir_nofollow(parent_fd, name, create):
    if create:
        try:
            os.mkdir(name, 0o755, dir_fd=parent_fd)
        except FileExistsError:
            pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)


def _walk_parent(root_fd, parts, create):
    """Return fd of the parent directory of parts (no symlink following); None if absent."""
    fd = os.dup(root_fd)
    try:
        for name in parts[:-1]:
            try:
                nfd = _open_dir_nofollow(fd, name, create)
            except FileNotFoundError:
                os.close(fd)
                return None
            except OSError as exc:  # ELOOP (symlink) / ENOTDIR
                raise IntegrityError(f'path component is a symlink or not a directory: {name}') from exc
            os.close(fd)
            fd = nfd
        return fd
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def restore(archive, dest_dir, password=None, recover=False, failpoint=None, max_expansion=None):
    """Restore into dest_dir (created if missing). Fail closed: every file is staged, checked
    against its SHA-256 and the root hash, then published with no-clobber links. --recover
    publishes only files that verify and reports the rest (skip-and-warn)."""
    if not (hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY') and os.link in os.supports_dir_fd
            and os.open in os.supports_dir_fd):
        import rdc4  # Windows: same contract through rdc4's path-based portable restore (reads RDCv003)
        return rdc4.restore(archive, dest_dir, password, recover, failpoint, max_expansion, portable=True)
    with Archive(archive, password, max_expansion=max_expansion) as a:
        if os.path.islink(dest_dir):
            raise IntegrityError('destination is a symlink')
        created = not os.path.exists(dest_dir)
        check_free_space(dest_dir if not created else os.path.dirname(os.path.abspath(dest_dir)) or '.',
                         a.total, a.limits)
        if created:
            os.mkdir(dest_dir, 0o755)
        try:
            return _restore_into(a, dest_dir, recover, failpoint)
        except PublicationError:
            raise  # validated files are published; never remove them
        except BaseException:
            if created:
                try:
                    os.rmdir(dest_dir)  # only succeeds if still empty
                except OSError:
                    pass
            raise


def check_free_space(path, needed, limits=Limits):
    """Refuse before staging unless the filesystem keeps headroom after writing `needed` bytes."""
    free = shutil.disk_usage(path).free
    want = needed + limits.free_space_headroom + needed // 20
    if free < want:
        raise LimitError(f'insufficient free space on {path}: need {want:,} bytes '
                         f'({needed:,} output + headroom), {free:,} free; nothing written')
    return free


def _restore_into(a, dest_dir, recover, failpoint, sync_log=None):
    """POSIX descriptor-relative restore. Returns dict incl. directories_fsynced (True only once every
    published file's directory and the root were synced) and sync_mode (see _durable_sync)."""
    log = sync_log if sync_log is not None else SyncLog()
    dsynced = False
    if True:
        root_fd = os.open(dest_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            # 1. conflict pre-check: refuse before writing anything
            for e in a.files:
                parts = e[0].split('/')
                pfd = _walk_parent(root_fd, parts, create=False)
                if pfd is not None:
                    try:
                        os.lstat(parts[-1], dir_fd=pfd)
                        raise FileExistsError(f'destination exists, refusing to overwrite: {e[0]}')
                    except FileNotFoundError:
                        pass
                    finally:
                        os.close(pfd)
            staging = tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=dest_dir)
            sfd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            staged, damaged, digests = [], [], []
            published = []
            try:
                # 2. stage + verify (readers may supply a bounded-decode stager, e.g. RDCv004 pack order)
                stage_all = getattr(a, 'stage_all', None)
                for n, e in enumerate(a.files if stage_all is None else ()):
                    name = f'{n:08d}'
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=sfd)
                    try:
                        h = hashlib.sha256()
                        with os.fdopen(fd, 'wb') as out:
                            for b in a.iter_file(e):
                                h.update(b)
                                out.write(b)
                            if h.hexdigest() != e[2]:
                                raise IntegrityError(f'file digest mismatch: {e[0]}')
                            os.fchmod(out.fileno(), 0o644)
                            out.flush()
                            _durable_sync(out.fileno(), log)
                        staged.append((name, e))
                        digests.append([e[0], e[1], e[2]])
                    except IntegrityError as exc:
                        os.unlink(name, dir_fd=sfd)
                        if not recover:
                            raise
                        damaged.append(dict(path=e[0], error=str(exc)))
                if stage_all is not None:
                    staged, damaged, digests = stage_all(sfd, recover, spill_dir=staging)
                if not recover:
                    root = a.ctx.tag(b'rdc3-root\0' + canonical(dict(files=digests, dirs=a.dirs)))
                    if not hmac.compare_digest(root, a.root):
                        raise IntegrityError('root hash mismatch on restore')
                if failpoint == 'before_publish':
                    raise IntegrityError('injected before_publish')
                # 3. publish (no clobber)
                for d in a.dirs:
                    pfd = _walk_parent(root_fd, d.split('/') + ['x'], create=True)
                    os.close(pfd)
                stage = 'publish'
                try:
                    for name, e in staged:
                        parts = e[0].split('/')
                        pfd = _walk_parent(root_fd, parts, create=True)
                        try:
                            os.link(name, parts[-1], src_dir_fd=sfd, dst_dir_fd=pfd, follow_symlinks=False)
                        finally:
                            os.close(pfd)
                        published.append(e[0])
                        if failpoint == 'after_first_publish':
                            raise OSError('injected after_first_publish')
                    stage = 'directory_fsync'
                    dirs_to_sync = {''} | {'/'.join(e[0].split('/')[:-1]) for _, e in staged}
                    for d in sorted(dirs_to_sync):
                        if d:
                            pfd = _walk_parent(root_fd, d.split('/') + ['x'], create=False)
                            try:
                                _durable_sync(pfd, log)
                            finally:
                                os.close(pfd)
                        else:
                            _durable_sync(root_fd, log)
                    dsynced = True
                except Exception as exc:
                    if published:
                        raise PublicationError(published, stage, exc) from exc
                    raise
            finally:
                for name in os.listdir(sfd):
                    try:
                        os.unlink(name, dir_fd=sfd)
                    except OSError:
                        pass
                os.close(sfd)
                try:
                    os.rmdir(staging)
                except OSError:
                    pass
        finally:
            os.close(root_fd)
        return dict(files=len(published), bytes=sum(e[1] for _, e in staged), damaged=damaged,
                    parity_repairs_used=a.repairs, recover=recover, directories_fsynced=dsynced,
                    sync_mode=log.mode)


def list_archive(path, password=None, max_expansion=None):
    with Archive(path, password, max_expansion=max_expansion) as a:
        return dict(files=[dict(path=f[0], size=f[1], sha256=f[2]) for f in a.files], dirs=a.dirs,
                    chunks=len(a.chunks), parity=a.parity[:2] if a.parity else None,
                    encrypted=a.ctx.encrypted, keyed=a.ctx.keyed, total=a.total)


# ---------------------------------------------------------------- CLI
def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    pk = sub.add_parser('pack')
    pk.add_argument('source')
    pk.add_argument('archive')
    pk.add_argument('--level', type=int, default=3)
    pk.add_argument('--dict', action='store_true')
    pk.add_argument('--delta', action='store_true', help='experimental delta+zstd codec')
    pk.add_argument('--parity', help='K,M[,SHARD] e.g. 10,2,65536')
    pk.add_argument('--encrypt', action='store_true', help='password from env RDC_PASSWORD')
    pk.add_argument('--gear', choices=['public', 'seeded', 'keyed'], default=None)
    pk.add_argument('--seed')
    pk.add_argument('--hash', choices=['sha256', 'blake3'], default='sha256')
    pk.add_argument('--min', type=int, default=8192)
    pk.add_argument('--avg', type=int, default=32768)
    pk.add_argument('--max', type=int, default=131072)
    for name in ('unpack', 'verify', 'repair', 'ls'):
        s = sub.add_parser(name)
        s.add_argument('archive')
        if name in ('unpack', 'repair'):
            s.add_argument('destination')
        if name == 'unpack':
            s.add_argument('--recover', action='store_true', help='skip-and-warn damaged files')
        s.add_argument('--max-expansion', type=int, default=None,
                       help=f'max declared-output/archive-size ratio (default: {Limits.max_expansion} unkeyed, '
                            'none for keyed archives after MAC check; 0 disables)')
    a = p.parse_args(argv)
    pw = os.environ.get('RDC_PASSWORD')
    try:
        if a.cmd == 'pack':
            par = None
            if a.parity:
                v = [int(x) for x in a.parity.split(',')]
                par = (v[0], v[1], v[2] if len(v) > 2 else 65536)
            if a.encrypt and not pw:
                raise ValueError('--encrypt needs RDC_PASSWORD in the environment')
            gear = a.gear or ('keyed' if a.encrypt else 'public')
            r = pack(a.source, a.archive, level=a.level, use_dict=a.dict, delta=a.delta, parity=par,
                     password=pw if a.encrypt else None, gear=gear, seed=a.seed, hash_name=a.hash,
                     min_size=a.min, avg_size=a.avg, max_size=a.max)
        elif a.cmd == 'unpack':
            r = restore(a.archive, a.destination, pw, recover=a.recover, max_expansion=a.max_expansion)
            if r['damaged']:
                print(json.dumps(r), file=sys.stderr)
                return 3
        elif a.cmd == 'verify':
            r = verify(a.archive, pw, a.max_expansion)
            if r['needs_repair']:
                print(json.dumps(r))
                return 4
        elif a.cmd == 'repair':
            r = repair(a.archive, a.destination, pw, a.max_expansion)
        else:
            r = list_archive(a.archive, pw, a.max_expansion)
    except PublicationError as exc:
        print(json.dumps(dict(error='PublicationError', published=exc.published, stage=exc.stage,
                              durability_confirmed=False, message=str(exc))), file=sys.stderr)
        return 2
    except (IntegrityError, FileExistsError, ValueError) as exc:
        print(json.dumps(dict(error=type(exc).__name__, message=str(exc))), file=sys.stderr)
        return 1
    print(json.dumps(r, default=str))
    return 0


if __name__ == '__main__':
    sys.exit(main())
