"""RDC_SIM_NT=1: run the whole suite with the POSIX-only pieces Windows Python lacks removed
(O_DIRECTORY, O_NOFOLLOW, pwrite/pread, fchmod, dir_fd support), so restore/verify/pack must take
the portable path. Not a substitute for a run on real Windows (see README: Windows)."""
import os
import pytest

SIM_NT = os.environ.get('RDC_SIM_NT') == '1'


def _strip(monkeypatch):
    for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'pwrite', 'pread', 'fchmod'):
        if hasattr(os, name):
            monkeypatch.delattr(os, name)
    monkeypatch.setattr(os, 'supports_dir_fd', set())


@pytest.fixture(autouse=SIM_NT)
def _sim_nt(monkeypatch):
    _strip(monkeypatch)
    yield


@pytest.fixture
def sim_nt(monkeypatch):
    if not SIM_NT:
        _strip(monkeypatch)
    yield


def _probe_links(where, kind):
    """None if `kind` ('symlink' or 'hardlink') can be created in folder `where`, else the OSError."""
    probe = where / '.link-probe'
    probe.mkdir(exist_ok=True)
    target, link = probe / 'target', probe / f'{kind}'
    try:
        target.write_bytes(b'x')
        (os.symlink if kind == 'symlink' else os.link)(target, link)
        return None
    except OSError as e:   # exFAT/FAT (WinError 1), no symlink privilege (1314), EPERM/ENOTSUP elsewhere
        return e
    finally:
        for p in (link, target):
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            os.rmdir(probe)
        except OSError:
            pass


@pytest.fixture
def need_links(tmp_path):
    """Skip (not fail) a test whose own setup needs links when the filesystem under tmp_path has none.
    Usage: need_links('symlink'), need_links('hardlink'), or both."""
    def check(*kinds):
        for kind in kinds:
            err = _probe_links(tmp_path, kind)
            if err is not None:
                pytest.skip(f'filesystem under {tmp_path} cannot create {kind}s ({err})')
    return check
