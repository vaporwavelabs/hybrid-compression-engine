"""Tests for the opt-in GUI add-on options of rdc4.py: --progress and --password-stdin.
They must not change any archive byte, any result line, or the default behaviour."""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
RDC4 = os.path.join(HERE, 'rdc4.py')


def run(args, stdin=None, env_pw=None):
    env = dict(os.environ)
    env.pop('RDC_PASSWORD', None)
    env['PYTHONIOENCODING'] = 'utf-8'
    if env_pw is not None:
        env['RDC_PASSWORD'] = env_pw
    p = subprocess.run([sys.executable, RDC4] + args, input=stdin, capture_output=True, text=True,
                       encoding='utf-8', env=env, timeout=600)
    return p.returncode, p.stdout, p.stderr


def make_tree(root):
    os.makedirs(os.path.join(root, 'd', 'e'))
    rnd = os.urandom(700_000)
    with open(os.path.join(root, 'a.txt'), 'w') as f:
        f.write('\n'.join('line %d of a log file' % i for i in range(60_000)))
    with open(os.path.join(root, 'd', 'b.bin'), 'wb') as f:
        f.write(rnd)
    with open(os.path.join(root, 'd', 'e', 'b-copy.bin'), 'wb') as f:
        f.write(rnd[:500_000] + b'edited' + rnd[500_000:])
    open(os.path.join(root, 'empty'), 'wb').close()


def progress_lines(stderr):
    out = []
    for line in stderr.splitlines():
        if line.startswith('{'):
            obj = json.loads(line)
            if obj.get('event') == 'progress':
                out.append(obj)
    return out


@pytest.mark.parametrize('threads', ['1', '4'])
def test_progress_does_not_change_archive_bytes(tmp_path, threads):
    src = tmp_path / 'src'
    make_tree(str(src))
    a, b = tmp_path / 'a.rdc4', tmp_path / 'b.rdc4'
    rc1, out1, err1 = run(['pack', str(src), str(a), '--threads', threads])
    rc2, out2, err2 = run(['pack', str(src), str(b), '--threads', threads, '--progress'])
    assert rc1 == rc2 == 0
    assert a.read_bytes() == b.read_bytes()
    assert json.loads(out1) == json.loads(out2)          # same result line
    assert progress_lines(err1) == []                     # default: no progress output at all
    ev = progress_lines(err2)
    stages = [e['stage'] for e in ev]
    assert stages[0] == 'pack' and 'parity' in stages
    total = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(src) for f in fs)
    packs = [e for e in ev if e['stage'] == 'pack']
    assert packs[0]['total'] == total and packs[-1]['done'] == total
    for st in set(stages):
        dones = [e['done'] for e in ev if e['stage'] == st]
        assert dones == sorted(dones)
    assert ev[-1]['done'] == ev[-1]['total']


def test_progress_unpack_verify_repair(tmp_path):
    src = tmp_path / 'src'
    make_tree(str(src))
    arc = tmp_path / 'x.rdc4'
    assert run(['pack', str(src), str(arc)])[0] == 0
    rc, out, err = run(['unpack', str(arc), str(tmp_path / 'out'), '--progress'])
    assert rc == 0 and json.loads(out)['files'] == 4
    ev = progress_lines(err)
    assert ev[0]['stage'] == 'unpack' and ev[-1]['done'] == ev[-1]['total'] == json.loads(out)['bytes']
    for root, _, fs in os.walk(src):
        for f in fs:
            rel = os.path.relpath(os.path.join(root, f), src)
            with open(os.path.join(root, f), 'rb') as x, open(tmp_path / 'out' / rel, 'rb') as y:
                assert x.read() == y.read()
    rc, out, err = run(['verify', str(arc), '--progress'])
    assert rc == 0 and json.loads(out)['ok'] and progress_lines(err)[-1]['stage'] == 'verify'
    # damage a copy, repair with progress (re-verify reports progress), result unchanged in shape
    bad = tmp_path / 'bad.rdc4'
    data = bytearray(arc.read_bytes())
    data[20000:20100] = os.urandom(100)
    bad.write_bytes(bytes(data))
    rc, out, err = run(['verify', str(bad), '--progress'])
    assert rc == 4 and json.loads(out)['needs_repair']
    rc, out, err = run(['repair', str(bad), str(tmp_path / 'fixed.rdc4'), '--progress'])
    assert rc == 0 and json.loads(out)['reverify']['ok']
    assert (tmp_path / 'fixed.rdc4').read_bytes() == arc.read_bytes()


def test_progress_error_keeps_error_json_last(tmp_path):
    p = tmp_path / 'not-an-archive.rdc4'
    p.write_bytes(b'hello')
    rc, out, err = run(['verify', str(p), '--progress'])
    assert rc == 1
    last = json.loads(err.strip().splitlines()[-1])
    assert last['error'] == 'IntegrityError'


def test_password_stdin_matches_env(tmp_path):
    src = tmp_path / 'src'
    make_tree(str(src))
    arc = tmp_path / 'enc.rdc4'
    pw = 'Pässwörd with spaces '
    rc, out, err = run(['pack', str(src), str(arc), '--encrypt', '--password-stdin'], stdin=pw + '\n')
    assert rc == 0 and json.loads(out)['encrypted']
    # readable with the classic environment variable ...
    rc, out, err = run(['ls', str(arc)], env_pw=pw)
    assert rc == 0 and len(json.loads(out)['files']) == 4
    # ... and with stdin, for every command
    rc, out, err = run(['verify', str(arc), '--password-stdin'], stdin=pw + '\r\n')
    assert rc == 0 and json.loads(out)['ok']
    rc, out, err = run(['unpack', str(arc), str(tmp_path / 'o'), '--password-stdin', '--progress'], stdin=pw + '\n')
    assert rc == 0
    rc, out, err = run(['ls', str(arc), '--password-stdin'], stdin='wrong\n')
    assert rc == 1 and 'wrong password' in json.loads(err.strip().splitlines()[-1])['message']
    rc, out, err = run(['ls', str(arc), '--password-stdin'], stdin='')
    assert rc == 1 and '--password-stdin' in json.loads(err)['message']
    # stdin wins over a stale environment variable
    rc, out, err = run(['ls', str(arc), '--password-stdin'], stdin=pw + '\n', env_pw='stale')
    assert rc == 0


def test_default_cli_unchanged_without_new_flags(tmp_path):
    src = tmp_path / 'src'
    make_tree(str(src))
    rc, out, err = run(['pack', str(src), str(tmp_path / 'e.rdc4'), '--encrypt'])
    assert rc == 1 and 'RDC_PASSWORD' in json.loads(err)['message']
