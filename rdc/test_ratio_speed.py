"""Tests for the repair-strength presets (--parity light/standard) and --threads auto in rdc4.py, and the
window's matching choices. Defaults must stay byte-identical; light parity must still repair damage."""
import json
import os
import subprocess
import sys

import pytest

import rdc4
from test_gui_addon import make_tree, run

HERE = os.path.dirname(os.path.abspath(__file__))
SMALL = ['--pack-size', str(64 * 1024)]


def pack(tmp_path, name, *extra):
    src = tmp_path / 'src'
    if not src.exists():
        make_tree(str(src))
    arc = str(tmp_path / name)
    rc, out, err = run(['pack', str(src), arc] + SMALL + list(extra))
    assert rc == 0, err
    return arc, json.loads(out.strip().splitlines()[-1])


def data(path):
    with open(path, 'rb') as f:
        return f.read()


def test_threads_auto_is_default_and_byte_identical(tmp_path):
    a1, r1 = pack(tmp_path, 'one.rdc4', '--threads', '1')
    a0, r0 = pack(tmp_path, 'default.rdc4')
    aa, ra = pack(tmp_path, 'auto.rdc4', '--threads', 'auto')
    assert r0['threads'] == ra['threads'] == rdc4.auto_threads()
    assert data(a1) == data(a0) == data(aa)


def test_auto_threads_bounds():
    assert 1 <= rdc4.auto_threads() <= rdc4.Limits4.max_threads


def test_threads_bad_value(tmp_path):
    src = tmp_path / 'src'
    make_tree(str(src))
    rc, _out, err = run(['pack', str(src), str(tmp_path / 'x.rdc4'), '--threads', 'many'])
    assert rc != 0 and 'auto' in err


def test_parity_standard_preset_equals_default(tmp_path):
    a, _ = pack(tmp_path, 'default.rdc4', '--threads', '1')
    b, _ = pack(tmp_path, 'standard.rdc4', '--threads', '1', '--parity', 'standard')
    assert data(a) == data(b)


def test_parity_light_preset_equals_numbers(tmp_path):
    a, ra = pack(tmp_path, 'light.rdc4', '--threads', '1', '--parity', 'light')
    b, rb = pack(tmp_path, 'nums.rdc4', '--threads', '1', '--parity', '20,2')
    assert data(a) == data(b)
    _d, rd = pack(tmp_path, 'default.rdc4', '--threads', '1')
    assert 0 < ra['parity_bytes'] < rd['parity_bytes']
    assert ra['data_bytes'] == rd['data_bytes']


def test_light_parity_repairs_damage(tmp_path):
    arc, r = pack(tmp_path, 'light.rdc4', '--parity', 'light')
    blob = bytearray(data(arc))
    start = r['header_bytes'] + r['manifest_bytes']
    for off in (start + 1000, start + 70_000):       # two different 64 KiB shards of the first group
        blob[off] ^= 0xFF
    with open(arc, 'wb') as f:
        f.write(blob)
    rc, out, _err = run(['verify', arc])
    assert rc == 4 and json.loads(out.strip().splitlines()[-1])['needs_repair']
    fixed = str(tmp_path / 'fixed.rdc4')
    rc, _out, err = run(['repair', arc, fixed])
    assert rc == 0, err
    rc, _out, err = run(['verify', fixed])
    assert rc == 0, err
    dest = str(tmp_path / 'out')
    rc, _out, err = run(['unpack', fixed, dest])
    assert rc == 0, err
    for rel in ('a.txt', os.path.join('d', 'b.bin'), os.path.join('d', 'e', 'b-copy.bin')):
        assert data(os.path.join(dest, rel)) == data(os.path.join(tmp_path, 'src', rel))


def test_gui_repair_choices_are_valid_pack_arguments(tmp_path):
    pytest.importorskip('tkinter')
    sys.path.insert(0, HERE)
    import rdc_gui
    assert rdc_gui.REPAIR_CHOICES[0][1] == []          # default choice adds nothing: same archive as before
    sizes = []
    for i, (_label, extra) in enumerate(rdc_gui.REPAIR_CHOICES):
        _a, r = pack(tmp_path, 'g%d.rdc4' % i, *extra)
        sizes.append(r['stored_bytes'])
    assert sizes[0] > sizes[1] > sizes[2]
