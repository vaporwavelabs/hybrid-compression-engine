#!/usr/bin/env python3
"""Error manager for hybrid stores: finds problems, fixes automatically the ones
that can be fixed without any risk to data, and reports the rest with the exact
next step.

  python doctor.py check <store> ... [--password-file F] [--max-age-days N] [--json]
  python doctor.py fix   <store> ... [--dry-run] [--approve RULE ...] [--copy-first DIR]
  python doctor.py watch --config doctor.json [--notify]
  python doctor.py run [--retries N] [--wait S] -- <hybridstore arguments>
  python doctor.py bugs [--days N] [--all] [--report SIGNATURE] [--ack SIGNATURE]
  python doctor.py rules
  python doctor.py schedule --config doctor.json [--time 03:17] [--install]

Automatic fixes are only the ones whose result is proven: `repair` writes a
shard only if it hashes to the value recorded when the store was good, footers
are rewritten from the manifest they must point at, and parity is only rebuilt
over a store that verifies. Anything that removes data (leftover temp stores,
lost snapshots) runs only with --approve RULE. Code bugs are never "fixed" by
editing code: crashes are grouped by signature, matched against known causes,
and `bugs --report` writes a bug report to attach.

Exit codes: 0 healthy (or everything was fixed), 1 something needs attention,
2 usage error.
"""
from __future__ import annotations

import argparse, json, os, re, shutil, subprocess, sys, time
from dataclasses import dataclass, field, asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hybridstore as hs

SEVERITY = {"info": 0, "warning": 1, "error": 2, "critical": 3}


@dataclass
class Rule:
    severity: str
    title: str
    fix: str              # "auto:<fixer>", "approve:<fixer>" or "manual"
    advice: str


RULES: dict[str, Rule] = {
    "STORE_MISSING": Rule("error", "the store file does not exist", "manual",
                          "check the path and that the drive is connected"),
    "BUSY": Rule("info", "another process is writing the store; deep checks were skipped", "manual",
                 "run again when the backup or prune has finished"),
    "NEEDS_PASSWORD": Rule("warning", "encrypted store and no password: only the parity check ran", "manual",
                           "give --password-file (or password_file in the config) for a full check"),
    "WRONG_PASSWORD": Rule("error", "the password does not open this store", "manual",
                           "check the password file; `passwd` changes only the key block, so older copies "
                           "keep the old password"),
    "STORE_UNOPENABLE": Rule("critical", "the store does not open", "auto:parity_repair",
                             "rebuilt from parity when parity can; otherwise restore the store from another copy"),
    "DAMAGE_REPAIRABLE": Rule("error", "damaged bytes that parity can rebuild exactly", "auto:parity_repair",
                              "rebuilt from parity (each shard is written only if it hashes to its recorded value)"),
    "DAMAGE_BEYOND_REPAIR": Rule("critical", "damage that parity cannot rebuild", "approve:parity_repair",
                                 "stop writing to this disk, copy the store off it (`fix --copy-first DIR`), "
                                 "rebuild what parity can (`fix --approve DAMAGE_BEYOND_REPAIR`), and restore "
                                 "the affected files from another backup (TROUBLESHOOTING.md 1)"),
    "DAMAGE_NO_PARITY": Rule("critical", "damage and no parity file to rebuild it", "manual",
                             "restore the damaged packs from another copy; after a clean verify, add parity "
                             "(`hybridstore.py parity <store>`)"),
    "OLD_FOOTER_DAMAGED": Rule("warning", "a superseded snapshot footer is damaged", "auto:repair",
                               "rewritten from the manifest it must point at"),
    "FOOTER_MISSING": Rule("error", "the newest snapshot is complete but its footer is missing or damaged",
                           "auto:repair", "the footer is written again; the snapshot becomes visible"),
    "INTERRUPTED_WRITE": Rule("warning", "bytes from an interrupted write after the last snapshot",
                              "auto:repair", "cut off; they hold no complete snapshot (the next backup would "
                                             "discard them too)"),
    "PARITY_MISSING": Rule("warning", "no parity file: damage could be detected but not repaired",
                           "auto:parity", "parity is built over the verified store (~12.5% of its size)"),
    "PARITY_STALE": Rule("warning", "the parity file does not cover the whole store, or is damaged",
                         "auto:repair", "rebuilt from the store once the store verifies"),
    "SNAPSHOT_LIST_LOST": Rule("error", "a snapshot's file list is unreadable", "approve:prune_lost",
                               "the snapshot cannot be restored; removing it (`prune --remove N`) makes the "
                               "rest of the store clean again"),
    "INDEX_WRONG": Rule("error", "the dedup index points at wrong data", "manual",
                        "restores are not affected, but later backups could reuse bad data: send new "
                        "backups to a new store"),
    "LEFTOVER_TEMP": Rule("warning", "a leftover temporary file from an interrupted pack / prune / parity run",
                          "approve:delete_leftovers", "the original store is untouched; the leftover only "
                                                      "takes space"),
    "LOW_SPACE": Rule("warning", "little free space on the store's drive", "manual",
                      "`prune` and `pack --force` need room for a full copy of the store: free space or "
                      "move the store"),
    "BACKUP_STALE": Rule("warning", "no new snapshot for longer than expected", "manual",
                         "check that the scheduled backup still runs (Task Scheduler history, `bugs`)"),
    "SKIPPED_REPEATEDLY": Rule("info", "the same items were skipped in each of the last snapshots", "manual",
                               "see the hint for each reason (TROUBLESHOOTING.md 3)"),
    "REPEATED_FAILURES": Rule("warning", "commands on this store keep failing", "manual",
                              "see the messages below and `doctor.py bugs`"),
    "CRASH": Rule("error", "the engine crashed (a bug)", "manual",
                  "`doctor.py bugs --report <signature>` writes a report to attach to an issue"),
}

# Known causes, matched against crash and error messages.
KNOWN = [
    (r"WinError 3[23]\b|being used by another process|sharing violation",
     "another program (antivirus, OneDrive/Dropbox sync, a search indexer) has the file open",
     "transient: `doctor.py run` retries; keep the store out of synced folders"),
    (r"WinError 112\b|No space left|\[Errno 28\]|not enough space",
     "the disk is full", "free space, or `prune` old snapshots (prune needs room for a copy)"),
    (r"MemoryError|Unable to allocate", "out of memory",
     "close other programs, use fewer --workers, or split the source into several stores"),
    (r"WinError 1314\b|required privilege", "creating symlinks needs Developer Mode or admin",
     "turn on Developer Mode (junctions need nothing)"),
    (r"WinError 5\b|Access is denied|PermissionError", "permission denied",
     "check the file's permissions and that no program holds it exclusively"),
    (r"WinError 206\b|too long", "a path is longer than Windows allows", "enable long paths (LongPathsEnabled)"),
    (r"WinError (21|23|1006|1117|483)\b|device is not ready|I/O device error|cyclic redundancy",
     "the disk or its connection failed while reading/writing", "check the cable / USB port and the disk's "
                                                               "SMART data before trusting it (TROUBLESHOOTING.md 6)"),
    (r"No module named '?(\w+)", "a Python package is missing",
     "install it into the venv: `.venv\\Scripts\\pip install <name>` (see requirements.txt)"),
]


def known_cause(text: str) -> tuple[str, str] | None:
    for pat, cause, fix in KNOWN:
        m = re.search(pat, text or "")
        if m:
            return cause, fix.replace("<name>", m.group(1)) if "<name>" in fix and m.groups() else fix
    return None


@dataclass
class Finding:
    rule: str
    detail: str
    data: dict = field(default_factory=dict)

    @property
    def severity(self) -> str:
        return RULES[self.rule].severity

    @property
    def fix(self) -> str:
        return RULES[self.rule].fix


# --------------------------------------------------------------------------
# diagnosis (reads only)
# --------------------------------------------------------------------------
def leftovers(path: str) -> list[str]:
    return [p for p in (path + ".hcs-new", hs.Parity(path).path + "-new") if os.path.exists(p)]


def _busy(path: str) -> str | None:
    try:
        lock = hs._StoreLock(path)
    except hs.StoreLockedError as e:
        return str(e)
    lock.release()
    return None


def _parity_findings(pc: dict | None, damage_seen: bool) -> list[Finding]:
    if pc is None:
        return [] if damage_seen else [Finding("PARITY_MISSING", "no <store>.hcp")]
    out = []
    if not pc["header_ok"]:
        out.append(Finding("PARITY_STALE", hs.parity_summary(pc)))
    elif pc["bad_shards"]:
        rule = "DAMAGE_BEYOND_REPAIR" if pc["unrepairable_groups"] else "DAMAGE_REPAIRABLE"
        out.append(Finding(rule, hs.parity_summary(pc),
                           {"bad_shards": pc["bad_shards"], "unrepairable_groups": len(pc["unrepairable_groups"])}))
    if pc["header_ok"] and (pc["bad_records"] or pc["covered"] != pc["size"]):
        out.append(Finding("PARITY_STALE", hs.parity_summary(pc)))
    return out


def diagnose(path: str, password: str | None = None, max_age_days: float | None = None,
             events: list[dict] | None = None) -> list[Finding]:
    """Everything that is wrong with one store; changes nothing."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return [Finding("STORE_MISSING", path)]
    found: list[Finding] = []
    busy = _busy(path)
    if busy:
        return [Finding("BUSY", busy)]
    left = leftovers(path)
    if left:
        found.append(Finding("LEFTOVER_TEMP", ", ".join(f"{p} ({os.path.getsize(p):,} bytes)" for p in left),
                             {"paths": left}))
    par = hs.Parity(path)
    pc = par.check() if par.exists() else None
    size = os.path.getsize(path)
    try:
        free = shutil.disk_usage(os.path.dirname(path)).free
        if free < size or free < 1 << 30:
            found.append(Finding("LOW_SPACE", f"{free / 1e9:,.1f} GB free, store {size / 1e9:,.1f} GB",
                                 {"free": free, "store": size}))
    except OSError:
        pass
    if events:
        found += _event_findings(path, events)
    hs.set_password(password)
    try:
        r = hs.StoreReader(path, password=password)
    except hs.PasswordError as e:
        found.append(Finding("WRONG_PASSWORD" if password else "NEEDS_PASSWORD", str(e)))
        return found + _parity_findings(pc, damage_seen=False)
    except (hs.IntegrityError, ValueError, OSError) as e:
        found.append(Finding("STORE_UNOPENABLE", str(e)))
        return found + _parity_findings(pc, damage_seen=True)
    with r:
        rep = r.scan(strict=True)
        tail = r._tail_message() if r.end != r.file_size else None
        problems = [p for p in rep["problems"] if p != tail]
        if r.tail_snapshot is not None:
            found.append(Finding("FOOTER_MISSING", tail))
        elif tail:
            found.append(Finding("INTERRUPTED_WRITE", f"{r.file_size - r.end:,} bytes"))
        par_f = _parity_findings(pc, damage_seen=bool(problems))
        found += par_f
        if any(f.rule == "DAMAGE_REPAIRABLE" for f in par_f):
            # repair rebuilds the bytes first; whatever is left is classified on the next pass
            return found
        lost = [n for n, s in enumerate(r.snapshots, 1) if s.damaged]
        for n in lost:
            found.append(Finding("SNAPSHOT_LIST_LOST", f"snapshot {n}: {r.snapshots[n - 1].damaged}",
                                 {"snapshot": n}))
        rest = []
        for p in problems:
            if "file list is lost" in p:
                continue
            if "damaged snapshot footer" in p:
                found.append(Finding("OLD_FOOTER_DAMAGED", p))
            elif "dedup index" in p:
                found.append(Finding("INDEX_WRONG", p))
            else:
                rest.append(p)
        if rest:
            n_files = sum(map(len, rep["damaged_files"].values()))
            data = {"problems": rest[:50], "damaged_files": n_files, "bad_packs": len(rep["bad_packs"]),
                    "intact_snapshots": [i for i in range(1, len(r.snapshots) + 1)
                                         if i not in rep["damaged_files"] and not r.snapshots[i - 1].damaged]}
            detail = f"{len(rest)} problem(s), {n_files} item(s) affected; first: {rest[0]}"
            if pc is None:
                found.append(Finding("DAMAGE_NO_PARITY", detail, data))
            elif not any(f.rule == "DAMAGE_BEYOND_REPAIR" for f in found):
                found.append(Finding("DAMAGE_BEYOND_REPAIR", detail + " (the parity file does not cover this "
                                     "damage: it was built after it, or belongs to another store)", data))
            else:
                next(f for f in found if f.rule == "DAMAGE_BEYOND_REPAIR").data.update(data)
        snaps = [s for s in r.snapshots if not s.damaged]
        if max_age_days and snaps and snaps[-1].created:
            age = (time.time() - snaps[-1].created) / 86400
            if age > max_age_days:
                found.append(Finding("BACKUP_STALE", f"newest snapshot is {age:.1f} days old "
                                                     f"(limit {max_age_days:g})", {"age_days": round(age, 1)}))
        found += _skipped_findings(snaps)
    return found


def _skipped_findings(snaps) -> list[Finding]:
    by_label: dict[str, list] = {}
    for s in snaps:
        by_label.setdefault(s.label, []).append(s)
    out = []
    for label, ss in by_label.items():
        last = ss[-3:]
        if len(last) < 3:
            continue
        common = set(p for p, _ in last[0].skipped)
        for s in last[1:]:
            common &= {p for p, _ in s.skipped}
        if not common:
            continue
        reasons = {p: why for p, why in last[-1].skipped if p in common}
        hints = sorted({_skip_hint(why) for why in reasons.values()})
        out.append(Finding("SKIPPED_REPEATEDLY", f"{len(common)} item(s) of {label or '(no label)'} in each of "
                                                 f"the last 3 snapshots; " + "; ".join(hints),
                           {"examples": sorted(reasons.items())[:10]}))
    return out


def _skip_hint(why: str) -> str:
    w = why.lower()
    if "cloud" in w:
        return "cloud placeholders: --cloud-files, or 'Always keep on this device'"
    if "permission" in w or "denied" in w or "sharing" in w or "used by another" in w:
        return "locked or protected files: close the program or back up from a shadow copy (VSS)"
    if "long" in w or "not found" in w:
        return "path too long: enable LongPathsEnabled or back up a shorter parent"
    if "changing" in w or "changed" in w:
        return "files written during the backup: back up when the program is closed, or from VSS"
    return f"reason: {why}"


def _event_findings(path: str, events: list[dict]) -> list[Finding]:
    norm = os.path.normcase(os.path.abspath(path))
    mine = [e for e in events if e.get("store") and os.path.normcase(os.path.abspath(e["store"])) == norm]
    out = []
    week = time.time() - 7 * 86400
    errs = [e for e in mine if e.get("kind") == "error" and e.get("exit") not in (2, 3) and _t(e) > week]
    if len(errs) >= 3:
        msgs = sorted({(e.get("message") or "").splitlines()[-1][:200] for e in errs if e.get("message")})
        out.append(Finding("REPEATED_FAILURES", f"{len(errs)} failed command(s) in 7 days: " + " | ".join(msgs[:3]),
                           {"exits": sorted({e.get('exit') for e in errs})}))
    acked = {e.get("signature") for e in events if e.get("kind") == "ack"}
    for sig, group in _crash_groups([e for e in mine if e.get("kind") == "crash"]).items():
        if sig not in acked:
            out.append(Finding("CRASH", f"{group['count']}x {group['error'][:200]} (signature {sig})",
                               {"signature": sig}))
    return out


# --------------------------------------------------------------------------
# fixing
# --------------------------------------------------------------------------
def _fix_parity_repair(path: str, password: str | None) -> list[str]:
    """Only the parity part of repair: writes nothing but shards whose rebuilt
    bytes hash to their recorded value. Needs no password, never truncates."""
    lock = hs._StoreLock(path)
    try:
        c = hs.Parity(path).check(fix=True)
    finally:
        lock.release()
    done = []
    if c["repaired_shards"]:
        done.append(f"rebuilt {c['repaired_shards']} damaged shard(s) from parity, each hash-checked")
    if c["unrepairable_groups"]:
        done.append(f"{len(c['unrepairable_groups'])} parity group(s) could not be rebuilt")
    return done or ["parity repair: nothing to rebuild"]


def _fix_repair(path: str, password: str | None) -> list[str]:
    """Full repair (footers, interrupted-write tail, stale parity). Planned only
    when no critical damage is open, so its tail cut can never remove bytes
    that parity might still have recovered."""
    hs.set_password(password)
    try:
        return hs.repair(path) or ["repair: nothing needed"]
    except hs.PasswordError:
        return ["footer / tail checks need the password (parity part done)"]


def _fix_parity(path: str, password: str | None) -> list[str]:
    lock = hs._StoreLock(path)
    try:
        hs.set_password(password)
        with hs.StoreReader(path, password=password) as r:
            if r.scan()["problems"]:
                return ["parity NOT built: the store does not verify"]
        info = hs.Parity(path).build()
        return [f"built parity: {info['bytes']:,} bytes covering {info['covered']:,}"]
    finally:
        lock.release()


def _fix_delete_leftovers(path: str, password: str | None) -> list[str]:
    done = []
    for p in leftovers(path):
        os.remove(p)
        done.append(f"deleted leftover {p}")
    return done


def _fix_prune_lost(path: str, password: str | None, snapshots: list[int]) -> list[str]:
    hs.set_password(password)
    st = hs.prune(path, remove=snapshots)
    return [f"removed snapshot(s) {snapshots} whose file list was lost "
            f"({st.bytes_before - st.bytes_after:,} bytes freed)"]


def plan(findings: list[Finding], approve: set[str]) -> list[tuple[str, list[Finding]]]:
    """Which fixers to run, in order, and for which findings."""
    want: dict[str, list[Finding]] = {}
    for f in findings:
        kind, _, fixer = f.fix.partition(":")
        if kind == "auto" or (kind == "approve" and (f.rule in approve or "ALL" in approve)):
            want.setdefault(fixer, []).append(f)
    if "parity" in want and any(SEVERITY[f.severity] >= 2 for f in findings):
        del want["parity"]      # only over a clean store; the next pass picks it up after repair
    if any(f.severity == "critical" for f in findings):
        want.pop("repair", None)        # never cut or rewrite around damage that is still open
        want.pop("prune_lost", None)
    if any(f.rule == "DAMAGE_BEYOND_REPAIR" for f in findings) and not approve & {"DAMAGE_BEYOND_REPAIR", "ALL"}:
        want.pop("parity_repair", None)  # likely a failing disk: copy it off first (TROUBLESHOOTING.md 1)
    if "parity_repair" in want:
        want.pop("repair", None)        # bytes first; footers etc. are re-checked on the next pass
    order = ["parity_repair", "repair", "delete_leftovers", "prune_lost", "parity"]
    return [(k, want[k]) for k in order if k in want]


def fix(path: str, password: str | None = None, approve: set[str] | None = None, dry_run: bool = False,
        copy_first: str | None = None, max_age_days: float | None = None, events: list[dict] | None = None,
        rounds: int = 3) -> dict:
    """Diagnose, apply the allowed fixers, diagnose again (up to `rounds`
    passes, so a repair can be followed by a parity build)."""
    approve = approve or set()
    path = os.path.abspath(path)
    before = diagnose(path, password, max_age_days, events)
    findings, done, ran, copied = before, [], set(), None
    for _ in range(rounds):
        steps = [(k, fs) for k, fs in plan(findings, approve) if k not in ran]
        if not steps or dry_run:
            if dry_run:
                done = [f"would run {k} for {', '.join(sorted({f.rule for f in fs}))}" for k, fs in steps]
            break
        if copy_first and copied is None:
            copied = _copy_first(path, copy_first)
            done.append(f"copied the store to {copied} before fixing")
        for k, fs in steps:
            ran.add(k)
            try:
                if k == "parity_repair":
                    done += _fix_parity_repair(path, password)
                elif k == "repair":
                    done += _fix_repair(path, password)
                elif k == "parity":
                    done += _fix_parity(path, password)
                elif k == "delete_leftovers":
                    done += _fix_delete_leftovers(path, password)
                elif k == "prune_lost":
                    done += _fix_prune_lost(path, password, sorted(f.data["snapshot"] for f in fs))
            except Exception as e:      # a fixer failing must not hide the other findings
                done.append(f"{k} FAILED: {type(e).__name__}: {e}")
        findings = diagnose(path, password, max_age_days, events)
    after = findings
    if not dry_run and done:
        hs.log_event({"kind": "doctor", "store": path, "before": [f.rule for f in before],
                      "after": [f.rule for f in after], "done": done})
    return {"store": path, "before": before, "done": done, "after": after}


def _copy_first(path: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(dest_dir, f"{os.path.basename(path)}.{stamp}")
    need = os.path.getsize(path) + (os.path.getsize(hs.Parity(path).path) if hs.Parity(path).exists() else 0)
    if shutil.disk_usage(dest_dir).free < need * 1.05:
        raise OSError(f"not enough space in {dest_dir} for a copy ({need:,} bytes)")
    shutil.copyfile(path, dest)
    if hs.Parity(path).exists():
        shutil.copyfile(hs.Parity(path).path, hs.Parity(dest).path)
    return dest


# --------------------------------------------------------------------------
# event log: crashes ("bugs") and failures
# --------------------------------------------------------------------------
def _t(e: dict) -> float:
    try:
        return time.mktime(time.strptime(e["time"], "%Y-%m-%dT%H:%M:%S"))
    except (KeyError, ValueError):
        return 0.0


def read_events(days: float | None = 30) -> list[dict]:
    p = hs.event_log_path()
    out = []
    for f in ((p + ".1", p) if p else ()):
        try:
            with open(f, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass      # a line cut by a crash or a concurrent writer
        except OSError:
            pass
    if days:
        since = time.time() - days * 86400
        out = [e for e in out if _t(e) >= since or e.get("kind") == "ack"]
    return out


def _crash_groups(events: list[dict]) -> dict[str, dict]:
    groups: dict[str, dict] = {}
    for e in events:
        if e.get("kind") != "crash":
            continue
        g = groups.setdefault(e.get("signature", "?"), {"count": 0, "first": e["time"], "cmds": set(),
                                                        "stores": set()})
        g["count"] += 1
        g["last"] = e["time"]
        g["cmds"].add(e.get("cmd"))
        if e.get("store"):
            g["stores"].add(e["store"])
        g["error"], g["traceback"], g["version"] = e.get("error", ""), e.get("traceback", ""), e.get("version")
    return groups


def bug_report(sig: str, events: list[dict], out: str) -> str:
    g = _crash_groups(events).get(sig)
    if not g:
        raise SystemExit(f"no crash with signature {sig} in the event log")
    import platform
    lines = [f"# hybridstore crash {sig}", "",
             f"* seen {g['count']} time(s), {g['first']} .. {g['last']}",
             f"* commands: {', '.join(sorted(map(str, g['cmds'])))}",
             f"* engine source version: {g['version']}",
             f"* Python {platform.python_version()}, {platform.platform()}"]
    for mod in ("numpy", "zstandard", "cryptography", "psutil"):
        try:
            lines.append(f"* {mod} {__import__(mod).__version__}")
        except Exception:
            lines.append(f"* {mod}: not installed")
    k = known_cause(g["error"] + "\n" + g["traceback"])
    if k:
        lines += ["", f"Known cause: {k[0]}. Fix: {k[1]}"]
    lines += ["", "## Error", "", "```", g["error"], "```", "", "## Traceback (last)", "", "```",
              g["traceback"].rstrip(), "```"]
    for st in sorted(g["stores"]):
        lines += ["", f"## Store {st} (read-only checks)", ""]
        try:
            lines += [f"* {f.rule}: {f.detail}" for f in diagnose(st)] or ["* no problems found"]
            lines += [f"* repair plan: {p}" for p in hs.repair(st, dry_run=True)]
        except Exception as e:
            lines.append(f"* could not check: {type(e).__name__}: {e}")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return out


# --------------------------------------------------------------------------
# run: a hybridstore command with automatic recovery from known transient errors
# --------------------------------------------------------------------------
_VALUE_OPTS = {"--password-file", "--level", "--workers", "--pack-mb", "--snapshot", "--m", "--depth",
               "--repack-below", "--new-password-file", "--keep-last", "--keep-daily", "--keep-weekly",
               "--keep-monthly"}


def _store_arg(args: list[str]) -> str | None:
    pos, skip = [], False
    for x in args:
        if skip:
            skip = False
        elif x in _VALUE_OPTS:
            skip = True
        elif x == "--remove":
            continue
        elif not x.startswith("-"):
            pos.append(x)
    if not pos:
        return None
    return pos[2] if pos[0] in ("pack", "backup") and len(pos) > 2 else (pos[1] if len(pos) > 1 else None)


def _password_from_args(args: list[str]) -> str | None:
    if "--password-file" in args:
        i = args.index("--password-file")
        with open(args[i + 1], encoding="utf-8") as fh:
            return fh.readline().rstrip("\r\n")
    return None


def run(args: list[str], retries: int = 3, wait: float = 30, echo: bool = True) -> int:
    store = _store_arg(args)
    cmd = [sys.executable, os.path.join(HERE, "hybridstore.py")] + args
    repaired = False
    for attempt in range(retries + 1):
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        err = []
        for line in p.stderr:
            err.append(line)
            if echo:
                sys.stderr.write(line)
        code = p.wait()
        text = "".join(err[-200:])
        if code in (0, 3):
            if code == 3 and echo:
                hints = sorted({_skip_hint(l) for l in err if l.startswith("  ")})[:4]
                for h in hints:
                    print(f"[doctor] skipped items: {h}", file=sys.stderr)
            return code
        action, why = None, ""
        if code == 4:
            action, why = "wait", "the store is locked by another backup"
        elif re.search(KNOWN[0][0], text):
            action, why = "wait", "a file was held by another program"
        elif store and not repaired and code == 1 and re.search(r"repair|footer|interrupted write", text):
            action, why = "repair", "the store needs a repair first"
        if action is None or attempt == retries:
            k = known_cause(text)
            if k and echo:
                print(f"[doctor] cause: {k[0]}. Fix: {k[1]}", file=sys.stderr)
            if "internal error" in text and echo:
                print("[doctor] this was a crash (a bug): `python doctor.py bugs` groups and reports it",
                      file=sys.stderr)
            hs.log_event({"kind": "recovery", "store": store, "cmd": args[:1], "exit": code,
                          "result": "gave up" if action else "not recoverable", "attempts": attempt + 1})
            return code
        if action == "wait":
            delay = wait * (2 ** attempt)
            if echo:
                print(f"[doctor] {why}; retry {attempt + 1}/{retries} in {delay:.0f} s", file=sys.stderr)
            time.sleep(delay)
        else:
            res = fix(store, password=_password_from_args(args))
            repaired = True
            if echo:
                for d in res["done"]:
                    print(f"[doctor] {d}", file=sys.stderr)
            if any(SEVERITY[f.severity] >= 2 for f in res["after"]):
                if echo:
                    print("[doctor] the store still has problems; not retrying:", file=sys.stderr)
                    print_findings(res["after"])
                return code
        hs.log_event({"kind": "recovery", "store": store, "cmd": args[:1], "exit": code, "action": action,
                      "why": why, "attempt": attempt + 1})
    return code


# --------------------------------------------------------------------------
# output, watch, schedule
# --------------------------------------------------------------------------
def print_findings(fs: list[Finding], out=None):
    out = out or sys.stdout
    planned = {k for k, _ in plan(fs, set())}
    for f in sorted(fs, key=lambda f: -SEVERITY[f.severity]):
        r = RULES[f.rule]
        kind, _, fixer = f.fix.partition(":")
        if kind == "auto":
            how = "fixed automatically by `fix`" if fixer in planned else \
                "automatic fix held back until the critical items are dealt with"
        else:
            how = f"fix with `fix --approve {f.rule}`" if kind == "approve" else "manual"
        print(f"  [{f.severity.upper():8}] {f.rule}: {r.title}", file=out)
        print(f"             {f.detail}", file=out)
        print(f"             -> {r.advice} ({how})", file=out)
        k = known_cause(f.detail) if f.rule in ("CRASH", "REPEATED_FAILURES") else None
        if k:
            print(f"             known cause: {k[0]}; {k[1]}", file=out)


def worst(fs: list[Finding]) -> int:
    return max((SEVERITY[f.severity] for f in fs), default=-1)


def _notify(title: str, text: str):
    if os.name != "nt":
        return
    ps = ("Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
          "$n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; "
          "$n.Visible = $true; $n.ShowBalloonTip(15000, $env:HCS_T, $env:HCS_M, 'Warning'); "
          "Start-Sleep -Seconds 16; $n.Dispose()")
    env = dict(os.environ, HCS_T=title[:60], HCS_M=text[:250])
    subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps], env=env,
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _password_file(p: str | None) -> str | None:
    if not p:
        return None
    with open(p, encoding="utf-8") as fh:
        return fh.readline().rstrip("\r\n")


def watch(config: str, notify: bool = False) -> int:
    with open(config, encoding="utf-8") as f:
        cfg = json.load(f)
    base = os.path.dirname(os.path.abspath(config))
    events = read_events(30)
    lines = [f"hybridstore doctor, {time.strftime('%Y-%m-%d %H:%M:%S')}"]
    status, attention, fixed = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "stores": []}, [], []
    for s in cfg.get("stores", []):
        res = fix(s["path"], password=_password_file(s.get("password_file")),
                  approve=set(s.get("approve", [])), copy_first=s.get("copy_first", cfg.get("copy_first")),
                  max_age_days=s.get("max_age_days", cfg.get("max_age_days", 7)), events=events)
        left = [f for f in res["after"] if f.severity != "info"]
        status["stores"].append({"path": res["store"], "fixed": res["done"],
                                 "open": [asdict(f) | {"severity": f.severity} for f in res["after"]]})
        lines.append(f"\n{res['store']}: " + ("OK" if not left else f"{len(left)} item(s) need attention"))
        for d in res["done"]:
            lines.append(f"  fixed: {d}")
            fixed.append(f"{os.path.basename(res['store'])}: {d}")
        import io
        buf = io.StringIO()
        print_findings(res["after"], buf)
        lines.append(buf.getvalue().rstrip())
        if left:
            attention.append(f"{os.path.basename(res['store'])}: {', '.join(sorted({f.rule for f in left}))}")
    acked = {e.get("signature") for e in events if e.get("kind") == "ack"}
    crashes = {k: g for k, g in _crash_groups(events).items() if k not in acked}
    if crashes:
        lines.append(f"\n{len(crashes)} crash signature(s) in 30 days (`doctor.py bugs`):")
        for k, g in crashes.items():
            lines.append(f"  {k}: {g['count']}x {g['error'][:150]}")
        attention.append(f"{len(crashes)} crash signature(s)")
    status["attention"], status["crashes"] = attention, sorted(crashes)
    report = os.path.join(base, cfg.get("report", "doctor-report.txt"))
    with open(report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(base, cfg.get("status", "doctor-status.json")), "w", encoding="utf-8") as f:
        json.dump(status, f, indent=1)
    print("\n".join(lines))
    if notify and (attention or fixed):
        _notify("Backup needs attention" if attention else "Backup problems fixed",
                "; ".join(attention or fixed) + f". Report: {report}")
    return 1 if attention else 0


def schedule(config: str, at: str, install: bool) -> int:
    py = sys.executable.replace("python.exe", "pythonw.exe") if os.name == "nt" else sys.executable
    if not os.path.exists(py):
        py = sys.executable
    tr = f'"{py}" "{os.path.join(HERE, "doctor.py")}" watch --config "{os.path.abspath(config)}" --notify'
    cmd = ["schtasks", "/Create", "/SC", "DAILY", "/ST", at, "/TN", "hybridstore doctor", "/TR", tr, "/F"]
    print(" ".join(f'"{c}"' if " " in c else c for c in cmd))
    if not install:
        print("(not installed: add --install to register it)")
        return 0
    return subprocess.call(cmd)


def main(argv) -> int:
    ap = argparse.ArgumentParser(prog="doctor", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "fix"):
        p = sub.add_parser(name)
        p.add_argument("stores", nargs="+")
        p.add_argument("--password-file", default=None)
        p.add_argument("--max-age-days", type=float, default=None)
        p.add_argument("--json", action="store_true")
        if name == "fix":
            p.add_argument("--dry-run", action="store_true")
            p.add_argument("--approve", nargs="+", default=[], metavar="RULE",
                           help="also run fixers that remove data for these rules (ALL = every rule)")
            p.add_argument("--copy-first", default=None, metavar="DIR",
                           help="copy the store and its parity here before changing anything")
    p = sub.add_parser("watch")
    p.add_argument("--config", required=True)
    p.add_argument("--notify", action="store_true", help="Windows notification when something was fixed or "
                                                         "needs attention")
    p = sub.add_parser("run")
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--wait", type=float, default=30, help="first retry delay in seconds (doubles each time)")
    p = sub.add_parser("bugs")
    p.add_argument("--days", type=float, default=30)
    p.add_argument("--all", action="store_true", help="include acknowledged signatures")
    p.add_argument("--report", metavar="SIGNATURE")
    p.add_argument("--out", default=None)
    p.add_argument("--ack", metavar="SIGNATURE", help="mark a crash as dealt with (watch stops reporting it)")
    sub.add_parser("rules")
    p = sub.add_parser("schedule")
    p.add_argument("--config", required=True)
    p.add_argument("--time", default="03:17")
    p.add_argument("--install", action="store_true")
    if argv and argv[0] == "run":
        if "--" not in argv:
            print("usage: doctor.py run [--retries N] [--wait S] -- <hybridstore arguments>", file=sys.stderr)
            return 2
        i = argv.index("--")
        a = ap.parse_args(argv[:i])
        return run(argv[i + 1:], a.retries, a.wait)
    a = ap.parse_args(argv)
    if a.cmd == "rules":
        for k, r in RULES.items():
            print(f"{k:20} {r.severity:8} {r.fix:26} {r.title}")
        return 0
    if a.cmd == "watch":
        return watch(a.config, a.notify)
    if a.cmd == "schedule":
        return schedule(a.config, a.time, a.install)
    if a.cmd == "bugs":
        if a.ack:
            hs.log_event({"kind": "ack", "signature": a.ack})
            print(f"acknowledged {a.ack}")
            return 0
        events = read_events(None if a.all else a.days)
        if a.report:
            out = bug_report(a.report, events, a.out or f"bug-{a.report}.md")
            print(f"bug report written: {out}")
            return 0
        acked = set() if a.all else {e.get("signature") for e in events if e.get("kind") == "ack"}
        groups = {k: g for k, g in _crash_groups(events).items() if k not in acked}
        errs = [e for e in events if e.get("kind") == "error"]
        print(f"event log: {hs.event_log_path()}")
        print(f"{len(groups)} crash signature(s), {len(errs)} failed command(s) in the period")
        for k, g in sorted(groups.items(), key=lambda kv: kv[1]["last"], reverse=True):
            print(f"\n{k}  {g['count']}x  {g['first']} .. {g['last']}  ({', '.join(sorted(map(str, g['cmds'])))})")
            print(f"  {g['error'][:300]}")
            kc = known_cause(g["error"] + g["traceback"])
            print(f"  known cause: {kc[0]}; {kc[1]}" if kc else
                  f"  unknown cause: `doctor.py bugs --report {k}` writes a report to attach to an issue")
        by_exit: dict = {}
        for e in errs:
            by_exit.setdefault(e.get("exit"), []).append(e)
        for code, es in sorted(by_exit.items(), key=lambda kv: str(kv[0])):
            last = es[-1]
            msg = (last.get("message") or "").splitlines()
            print(f"\nexit {code}: {len(es)}x, last {last['time']} ({last.get('cmd')} {last.get('store') or ''})")
            if msg:
                print(f"  {msg[-1][:300]}")
        return 1 if groups else 0
    password = _password_file(a.password_file)
    events = read_events(30)
    rc = 0
    results = []
    for st in a.stores:
        if a.cmd == "check":
            res = {"store": os.path.abspath(st), "before": [], "done": [],
                   "after": diagnose(st, password, a.max_age_days, events)}
        else:
            res = fix(st, password, set(a.approve), a.dry_run, a.copy_first, a.max_age_days, events)
        results.append(res)
        if worst([f for f in res["after"] if f.severity != "info"]) >= 1:
            rc = 1
    if a.json:
        print(json.dumps([{"store": r["store"], "done": r["done"],
                           "findings": [asdict(f) | {"severity": f.severity} for f in r["after"]]}
                          for r in results], indent=1))
        return rc
    for r in results:
        print(r["store"])
        for d in r["done"]:
            print(f"  {'plan' if a.cmd == 'fix' and a.dry_run else 'fixed'}: {d}")
        if r["after"]:
            print_findings(r["after"])
        else:
            print("  healthy: verified, parity complete, nothing to do")
    return rc


if __name__ == "__main__":
    with hs.terminal_safe_output():      # store text must not drive the terminal
        code = main(sys.argv[1:])
    sys.exit(code)
