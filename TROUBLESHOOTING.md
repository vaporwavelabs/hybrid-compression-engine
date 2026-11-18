# Troubleshooting

**Start with `python doctor.py check <store>`** (or `fix`): it runs the checks below, applies the fixes marked safe here automatically, and prints the rule and next step for the rest. `python doctor.py bugs` lists crashes and repeated failures from the event log, with known causes.

Each entry gives the symptom, what it means, and what to do, safest step first. One rule covers all of them: **before any `repair`, `prune` or `--force`, copy the store and its `.hcp` sidecar somewhere else.** Repairs here never write a byte that does not hash to its recorded value, but a copy costs minutes and protects against the cause you have not found yet: a failing disk, bad RAM, a full volume.

## 1. `verify` reports damage (exit 1)

| What `verify` says | What it means | What to do |
|---|---|---|
| damaged shards, all repairable | bit rot, a bad sector, or a short burst | `repair --dry-run` to see the plan, then `repair`, then `verify` again |
| some groups "beyond repair" | more damage in one parity group than `--m` covers: a large burst (over 2 MiB per 16 MiB at m=2), or the disk is failing | stop writing to that disk. Copy the store off it (`robocopy /J`, or `ddrescue` for a failing disk). Run `repair` on the copy: it fixes every group it can and leaves the rest as they were. `verify` then lists the files that are still affected and which snapshots are fully intact. Restore those from another copy (see section 7) |
| CRC errors but no parity file | the store has no sidecar | restore the damaged packs from another copy. For the future run `parity <store>` (after a clean `verify`) |
| "… or the parity does not match the store", or parity covers fewer bytes than the store | the sidecar is older than the store (a backup that did not finish its parity step, or a store copied without its `.hcp`) | if the store verifies, `parity <store>` rebuilds it. If the store does not verify, do **not** rebuild parity: that would bake the damage in. Look for a matching `.hcp` first |
| damage keeps coming back after `repair`, or in different places each run | the disk, cable, controller or RAM is corrupting data as it is read or written | check the disk (section 6) and RAM (Windows Memory Diagnostic or MemTest86) before trusting any repair |

`backup` runs the same check before it writes (README, "Checks before and after every backup"):

| What `backup` says | What it means | What to do |
|---|---|---|
| "warning: checked before writing: REBUILT n damaged shard(s)", exit 3 | the store had damage parity could prove and rebuild; the backup then went ahead | nothing for the store. Damage that appears on its own is the disk's doing: run section 6 checks, and watch whether it happens again |
| "the check before writing found damage … Nothing was written", exit 1 | damage parity cannot rebuild, or (no parity) a pack fails its CRC. A new snapshot would reuse that data, so it was refused | `python doctor.py fix <store>` for the plan; copy the store off the disk first if it may be failing. `--no-precheck` writes anyway, but the new snapshot may then depend on the damage |
| "read-back check failed … NOT published", exit 1 | what was read back from the disk differs from what was written. The store is exactly as before | run the backup again. If it fails again, suspect RAM, the cable / USB enclosure or the disk (section 6) |

Why repair is safe to try: every shard's BLAKE2b is stored in the sidecar, so a rebuilt shard is written only if it hashes to the value recorded when the store was good. A stale or wrong sidecar can refuse to repair; it cannot "repair" the store into something else. Other tools learned this the hard way: `borg check --repair` and `restic repair` warn that repair can remove data that is merely unreadable now, which is why they ask for a backup copy first [1][2]. Here `repair` changes nothing it cannot prove, and `--dry-run` shows what it would do.

## 2. Wrong password, lost password, encrypted stores

| Symptom | Cause | Fix |
|---|---|---|
| exit 5, "this store is encrypted: give its password" | no password was given | `--password-file F`, or set `HYBRIDSTORE_PASSWORD`, or run in a terminal and type it |
| exit 5, "wrong password" | the key block opened with the CRC intact but the password does not unwrap the key | try older passwords (`passwd` changes only the key block; an old copy of the store still uses the old password). There is no recovery without the password: that is the point of encryption |
| "key block is damaged" | the bytes of the key block changed | `repair`: parity covers the key block and needs no password |
| "encrypted block … failed authentication" while its CRC is fine | the ciphertext matches what was written, but decryption fails: a block written with a different key, or memory corruption while reading | run it again. If it moves around between runs, test the RAM. If it is always the same block, `verify` lists the affected files |
| semantic `index` refuses the store | the `.sem` index would hold readable text from an encrypted store | `--allow-plaintext-index` if the `.sem` file is kept as safe as the password, otherwise do not index |

Keep the password file out of the folder being backed up, and never in the same place as the only copy of the store. Losing the password loses the data; this cannot be repaired.

Crypto choices and their limits: ChaCha20-Poly1305 [3] with random 96-bit nonces is safe for about 2^32 messages per key [4]; the store stops at 2^30 sealed blocks (far beyond any real store at 1 MiB per pack). scrypt N=2^17, r=8, p=1 is OWASP's minimum [5]; a key block that asks for more than N=2^20, r=16, p=4 is refused, so a hostile file cannot make the reader allocate gigabytes [6].

## 3. Files skipped (exit 3)

`backup`/`pack` list skipped files on stderr, and the snapshot's manifest records them (`list --skipped`).

| Reason shown | Cause | Fix |
|---|---|---|
| permission denied / sharing violation | the file is open exclusively by another program (Outlook PST, browser profiles, databases, VM disks), or ACLs deny read | close the program, or back up from a Volume Shadow Copy (below) |
| file kept changing while read | something wrote to it during the backup; it was stored but may be a mixed copy | the next backup reads it again. For databases, use the program's own export or a VSS snapshot |
| cloud placeholder, not downloaded | OneDrive "files on demand": the file has the `RECALL_ON_DATA_ACCESS` / `OFFLINE` attributes [7], and reading it would download it | `--cloud-files` to include them (downloads everything: check the disk space and the time first), or mark the folder "Always keep on this device" in OneDrive |
| path not found / name too long | a path over 260 characters with Windows long paths off [8] | enable long paths (`LongPathsEnabled`, Group Policy or registry; needs admin), or back up a shorter parent folder |

### Links and junctions

Symlinks and junctions are stored as links (their target path), not followed, the way `tar` and `robocopy /SL` do it. So a junction to another `node_modules` is not backed up twice, but **the files behind a junction are only in the backup if their real folder is also inside the source** (a junction pointing to another drive, e.g. `G:\FORGED\…`, keeps only the link: back up that folder too). On restore:

| Restore target | Result |
|---|---|
| NTFS | junctions come back as junctions to the same absolute target; no privilege needed |
| NTFS with Developer Mode or as admin | symlinks are created too |
| NTFS, no Developer Mode, not admin | junctions are fine; a symlink gives "symlink … not created (A required privilege is not held)", exit 3: turn on Developer Mode, or run as admin |
| exFAT / FAT32 (most USB disks and SD cards) | "symlink … not created (Incorrect function)", exit 3: these filesystems have no links. Restore to an NTFS drive if the links matter; every regular file is restored either way |

When you compare a restore with the source yourself, do not follow junctions (`os.walk` and Python's `tarfile` do follow them on Windows); `real_run.py` shows how.

**Backing up locked files with a shadow copy** (admin PowerShell; Windows Home has no `vssadmin create`):

```powershell
$s = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
$dev = (Get-WmiObject Win32_ShadowCopy | Where-Object ID -eq $s.ShadowID).DeviceObject
cmd /c mklink /d C:\shadow "$dev\"
python hybridstore.py backup C:\shadow\Users\you\Documents D:\backup\docs.hcs
cmd /c rmdir C:\shadow
(Get-WmiObject Win32_ShadowCopy | Where-Object ID -eq $s.ShadowID).Delete()
```

VSS gives a frozen, crash-consistent view of the whole volume, so open files are read as they were at that moment [9].

## 4. Slow runs

Run any command under the monitor to see where the time goes:

```
python monitor.py --csv run.csv -- python hybridstore.py backup <dir> <store>
```

| What the monitor shows | Likely cause | Fix |
|---|---|---|
| low MB/s and under 1 CPU core | many small files: Windows file open/close dominates, and Defender scans each file as it is read or written | add the store folder (and, for restores, the target folder) to Defender's exclusions [10]: only for folders you trust. Keep the source folder scanned |
| all cores busy, low MB/s | zstd level 19 on compressible data is CPU-bound | `--level 9` is several times faster for a few % more size; `--workers N` if not all cores are used |
| high MB/s read, low out, then a long pause | the parity step at the end of `pack` (reads the whole store) | expected; it scales with the store size (see the real-data run in the README) |
| restore of many small files to a USB HDD at under 100 files/s | each new file costs a directory update on a slow disk (exFAT external HDD: 78 files/s in the real run, 54k files in 11 min) | restore to an internal SSD, or only the folder needed (`unpack` into a fresh folder, then copy); the store reads at 240 MB/s, so the disk is the limit |
| restore slow with `--fsync` | each file is flushed to disk; very expensive on Windows | leave `--fsync` off unless a power cut during the restore would matter |
| a cloud folder takes hours | OneDrive placeholders are being downloaded (`--cloud-files`) | leave `--cloud-files` off, or let OneDrive download the folder first |
| RAM keeps growing | very many files in one snapshot (the manifest is built in memory) | split the source into several stores |

## 5. Crashes, power cuts, full disks

* **During `backup`:** the store is appended to; a snapshot counts only once its footer is written. After a crash, `verify` shows the earlier snapshots intact. If the newest snapshot's footer is missing, `backup` refuses until `repair` writes it again (the data was already on disk). Trailing bytes with no snapshot are cut off by `repair`.
* **During `pack --force` or `prune`:** a new store is written to `<store>.hcs-new` and renamed over the old one only when complete. A leftover `.hcs-new` after a crash can be deleted; the original store is untouched.
* **"Another backup is writing" (exit 4):** the lock is an operating-system lock that is released when its process ends, so a crash never leaves it behind. Exit 4 means a process really holds it: the message names its PID and host. Wait for it, or end that process (Task Manager), then run again.
* **Disk full:** the write fails, the snapshot is not committed, earlier snapshots are fine. Free space (`prune` old snapshots, which needs room for the new copy) and run `backup` again.
* **A `.hcs-new` file left next to a store:** a `pack --force` or `prune` that did not finish. If the message said "the new store is complete at …hcs-new", the rename failed (often antivirus or a sync client holding the file): `verify` the `.hcs-new` and rename it yourself if you want it.

## 6. The disk itself

Parity repairs damage; it does not stop a failing disk. Signs: new damage on every `verify`, "beyond repair" groups growing, slow reads, Windows "disk" event log errors.

* Read SMART: `smartctl -a /dev/sdX` (smartmontools [11]) or CrystalDiskInfo. Rising *Reallocated*, *Pending* or *Uncorrectable* sector counts mean: copy everything off now.
* Run `verify` on a schedule (monthly). Bit rot on a disk that is never read is found only when the file is needed.
* Copy a store with its `.hcp`: the sidecar is useless without the store, and the store loses its repairability without the sidecar.

## 7. Parity is not a backup

The sidecar sits on the same disk as the store. It covers bit rot and bad sectors, not a dead disk, theft, ransomware, or deleting the folder. Keep **3 copies, on 2 different media, 1 off site** [12]: for example, the store on the PC, a copy on a USB disk, and a copy in the cloud (encrypted with `--encrypt` before it leaves the machine). For a store that matters, `parity --m 4` doubles the burst it can rebuild for 12.5% more space.

## 8. Before reporting a bug

1. `verify <store>` output (full).
2. `repair --dry-run <store>` output.
3. The command that failed, its exit code, and the monitor CSV if it was slow.
4. Python version, OS, and whether the disk is local, USB, network or cloud-synced.

## 9. `unpack` refused or skipped something

| Message | Cause | Fix |
|---|---|---|
| "the newest snapshot (#N) is complete but its footer is damaged … Nothing was restored", exit 1 | one damaged footer hides the newest snapshot; restoring "newest" would quietly give you the one before it | `python hybridstore.py repair <store>` brings it back. To restore the older one anyway: `unpack … --snapshot N-1` |
| "… need N bytes but only M are free … nothing was restored", exit 2 | the snapshot's files do not fit on the output disk (a restore needs room for the new files before old ones are replaced) | free space, or restore to another disk |
| "unsafe file list: … lies inside the symlink …" / "… appears twice …", exit 1 | the file list could not have come from a backup: a damaged or crafted store. `verify` reports the same | do not restore it. If it is your own store, `doctor.py fix <store>` and `verify`; restore another snapshot with `--snapshot` |
| "unsafe path: … would be written outside …", exit 1 | the output folder already holds a link or junction (at that path) that leads elsewhere | restore into an empty folder, or remove that link first |
| "… not restored (… reserved device name on Windows)", "(… ends with a dot or space …)", "(… ignores case in names …)", exit 3 | the store was made on Linux or macOS with names Windows cannot hold (`aux.c`, `CON`, `name.`, `A.txt` beside `a.txt`) | everything else was restored. Restore those files on a Linux machine, or rename them there and back up again |
| "the data runs past its recorded size" / "more chunks … than bytes", exit 1 | the file list is damaged or crafted; reading stopped before writing anything | as for damage: `verify`, then `repair` if there is parity |

## Sources

1. BorgBackup, `borg check --repair` warnings: https://borgbackup.readthedocs.io/en/stable/usage/check.html
2. restic, troubleshooting a damaged repository: https://restic.readthedocs.io/en/stable/077_troubleshooting.html
3. RFC 8439, ChaCha20 and Poly1305: https://www.rfc-editor.org/rfc/rfc8439
4. NIST SP 800-38D, section 8.3 (limit on random 96-bit IVs per key): https://csrc.nist.gov/pubs/sp/800/38/d/final
5. OWASP Password Storage Cheat Sheet (scrypt parameters): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
6. RFC 7914, the scrypt KDF: https://www.rfc-editor.org/rfc/rfc7914
7. Microsoft, file attribute constants (`FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`, `OFFLINE`): https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
8. Microsoft, maximum path length limitation: https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
9. Microsoft, Volume Shadow Copy Service: https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service
10. Microsoft, Defender Antivirus exclusions: https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus
11. smartmontools: https://www.smartmontools.org/
12. Backblaze, the 3-2-1 backup strategy: https://www.backblaze.com/blog/the-3-2-1-backup-strategy/
13. Parchive (PAR2), Reed-Solomon recovery files, the same idea as the `.hcp` sidecar: https://parchive.github.io/
