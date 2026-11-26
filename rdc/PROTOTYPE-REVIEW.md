# How the Komp2 prototype ideas compare to our RDC Archiver

The review's author says they only saw our window's code, not rdc4.py. So I checked each claim against
the real rdc4.py (v3.1.6) and against the window, and tested each change on Ubuntu 24.04 with Python 3.12.

**Short answer:** about half of the ideas were real improvements, and those are now built in. A few of the
claimed bugs don't happen with our rdc4.py. The rest would need changes to rdc4.py itself, or would make a
simple tool more complicated without much benefit. rdc4.py and rdc3.py are still unchanged.

## Prototype 1: "Hardened core"

| Suggestion | Real in our build? | What I did |
|---|---|---|
| A picked-files list stays attached after you switch to a different archive | **Yes, a real bug.** If you picked some files to unpack and then chose another archive, the old pick still applied. | **Fixed.** Changing the archive now resets the pick. |
| Verify sends a damaged archive to Repair but leaves "Save fixed copy as" blank | **Yes.** | **Fixed.** The fixed-copy name is now filled in too. It won't replace a name you typed yourself. |
| Dropped network-share links (file://server/share/…) lose the server name | **Yes, but rare.** File managers usually drop plain paths, not links. | **Fixed** anyway, since it was cheap. |
| "Saving inside the folder you're packing" check misses mixed-case paths on Windows | **Yes, Windows only.** | **Fixed.** |
| Blurry text on high-resolution Windows screens | **Yes, Windows only.** | **Fixed.** The window now tells Windows it handles scaling itself. |
| The settings file could be cut short if the PC crashes mid-save | **Technically yes.** It only stores the last folder you used. | **Fixed.** It now writes a temporary copy and swaps it in. |
| Cancel may leave rdc4's helper processes running | **No.** rdc4.py uses threads, not separate processes, so stopping it stops everything. | No change needed. |
| The result could be confused by progress lines in rdc4's output | **No.** rdc4.py prints exactly one result line when it finishes. | No change needed. |
| The password is sent to commands that don't need it | **Partly.** It is only sent when you've typed one. Before trying, there's no way to know whether an archive is encrypted. | Added a **Clear** button for the password. |
| Raw JSON output clutters the log | **Yes,** for a non-technical user. | Raw output is now hidden behind a **Technical details** checkbox. |
| Split the code into separate files for automated testing | Not useful for a single-person tool. One file is easier for you to copy. | Not done. I test it headlessly anyway. |

## Prototype 2: "Live output and explorer"

| Suggestion | Worth it? | What I did |
|---|---|---|
| Search, sort and "Extract selected" in What's inside | **Yes,** this is the most useful idea in the review. | **Built.** Type to search, click File or Size to sort, select files or folders, then press **Extract selected…** |
| Live output while a job runs, and a real % progress bar | **Not with our rdc4.py.** It prints nothing until it finishes, so there's nothing to show. A % bar would mean changing rdc4.py. | Not done. The moving bar and seconds counter stay. |
| An "Advanced options" box where you type command-line flags | Brings back the typing the window was meant to remove. | Not done. |

## Prototype 3: "Batch workbench"

| Suggestion | Worth it? | What I did |
|---|---|---|
| Check many archives in one go | **Yes,** handy for checking a whole backup folder. | **Built.** The Verify tab now holds a list: add, drop or remove archives, press Verify, and get a summary such as "3 archives: 2 healthy, 1 needs repair". Cancel stops the rest. |
| Save a report of a run | **Yes,** a simple version. | **Built** as **Save log…** (a text file). |
| "Repair, then re-verify" in one click | **Already happens.** rdc4's repair re-checks the fixed copy itself, and the window reports that result. | No change needed. |
| A general job queue for every kind of task | More complicated than it's worth. Pack and unpack jobs compete for the same disk, so running them in sequence by hand is fine. | Not done beyond the Verify list. |
| Pass the password through a pipe instead of the environment (`--password-stdin`) | **Doesn't exist in rdc4.py v3.1.6.** Only programs running as your own user could read the environment anyway. | Not done. It would mean changing rdc4.py, so it's your call. |

## Tested

All the earlier checks still pass: pack, encrypted pack, unpack, unpack-some, verify, deliberate damage
and repair, wrong password, cancel, and drag and drop with and without the extra package. New checks
cover:

- batch verify with a healthy archive, a damaged archive and a non-archive in the same run
- cancelling a batch partway
- the reset of the picked files when the archive changes
- the fixed-copy name being filled in
- search, sort and Extract selected through to a real unpack
- the technical-details toggle and Save log
- network-share links and mixed-case paths
- the crash-safe settings save
