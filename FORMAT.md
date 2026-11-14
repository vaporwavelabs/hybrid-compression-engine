# Hybrid store file format (`.hcs`)

This document specifies the on-disk format written by `hybridstore.py`. A reader
built only from this document must be able to restore every file bit-exact.
All integers are little-endian. Offsets are absolute byte offsets in the file.

## 1. File layout

```
offset 0   "HCSTORE1"                                   8 bytes, store magic
           [dictionary block]                           optional, only directly after the magic
           snapshot 1: pack blocks... | manifest block | footer
           snapshot 2: pack blocks... | manifest block | footer
           ...
```

* Snapshots are only ever **appended**. Nothing before the last footer is rewritten.
* Every byte between the magic and the last footer belongs to exactly one
  block or footer, in the order shown. `verify` checks this (no gaps, no overlaps).
* The newest footer is the last 16 bytes of the file.

### Footer (16 bytes)

| field | type | meaning |
|---|---|---|
| manifest_offset | u64 | offset of this snapshot's manifest block |
| magic | 8 bytes | `HCSTORE1` |

Superseded footers stay in place. Each one must still point at its own
manifest, and `verify` checks that too.

### Crash recovery

A writer fsyncs all packs and the manifest, then writes and fsyncs the footer.
If the last 16 bytes are not a valid footer, an append was interrupted. A
reader then scans backwards for the newest `HCSTORE1` that ends a footer whose
manifest decodes and whose manifest block ends exactly where that footer starts.
Bytes after that point are **trailing bytes**:

* Readers ignore them and print a warning.
* The next `backup` truncates them.
* `verify` fails (exit 1) while they exist, because newer snapshots may have
  been lost. `--allow-partial` checks everything else.

Limitation: if a store is cut exactly at an older footer boundary, it looks
exactly like a valid store with fewer snapshots. Detecting that needs an
outside record of the expected snapshot count.

## 2. Blocks

Every pack, manifest and dictionary is stored as one block:

```
header (16 bytes): magic "HCB" (3) | flags u8 | orig_len u32 | stored_len u32 | crc32 u32
payload:           stored_len bytes
```

* `crc32` is the zlib CRC-32 of the **decoded** bytes, so it also checks the codec.
* `flags & 0x07` is the codec:
  * 0 = raw
  * 1 = zlib (RFC 1950)
  * 2 = zstd frame
  * 3 = neural (reserved, never written)
* Other flag bits:

| bit | name | meaning |
|---|---|---|
| 0x08 | MEDIA | payload is media / already-compressed data |
| 0x10 | MANIFEST | block is a snapshot manifest |
| 0x20 | DICT | block is the zstd dictionary (must be the first block) |
| 0x40 | USES_DICT | zstd payload was compressed with the dictionary |

* **Decoding limit.** A reader must reject a block whose `orig_len` exceeds
  `max(256 MiB, 256 × stored_len)`. A reader must never produce more than
  `orig_len` bytes: zlib output is capped at `orig_len`, and any further data
  in the stream is an error. Real blocks are around 1 MiB (packs) and at most
  64 MiB (whole media objects).

## 3. Packs

A pack's decoded payload is:

```
u32 count | count × u32 chunk_length | chunk bytes concatenated
```

* The lengths must add up to exactly the end of the payload.
* A **chunk pointer** is a u64: `(pack_id << 20) | index_in_pack`.
* Pack ids are global and dense: snapshot *k*'s first pack id equals the total
  number of packs in snapshots 1..k-1.
* A pack holds either only MEDIA chunks or only non-media chunks.

## 4. Manifests

### v3 (`HCM3`, written by the current version)

```
"HCM3"
u64 prev_manifest_offset        0 for the first snapshot
u64 created                     unix seconds
u16 label_len | label           utf-8 (source directory)
u32 first_pack_id | u32 n_packs | n_packs × u64 pack_offset
u32 n_index | n_index × 32-byte sha256 | n_index × u64 pointer
u32 n_entries | entries...
u32 n_skipped | skipped...
```

**Entry:**

```
u16 path_len | path             utf-8, '/' separated, relative
u8  kind                        0 file, 1 directory, 2 symlink, 3 directory symlink
u64 size                        content length
32  sha256                      of the content
i64 mtime_ns                    -1 = not recorded
u32 st_mode                     0 = not recorded
u32 win_attrs                   Windows file attributes, 0 = not recorded
u32 n | n × u64 chunk pointer   content = chunks concatenated
```

* **Content by kind:**
  * A directory has no content (size 0, sha256 of the empty string, no pointers).
  * A symlink's content is its target path in utf-8, with `surrogateescape`
    used for non-UTF-8 bytes on POSIX.
* **Order:** entries are in walk order, with each directory before the things
  inside it.
* **Skipped** (items that could not be read during this backup and are not in
  the snapshot):

  ```
  u16 path_len | path | u16 reason_len | reason (utf-8)
  ```

* **Index:** the index lists the chunks this snapshot added, as SHA-256 → pointer.
  * Every index pointer must refer to a pack of this same snapshot, and
    `verify` checks that each one hashes to its digest.
  * Writers load the union of all snapshot indexes to deduplicate. Packs are
    never rewritten.

### v2 (`HCM2`)

Same as v3, with two differences:

* Each entry is only `u16 path_len | path | u64 size | 32 sha256 | u32 n | pointers`,
  and every entry is a regular file.
* There is no skipped list.

### v1 (no magic, single-snapshot stores from the first prototype)

```
u32 n_packs | n_packs × u64 pack_offset | u32 n_entries | v2-style entries
```

* There is no index. A writer appending to a v1 store rebuilds it by hashing
  every chunk once.

Readers must accept all three versions in one chain, since v2 and v3
snapshots can be appended to older stores. Versions before v3 cannot read v3
manifests.

## 5. Restoring a snapshot

1. **Paths:** split each path on `/` or `\`. Reject the path if any part is
   empty, `.`, or `..`, or (on Windows) contains `:`. Each resolved
   destination must stay inside the output directory.
2. **Files:**
   * Concatenate the chunks.
   * The result must match `size` and `sha256`; otherwise fail.
   * Write to a temporary name, then rename over the destination.
3. **Metadata for each file:** set the mtime first, then the mode bits or
   Windows attributes. Read-only is applied last, so it can't block the mtime.
4. **Symlinks** are created after all files, so no file is ever written
   through a restored link.
5. **Directory metadata** is applied last, deepest first, so writing a
   directory's contents doesn't change its mtime afterwards.

## 6. Concurrency

* A writer holds an exclusive OS lock on `<store>.lock` (on Windows,
  `LockFile` on byte 1 MiB; on POSIX, `flock`) for the whole run. The lock
  file's first line names the holder.
* A second writer fails at once instead of overwriting the first one's snapshot.
* The OS releases the lock if the process dies.
* `pack`, which creates a new store or overwrites an existing one, writes to
  `<store>.hcs-new` and renames it over the old store only after the footer is
  durable.
* Readers take no lock. They see the newest complete snapshot.
