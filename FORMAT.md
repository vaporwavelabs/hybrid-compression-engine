# Hybrid store file format (`.hcs`)

This document specifies the on-disk format written by `hybridstore.py`. A reader
built only from this document must be able to restore every file bit-exact.
All integers are little-endian. Offsets are absolute byte offsets in the file.

## 1. File layout

```
offset 0   "HCSTORE1"                                   8 bytes, store magic
           [key block]                                  encrypted stores only, directly after the magic
           [dictionary block]                           optional, directly after the magic / key block
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
* If they hold a **complete snapshot** whose footer is missing or damaged
  (walking the block headers from the end of the last complete snapshot
  reaches a manifest that decodes, links to that snapshot, lists exactly the
  packs before it, and is followed by at most 16 bytes), a writer must not
  remove them. `backup` refuses; `repair` writes the footer again.
* Otherwise (an interrupted write: packs without a manifest) the next
  `backup` or `repair` truncates them.
* `verify` fails (exit 1) while they exist, because newer snapshots may have
  been lost. `--allow-partial` checks everything else.

### Damaged manifests

If following the manifests' `prev` links fails (a manifest does not decode),
a reader can still rebuild the snapshot list, because every byte belongs to
a block or footer in a fixed order: walk the block headers from the start
(after the key block and dictionary), collecting packs until a MANIFEST block; the 16 bytes
after a manifest are its footer. A manifest that decodes must list exactly
the packs collected since the previous one. One that does not decode marks a
**damaged snapshot**: its packs are known, its file list is lost. Other
snapshots read normally. A damaged snapshot cannot be kept by `prune`;
removing it rebuilds a clean store. This needs block headers to be intact.

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
  * 7 = key block (flags byte exactly 7; see section 8)
* Other flag bits:

| bit | name | meaning |
|---|---|---|
| 0x08 | MEDIA | payload is media / already-compressed data |
| 0x10 | MANIFEST | block is a snapshot manifest |
| 0x20 | DICT | block is the zstd dictionary (must be the first block) |
| 0x40 | USES_DICT | zstd payload was compressed with the dictionary |
| 0x80 | ENCRYPTED | payload is sealed (section 8); `crc32` is then the CRC-32 of the **stored** payload |

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
u64 created                     unix seconds when the run STARTED (every file was read after it)
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
  * A Windows junction is kind 3 with a directory `st_mode` (`S_IFDIR`); a
    real directory symlink has `S_IFLNK`. Readers on Windows recreate a
    junction as a junction (no privilege needed) when its target is an
    absolute drive path, otherwise as a directory symlink.
* **Block lengths:** packs of a snapshot are contiguous and followed by its
  manifest, so each pack's end is known from the footer chain. A reader
  must reject a block whose header length disagrees with that end, or runs
  past the end of the file, before reading its payload.
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

### Reusing unchanged files (writer behaviour, no format change)

A `backup` can copy a file's entry (size, sha256, pointers) from the newest
earlier v3 snapshot whose `label` (source folder) matches, without reading
the file. All of these must hold:

* the path is the same;
* the kind is `file` in both snapshots;
* the size is equal;
* `mtime_ns` is equal;
* that earlier `mtime_ns` is more than 3 s before that snapshot's `created`.

The last rule protects against an edit made in the same timestamp tick as
the earlier read. The new entry records the file's current `mtime_ns`,
`st_mode` and `win_attrs`. `--rehash` disables reuse.

Limitation: content changed while both size and mtime stay exactly the same
(some tools restore mtimes) is not seen until a `--rehash` run.

### Pruning (rewriting a store without some snapshots)

The format is append-only, so deleting snapshots writes a new store. It
keeps the same layout and moves kept snapshots in order:

* The dictionary block, if any, is copied first.
* For each kept snapshot, every pack it is the first kept snapshot to use is
  emitted before its manifest:
  * as the original block, byte-for-byte (its pack id changes and chunk
    indexes stay the same), or
  * with only its live chunks re-encoded into new packs. MEDIA and
    non-media chunks are never mixed.
* Each rewritten manifest:
  * has its pointers remapped;
  * keeps `created`, `label`, entries' metadata and the skipped list;
  * has `prev` pointing at the previous kept manifest;
  * has an index that lists every chunk in its own packs.
* Older snapshots (v1/v2) are rewritten as v3.

The new store must pass a full `verify` before it is renamed over the old one.

## 5. Restoring a snapshot

1. **Paths:** split each path on `/` or `\`. Reject the path if any part is
   empty, `.`, or `..`, or (on Windows) contains `:`. Reject the snapshot if a
   path appears twice, or if any entry lies below a link entry of the same
   snapshot (no backup produces either). Each resolved destination must stay
   inside the output directory: resolve the parent folder again just before
   writing each entry, links included. Names the restoring system cannot hold
   (Windows device names such as `CON` or `aux.c`, a trailing dot or space,
   names differing only in case on a case-insensitive disk) may be skipped
   with a warning.
2. **Files:**
   * A file list entry may not have more pointers than `size` bytes (each
     chunk holds at least one byte); otherwise the manifest is damaged.
   * Concatenate the chunks. Stop with an error as soon as the total passes
     `size`; at the end it must match `size` and `sha256`.
   * Write to a new temporary file created exclusively (a random name, never
     an existing file or link), then rename over the destination. The
     reference reader proves every file of the snapshot this way before it
     renames any of them, so a damaged store changes nothing in the folder.
   * Do not restore setuid/setgid bits.
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

## 7. Parity sidecar (`<store>.hcp`)

Optional Reed-Solomon recovery data, in a separate file so the store format
is unchanged and old readers ignore it. It covers **every byte** of the
store (packs, manifests, footers, dictionary) up to `covered`.

```
header (64 bytes): "HCPAR001" | u32 shard | u16 k | u16 m | u64 covered | u32 groups
                   | 32 reserved | u32 crc32 of the 60 bytes before it
record per group:  u32 group | u32 data_len | (k+m) x 16-byte BLAKE2b
                   | u32 crc32 of the fields before it | m x shard parity bytes
```

* Defaults: shard 64 KiB, k = 16, m = 2, interleaving depth D = 16. The
  first u16 of the reserved bytes is D (0 means 1). Records are fixed-size, at
  `64 + g × record_size`; `data_len` is the number of store bytes the group's
  shards hold.
* **Interleaving.** The store is cut into shards (store shard s = bytes
  `[s·shard, (s+1)·shard)`, the last one zero-padded) and the shards into
  super-groups of D·k shards. A super-group has `ng` groups: D, except the last
  one, which has `ceil(shards_in_it / k)`. Data shard i of group j of
  super-group q is store shard `q·D·k + i·ng + j` (zero when past the end);
  its group number is `q·D + j`. With D = 1 this is the plain layout (group g =
  bytes `[g·k·shard, (g+1)·k·shard)`). Consecutive shards fall into different
  groups, so a burst of up to m·ng shards per super-group (2 MiB per 16 MiB
  with the defaults) is repairable, versus m shards (128 KiB) per 1 MiB without
  interleaving. `parity --m 4` doubles that at 25% overhead.
* Parity shard j is `Σ_i C[j][i] · data_i` over GF(256) (polynomial 0x11D),
  with the Cauchy matrix `C[j][i] = 1 / (j XOR (m + i))`. Any k of the k+m
  shards determine the others.
* The hashes are BLAKE2b-128 of each data shard (zero-padded) and each parity
  shard. They locate damage exactly, so any m damaged shards per group (data
  or parity) are erasures that can be rebuilt. A group with more is reported
  and left alone.
* **Never write unproven bytes.** A rebuilt shard is written back only if its
  BLAKE2b equals the recorded one. Parity that belongs to another store or an
  older state can therefore never change the store.
* **Updates.** After an append, only the super-groups from the one holding
  the old end of the store onward are recomputed. The shards of that first
  super-group that lie before the old end are checked against their recorded
  hashes first (with the old layout); if one does not match, the update is
  refused (the old damage is repaired with the old parity instead of being
  baked into new parity).
* `prune` computes parity for the new store before it replaces the old one.
* A record whose crc32 fails, or a stale `covered`, is rebuilt by `repair`
  only after the store itself verifies.

## 8. Encryption

Chosen when a store is created (`pack --encrypt`, or the first `backup
--encrypt`); every later snapshot is sealed with the same key.

**Key block** (right after the magic; header flags = 7, `orig_len` =
`stored_len` = 84, `crc32` of the payload):

```
"HCK1" | u8 kdf = 1 (scrypt) | u8 log2 N | u8 r | u8 p | 16-byte salt
| 12-byte nonce | 48 bytes = ChaCha20-Poly1305(KEK, nonce, data_key[32], AAD = the first 24 bytes)
KEK = scrypt(password utf-8, salt, N, r, p, 32 bytes); written with N = 2^17, r = 8, p = 1
```

**Every other block** (dictionary, packs, manifests) has flag 0x80 and
`orig_len` = 0 in the clear. The codec bits still say how the plaintext was
compressed; compression happens first. The payload is

```
12-byte random nonce | ChaCha20-Poly1305(data_key, nonce, inner, AAD = header bytes 0..11)
inner = u32 orig_len | u32 compressed_len | compressed bytes | zero padding
        (padded so that len(inner) is a multiple of 4096)
```

so `stored_len` = len(inner) + 28, i.e. `stored_len` mod 4096 = 28. Neither
the plaintext size nor the exact compressed size appears in the clear; this
matters for media files, which are stored one per block. The AAD binds magic,
flags, `orig_len` (0) and `stored_len`; `crc32` covers the stored payload,
which lets `verify`, parity and the walk tell damage (CRC) from a wrong key or
an altered block (authentication failure), and lets parity repair the store
without the password. After decryption, `compressed_len` must fit inside
`inner`, the inner `orig_len` must pass the same size-ratio check as a plain
block, and the decoded length must equal it.

* Readable without the password: block kinds, padded block sizes (4 KiB
  steps), footers, the number of snapshots, the store size. Not readable: file names, sizes
  per file, contents, chunk hashes, the dictionary, timestamps.
* Random nonces: the collision bound for 96-bit nonces stays negligible up to
  2^32 blocks per key (NIST SP 800-38D); writers stop at 2^30 sealed blocks.
* Key block limits on read: 14 <= log2 N <= 20, r <= 16, p <= 4, so a
  hostile key block cannot demand gigabytes of memory.
* `passwd` re-seals the same data key under a new password and salt; the data
  is not re-encrypted, so an older copy of the store (or of its key block)
  still opens with the old password.
* `prune` copies the key block and sealed packs as they are (same key).
* The semantic sidecar (`<store>.sem`) is not encrypted; `hybridstore_semantic
  index` refuses an encrypted store unless `--allow-plaintext-index`.
