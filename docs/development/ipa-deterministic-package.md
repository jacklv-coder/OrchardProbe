# Deterministic unsigned analysis IPA packaging

`HOST-009` adds a Unix host-library packaging primitive:

```rust
package_ipa_analysis_worktree(&worktree)
    -> Result<IpaAnalysisArchive, IpaPackageError>
```

The input must be an owned `IpaPrivateWorktree` from `HOST-008`; an arbitrary
directory or caller-selected output path is never accepted. The result owns a
fresh `0600` temporary IPA and implements `Read + Seek`, but not `Write`, and
does not expose its private host path. Dropping it removes the temporary file.

This is not the `oprobe decrypt` command. It is a device-free, library-only
repackaging stage for later reconstruction and manifest work.

## Data authority

Three sources have deliberately separate roles:

| Source | Authority |
|---|---|
| Source `IpaInventory` | Canonical paths, source entry kind, sanitized executable class, and exclusion provenance. |
| Immutable worktree records | Exact included set, implicit/explicit directory provenance, and expected regular-file lengths. |
| Retained worktree descriptors/identities | Which private host nodes may be read. |

The packager never scans the host tree to invent archive records. It does
enumerate each retained directory descriptor before and after packaging only to
prove that its direct child names equal the closed plan. An added, missing,
renamed, replaced, symlinked, or special node is a failure, not new input.

Before each file read, the implementation:

1. walks every parent from the retained root descriptor with directory-only,
   no-follow opens and device/inode checks;
2. opens the exact final component read-only, nonblocking, and no-follow;
3. requires a regular file with the materialized identity and exact length;
4. streams through one 64 KiB buffer and probes for short/long output; and
5. compares identity, length, modification time, and change time before/after
   the read and once more after the archive is finalized.

These checks permit a later reconstruction stage to change bytes in place while
rejecting replacement, size drift, or concurrent mutation during packaging.

## Deterministic policy v1

Identical authoritative metadata and worktree bytes produce identical IPA bytes
under the pinned toolchain:

| Property | Policy |
|---|---|
| Entry order | Strict canonical path order; directories precede descendants. |
| Directories | Explicit ZIP entries, Stored, mode `0755`. |
| Regular files | Deflate level 6, mode `0644`. |
| Source executable-class files | Deflate level 6, normalized mode `0755`. |
| Timestamp | `1980-01-01 00:00:00` in the ZIP DOS field. |
| Comments | Empty archive and entry comments. |
| Extra metadata | None except ZIP64 fields when required by format limits. |
| Semantic state | `unsigned_analysis_only`. |

The source execute class is true only when validated source ZIP metadata grants
at least one regular-file execute bit. The packager does not copy a complete
untrusted mode. Setuid, setgid, sticky bits, ownership, ACLs, extended
attributes, quarantine state, and source/host timestamps never survive. Host
worktree files remain `0600`; their mode is not package metadata.

Embedded signature files can remain ordinary source bytes, but this layer does
not validate or re-sign them. An unchanged synthetic fixture is still labelled
`unsigned_analysis_only`, never “decrypted” or installable.

## Exclusions and bounds

Every exact-component `_MASReceipt` and `SC_Info` exclusion from `HOST-008`
remains absent and is propagated in sorted evidence. Similar names such as
`SC_Info.txt` remain ordinary included files.

The packager reuses the lower path, per-file, and aggregate-uncompressed limits
and adds:

| Resource | Maximum |
|---|---:|
| Output ZIP entries | 16,384 |
| One included worktree file | 512 MiB (inherited) |
| Complete emitted IPA | 16 GiB |
| Streaming buffer | 64 KiB |

The entry cap includes explicit entries created for formerly implicit
directories. Output accounting tracks the writer's position and high-water mark
across ZIP header rewrites; a seek or write beyond 16 GiB fails. Packaging is
sequential and never loads one file or the final IPA into memory.

## Final validation and result

After ZIP finalization and flush, the output is rewound and passed through the
same bounded IPA preflight. Its app root, sorted paths, kinds, actual lengths,
stream-computed CRCs, and normalized executable classes must match the packaging
plan exactly. Compressed sizes come from the newly written bytes and remain
visible in the returned output inventory.

`IpaAnalysisArchive` returns read-only access plus:

- the authoritative source inventory;
- the final validated output inventory;
- sorted included and excluded records;
- exact output byte length;
- deterministic policy v1; and
- the explicit `unsigned_analysis_only` state.

Input/output hash binding belongs to `HOST-010`; this stage does not invent
manifest evidence early.

## Failure cleanup and tests

Any tree, identity, kind, size, concurrent-read, compression, output-limit,
filesystem, finalization, or final-preflight error drops the partial temporary
artifact. Errors contain canonical archive-relative context or stable policy
values, not the private worktree/output paths.

Synthetic tests cover Stored and Deflate source entries, implicit directories,
exact exclusions, byte-identical payload round trips, repeated package-byte
determinism, fixed timestamps/comments/compression/modes, symlink and directory
replacement, same-size regular-file replacement, unexpected nodes, FIFO
replacement on Linux, size mutation, short/long reads, sink failures,
bounded-writer seek/write limits, corrupted final-preflight rejection, and
success/error cleanup.

Run the focused suite with:

```sh
cargo test -p orchardprobe-core ipa_package::tests --locked
```

This module does not publish an IPA, modify Mach-O, access a device, match an
installed build, decrypt, prove plaintext, sign, install, redistribute, or make
a compatibility claim.
