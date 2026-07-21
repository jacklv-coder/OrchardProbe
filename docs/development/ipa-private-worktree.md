# Private bounded IPA worktree

`HOST-008` adds a Unix host-library staging primitive for later reconstruction:

```rust
materialize_ipa_private_worktree(reader, archive_size)
    -> Result<IpaPrivateWorktree, IpaWorktreeError>
```

It is intentionally not a general ZIP extractor. It accepts the same
`Read + Seek` source and secured byte length as IPA preflight, creates a fresh
owner-only temporary root, and materializes only the already validated
`Payload/<App>.app` tree. The returned value owns that root, and dropping it
attempts to remove the complete tree.

This API is library-only and is not connected to `oprobe decrypt`.

## Processing contract

Materialization has two phases:

1. `inspect_ipa` produces one complete authoritative `IpaInventory`.
2. Before any temporary root or payload copy exists, the planner validates the
   destination-tree shape, computes all explicit and implicit directories,
   included files, exclusions, node counts, and checked compressed and
   uncompressed totals.
3. A fresh unpredictable temporary directory is restricted to `0700`.
4. Directories are created parent-first as `0700`. Each parent is reopened
   component-by-component using descriptor-relative, directory-only,
   no-follow operations and checked against its recorded device/inode identity.
5. Files are created sequentially with create-new, no-follow semantics and mode
   `0600`. The existing 64 KiB bounded streaming-copy loop validates Stored or
   Deflate data, declared and actual lengths, and ZIP CRC. Every returned full
   inventory must equal the authoritative inventory.
6. Materialized and excluded records are returned in canonical path order.

The implementation does not derive metadata by scanning the resulting host
tree. Archive paths were already restricted to canonical relative ASCII `/`
components by preflight; this layer never accepts a destination, absolute path,
`..`, basename fallback, case fallback, or Unicode-normalized alternative.

## Closed scope and exclusions

An entry is excluded when any canonical relative path component is exactly one
of these case-sensitive values:

| Component | Stable reason |
|---|---|
| `_MASReceipt` | `mas_receipt` |
| `SC_Info` | `sc_info` |

The matching entry and every descendant are absent from the worktree and remain
visible in `excluded_entries`. Similar names such as `SC_Info.txt` are ordinary
included entries. Tree-shape validation runs before exclusions, so an excluded
file cannot hide a file-as-ancestor conflict.

Only validated regular files and directories are accepted. Missing ZIP
directory entries become explicit `implicit_directory` records. Archive modes,
ownership, timestamps, ACLs, extended attributes, quarantine state, executable
bits, and special-file metadata are never copied.

## Bounds

The lower IPA preflight limits remain authoritative. Materialization adds the
narrower streaming profile and destination-node accounting below:

| Resource | Limit |
|---|---:|
| Included compressed bytes per file | 512 MiB |
| Included uncompressed bytes per file | 512 MiB |
| Included compressed bytes total | 16 GiB |
| Included uncompressed bytes total | 32 GiB |
| Explicit plus implicit directories | 16,384 |
| Included files plus directories | 32,768 |

All totals use checked arithmetic. A declaration outside this profile fails
before temporary-root creation; it is never silently skipped. Payload copies
are sequential and use bounded memory.

## Filesystem and cleanup guarantees

The path returned by `IpaPrivateWorktree::path()` is a private staging detail,
not a publication path. The public `Debug` representation redacts it. The
implementation:

- never merges into or overwrites an existing caller-selected destination;
- anchors traversal to open directory descriptors beneath the fresh root;
- rejects symlink replacement, non-directory ancestry, identity drift, and
  create-new collisions;
- does not modify the input reader or source file; and
- destroys the whole partial root on planning, copy, CRC, inventory, identity,
  permission, filesystem, or flush failure.

The root's unpredictability and `0700` mode reduce interference, while
descriptor-relative no-follow traversal supplies the fail-closed boundary if a
same-user host process still attempts replacement. This is a Unix host API;
the initial supported host remains Apple Silicon macOS.

## Result model

`IpaPrivateWorktree` contains:

- the authoritative source `inventory`;
- sorted `entries` with `file`, `explicit_directory`, or
  `implicit_directory` provenance and observed bytes written;
- sorted `excluded_entries`, each retaining canonical source metadata and a
  stable exclusion reason; and
- checked included compressed and uncompressed totals.

Errors name only canonical archive-relative paths in their contextual path
fields. Arbitrary host paths and the private temporary root are not stable
machine-facing result data.

## Verification

Focused tests cover Stored and Deflate byte identity, implicit and explicit
directories, exact-component exclusions, normalized modes, immutable source
bytes, deterministic records, file-as-ancestor rejection before payload reads,
host-side symlink replacement, create-new collision, CRC failure, inventory
drift detection, resource limits, and success/error cleanup.

Run them with:

```sh
cargo test -p orchardprobe-core ipa_materialize::tests --locked
```

`HOST-009` may consume this owned tree to construct a deterministic unsigned
analysis IPA, but it must be activated and reviewed separately. This module
does not modify Mach-O, decrypt, prove plaintext, package or publish an IPA,
access a device, sign, install, or redistribute anything.
