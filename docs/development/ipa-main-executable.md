# Bounded IPA main-executable inspection

The `orchardprobe_core::ipa_code` module connects three device-free ingest
layers: root app identity from `Info.plist`, exact IPA entry streaming, and the
existing bounded Mach-O parser. It produces metadata for the one executable
declared by the root app bundle without loading a production-sized executable
wholly into memory.

> [!IMPORTANT]
> This is a library-only structural inspection stage. No current CLI command
> accepts an IPA. It does not enumerate frameworks, dylibs, or extensions,
> connect to a device, match an installed build, decrypt or rewrite code,
> validate a code signature, package an IPA, or prove plaintext. A missing
> encryption command or `cryptid == 0` remains metadata only.

## APIs and output

```rust
copy_ipa_entry_bounded(
    reader,
    archive_size,
    exact_entry_path,
    max_output_bytes,
    caller_owned_writer,
) -> Result<IpaEntryCopy, IpaEntryReadError>

inspect_ipa_main_executable(reader, archive_size)
    -> Result<IpaMainExecutable, IpaMainExecutableError>
```

`copy_ipa_entry_bounded` is the streaming counterpart to the 16 MiB in-memory
entry reader. On success it returns the observed byte count and the complete
IPA inventory validated immediately before the copy. The entry bytes go only
to the supplied `Write` sink; an archive path is never interpreted as a host
path.

`inspect_ipa_main_executable` returns:

- validated root app identity and versions;
- the exact main-executable archive path from `CFBundleExecutable`;
- its declared IPA entry metadata; and
- the existing `MachOReport` for all validated thin or FAT slices.

The report intentionally retains `PlaintextStatus::NotProven` for every slice.

## Validation sequence

1. Parse the bounded root `Info.plist` and obtain the exact regular main-entry
   path plus the authoritative inventory returned by that plist read.
2. Reject a main executable above 512 MiB before creating the temporary file.
3. Create an anonymous operating-system temporary file with automatic cleanup.
4. Repeat the complete IPA preflight on the same secured `Read + Seek` handle.
5. Resolve the exact case-sensitive regular entry and reject an unsafe,
   missing, directory, encrypted, or changed selector.
6. Accept only Stored or Deflate and reject declared compressed or
   uncompressed data above 512 MiB.
7. Stream through entry EOF with a fixed 64 KiB transfer buffer. Stop before
   writing bytes beyond the caller limit, require ZIP CRC success, and compare
   the observed and declared lengths.
8. Re-run full preflight after the copy, require its complete inventory to
   match the copy's pre-read inventory, then compare that post-copy inventory
   with the inventory bound to the
   parsed plist. Any path, kind, size, CRC, aggregate, count, app-root, or
   archive-size difference fails closed.
9. Parse the anonymous file with the bounded Mach-O parser, which reads only
   headers, FAT records, and limited load-command metadata.
10. Drop the temporary file on every success or error path.

The fixed copy limit is both 512 MiB of compressed input and 512 MiB of
uncompressed output. The earlier whole-IPA limits still apply, including entry
count, aggregate size, compression ratio, local-range overlap, and path rules.
The 64 KiB transfer buffer bounds memory use; the temporary file bounds random
access without retaining the entire executable in memory.

## Sink and temporary-file behavior

The generic copy API cannot roll back a caller-owned sink. If a write, CRC, or
length check fails after some bytes were written, the caller must discard or
truncate that partial output. Success does not flush or publish the sink; those
operations remain the caller's responsibility. This makes ownership and
atomic-publication policy explicit instead of hiding filesystem effects in the
archive layer.

The main-executable API does not use a caller-visible path. `tempfile::tempfile`
creates an automatically removed anonymous temporary file (or a securely
created file that is immediately unlinked on platforms without anonymous-file
support). The operating system can still write those bytes to local storage or
swap. Users must treat the host and its temporary storage as part of the trusted
local analysis environment. OrchardProbe does not upload the bytes.

The workspace pins `tempfile` exactly to 3.27.0. That release declares Rust
1.63 compatibility, below OrchardProbe's Rust 1.85 toolchain, and is dual
MIT/Apache-2.0 licensed. Dependency and MSRV changes remain subject to locked
CI review.

## Failure semantics

Typed failures distinguish:

- app metadata and full IPA preflight errors;
- invalid caller limits and compressed/uncompressed resource excess;
- unsupported compression or reopened metadata drift;
- archive read/CRC errors and caller sink write errors;
- any complete-inventory change between plist and executable observations;
- temporary-file creation or capacity errors; and
- bounded Mach-O structural errors.

No partial result is returned as a valid code-object inventory. The source IPA
is never modified.

## Test scope and next step

Synthetic tests cover Stored and Deflate copies, deterministic source
preservation, copy limits, sink failure, CRC corruption, unsupported
compression, valid thin arm64 metadata, non-Mach-O input, app/preflight failure,
main-entry size limits, and complete-inventory drift detection. Existing IPA
and Mach-O adversarial suites continue to cover the lower layers.

Run the focused tests with:

```sh
cargo test -p orchardprobe-core ipa::tests --locked
cargo test -p orchardprobe-core ipa_code::tests --locked
```

The separate [deterministic code candidate inventory](ipa-code-inventory.md)
now resolves conventional framework, dylib, and extension paths through this
streaming boundary. A filename suffix or bundle convention remains only a
candidate signal; an entry becomes a code object only after bounded Mach-O
parsing. Nested plist resolution for nonstandard executable names remains a
follow-up.
