# Mach-O inspect contract

`oprobe inspect` is a device-free, read-only metadata command. It parses one local Mach-O file so OrchardProbe can exercise the same bounded structural foundation against synthetic tests and the repository-owned DemoLab fixture.

It does not connect to an iOS device, recurse through an app bundle, unpack an IPA, decrypt or rewrite bytes, validate a code signature, or prove that any byte range is plaintext.

## Command

```text
oprobe inspect <MACH-O> [--json]
```

The input must be a regular file named directly by the caller. Directories, symbolic links, sockets, pipes, and device files are rejected before parsing. On the currently supported Unix hosts, OrchardProbe opens the file with no-follow and nonblocking flags, then verifies the opened handle is the same regular file that was checked by device and inode. This closes the check/open race without following a swapped final symlink or blocking on a swapped pipe.

The parser supports 32-bit and 64-bit thin Mach-O files plus FAT and FAT64 containers in either byte order. It reads fixed-size headers, FAT architecture records, and bounded load-command fields through seekable file I/O; it does not load the complete executable into memory.

## Resource and structural limits

The parser rejects malformed or ambiguous structures rather than guessing:

- at most 64 slices in a FAT container;
- at most 4,096 load commands per slice;
- at most 16 MiB of declared load-command data per slice;
- checked arithmetic and file/slice bounds for every offset and size;
- no nested FAT containers, overlapping slices, FAT-table overlap, or CPU metadata mismatch;
- load-command sizes must satisfy the alignment required by the slice bitness;
- the load commands must consume exactly the declared `sizeofcmds` region; and
- duplicate, malformed, bitness-mismatched, or out-of-range encryption commands are rejected.

These are parser safety limits, not device or app compatibility claims.

## JSON output

With `--json`, a successful command emits this top-level shape:

```json
{
  "schema_version": 1,
  "command": "inspect",
  "input_path": "path/to/Mach-O",
  "report": {
    "container": "thin",
    "container_endianness": "little",
    "file_size": 32,
    "slices": [
      {
        "offset": 0,
        "size": 32,
        "is_64_bit": true,
        "endianness": "little",
        "cpu_type": 16777228,
        "cpu_subtype": 0,
        "architecture": "arm64",
        "file_type": 2,
        "file_type_name": "execute",
        "load_command_count": 0,
        "load_command_bytes": 0,
        "encryption_state": "not_declared",
        "encryption": null,
        "plaintext_status": "not_proven"
      }
    ]
  },
  "evidence_level": "metadata",
  "plaintext_proven": false,
  "notice": "Mach-O encryption metadata does not prove plaintext"
}
```

`container` is `thin`, `fat32`, or `fat64`. Unknown CPU and file-type values remain visible through their raw numeric fields; a conservative readable label is provided separately.

When present, `encryption` records the load-command variant plus `cryptoff`, `cryptsize`, and `cryptid`. `encryption_state` has deliberately narrow semantics:

- `not_declared`: the slice has no `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64` command;
- `not_marked_encrypted`: an encryption command exists and its `cryptid` is zero; or
- `marked_encrypted`: an encryption command exists and its `cryptid` is nonzero.

Every successful slice also reports `plaintext_status: "not_proven"`, and every successful command reports `plaintext_proven: false`. Header metadata alone cannot establish that the bytes are correct plaintext.

## Error behavior

Failures return a nonzero exit code, leave standard output empty, and write an `error:` message to standard error. `--json` changes successful output only; it does not create a separate error schema in this pre-alpha contract.

Tests construct minimal Mach-O byte sequences in the repository. DemoLab smoke tests inspect only binaries compiled from this project's own source. No proprietary or third-party binary fixture is required.
