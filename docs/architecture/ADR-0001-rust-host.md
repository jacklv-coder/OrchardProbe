# ADR-0001: Rust host with a narrow Objective-C/C device helper

- Status: Accepted
- Date: 2026-07-21

## Context

OrchardProbe needs to coordinate an authorized export, parse bundle and Mach-O data, validate reconstruction results, and produce auditable evidence. Most of that work can run on the macOS host. A future device-side component may still need direct access to iOS APIs and runtime facilities that are most practical to call from Objective-C or C.

Data received from a device, an app bundle, a Mach-O file, or a saved manifest is untrusted input. A malformed or compromised peer must not be able to turn parsing into arbitrary host file access, excessive allocation, integer overflow, or code execution. The project also must not turn its device helper into a general-purpose remote administration interface.

## Decision

The primary CLI and processing pipeline will run on the host and be written in Rust. The Rust host owns:

- authorization and scope checks, CLI behavior, and capability negotiation;
- transport orchestration and validation of every protocol message;
- bundle-path containment and explicit file and message size limits;
- bounded Mach-O parsing, reconstruction, hashing, verification, packaging, and manifest generation; and
- user-facing diagnostics and structured error reporting.

The host must parse all external bytes defensively. Lengths and offsets are checked before arithmetic or allocation, paths are normalized and proven to remain beneath the selected bundle root, protocol fields are allow-listed, and resource limits fail closed. Device metadata is evidence to validate, not authority to trust. Unsafe Rust is forbidden by the workspace lint unless a later ADR identifies a narrowly reviewed exception.

A future Objective-C/C helper may run on the device, but its responsibility is limited to the smallest operation that cannot reasonably live on the host. It will use a versioned capability handshake, be short-lived, request only demonstrated privileges, and expose narrowly typed operations bound to the selected app. It will not expose a shell, arbitrary filesystem paths, caller-selected PIDs, unrestricted memory reads, or a general command execution channel. Both sides validate protocol bounds; crossing into Objective-C/C never relaxes the host's validation requirements.

There is **no device backend today**. The current Rust workspace is a host-side foundation with a device-free demo. It does not discover devices, decrypt binaries, reconstruct an app from a device, or export an IPA. Adding the first backend requires a separate ADR describing the tested device environment, privileges, protocol operations, limits, and threat model.

## Consequences

- Most untrusted-input handling lives in a memory-safe host implementation with unit-test and fuzz-test seams.
- Device-specific and privilege-sensitive code remains small enough to audit independently.
- The protocol boundary adds versioning and validation work, but it prevents device implementation details from spreading through the host.
- A successful host demo is not evidence of device compatibility or export support.
- Compatibility claims remain blocked until a backend has been implemented and tested on a documented, authorized device configuration.

## Alternatives considered

- **Objective-C/C for the entire tool:** rejected because it would put more untrusted parsing and orchestration in a less memory-safe implementation without a device-API benefit.
- **Rust for every host and device operation:** deferred because the first technical spike must establish which iOS runtime APIs and entitlements are required before choosing device implementation details.
- **SSH commands or a general remote agent as the backend:** rejected because broad shell, path, process, and memory access would violate the project's minimum-necessary-privilege boundary and make auditing materially harder.
