# Contributing to OrchardProbe

Thank you for helping shape OrchardProbe. The project is pre-alpha, so the most valuable contributions establish a safe, testable foundation rather than claiming broad device compatibility.

Before participating, read:

- [PROJECT_PLAN.md](PROJECT_PLAN.md) for product scope and release gates;
- [LEGAL.md](LEGAL.md) and [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) for authorization boundaries;
- [SECURITY.md](SECURITY.md) for private vulnerability reporting; and
- [compatibility evidence policy](docs/compatibility/README.md) before reporting a device or environment result.

## Good early contributions

- threat-model and architecture review;
- capability, export-manifest, and error-code schema design;
- memory-safe Mach-O, plist, and archive parsing approaches;
- first-party DemoLab fixtures and deterministic expected outputs;
- diagnostics, privacy redaction, and reproducible compatibility reporting;
- bilingual documentation and narrowly scoped RFCs;
- tests for malformed input, interrupted transport, path traversal, symlink escape, and short reads.

The repository contains a buildable Rust host workspace and the first-party DemoLab simulator fixture, but no device backend or working exporter. Follow the [Rust development guide](docs/development/getting-started.md), [Mach-O inspect contract](docs/development/macho-inspect.md), and [DemoLab guide](docs/development/demolab.md) for current build and test commands.

## Before opening an issue

Search existing issues and the project plan first. Explain the problem, the desired outcome, and why it belongs within OrchardProbe's authorized-use-only scope.

For compatibility or diagnostic reports, use the repository's Compatibility intake Issue Form and follow the [compatibility evidence policy](docs/compatibility/README.md). Community reports remain unverified until maintainers reproduce them; a single report never creates an official support claim. The [sanitized test-record template](docs/compatibility/test-record-template.md) is for that maintainer-run verification. State whether the app is owned by you or covered by explicit testing authorization. Never publish an app name when client confidentiality or third-party rights prohibit it.

Do not attach proprietary IPAs, decrypted commercial binaries, store receipts, credentials, tokens, raw device identifiers, crash dumps containing private data, or client-confidential logs. Reduce bugs to a generated fixture whenever possible.

For a suspected security vulnerability, stop and follow [SECURITY.md](SECURITY.md) instead of filing a public issue.

## Proposing a design

Changes to the device protocol, privilege model, backend interface, authorization flow, output format, or project scope should begin as a focused design issue or RFC. Describe:

- the user problem and explicit non-goals;
- trust boundaries and new privileges or data flows;
- capability detection and honest failure behavior;
- privacy, security, and compatibility implications;
- how the design can be tested using first-party fixtures;
- migration or schema-versioning impact.

Do not build a new high-privilege backend before its protocol and threat-model impact have been reviewed.

## Pull requests

Keep pull requests small enough to review and give them a single clear purpose. Draft pull requests are welcome for early architectural feedback.

A ready-for-review pull request should:

- stay within the documented goals and non-goals;
- include tests appropriate to the changed behavior;
- update schemas and documentation when interfaces or output change;
- report unsupported or partial results explicitly instead of silently succeeding;
- preserve local-first operation and add no telemetry or implicit upload path;
- avoid arbitrary shell, file, PID, and memory primitives in device-side interfaces;
- use only original or clearly compatible code and redistributable test artifacts;
- contain no secrets, receipts, proprietary apps, raw device identifiers, or customer data;
- note any real-device validation without publishing sensitive identifiers or artifacts.

Maintainers may ask for design changes, additional tests, or a smaller patch before merging. Automated checks and maintainer review are required once those workflows exist; a passing check alone does not establish safety or compatibility.

## Testing principles

- Prefer unit tests and synthetic malformed inputs for parsers.
- Use only project-generated DemoLab binaries or fixtures you have the right to redistribute.
- Record expected hashes and byte ranges so results are reproducible.
- Test failure paths such as disconnects, short reads, low disk space, helper restarts, and unlaunchable extensions.
- Never expose personal device credentials or privileged device runners to untrusted fork pull requests.
- Back every public compatibility claim with a concrete, sanitized real-device test record.

## Source and license hygiene

Submit only material you created or have the right to contribute under the repository's license. Identify third-party dependencies and their licenses. Do not paste or translate source from projects with missing, unclear, or incompatible licensing, and do not contribute code derived from decompiled commercial apps, leaked source, or confidential client work.

Unless explicitly stated otherwise, submitted contributions are made under the repository's license. If you cannot agree to that, raise the licensing question before submitting code.

## Community expectations

Be precise, respectful, and evidence-driven. Avoid naming or shaming app vendors, jailbreak authors, researchers, or users. Compatibility failures are engineering data, not grounds for harassment. Project channels must not be used to request decrypted apps, protection bypasses, or help with activity prohibited by the [Acceptable Use Policy](ACCEPTABLE_USE.md).
