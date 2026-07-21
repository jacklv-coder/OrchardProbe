# OrchardProbe documentation

[简体中文文档索引](zh-CN/README.md)

OrchardProbe separates the simple user experience from the security-sensitive
implementation behind it. Start with the document that matches what you need:

## Use the tool

- [User guide](user-guide.md) — the planned one-command IPA workflow, its
  prerequisites, outputs, failure behavior, and the current pre-alpha limit.
- [Compatibility evidence](compatibility/README.md) — what a supported device
  claim means and how it is verified.

## Understand the system

- [Sequential execution plan](../EXECUTION_PLAN.md) — the authoritative step
  order, current gate, Issue/PR evidence, and definition of done.
- [Technical overview](technical-overview.md) — end-to-end data flow, component
  boundaries, Mach-O reconstruction, evidence semantics, and a code-reading
  path for learners.
- [Scope and threat model](architecture/RFC-0001-scope-and-threat-model.md) —
  authorization boundary, security invariants, and No-Go conditions.
- [Bounded host/helper protocol](architecture/RFC-0002-bounded-host-helper-protocol.md)
  — the accepted device-free protocol design gate.
- [Rust host architecture decision](architecture/ADR-0001-rust-host.md) — why
  the host is Rust and the future device helper remains narrow.

## Develop and verify

- [Rust workspace guide](development/getting-started.md)
- [Mach-O inspect contract](development/macho-inspect.md)
- [Bounded IPA preflight and entry read](development/ipa-preflight.md)
- [Bounded IPA Info.plist metadata](development/ipa-info-plist.md)
- [Bounded IPA nested-bundle metadata](development/ipa-nested-bundles.md)
- [Bounded IPA main-executable inspection](development/ipa-main-executable.md)
- [Declared standard-bundle IPA code inventory](development/ipa-code-inventory.md)
- [Private bounded IPA worktree](development/ipa-private-worktree.md)
- [Deterministic unsigned analysis IPA packaging](development/ipa-deterministic-package.md)
- [Device-free IPA package evidence manifest](development/ipa-package-manifest.md)
- [Versioned schema guide](development/schemas.md)
- [DemoLab development guide](development/demolab.md)
- [Compatibility test-record template](compatibility/test-record-template.md)

> [!IMPORTANT]
> OrchardProbe is pre-alpha. The repository does not yet implement the planned
> `oprobe decrypt` command, a device backend, or Mach-O reconstruction. Documents
> describing that flow are product and technical contracts, not a claim that
> the current checkout can decrypt an IPA.
