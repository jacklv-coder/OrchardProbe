# Maintainer compatibility test record

Copy this file for a maintainer-run verification. Do not use a public user issue
as the test record. Complete every field or mark the decision No-Go.

## Authorization and fixture gate

- [ ] The app and device are project-owned or explicitly authorized for this
      exact test.
- [ ] The target is OrchardProbe DemoLab built from the commit recorded below.
- [ ] No third-party or proprietary application was used.
- [ ] The procedure stays within OrchardProbe's documented minimum-privilege
      boundaries.

If any box is unchecked, stop. Do not run or publish the test as compatibility
evidence.

## Exact test tuple

| Field | Recorded value |
| --- | --- |
| Claim under test | `<for example: transport integrity; contained bundle collection; protected-to-plaintext reconstruction>` |
| Device marketing model | `<for example: iPhone 15 Pro>` |
| SoC family | `<for example: A17 Pro>` |
| iOS version | `<major.minor.patch>` |
| iOS build | `<build number>` |
| Jailbreak/test environment | `<public name and exact version>` |
| Root mode | `<rootless or rootful>` |
| Host | `<macOS version; Apple Silicon or Intel>` |
| OrchardProbe commit | `<full commit SHA>` |
| Helper artifact SHA-256 | `<SHA-256, or not exercised>` |
| Transport capability IDs | `<comma-separated public OrchardProbe IDs>` |
| Backend capability IDs | `<comma-separated public OrchardProbe IDs>` |
| DemoLab commit | `<full commit SHA>` |
| Installed DemoLab build identity | `<sanitized artifact/build hash and reproducible lineage>` |

Capability IDs are public identifiers returned by OrchardProbe's versioned
handshake. Do not record addresses, ports, device identifiers, shell output, or
private environment values.

## Reproduction procedure

Record concise, deterministic steps. Commands must use DemoLab-relative paths
and sanitized placeholders. Do not paste raw logs.

1. `<build and install DemoLab from the recorded commit>`
2. `<establish the recorded transport capability>`
3. `<run the narrowly scoped backend operation>`
4. `<verify each binary against its independently generated oracle>`
5. `<repeat from a clean state>`

Number of clean runs attempted: `<number>`

Number of clean runs with identical results: `<number>`

## Per-binary evidence

Create one row for every in-scope DemoLab Mach-O. Do not combine a main
executable, framework, and extension into one aggregate result.

| DemoLab-relative binary | Initial protection evidence | Evidence level | Observed SHA-256 | Known-plaintext oracle SHA-256 | Oracle source | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| `DemoLab.app/DemoLab` | `<sanitized evidence, or unprotected>` | `<metadata / structure / range_hash / known_plaintext>` | `<SHA-256 or not collected>` | `<SHA-256 or unavailable>` | `<artifact from recorded DemoLab commit>` | `<Pass / Inconclusive / Fail / Skipped>` |
| `DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |
| `DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |

`Pass` is valid only when the evidence level is `known_plaintext` and the
observed SHA-256 exactly matches the oracle from the recorded DemoLab commit.
Metadata such as `cryptid == 0` is not a plaintext oracle.

For a protected-to-plaintext or end-to-end export claim, the initial protection
evidence must also show that this exact installed binary exercised the claimed
transition. An unencrypted development build may support a transport or
collection claim, but it cannot support a decryption claim. A source commit by
itself is not an installed-artifact identity or protection-state oracle.

## Limitations and observations

- Incomplete coverage: `<none, or list DemoLab-relative binaries and reason>`
- Intermittent behavior: `<none, or sanitized summary>`
- Capability constraints: `<none, or public capability IDs and limitation>`
- Other limitations: `<none, or sanitized summary>`

Do not paste raw logs. Record only the minimal observation needed to explain the
decision.

## Redaction review

- [ ] No UDID, ECID, serial number, IP address, host/device username, credential,
      token, certificate, or provisioning material is present.
- [ ] No proprietary application name, bundle identifier, IPA, binary content,
      or link to such material is present.
- [ ] No raw or unsanitized log is present.
- [ ] All paths and commands use DemoLab-relative or sanitized placeholders.
- [ ] All hashes refer only to DemoLab artifacts from the recorded commit.

## Go/No-Go decision

Select exactly one:

- [ ] **Go — Verified:** all Verified requirements are met, every required
      binary has matching known-plaintext evidence, and at least two clean runs
      produced identical results for the narrowly recorded claim. A protected-
      to-plaintext claim also has independently reviewed initial-protection
      evidence for every required binary.
- [ ] **No-Go — Experimental:** some intended behavior was observed, but at
      least one Verified requirement is not met.
- [ ] **No-Go — Unsupported:** this exact tuple is confirmed unable to satisfy
      the required behavior or is outside the documented project boundary.
- [ ] **No-Go — Insufficient evidence:** no support-tier decision can be made.

Decision rationale: `<concise evidence-based explanation>`

## Maintainer verification sign-off

- Verified by (maintainer GitHub identity): `<@handle>`
- Verification date (UTC): `<YYYY-MM-DD>`
- OrchardProbe commit reviewed: `<full commit SHA>`
- Linked review issue or pull request: `<repository URL>`
- Second maintainer review, when available: `<@handle and UTC date, or pending>`

Signing a record confirms only the exact tuple and scope above. It does not
extend the claim to adjacent models, builds, environments, capabilities, or
commits.
