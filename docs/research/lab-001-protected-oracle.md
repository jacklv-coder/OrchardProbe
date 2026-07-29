# LAB-001 protected DemoLab oracle result

Status: **No-Go — Unsupported for this exact research tuple**

Date: 2026-07-29

This decision becomes authoritative when its result PR merges.

This note records the bounded result of Issue #9. It covers only the
project-owned DemoLab, an owned iPhone, internal TestFlight, and the public
Xcode/CoreDevice interfaces exercised below. It does not evaluate a device
backend, third-party application, jailbreak, decryption implementation, or
user-facing IPA workflow.

## Decision

LAB-001 is No-Go for this exact tuple:

- DemoLab source commit
  `5785c56e8bee8e30fdaefcb6e263852e9be874ab`;
- DemoLab version `1.0`, build `2`, App Store distribution configuration;
- Xcode `26.1.1` (`17B100`), iPhoneOS SDK `26.1` (`23B77`), XcodeGen
  `2.45.4`, and Fastlane `2.237.0`;
- Apple Silicon macOS `26.2` host;
- iPhone 14 Pro running iOS `26.6` (`23G5065a`); and
- internal TestFlight delivery without a jailbreak, helper, device backend, or
  general-purpose file/process/memory primitive.

The build was accepted by App Store Connect, installed on the owned device, and
remained running after a controlled launch. Those facts establish the lawful
distribution path and clear the launch prerequisite. They do not bind the
installed Mach-O bytes to the pre-upload oracle or independently establish the
installed binaries' initial protection state.

Public CoreDevice app metadata exposed the installed version/build and bundle
location but no per-binary UUID, code-signature identity, digest, slice, or
range hash. Its process record exposed an executable location and process
identifier but no image identity. Its supported file-service domains covered
temporary storage, app data containers, app-group data containers, and crash
logs—not the installed application bundle.

The exported App Store IPA had a valid distribution signature with
`get-task-allow=false`. A public LLDB device attach could identify a running
process, but it had no associated executable images and could neither interrupt
the process nor enumerate images. Reading the installed bundle or mapped image
would therefore require a capability outside the LAB-001 boundary. Issue #9
explicitly prohibited adding a device backend, helper, transport, process
selection, memory access, or decryption implementation during this research.

Because exact installed lineage, initial protection, and the compared plaintext
range cannot all be independently established, the Go criteria fail. No hash
match was attempted or inferred.

## Why the upload artifact is not the installed oracle

Apple documents that Xcode repackages an archive according to its selected
distribution configuration, and that TestFlight is an Apple-distributed beta
path:

- [Distributing your app for beta testing and releases](https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases)

Apple also documents that the App Store performs additional binary processing,
including adding DRM and recompressing binaries, and that the uploaded IPA is
not the same artifact users install:

- [Reducing your app's size](https://developer.apple.com/documentation/xcode/reducing-your-app-s-size)

The App Store Connect API defines a Build as a processed uploaded binary, but
its public Build resource is a distribution record rather than a per-slice
installed-byte manifest:

- [App Store Connect API Build](https://developer.apple.com/documentation/appstoreconnectapi/build)

Apple's distribution-entitlement guidance also distinguishes development and
distribution entitlements:

- [Checking Distribution Entitlements (QA1798)](https://developer.apple.com/library/archive/qa/qa1798/_index.html)

Consequently, source identity, the upload IPA SHA-256, App Store Connect build
identity, and the installed version/build are related lineage facts, but none
may be silently substituted for the exact installed Mach-O bytes.

## Sanitized provenance

The evidence-bound IPA SHA-256 was:

```text
e383fcf0ee550effb68b183965208b1ef274688cc5233649b8e452135aafde40
```

The source tree was clean. The build, export, signature, package metadata,
Archive linkage, and exported-IPA linkage checks passed before the single
upload. App Store Connect reported the exact build as `VALID`, internal state
`IN_BETA_TESTING`, with no missing export compliance. The existing internal
group covered all builds. No group mutation, public link, external
distribution, Beta App Review, or App Store submission occurred.

The owned device independently reported DemoLab `1.0 (2)`. A
terminate-existing launch succeeded, and the exact launched process remained
present after both 12 and 32 seconds.

No private credential, certificate, provisioning profile, receipt, device
identifier, pairing material, protected binary, IPA, installed application
path, private bundle identifier, or raw private log is retained in this
repository. The generic public DemoLab-relative paths and fixture identifiers
remain intentionally documented.

## Audit record and maintainer sign-off

| Field | Recorded value |
|---|---|
| Claim under test | Whether the exact stock internal-TestFlight/public-CoreDevice tuple can independently establish installed binary lineage, initial protection, and matching plaintext ranges for a protected-oracle claim |
| OrchardProbe observation baseline | `17df24f768d69c2cad1df7d028bb69efb5f0a0aa` |
| DemoLab commit | `5785c56e8bee8e30fdaefcb6e263852e9be874ab` |
| Helper artifact | Not exercised |
| OrchardProbe transport/backend capability IDs | Not exercised; no OrchardProbe device transport or backend existed |
| Controlled clean runs attempted | `1` |
| Controlled clean runs with the recorded result | `1` |
| Decision | **No-Go — Unsupported for this exact research tuple** |
| Verified by | `@jacklv-coder` |
| Verification date | `2026-07-29` UTC |
| Review links | [Issue #9](https://github.com/jacklv-coder/OrchardProbe/issues/9) and [result PR #54](https://github.com/jacklv-coder/OrchardProbe/pull/54) |
| Second maintainer review | Pending |

One run is recorded because the experiment stopped at the approved capability
boundary; no installed byte or range comparison was available to repeat. This
does not meet or claim the two-clean-run requirement for `Go — Verified`.
`Unsupported` here records the confirmed capability boundary for only the
named tuple, not verified decryption behavior or broader device support. PR #54
contains the reviewed procedure and publishes the final merge commit alongside
its checks and discussion.

## Per-binary evidence

The SHA-256 values and Mach-O UUIDs below describe pre-upload Archive binaries
only. All three were arm64 slices whose encryption command reported
`cryptid=0`. They are candidate plaintext inputs and build metadata, not
observations of the TestFlight-installed binaries.

| DemoLab-relative binary | Pre-upload SHA-256 | Pre-upload Archive Mach-O UUID | Installed initial protection | Installed compared range | Result |
|---|---|---|---|---|---|
| `DemoLab.app/DemoLab` | `e364eb1c0dbca31ff270396f12ee1d92f378db40a2dc8a91f407604db597867b` | `089f5141-4c09-3e8d-a2ae-0b5b27085319` | Not observable within boundary | Unavailable; no hash collected | Inconclusive |
| `DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework` | `899c2caa3640b486bf52b60ed045816a0c670cec157b408558cca9ffc3175e1c` | `a147d991-5e3b-3269-85c7-02347a464e27` | Not observable within boundary | Unavailable; no hash collected | Inconclusive |
| `DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension` | `8ad60c0e225616fe463da0f0ac7dc2136f0ddd71ebb8930b554efbd76fd25139` | `d4845432-8dc6-314a-a83e-3935b244223d` | Not observable within boundary | Unavailable; no hash collected | Inconclusive |

No exact installed range can be named without first obtaining independently
reviewable installed image metadata. A fabricated offset, whole-file upload
hash, or pre-upload `cryptid=0` observation would violate the evidence policy.

## Reproduction procedure

Use placeholders for private identifiers and store JSON output only in an
owner-only temporary directory:

1. Reconcile and reuse the existing evidence-bound DemoLab `1.0 (2)` build in
   App Store Connect. Never retry its upload. If that immutable build is no
   longer available, stop; a method-level repeat must allocate a new build
   number and record a separate research tuple.
2. Install the build from internal TestFlight on the owned device.
3. Use `devicectl device info apps` and retain only the sanitized version/build
   fact. Observe that the public record contains no UUID or binary digest.
4. Launch the exact app through `devicectl`, then use
   `devicectl device info processes` to confirm process survival. Observe that
   the process record contains no image UUID or range digest.
5. Verify the exported IPA signature and its `get-task-allow` entitlement.
6. Select `<owned-device>` in LLDB and attempt the public device-process attach.
   On this tuple, the process connects without an executable image target;
   image enumeration and interruption are unavailable.
7. Inspect `devicectl device info files --help` and
   `devicectl device copy from --help`. On this toolchain, no installed
   application-bundle domain is offered.
8. Stop. Do not add a helper, arbitrary file access, process selection, memory
   access, or a weaker identity fallback.

This procedure is reproducible as a No-Go check. It is not a procedure for
obtaining protected or plaintext bytes.

## Criteria evaluation

| LAB-001 criterion | Result | Reason |
|---|---|---|
| Lawful first-party provenance | Pass | Source, account, device, build, and internal distribution were project-controlled. |
| Installed artifact lineage beyond version/build | Fail | Public installed records exposed no per-binary UUID, signature identity, or digest. |
| Independent initial protection for exact binary/slice | Fail | Installed bundle and mapped images were unavailable within the boundary. |
| Independent expected plaintext for exact installed ranges | Fail | Pre-upload plaintext candidates exist, but exact transformed installed ranges cannot be bound. |
| Reproducible sanitized comparison | Fail | The inability is reproducible, but no exact installed range/hash comparison is possible. |
| Narrow future compatibility test | Fail | Promoting the result would require an unapproved capability or weaker evidence. |

Decision: **No-Go — Unsupported for this exact research tuple.**

This is not a product-wide impossibility result. It says only that a stock
internal-TestFlight installation plus the exercised public Xcode/CoreDevice
interfaces cannot satisfy OrchardProbe's stronger evidence standard without
crossing the approved LAB-001 boundary.

## Required plan change and current disposition

At the time this result was accepted, LAB-001 completed with No-Go, blocked
DEVICE-001, and required a replacement-oracle step to be proposed and ordered
through a separate reviewed plan change. That requirement is now represented by
the planned `LAB-002` step and Issue #55 in the authoritative execution ledger.
LAB-002 is not active or implemented; it still must complete with a Go result
for an independent protected oracle before any device-backend work starts. The
replacement method must:

- remain limited to project-owned DemoLab;
- avoid a reusable arbitrary process, filesystem, or memory API;
- bind each installed binary, architecture, slice, and exact code range;
- preserve independent initial-protection and plaintext evidence;
- keep credentials, stable device identifiers, receipts, binaries, and raw logs
  private; and
- undergo its own threat-model, documentation, CR, and Go/No-Go review before
  DEVICE-001 can be activated.

Planning LAB-002 does not establish a protected oracle. OrchardProbe still has
no device backend, protected oracle, verified compatibility row, or working
`oprobe decrypt` command.
