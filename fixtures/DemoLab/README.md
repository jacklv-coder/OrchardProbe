# DemoLab iOS fixture

DemoLab is a small, first-party iOS application used to test OrchardProbe against artifacts that this project owns and compiles itself. It deliberately includes multiple Mach-O products:

- `DemoLab.app`, a SwiftUI application with bundle identifier `com.example.orchardprobe.demolab`;
- `DemoFramework.framework`, a dynamic Objective-C framework whose public API is called by the app; and
- `DemoShareExtension.appex`, a Swift share extension with bundle identifier `com.example.orchardprobe.demolab.share`.

Every source file is kept in this directory, and the fixture has no third-party source or binary dependencies.
The fixture does not use non-exempt encryption, and its main app declares
`ITSAppUsesNonExemptEncryption=false` for App Store Connect processing.

The checked-in identifiers remain generic. The maintainer-only `LAB-001`
Fastlane lane overrides them from local environment variables for one
first-party signed build; no Apple team or registered identifier is committed.
The checked-in App Group is likewise the generic
`group.com.example.orchardprobe.demolab`; the controlled signed archive now
requires and injects the registered first-party group for both the app and
share extension. It also requires the reviewed Host authorization public key,
rejects all eight encoded Ed25519 low-order points, and compiles the accepted
key into the app, so the production validator accepts only exact canonical
enrollment/run envelopes signed by that pinned Ed25519 key. The checked-in
public-key setting is empty and production coordination therefore fails closed
in an ordinary fixture build. The main app's fixed Keychain access group is one explicit
build setting shared by its entitlement and Info.plist. The controlled signed
lane injects the full Team ID plus bundle identifier instead of relying on
`AppIdentifierPrefix` expansion; its enrollment key is non-synchronizable and
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. The Keychain item also binds
the exact build digest: if enrollment is interrupted after key persistence but
before nonce-state persistence, only a later authenticated enrollment for that
same build may recover the orphaned key and finish exclusive state creation.
If state persistence completed but authorization deletion was interrupted,
Enrollment alone may resume and revalidate that exact quarantined
authorization, strictly load the same-build state/key, and finish deletion.
Run paths cannot invoke either recovery, a fresh re-enrollment cannot reuse
persisted state, and another build is rejected.
LAB-002 enrollment/run/discard production entry points source wall-clock time
internally and require `DEMO_LAB_BUILD_BINDING_SHA256` to inject the exact
lowercase 64-hex build binding into the app Info.plist. The checked-in setting
is deliberately empty, so production coordination fails closed until the
reviewed LAB-002 pre-build step derives it from every frozen binding input.
The same pre-build step supplies the private 32-byte identity nonce as exact
lowercase hex. The signed archive lane refuses a missing or malformed
precomputed binding/nonce, requires the frozen 40-hex LAB-002 source-commit
wire form, and injects those values plus the fixed observer revision into the
compiled Info.plist; it does not invent defaults. A valid run authorization is
fully validated against those compiled facts, enrollment continuity, the
current installation binding, retained authorized-target manifest,
experiment/enrollment binding, and exact next counter before it can consume
authorization or counter state. It
then exclusively persists one
bounded canonical `reports/current/session.json`; an existing session rejects
the run before either state is consumed. Fixed enrollment-control and
run-lifecycle records make observer failure, completion uncertainty, and
cleanup uncertainty terminal across relaunch while preserving only the exact
quarantined pre-observation recovery path. Runtime caller-controlled
overrides are available only through the Debug test initializer.
See the
[controlled TestFlight runbook](../../docs/development/demolab-testflight.md).
The merged LAB-002 checkpoint-2 app/extension capability, fixed-container, and
state-machine boundary is documented in the
[device implementation contract](../../docs/research/lab-002-device-implementation.md).

## Device workflow

The signed LAB-002 build presents one three-step screen:

1. choose the fresh Host-signed authorization JSON;
2. complete the operation selected by that verified authorization—either
   enroll, compare the displayed full device-selection fingerprint with the
   Host, and share the receipt; or start a run and select **DemoLab Share**
   from Apple's share panel; and
3. share the generated session-export JSON, then explicitly confirm receipt
   before DemoLab removes only the completed report subtree.

New imports remain disabled until the pending operation finishes. Relaunching
the app restores the fixed pending authorization, durable enrollment
receipt/fingerprint recovery record,
collecting session, or completed export. An interrupted atomic authorization
publication is promoted from its fixed owner-only temporary name. A proven
malformed, expired, wrong-build, or enrollment/run-prerequisite-incompatible
authorization exposes the destructive discard action so the operator can
import the required authorization.

The exact button order, output filenames, and failure-closed configuration
requirements are in the
[device implementation contract](../../docs/research/lab-002-device-implementation.md).

## Safety boundary

This fixture is only for repeatable builds and tests of artifacts owned by the project. It contains no DRM bypass, decryption, code-signing circumvention, device extraction, installed-app export, or third-party application acquisition capability. Do not extend it with those capabilities.

## Generate and build

Install XcodeGen, then copy the fixture to a disposable directory before generating the project. Keeping the spec and generated project together preserves Xcode's relative Info.plist paths without writing generated files into the repository:

```sh
work_dir="$(mktemp -d)"
cp -R fixtures/DemoLab "$work_dir/DemoLab"

xcodegen generate \
  --spec "$work_dir/DemoLab/project.yml" \
  --project "$work_dir/DemoLab"

xcodebuild \
  -project "$work_dir/DemoLab/DemoLab.xcodeproj" \
  -scheme DemoLab \
  -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$work_dir/DerivedData" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  build
```

The built fixture is under `DerivedData/Build/Products/Debug-iphonesimulator/DemoLab.app`. Its dynamic framework and share extension are embedded at:

```text
DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework
DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension
```

The generated `DemoLab` scheme also has an explicit `DemoLabTests` test action.
Select an available Simulator identifier from `xcrun simctl list devices
available`, then run the device-free storage tests:

```sh
xcodebuild \
  -project "$work_dir/DemoLab/DemoLab.xcodeproj" \
  -scheme DemoLab \
  -configuration Debug \
  -destination 'platform=iOS Simulator,id=SIMULATOR-UDID' \
  -derivedDataPath "$work_dir/DerivedData" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  test
```

DemoFramework's install name and the app dependency must both be
`@rpath/DemoFramework.framework/DemoFramework`. The controlled Fastlane check
validates that linkage in the Simulator product and packaged IPA; the signed
workflow repeats it for the Archive, exported IPA, and upload-time Archive
revalidation.

The generated `.xcodeproj`, copied fixture, and `DerivedData` directory are disposable build products and must not be committed.
