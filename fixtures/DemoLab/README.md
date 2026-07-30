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
`group.com.example.orchardprobe.demolab`; a future reviewed signed LAB-002
build must replace it with the registered first-party group for both the app
and share extension.
See the
[controlled TestFlight runbook](../../docs/development/demolab-testflight.md).
The branch-local LAB-002 app/extension capability, fixed-container, and state
machine boundary is documented in the
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
