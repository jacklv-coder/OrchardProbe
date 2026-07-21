# DemoLab iOS fixture

DemoLab is a small, first-party iOS application used to test OrchardProbe against artifacts that this project owns and compiles itself. It deliberately includes multiple Mach-O products:

- `DemoLab.app`, a SwiftUI application with bundle identifier `com.example.orchardprobe.demolab`;
- `DemoFramework.framework`, a dynamic Objective-C framework whose public API is called by the app; and
- `DemoShareExtension.appex`, a Swift share extension with bundle identifier `com.example.orchardprobe.demolab.share`.

Every source file is kept in this directory, and the fixture has no third-party source or binary dependencies.

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

The generated `.xcodeproj`, copied fixture, and `DerivedData` directory are disposable build products and must not be committed.
