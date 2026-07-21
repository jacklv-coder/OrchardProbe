# DemoLab simulator fixture

DemoLab is a small, repository-owned iOS Simulator app used to exercise the project's build and analysis paths without a physical device or third-party application. It contains a main app, `DemoFramework.framework`, and `DemoShareExtension.appex`.

This is a simulator-only test fixture built from source. It has no FairPlay or other DRM, is not a decrypted application, and must not be treated as evidence that device-side extraction or IPA export works.

## Build locally

Install Xcode and XcodeGen on macOS. From the repository root, run:

```sh
brew list xcodegen || brew install xcodegen
xcodegen generate \
  --spec fixtures/DemoLab/project.yml \
  --project fixtures/DemoLab
xcodebuild \
  -project fixtures/DemoLab/DemoLab.xcodeproj \
  -scheme DemoLab \
  -configuration Debug \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath fixtures/DemoLab/DerivedData \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  build
```

Both `fixtures/DemoLab/DemoLab.xcodeproj` and `fixtures/DemoLab/DerivedData` are generated locally and ignored by Git. Pull requests copy the fixture to the runner's temporary `fixtures/DemoLab` directory, then generate and build it there, so CI does not modify the checkout.

## Build products

After a local Debug build, the products are under:

```text
fixtures/DemoLab/DerivedData/Build/Products/Debug-iphonesimulator/
```

The fixture binaries checked by CI are:

```text
DemoLab.app/DemoLab
DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework
DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension
```
