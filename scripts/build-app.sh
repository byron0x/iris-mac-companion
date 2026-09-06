#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Local builds are ad-hoc signed for development only. release.sh creates public builds.
configuration="${CONFIGURATION:-debug}"
if [[ "${UNIVERSAL:-0}" == "1" ]]; then
  for arch in arm64 x86_64; do
    swift build -c "$configuration" --product IRISCompanion --triple "$arch-apple-macosx13.0"
  done
  arm_binary="$(swift build -c "$configuration" --triple arm64-apple-macosx13.0 --show-bin-path)/IRISCompanion"
  intel_binary="$(swift build -c "$configuration" --triple x86_64-apple-macosx13.0 --show-bin-path)/IRISCompanion"
  mkdir -p .build/universal
  binary="$PWD/.build/universal/IRISCompanion"
  /usr/bin/lipo -create "$arm_binary" "$intel_binary" -output "$binary"
else
  swift build -c "$configuration"
  binary="$(swift build -c "$configuration" --show-bin-path)/IRISCompanion"
fi
bundle="$PWD/dist/IRIS Mac Companion.app"
if [[ "$configuration" == "debug" ]]; then bundle="$PWD/dist/IRIS Mac Companion Development.app"; fi
# Never merge a new release into a previously signed app bundle.
rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "$binary" "$bundle/Contents/MacOS/IRISCompanion"
cp Resources/Info.plist "$bundle/Contents/Info.plist"
if [[ "$configuration" == "debug" ]]; then
  /usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier io.undercoveriris.companion.development' "$bundle/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c 'Set :CFBundleDisplayName IRIS Development' "$bundle/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c 'Delete :CFBundleURLTypes' "$bundle/Contents/Info.plist"
fi
cp Resources/IRISAvatar.jpg "$bundle/Contents/Resources/"
cp Resources/HANSIcon.png Resources/IRIS.icns "$bundle/Contents/Resources/"
cp LICENSE THIRD_PARTY_NOTICES.md "$bundle/Contents/Resources/"
ditto Resources/Licenses "$bundle/Contents/Resources/Licenses"
IRIS_APP_BUNDLE="$bundle" python3 scripts/prepare-clamav.py
sparkle=$(python3 -c 'from pathlib import Path; p=list(Path(".build/artifacts").glob("*/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework")); assert len(p)==1, "Expected one pinned Sparkle framework"; print(p[0].resolve())')
[[ -d "$sparkle" ]] || { echo 'Resolved Sparkle framework is missing.' >&2; exit 1; }
ditto "$sparkle" "$bundle/Contents/Frameworks/Sparkle.framework"
# Remove build-machine metadata before signing, never from a user's installed app.
xattr -cr "$bundle"
codesign --force --sign - "$bundle"
printf 'Local development app: %s\n' "$bundle"
