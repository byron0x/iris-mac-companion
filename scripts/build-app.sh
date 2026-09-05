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
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "$binary" "$bundle/Contents/MacOS/IRISCompanion"
cp Resources/Info.plist "$bundle/Contents/Info.plist"
cp Resources/IRISAvatar.jpg "$bundle/Contents/Resources/"
cp Resources/HANSIcon.png Resources/IRIS.icns "$bundle/Contents/Resources/"
cp LICENSE THIRD_PARTY_NOTICES.md "$bundle/Contents/Resources/"
python3 scripts/prepare-clamav.py
codesign --force --sign - "$bundle"
printf 'Local development app: %s\n' "$bundle"
