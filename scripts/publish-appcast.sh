#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Resources/Info.plist)
archive="$PWD/dist/IRIS-Mac-$version.zip"
python3 scripts/verify-archive.py "$archive"
(cd dist && shasum -a 256 --check "IRIS-Mac-$version.zip.sha256")
feed_stage="$PWD/dist/update-feed-$version"
mkdir -p "$feed_stage" updates
cp "$archive" "$feed_stage/"
cp "releases/mac-$version-notes.txt" "$feed_stage/IRIS-Mac-$version.txt"
# Never export or echo the signing key: Sparkle reads the dedicated Keychain item.
.build/artifacts/iris-mac-companion/Sparkle/bin/generate_appcast \
  --account iris-mac-updates --maximum-deltas 0 --embed-release-notes \
  --download-url-prefix "https://github.com/byron0x/iris-mac-companion/releases/download/v$version/" \
  --link 'https://app.undercoveriris.io/device' \
  -o updates/appcast.xml "$feed_stage"
.build/artifacts/iris-mac-companion/Sparkle/bin/sign_update --account iris-mac-updates --verify updates/appcast.xml
printf 'Signed update feed ready. Publish only after the exact release archive passes verification.\n'
