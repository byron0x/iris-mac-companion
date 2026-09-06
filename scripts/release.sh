#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DEVELOPER_ID_APPLICATION:?Set the exact Developer ID Application certificate name}"
: "${NOTARY_KEYCHAIN_PROFILE:?Set the notarytool Keychain profile name}"
[[ "$DEVELOPER_ID_APPLICATION" == 'Developer ID Application: '* ]] || { echo 'A Developer ID Application identity is required.' >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo 'Commit the reviewed source before creating a public release.' >&2; exit 1; }
swift run IRISCoreChecks
CONFIGURATION=release UNIVERSAL=1 scripts/build-app.sh
python3 scripts/verify-engine.py
bundle="$PWD/dist/IRIS Mac Companion.app"
version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$bundle/Contents/Info.plist")
archive="$PWD/dist/IRIS-Mac-$version.zip"
team="${DEVELOPER_ID_APPLICATION##*(}"
team="${team%)}"
/usr/libexec/PlistBuddy -c "Add :IRISSigningTeam string $team" "$bundle/Contents/Info.plist"
while IFS= read -r -d '' file; do
  if /usr/bin/file "$file" | /usr/bin/grep -q 'Mach-O'; then
    codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APPLICATION" "$file"
  fi
done < <(find "$bundle/Contents/Frameworks" "$bundle/Contents/Helpers" -type f -print0)
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APPLICATION" "$bundle"
codesign --verify --deep --strict "$bundle"
ditto -c -k --keepParent "$bundle" "$archive"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait --output-format json > dist/notarization.json
python3 - <<'PY'
import json
with open('dist/notarization.json') as file:
    if json.load(file).get('status') != 'Accepted': raise SystemExit('Apple has not accepted this build. Do not publish.')
PY
xcrun stapler staple "$bundle"
xcrun stapler validate "$bundle"
spctl --assess --type execute --verbose=2 "$bundle"
ditto -c -k --keepParent "$bundle" "$archive"
(cd dist && shasum -a 256 "IRIS-Mac-$version.zip" > "IRIS-Mac-$version.zip.sha256")
printf 'Verified release archive: %s\n' "$archive"
