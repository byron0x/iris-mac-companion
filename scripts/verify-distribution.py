#!/usr/bin/env python3
"""Verify an extracted public Mac release without scanning personal files."""
import argparse
import pathlib
import plistlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("bundle", type=pathlib.Path)
parser.add_argument("--team-id", required=True)
parser.add_argument("--version", required=True)
args = parser.parse_args()
bundle = args.bundle.resolve()
with (bundle / "Contents/Info.plist").open("rb") as stream:
    info = plistlib.load(stream)
assert info["CFBundleIdentifier"] == "io.undercoveriris.companion"
assert info["CFBundleShortVersionString"] == args.version
assert info["IRISSigningTeam"] == args.team_id
assert info["LSMinimumSystemVersion"] == "13.0"
assert not list(bundle.rglob("._*")), "Extracted app contains unsigned AppleDouble metadata"
if tuple(map(int, args.version.split('.'))) >= (0, 3, 1):
    assert info["SUPublicEDKey"] == "PocwmuvcZk1XcKZSHTJXZV4dcQUMZq4JhBeQm37NtVE="
    assert info["SUFeedURL"] == "https://raw.githubusercontent.com/byron0x/iris-mac-companion/main/updates/appcast.xml"
    assert info["SURequireSignedFeed"] and info["SUVerifyUpdateBeforeExtraction"]
    assert (bundle / "Contents/Frameworks/Sparkle.framework/Sparkle").is_file()
    assert (bundle / "Contents/Resources/Licenses/Sparkle.txt").is_file()
requirement = ('=anchor apple generic and identifier "io.undercoveriris.companion" '
               f'and certificate leaf[subject.OU] = "{args.team_id}"')
subprocess.run(["codesign", "--verify", "--deep", "--strict", "-R", requirement, str(bundle)], check=True)
signature = subprocess.run(["codesign", "-d", "--verbose=4", str(bundle)], check=True, capture_output=True, text=True)
assert "runtime" in signature.stderr, "Hardened runtime is required"
assert f"TeamIdentifier={args.team_id}" in signature.stderr
assert "Timestamp=" in signature.stderr, "Secure timestamp is required"
for relative in ("MacOS/IRISCompanion", "Helpers/clamscan", "Helpers/freshclam", "Helpers/sigtool"):
    subprocess.run(["lipo", str(bundle / "Contents" / relative), "-verify_arch", "arm64", "x86_64"], check=True)
subprocess.run(["xcrun", "stapler", "validate", str(bundle)], check=True)
subprocess.run(["spctl", "--assess", "--type", "execute", "--verbose=2", str(bundle)], check=True)
for relative in ("Resources/LICENSE", "Resources/THIRD_PARTY_NOTICES.md", "Resources/IRIS.icns", "Resources/HANSIcon.png"):
    assert (bundle / "Contents" / relative).is_file(), relative
print("PASS: release identity, hardened runtime, universal binaries, notarization, Gatekeeper and bundled notices.")
