#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
app="$REPO_ROOT/build/WatchDog.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
for arch in arm64 x86_64; do
  xcrun swiftc -O -parse-as-library -swift-version 5 -sdk "$sdk" -target "${arch}-apple-macosx14.0" \
    "$REPO_ROOT/src/menubar/WatchDog.swift" "$REPO_ROOT/src/menubar/Activity.swift" "$REPO_ROOT/src/menubar/PanelGeometry.swift" -o "$REPO_ROOT/build/WatchDog-$arch"
done
xcrun lipo -create "$REPO_ROOT/build/WatchDog-arm64" "$REPO_ROOT/build/WatchDog-x86_64" -output "$app/Contents/MacOS/WatchDog"
"$PYTHON_BIN" -I - "$app" "$REPO_ROOT/VERSION" <<'PY'
from pathlib import Path
import plistlib, sys
app=Path(sys.argv[1])
info={'CFBundleIdentifier':'local.watchdog.menubar','CFBundleName':'WatchDog','CFBundleDisplayName':'WatchDog',
      'CFBundleExecutable':'WatchDog','CFBundlePackageType':'APPL','CFBundleShortVersionString':Path(sys.argv[2]).read_text().strip(),
      'CFBundleVersion':'2','LSMinimumSystemVersion':'14.0','LSUIElement':True,
      'NSHighResolutionCapable':True,'NSPrincipalClass':'NSApplication'}
(app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
PY
codesign --force --sign - "$app"
codesign --verify --strict "$app"
echo 'WatchDog menu bar app built for Apple Silicon and Intel.'
