#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
app="$REPO_ROOT/build/WatchDog.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
resources="$app/Contents/Resources"
cp "$REPO_ROOT/assets/logo.png" "$resources/Logo.png"
cp "$REPO_ROOT/assets/Logo@2x.png" "$resources/Logo@2x.png"
cp "$REPO_ROOT/assets/Logo@3x.png" "$resources/Logo@3x.png"
cp "$REPO_ROOT/assets/MenuBarIcon.png" "$resources/MenuBarIcon.png"
cp "$REPO_ROOT/assets/MenuBarIcon@2x.png" "$resources/MenuBarIcon@2x.png"
cp "$REPO_ROOT/assets/MenuBarIcon@3x.png" "$resources/MenuBarIcon@3x.png"
cp "$REPO_ROOT/assets/AppIcon.png" "$resources/AppIcon.png"
cp "$REPO_ROOT/assets/AppIcon@2x.png" "$resources/AppIcon@2x.png"
cp "$REPO_ROOT/assets/WatchDog.icns" "$resources/WatchDog.icns"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
for arch in arm64 x86_64; do
    xcrun swiftc -O -parse-as-library -swift-version 5 -sdk "$sdk" -target "${arch}-apple-macosx14.0" \
    "$REPO_ROOT/src/menubar/WatchDog.swift" "$REPO_ROOT/src/menubar/Activity.swift" "$REPO_ROOT/src/menubar/PanelGeometry.swift" "$REPO_ROOT/src/menubar/Shields.swift" -o "$REPO_ROOT/build/WatchDog-$arch"
done
xcrun lipo -create "$REPO_ROOT/build/WatchDog-arm64" "$REPO_ROOT/build/WatchDog-x86_64" -output "$app/Contents/MacOS/WatchDog"
"$PYTHON_BIN" -I - "$app" "$REPO_ROOT/VERSION" <<'PY'
from pathlib import Path
import plistlib, sys
app=Path(sys.argv[1])
info={'CFBundleIdentifier':'local.watchdog.menubar','CFBundleName':'WatchDog','CFBundleDisplayName':'WatchDog',
      'CFBundleExecutable':'WatchDog','CFBundlePackageType':'APPL','CFBundleShortVersionString':Path(sys.argv[2]).read_text().strip(),
      'CFBundleVersion':'9','LSMinimumSystemVersion':'14.0','LSUIElement':True,
      'CFBundleIconFile':'WatchDog',
      'NSHighResolutionCapable':True,'NSPrincipalClass':'NSApplication'}
(app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
PY
codesign --force --sign - "$app"
codesign --verify --strict "$app"
echo 'WatchDog menu bar app built for Apple Silicon and Intel.'
