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
iconset="$REPO_ROOT/build/WatchDog.iconset"
rm -rf "$iconset" "$REPO_ROOT/build/WatchDog.xcassets"
/usr/bin/iconutil -c iconset -o "$iconset" "$REPO_ROOT/assets/WatchDog.icns"
appiconset="$REPO_ROOT/build/WatchDog.xcassets/AppIcon.appiconset"
mkdir -p "$appiconset"
cp "$iconset"/*.png "$appiconset/"
cat > "$REPO_ROOT/build/WatchDog.xcassets/Contents.json" <<'JSON'
{"info":{"author":"xcode","version":1}}
JSON
cat > "$appiconset/Contents.json" <<'JSON'
{
  "images": [
    {"size":"16x16","idiom":"mac","filename":"icon_16x16.png","scale":"1x"},
    {"size":"16x16","idiom":"mac","filename":"icon_16x16@2x.png","scale":"2x"},
    {"size":"32x32","idiom":"mac","filename":"icon_32x32.png","scale":"1x"},
    {"size":"32x32","idiom":"mac","filename":"icon_32x32@2x.png","scale":"2x"},
    {"size":"128x128","idiom":"mac","filename":"icon_128x128.png","scale":"1x"},
    {"size":"128x128","idiom":"mac","filename":"icon_128x128@2x.png","scale":"2x"},
    {"size":"256x256","idiom":"mac","filename":"icon_256x256.png","scale":"1x"},
    {"size":"256x256","idiom":"mac","filename":"icon_256x256@2x.png","scale":"2x"},
    {"size":"512x512","idiom":"mac","filename":"icon_512x512.png","scale":"1x"},
    {"size":"512x512","idiom":"mac","filename":"icon_512x512@2x.png","scale":"2x"}
  ],
  "info":{"author":"xcode","version":1}
}
JSON
xcrun actool --compile "$resources" --platform macosx --minimum-deployment-target 14.0 \
  --app-icon AppIcon --output-partial-info-plist "$REPO_ROOT/build/WatchDog-icon.plist" \
  --development-region en --target-device mac --enable-on-demand-resources NO \
  "$REPO_ROOT/build/WatchDog.xcassets"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
for arch in arm64 x86_64; do
    xcrun swiftc -O -parse-as-library -swift-version 5 -sdk "$sdk" -target "${arch}-apple-macosx14.0" \
    -framework Intents -framework UserNotifications \
    "$REPO_ROOT/src/menubar/WatchDog.swift" "$REPO_ROOT/src/menubar/Activity.swift" "$REPO_ROOT/src/menubar/PanelGeometry.swift" "$REPO_ROOT/src/menubar/Shields.swift" -o "$REPO_ROOT/build/WatchDog-$arch"
done
xcrun lipo -create "$REPO_ROOT/build/WatchDog-arm64" "$REPO_ROOT/build/WatchDog-x86_64" -output "$app/Contents/MacOS/WatchDog"
"$PYTHON_BIN" -I - "$app" "$REPO_ROOT/VERSION" <<'PY'
from pathlib import Path
import plistlib, sys
app=Path(sys.argv[1])
info={'CFBundleIdentifier':'local.watchdog.menubar','CFBundleName':'WatchDog','CFBundleDisplayName':'WatchDog',
      'CFBundleExecutable':'WatchDog','CFBundlePackageType':'APPL','CFBundleShortVersionString':Path(sys.argv[2]).read_text().strip(),
      'CFBundleVersion':'15','LSMinimumSystemVersion':'14.0','LSUIElement':True,
      'CFBundleIconFile':'WatchDog','CFBundleIconName':'AppIcon',
      'NSHighResolutionCapable':True,'NSPrincipalClass':'NSApplication'}
(app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
PY
codesign --force --sign - "$app"
codesign --verify --strict "$app"
echo 'WatchDog menu bar app built for Apple Silicon and Intel.'
