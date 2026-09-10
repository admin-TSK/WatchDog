#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
if [[ "$(uname -s)" != Darwin ]]; then echo 'WatchDog builds on macOS only.' >&2; exit 1; fi
mkdir -p "$REPO_ROOT/build"
xcrun clang -O2 -Wall -Wextra -Werror -arch arm64 -arch x86_64 \
  -mmacosx-version-min=14.0 \
  -framework Security -framework CoreFoundation \
  "$REPO_ROOT/src/watchdog.c" -o "$REPO_ROOT/build/watchdog"
codesign --force --sign - "$REPO_ROOT/build/watchdog"
codesign --verify --strict "$REPO_ROOT/build/watchdog"
"$PYTHON_BIN" -I -c 'import ast,pathlib,sys; [ast.parse(p.read_text()) for p in pathlib.Path(sys.argv[1]).glob("*.py")]' "$REPO_ROOT/src"
echo 'WatchDog built for Apple Silicon and Intel.'
