#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
/bin/bash "$REPO_ROOT/scripts/build-menubar.sh"
/usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" install
"$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" enable-login
