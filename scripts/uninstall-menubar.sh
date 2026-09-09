#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
/usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" remove
"$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" disable-login
