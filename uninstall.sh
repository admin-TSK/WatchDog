#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/scripts/common.sh"
echo 'Removing WatchDog and restoring recorded settings requires administrator authentication.'
/usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/manage.py" uninstall
/usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" remove
"$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" disable-login
