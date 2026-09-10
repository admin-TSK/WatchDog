#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/scripts/common.sh"
/bin/bash "$REPO_ROOT/scripts/build.sh"
/bin/bash "$REPO_ROOT/scripts/build-menubar.sh"
echo 'Installing WatchDog requires administrator authentication.'
/usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/manage.py" install
/usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" install
"$PYTHON_BIN" -I "$REPO_ROOT/src/menu_install.py" enable-login
