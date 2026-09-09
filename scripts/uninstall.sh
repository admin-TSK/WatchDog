#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
echo 'Removing WatchDog and restoring recorded settings requires administrator authentication.'
/usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/manage.py" uninstall

/bin/bash "$REPO_ROOT/scripts/uninstall-menubar.sh"
