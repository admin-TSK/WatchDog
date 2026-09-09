#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
echo 'Removing WatchDog and restoring recorded settings requires administrator authentication.'
exec /usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/manage.py" uninstall
