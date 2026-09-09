#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
/bin/bash "$REPO_ROOT/scripts/build.sh"
echo 'Installing WatchDog requires administrator authentication.'
exec /usr/bin/sudo "$PYTHON_BIN" -I "$REPO_ROOT/src/manage.py" install
