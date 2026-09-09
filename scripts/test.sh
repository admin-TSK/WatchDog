#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
/bin/bash "$REPO_ROOT/scripts/build.sh"
"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_watchdog.py"
"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_manage.py"
for script in "$REPO_ROOT"/*.command "$REPO_ROOT"/scripts/*.sh; do /bin/bash -n "$script"; done
