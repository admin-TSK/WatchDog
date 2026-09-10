#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
/bin/bash "$REPO_ROOT/scripts/build.sh"
"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_watchdog.py"
"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_manage.py"
"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_polling.py"
"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_processes.py"
"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_targets.py"
for script in "$REPO_ROOT"/install.sh "$REPO_ROOT"/uninstall.sh "$REPO_ROOT"/scripts/*.sh; do /bin/bash -n "$script"; done

"$PYTHON_BIN" -I "$REPO_ROOT/tests/test_events.py"
/bin/bash "$REPO_ROOT/scripts/build-menubar.sh"

xcrun swiftc "$REPO_ROOT/src/menubar/PanelGeometry.swift" "$REPO_ROOT/tests/test_layout.swift" -o "$REPO_ROOT/build/test-layout"
"$REPO_ROOT/build/test-layout"

xcrun swiftc "$REPO_ROOT/src/menubar/Activity.swift" "$REPO_ROOT/tests/test_activity.swift" -o "$REPO_ROOT/build/test-activity"
"$REPO_ROOT/build/test-activity"
