#!/bin/bash
# Sourced by the repository scripts.
set -euo pipefail
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${WATCHDOG_PYTHON:-$(command -v python3 || true)}"
if [[ -z "$PYTHON_BIN" ]]; then
  echo 'WatchDog requires Python 3.10 or later. Set WATCHDOG_PYTHON to its executable.' >&2
  exit 1
fi
PYTHON_BIN="$("$PYTHON_BIN" -I -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"; print(sys.executable)')"
