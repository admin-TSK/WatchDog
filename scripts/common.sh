#!/bin/bash
# Sourced by the repository scripts.
set -euo pipefail
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

pick_python() {
  local candidate
  if [[ -n "${WATCHDOG_PYTHON:-}" ]]; then
    candidate="$WATCHDOG_PYTHON"
    if [[ ! -x "$candidate" ]]; then
      echo "WATCHDOG_PYTHON is not executable: $candidate" >&2
      exit 1
    fi
    PYTHON_BIN="$("$candidate" -I -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"; print(sys.executable)')"
    return
  fi
  for candidate in /usr/bin/python3 "$(command -v python3 || true)"; do
    [[ -n "$candidate" && -x "$candidate" ]] || continue
    if "$candidate" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' 2>/dev/null; then
      PYTHON_BIN="$("$candidate" -I -c 'import sys; print(sys.executable)')"
      return
    fi
  done
  echo 'WatchDog requires Python 3.10 or later. Set WATCHDOG_PYTHON to its executable.' >&2
  exit 1
}

pick_python
case "$PYTHON_BIN" in
  */opt/homebrew/*|*/Cellar/*|*/Python.framework/Versions/*|*/.pyenv/*|*/venv/*|*/.venv/*)
    echo "WatchDog: warning: $PYTHON_BIN may disappear after an upgrade. Prefer /usr/bin/python3 when it is 3.10+." >&2
    ;;
esac
