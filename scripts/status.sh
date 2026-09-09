#!/bin/bash
set -euo pipefail
source "$(dirname -- "$0")/common.sh"
exec "$PYTHON_BIN" -I "$REPO_ROOT/src/manage.py" status
