#!/bin/bash
set -euo pipefail
exec /bin/bash "$(dirname -- "$0")/scripts/install.sh"
