#!/usr/bin/env bash
# Records sanitized fixtures from a live Pi-hole (read-only). See record-fixtures.py.
set -euo pipefail
exec python3 "$(dirname "$0")/record-fixtures.py" "$@"
