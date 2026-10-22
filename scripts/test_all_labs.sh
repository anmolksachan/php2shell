#!/usr/bin/env bash
# Test the exploit against all lab containers and print a summary table.
# Authorized testing only.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PHP2SHELL="$SCRIPTS_DIR/../toolkit"

if [ ! -d "$PHP2SHELL" ]; then
  echo "[-] Toolkit not found — run ./setup.sh first"
  exit 1
fi

cd "$PHP2SHELL"

echo "[*] Running dispatcher against all labs..."
python3 tools/php2shell_labs.py test
