#!/usr/bin/env bash
# Stop and remove all php2shell lab containers.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PHP2SHELL="$SCRIPTS_DIR/../toolkit"

if [ ! -d "$PHP2SHELL" ]; then
  echo "[-] Toolkit not found — nothing to clean up"
  exit 0
fi

cd "$PHP2SHELL"

echo "[*] Stopping lab containers..."
python3 tools/php2shell_labs.py down

echo "[+] All lab containers stopped."
