#!/usr/bin/env bash
# php2shell lab setup — CVE-2026-109618 / CVE-2026-109619
# Authorized testing only. Run against systems you own or have written permission to test.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLKIT_DIR="$SCRIPTS_DIR/../toolkit"

echo "[*] Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "[-] Docker not found. Install Docker Desktop first."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[-] Python 3 not found."; exit 1; }
command -v git >/dev/null 2>&1 || { echo "[-] git not found."; exit 1; }

PYTHON_VERSION=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PYTHON_VERSION" -lt 11 ]; then
  echo "[-] Python 3.11+ required (found 3.$PYTHON_VERSION)"
  exit 1
fi

docker info >/dev/null 2>&1 || { echo "[-] Docker daemon not running. Start Docker Desktop first."; exit 1; }

echo "[+] Prerequisites OK"

# Clone devploit toolkit if not already present
if [ ! -d "$TOOLKIT_DIR" ]; then
  echo "[*] Cloning devploit/php2shell toolkit..."
  git clone https://github.com/devploit/php2shell.git "$TOOLKIT_DIR"
else
  echo "[*] Toolkit already present at $TOOLKIT_DIR"
fi

cd "$TOOLKIT_DIR"

# Bootstrap the upstream exploit (9bie)
echo "[*] Bootstrapping upstream exploit..."
python3 tools/bootstrap_upstream.py

# Start labs
echo "[*] Starting Docker lab containers..."
python3 tools/php2shell_labs.py up

echo ""
echo "[+] Setup complete. Lab containers:"
echo "    PHP 7.4.33  -> http://127.0.0.1:8100/ (no RCE)"
echo "    PHP 8.0.30  -> http://127.0.0.1:8101/ (no RCE)"
echo "    PHP 8.1.34  -> http://127.0.0.1:8102/ (no RCE)"
echo "    PHP 8.2.34  -> http://127.0.0.1:8103/ (no RCE)"
echo "    PHP 8.3.35  -> http://127.0.0.1:8104/ (no RCE)"
echo "    PHP 8.4.26  -> http://127.0.0.1:8105/ (RCE confirmed)"
echo "    PHP 8.5.11  -> http://127.0.0.1:8106/ (RCE confirmed)"
echo ""
echo "Run ./run_exploit.sh to test RCE against PHP 8.5.11"
