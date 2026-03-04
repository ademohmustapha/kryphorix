#!/usr/bin/env bash
# kryphorix.sh  —  Kryphorix v2.0.0 Launcher (Linux / macOS)
# Detects Python, handles venv, advises on privileges.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON=""

# Find Python 3.8+
for cmd in python3 python python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=${ver%%.*}; minor=${ver##*.}
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[FATAL] Python 3.8+ not found. Install with:"
    echo "  sudo apt install python3  (Debian/Kali/Ubuntu)"
    echo "  brew install python       (macOS)"
    exit 1
fi

# Wireless needs root
if [[ "$*" == *"--wifi"* ]] || [[ "$*" == *"--full"* ]]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "[*] Wireless and full scans work best with elevated privileges."
        echo "[*] Consider: sudo $0 $*"
    fi
fi

cd "$SCRIPT_DIR"
exec "$PYTHON" kryphorix.py "$@"
