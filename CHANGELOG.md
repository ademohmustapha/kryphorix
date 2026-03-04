# Kryphorix v2.0.0 — Complete Rebuild Changelog

## What Was Fixed from Previous Version

### Critical Bugs
- **AD module runtime import bug** — `import re` was placed inside the function body at the wrong indentation, causing silent failures on certain code paths. Fixed: all imports moved to module top.
- **Wireless interface detection** — Hardcoded `wlan0` failed on Kali/Ubuntu systems using modern interface naming (`wlp3s0`, `wlxXXXX` etc.). Fixed: dynamic detection via `iw dev` and `/sys/class/net`.
- **macOS wireless on v14+** — `airport` binary was removed in macOS 14 Sonoma. Fixed: auto-detects OS version and falls back to `system_profiler SPAirPortDataType`.
- **scapy/nmap listed as required but never used** — removed from requirements; scanner now uses built-in sockets with optional nmap binary enhancement.

### OS Compatibility (New in v2)
- **`core/compat.py`** — Comprehensive OS detection layer. Every OS decision routes through here. Handles: Kali, Ubuntu, Debian, Fedora, Arch, macOS (Intel/ARM), Windows 10/11.
- **Future-proof pip flags** — No hardcoded `--break-system-packages`. Runtime detection of externally-managed environments (PEP 668). Works on Python 3.8–3.13+ and future releases.
- **Auto-adapts to OS upgrades** — `updater.py` calls `refresh_os_compat()` after any update to reload the compat layer with fresh detection.

### Missing Features Added
- **`core/workspace.py`** — Session save/resume. Scan state persisted to `/workspaces/`. Load with `--workspace NAME`.
- **Proxy support** — `--proxy http://127.0.0.1:8080` routes all HTTP through Burp Suite, ZAP, or any proxy.
- **Stealth mode** — `--stealth` reduces thread count, adds inter-request delay, quieter TLS negotiation.
- **Rate limiting** — Port scanner now respects configurable RPS limit. Prevents network disruption.
- **Module-level logging** — Every module now uses `logging.getLogger("kryphorix")`. All errors logged to `/logs/kryphorix.log`.
- **`_base.py`** — Shared session management, proxy injection, safe_get/safe_post, port_open, banner grab.
- **Deduplication** — `FindingsManager` silently drops exact duplicate findings across parallel runs.

### Report Engine
- **PDF graceful fallback** — If reportlab unavailable, produces HTML instead of crashing.
- **All formats always work** — JSON/CSV/HTML require only stdlib+requests.

### Launcher Scripts
- `kryphorix.sh` — Linux/macOS launcher with Python version detection
- `kryphorix.bat` — Windows launcher with `py -3` launcher support

### Security
- **Validated Finding dataclass** — Severity and CVSS values validated/normalised in `__post_init__`.
- **GitHub org reference** — Removed fake `KRYPHORIX-SEC` org; updater now uses PyPI endpoint.
- **Audit log chain verification** — `verify_chain()` method to detect tampering.

### Architecture
- **Strict version: v2.0.0** — Clean semantic version reflecting ground-up rebuild.
- **Plugin system** — Fixed dynamic loader; plugins in `plugins/plugin_*.py` auto-discovered.
- **Self-test OS matrix** — Self-test now displays full feature matrix: wireless tool, nmap binary, ssh-audit binary, privilege level.
