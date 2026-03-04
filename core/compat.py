"""
core/compat.py  —  Kryphorix OS Compatibility & Feature Detection Layer
==========================================================================
This module is the backbone of cross-platform support. Every OS-specific
decision in the tool routes through here.

Supported platforms:
  • Kali Linux (and all Debian/Ubuntu derivatives)
  • macOS (Intel + Apple Silicon, Homebrew + system Python)
  • Windows 10/11 (PowerShell 5+, WSL optional)

Auto-adapts to:
  • New OS versions (Python 3.13+, macOS 15+, Windows 12, etc.)
  • Externally-managed Python environments (PEP 668)
  • Virtual environments (venv, conda, pipx, pyenv)
  • Privilege levels (root, sudo-capable, standard user)
"""

import sys
import os
import platform
import shutil
import subprocess
import importlib
import importlib.util
from pathlib import Path

# ── Platform detection ─────────────────────────────────────────────────────────
OS_NAME    = platform.system()           # "Linux" | "Darwin" | "Windows"
OS_VERSION = platform.version()
OS_RELEASE = platform.release()
IS_WINDOWS = OS_NAME == "Windows"
IS_MACOS   = OS_NAME == "Darwin"
IS_LINUX   = OS_NAME == "Linux"
ARCH       = platform.machine().lower()  # "x86_64" | "arm64" | "aarch64"
IS_ARM     = "arm" in ARCH or "aarch64" in ARCH

# Distro detection (Linux only)
IS_KALI   = False
IS_UBUNTU = False
IS_DEBIAN = False
IS_FEDORA = False
IS_ARCH   = False
DISTRO    = "unknown"

if IS_LINUX:
    try:
        txt = Path("/etc/os-release").read_text(errors="ignore").lower()
        if "kali" in txt:
            IS_KALI   = True; DISTRO = "kali"
        elif "ubuntu" in txt:
            IS_UBUNTU = True; DISTRO = "ubuntu"
        elif "debian" in txt:
            IS_DEBIAN = True; DISTRO = "debian"
        elif "fedora" in txt:
            IS_FEDORA = True; DISTRO = "fedora"
        elif "arch" in txt:
            IS_ARCH   = True; DISTRO = "arch"
    except Exception:
        pass

# macOS version detection
MACOS_MAJOR = 0
if IS_MACOS:
    try:
        MACOS_MAJOR = int(platform.mac_ver()[0].split(".")[0])
    except Exception:
        pass

# Windows version
WIN_MAJOR = 0
if IS_WINDOWS:
    try:
        WIN_MAJOR = int(platform.version().split(".")[0])
    except Exception:
        pass

# Python version helpers
PY_MAJOR  = sys.version_info.major
PY_MINOR  = sys.version_info.minor
PY_MICRO  = sys.version_info.micro
PY_VER    = (PY_MAJOR, PY_MINOR)
PY_VER_STR = f"{PY_MAJOR}.{PY_MINOR}.{PY_MICRO}"


# ── Privilege detection ────────────────────────────────────────────────────────
def is_elevated() -> bool:
    """Return True if running as root/Administrator."""
    try:
        if IS_WINDOWS:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def can_sudo() -> bool:
    """Return True if current user can run sudo without password (Linux/macOS)."""
    if IS_WINDOWS:
        return False
    try:
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


# ── Binary capability detection ────────────────────────────────────────────────
def has_binary(name: str) -> bool:
    return shutil.which(name) is not None

def get_wireless_tool() -> str:
    """Return the best available wireless scanning tool for this OS."""
    if IS_LINUX:
        if has_binary("nmcli"):   return "nmcli"
        if has_binary("iwlist"):  return "iwlist"
        if has_binary("iw"):      return "iw"
        return None
    elif IS_MACOS:
        # airport binary location changes across macOS versions
        airport_paths = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "/usr/local/bin/airport",
        ]
        for p in airport_paths:
            if Path(p).exists():
                return p
        # macOS 14+ uses system_profiler instead
        if MACOS_MAJOR >= 14 and has_binary("system_profiler"):
            return "system_profiler"
        return None
    elif IS_WINDOWS:
        return "netsh"   # Always available
    return None

def get_nmap_binary() -> str:
    """Return nmap binary path if available."""
    for name in ["nmap", "nmap.exe"]:
        p = shutil.which(name)
        if p:
            return p
    # Common install paths
    common = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
    ]
    for p in common:
        if Path(p).exists():
            return p
    return None

def get_ssh_audit_binary() -> str:
    for name in ["ssh-audit", "ssh_audit"]:
        p = shutil.which(name)
        if p:
            return p
    return None


# ── Python environment detection ───────────────────────────────────────────────
def in_virtualenv() -> bool:
    return (
        hasattr(sys, "real_prefix") or
        (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix) or
        bool(os.environ.get("VIRTUAL_ENV")) or
        bool(os.environ.get("CONDA_DEFAULT_ENV")) or
        bool(os.environ.get("PIPX_HOME"))
    )

def is_externally_managed() -> bool:
    """
    Detect PEP 668 externally-managed Python (e.g. Kali 2024+, Ubuntu 23.04+,
    Homebrew Python 3.12+). When True we must pass --break-system-packages
    OR install into a user/venv.
    """
    if in_virtualenv():
        return False
    # Check for EXTERNALLY-MANAGED marker file
    for sp in getattr(sys, "path", []):
        if Path(sp, "EXTERNALLY-MANAGED").exists():
            return True
    # Dry-run pip check
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--dry-run", "pip"],
            capture_output=True, text=True, timeout=15
        )
        return "externally-managed" in (r.stderr + r.stdout)
    except Exception:
        return False

def get_pip_flags() -> list:
    """
    Return the correct pip flags for this Python environment.
    Future-proof: always check at runtime, never hardcode.
    """
    if in_virtualenv():
        return []
    if IS_WINDOWS:
        return []
    if is_externally_managed():
        return ["--break-system-packages"]
    # For newer Python where pip might warn even without the marker file:
    if IS_MACOS and PY_VER >= (3, 12):
        return ["--break-system-packages"]
    return []


# ── OS-aware temp/config directories ──────────────────────────────────────────
def get_config_dir(app_name: str = "Kryphorix") -> Path:
    """Return OS-standard config directory."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")
        return Path(base) / app_name
    elif IS_MACOS:
        return Path.home() / "Library" / "Application Support" / app_name
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
        return Path(xdg) / app_name.lower()

def get_log_dir(app_name: str = "Kryphorix") -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        return Path(base) / app_name / "logs"
    elif IS_MACOS:
        return Path.home() / "Library" / "Logs" / app_name
    else:
        return Path("/var/log") / app_name.lower() if is_elevated() else \
               Path.home() / ".local" / "share" / app_name.lower() / "logs"


# ── Feature matrix ────────────────────────────────────────────────────────────
def get_feature_matrix() -> dict:
    """
    Return a dict describing what features are available on this platform.
    Used by self-test and modules to skip unsupported operations gracefully.
    """
    return {
        "platform":          OS_NAME,
        "distro":            DISTRO,
        "os_version":        OS_RELEASE,
        "arch":              ARCH,
        "python":            PY_VER_STR,
        "elevated":          is_elevated(),
        "can_sudo":          can_sudo(),
        "in_virtualenv":     in_virtualenv(),
        "externally_managed":is_externally_managed(),
        "wireless_tool":     get_wireless_tool(),
        "nmap_binary":       get_nmap_binary(),
        "ssh_audit_binary":  get_ssh_audit_binary(),
        "has_nmap":          get_nmap_binary() is not None,
        "has_nmcli":         has_binary("nmcli"),
        "has_iwlist":        has_binary("iwlist"),
        "has_netsh":         IS_WINDOWS,
        "has_airport":       get_wireless_tool() in (
                                 "/System/Library/PrivateFrameworks/Apple80211.framework/"
                                 "Versions/Current/Resources/airport",
                                 "system_profiler"
                             ) if IS_MACOS else False,
        "is_kali":           IS_KALI,
        "is_macos":          IS_MACOS,
        "is_windows":        IS_WINDOWS,
        "is_arm":            IS_ARM,
    }

def describe_platform() -> str:
    """Human-readable one-liner for the current platform."""
    parts = [OS_NAME]
    if IS_KALI:
        parts.append("Kali Linux")
    elif DISTRO != "unknown":
        parts.append(DISTRO.title())
    parts.append(OS_RELEASE[:20])
    if IS_ARM:
        parts.append("ARM")
    parts.append(f"Python {PY_VER_STR}")
    return " | ".join(parts)
