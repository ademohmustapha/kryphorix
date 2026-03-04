"""
core/bootstrap.py  —  Kryphorix Smart Dependency Bootstrapper
==============================================================
Handles automatic installation of all Python dependencies.

Designed to work across:
  • Kali Linux 2024+ (externally-managed PEP 668)
  • Ubuntu 23.04+ (externally-managed)
  • macOS 13–15+ (Homebrew & system Python)
  • Windows 10/11 (standard pip)
  • venv / conda / pipx / pyenv environments
  • Future OS releases (runtime detection, not hardcoded flags)
"""

import sys
import subprocess
import importlib
from pathlib import Path

# Import compat; but guard because bootstrap runs before full init
try:
    from core.compat import get_pip_flags, in_virtualenv, describe_platform
except ImportError:
    # Minimal fallbacks if compat not yet importable
    def get_pip_flags():
        return []
    def in_virtualenv():
        return False
    def describe_platform():
        import platform
        return platform.system()

# ── Package manifest ───────────────────────────────────────────────────────────
# Format: import_name → pip_spec
REQUIRED = {
    "requests":     "requests>=2.31",
    "rich":         "rich>=13.7",
    "reportlab":    "reportlab>=4.0",
    "PIL":          "Pillow>=10.0",
    "cryptography": "cryptography>=41.0",
    "bs4":          "beautifulsoup4>=4.12",
    "colorama":     "colorama>=0.4",
    "tabulate":     "tabulate>=0.9",
    "dns":          "dnspython>=2.4",
    "paramiko":     "paramiko>=3.3",
    "yaml":         "PyYAML>=6.0",
    "lxml":         "lxml>=4.9",
    "jinja2":       "Jinja2>=3.1",
}

OPTIONAL = {
    # Better PDF cover pages
    "OpenSSL":  "pyOpenSSL>=23.0",
    # WHOIS lookups
    "whois":    "python-whois>=0.8",
    # ldap3 for AD tests
    "ldap3":    "ldap3>=2.9",
}

_STATUS: dict = {}   # import_name → True/False


def _check(import_name: str) -> bool:
    """Return True if module is importable."""
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


def _pip_install(specs: list, flags: list = None, user_fallback: bool = True) -> bool:
    """
    Attempt pip install with given flags.
    Falls back to --user if standard install fails and not in venv.
    """
    if not specs:
        return True

    base_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet"]
    flags     = flags or []
    cmd       = base_cmd + flags + specs

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            return True
        # If failure due to externally-managed, try --break-system-packages
        if "externally-managed" in (r.stderr + r.stdout) and \
                "--break-system-packages" not in flags:
            return _pip_install(specs, flags + ["--break-system-packages"],
                                user_fallback=user_fallback)
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        pass

    # Fallback: --user install (always works, no root needed)
    if user_fallback and "--user" not in flags and not in_virtualenv():
        try:
            r2 = subprocess.run(
                base_cmd + ["--user"] + specs,
                capture_output=True, text=True, timeout=300
            )
            if r2.returncode == 0:
                # Reload sys.path so user site-packages is found
                import site
                if hasattr(site, "getusersitepackages"):
                    usp = site.getusersitepackages()
                    if usp and usp not in sys.path:
                        sys.path.insert(0, usp)
                return True
        except Exception:
            pass

    return False


def run(verbose: bool = True) -> tuple:
    """
    Check and install all missing packages.

    Returns:
        (all_required_ok: bool, missing_optional: list)
    """
    global _STATUS

    missing_req = []
    missing_opt = []

    for mod, spec in REQUIRED.items():
        ok = _check(mod)
        _STATUS[mod] = ok
        if not ok:
            missing_req.append((mod, spec))

    for mod, spec in OPTIONAL.items():
        ok = _check(mod)
        _STATUS[mod] = ok
        if not ok:
            missing_opt.append((mod, spec))

    if not missing_req and not missing_opt:
        return True, []

    flags = get_pip_flags()

    if missing_req:
        specs = [s for _, s in missing_req]
        names = [m for m, _ in missing_req]
        if verbose:
            print(f"\n[*] Installing {len(specs)} required package(s): {', '.join(names)}")

        ok = _pip_install(specs, flags)

        if ok:
            if verbose:
                print(f"[+] Required packages installed successfully.\n")
            # Refresh status
            for mod, _ in missing_req:
                _STATUS[mod] = _check(mod)
        else:
            if verbose:
                print("[!] Auto-install failed. Please install manually:")
                print(f"    pip install {' '.join(specs)}")
                print("    or: pip install -r requirements.txt\n")
            still_missing = [m for m, _ in missing_req if not _STATUS.get(m)]
            if still_missing:
                return False, [m for m, _ in missing_opt]

    if missing_opt:
        opt_specs = [s for _, s in missing_opt]
        opt_names = [m for m, _ in missing_opt]
        if verbose:
            print(f"[*] Installing {len(opt_specs)} optional package(s): {', '.join(opt_names)}")
        _pip_install(opt_specs, flags, user_fallback=True)
        for mod, _ in missing_opt:
            _STATUS[mod] = _check(mod)

    still_opt_missing = [m for m, _ in missing_opt if not _STATUS.get(m)]
    return True, still_opt_missing


def is_available(import_name: str) -> bool:
    """Check cached availability of a module (after bootstrap.run())."""
    if import_name in _STATUS:
        return _STATUS[import_name]
    result = _check(import_name)
    _STATUS[import_name] = result
    return result
