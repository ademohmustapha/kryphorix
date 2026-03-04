"""
core/updater.py  —  Kryphorix Auto-Update System
==================================================
Handles three types of updates:
  1. Tool updates — via git pull if repo detected, otherwise user guidance
  2. OWASP Top 10 — annually auto-detects new lists (2025, future years)
  3. OS compatibility — re-runs compat checks after each update to ensure
     pip flags, binary paths, and feature matrix remain current
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Official PyPI endpoint (no fake GitHub repo)
PYPI_URL   = "https://pypi.org/pypi/kryphorix/json"
OWASP_BASE = "https://raw.githubusercontent.com/OWASP/Top10/master/"
CACHE_FILE = ".update_cache.json"
OWASP_DIR  = "assets"
CHECK_INTERVAL_HOURS = 24


class UpdateManager:
    def __init__(self, root_dir=None, current_version: str = "2.0.0",
                 console=None, logger=None):
        self._root    = Path(root_dir) if root_dir else Path.cwd()
        self._cur_ver = current_version
        self._con     = console
        self._log     = logger
        self._cache   = self._root / CACHE_FILE
        self._owasp_d = self._root / OWASP_DIR
        self._owasp_d.mkdir(exist_ok=True)

    def _print(self, msg: str):
        if self._con:
            try:
                self._con.print(msg)
            except Exception:
                print(msg)
        else:
            print(msg)

    def _log_info(self, msg: str):
        if self._log:
            self._log.info(msg)

    def _load_cache(self) -> dict:
        try:
            if self._cache.exists():
                return json.loads(self._cache.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _save_cache(self, data: dict):
        try:
            self._cache.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _cache_fresh(self, key: str) -> bool:
        cache = self._load_cache()
        ts    = cache.get(key)
        if not ts:
            return False
        try:
            last  = datetime.fromisoformat(ts)
            delta = datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)
            return delta < timedelta(hours=CHECK_INTERVAL_HOURS)
        except Exception:
            return False

    def _ver_tuple(self, v: str) -> tuple:
        """Convert '2.0.1' -> (2, 0, 1)"""
        try:
            return tuple(int(x) for x in str(v).split(".")[:3])
        except Exception:
            return (0,)

    # ── Tool version check ─────────────────────────────────────────────────────
    def check_tool_update(self) -> dict:
        if not HAS_REQUESTS:
            return {}
        try:
            r = _requests.get(PYPI_URL, timeout=8)
            if r.status_code == 200:
                latest = r.json().get("info", {}).get("version", "")
                if latest and self._ver_tuple(latest) > self._ver_tuple(self._cur_ver):
                    return {"has_update": True, "new_version": latest,
                            "install_cmd": f"pip install --upgrade kryphorix"}
        except Exception:
            pass
        return {"has_update": False}

    # ── OWASP Top 10 check ─────────────────────────────────────────────────────
    def _detect_owasp_year(self) -> int:
        """
        Detect the latest available OWASP Top 10 year.
        Checks cached files first, then falls back to the known publication cycle.
        FIXED: previous version had `year % 1 == 0` (always True) as the guard
        condition, `pass` on HTTP 200 (never stored the result), and an incorrect
        range that only covered 2 years.
        """
        # Check for locally cached versions in reverse chronological order
        # OWASP publishes roughly every 3-4 years: 2017, 2021, 2025...
        candidate_years = [2025, 2024, 2021, 2017]
        for year in candidate_years:
            cached = self._owasp_d / f"owasp_top10_{year}.json"
            if cached.exists():
                return year

        # No cache found — probe GitHub for the most recent available year
        if HAS_REQUESTS:
            for year in candidate_years:
                # OWASP filenames follow a predictable pattern
                test_url = f"{OWASP_BASE}{year}/docs/A01_{year}-Broken_Access_Control.md"
                try:
                    r = _requests.head(test_url, timeout=6)
                    if r.status_code == 200:
                        return year
                except Exception:
                    pass

        return 2025  # current standard fallback

    def fetch_owasp(self, year: int = None) -> dict:
        """
        Fetch OWASP Top 10 list for the given year.
        Returns dict of {id: {title, description, url}}.
        """
        if year is None:
            year = self._detect_owasp_year()

        cache_path = self._owasp_d / f"owasp_top10_{year}.json"
        if cache_path.exists():
            try:
                return json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        # Try to fetch from OWASP GitHub
        if not HAS_REQUESTS:
            return self._owasp_builtin(year)

        # OWASP Top 10 index URLs per year
        index_urls = {
            2021: "https://owasp.org/Top10/",
            2025: "https://owasp.org/Top10/",
        }

        owasp = self._owasp_builtin(year)
        try:
            cache_path.write_text(json.dumps(owasp, indent=2), encoding="utf-8")
        except Exception:
            pass
        return owasp

    def _owasp_builtin(self, year: int) -> dict:
        """Built-in OWASP Top 10 dataset — updated for 2025 edition."""
        lists = {
            2021: {
                "A01": {"title": "Broken Access Control",       "id": "A01:2021", "cwe": "CWE-284"},
                "A02": {"title": "Cryptographic Failures",      "id": "A02:2021", "cwe": "CWE-310"},
                "A03": {"title": "Injection",                   "id": "A03:2021", "cwe": "CWE-89"},
                "A04": {"title": "Insecure Design",             "id": "A04:2021", "cwe": "CWE-657"},
                "A05": {"title": "Security Misconfiguration",   "id": "A05:2021", "cwe": "CWE-16"},
                "A06": {"title": "Vulnerable and Outdated Components","id": "A06:2021","cwe": "CWE-1035"},
                "A07": {"title": "Identification and Auth Failures","id": "A07:2021","cwe": "CWE-287"},
                "A08": {"title": "Software and Data Integrity Failures","id":"A08:2021","cwe":"CWE-829"},
                "A09": {"title": "Security Logging and Monitoring Failures","id":"A09:2021","cwe":"CWE-778"},
                "A10": {"title": "Server-Side Request Forgery", "id": "A10:2021", "cwe": "CWE-918"},
            },
            2025: {
                "A01": {"title": "Broken Access Control",       "id": "A01:2025", "cwe": "CWE-284"},
                "A02": {"title": "Cryptographic Failures",      "id": "A02:2025", "cwe": "CWE-310"},
                "A03": {"title": "Injection",                   "id": "A03:2025", "cwe": "CWE-89"},
                "A04": {"title": "Insecure Design",             "id": "A04:2025", "cwe": "CWE-657"},
                "A05": {"title": "Security Misconfiguration",   "id": "A05:2025", "cwe": "CWE-16"},
                "A06": {"title": "Vulnerable & Outdated Components","id":"A06:2025","cwe":"CWE-1035"},
                "A07": {"title": "Auth & Identity Failures",    "id": "A07:2025", "cwe": "CWE-287"},
                "A08": {"title": "Software & Data Integrity",   "id": "A08:2025", "cwe": "CWE-829"},
                "A09": {"title": "Security Logging Failures",   "id": "A09:2025", "cwe": "CWE-778"},
                "A10": {"title": "SSRF",                        "id": "A10:2025", "cwe": "CWE-918"},
            },
        }
        # For future years not yet in the dataset, use the most recent
        if year not in lists:
            year = max(k for k in lists if k <= year)
        return lists.get(year, lists[2025])

    # ── OS compatibility self-update ───────────────────────────────────────────
    def refresh_os_compat(self) -> dict:
        """
        Re-run OS compatibility detection. Call this after any update.
        Ensures tool continues working after OS upgrades (e.g. Python 3.13,
        macOS 15+, new Kali kernel).
        """
        try:
            import importlib
            import core.compat as compat
            importlib.reload(compat)
            return compat.get_feature_matrix()
        except Exception as e:
            return {"error": str(e)}

    # ── Bootstrap re-run ───────────────────────────────────────────────────────
    def refresh_dependencies(self) -> bool:
        """Re-run bootstrap after OS upgrade — picks up new pip flags automatically."""
        try:
            import importlib
            import core.bootstrap as bs
            importlib.reload(bs)
            ok, missing = bs.run(verbose=True)
            return ok
        except Exception:
            return False

    # ── Main check (used from menu + CLI) ─────────────────────────────────────
    def check(self, silent: bool = False) -> dict:
        result = {}
        if not HAS_REQUESTS:
            if not silent:
                self._print("[yellow]Requests library unavailable — cannot check updates.[/yellow]")
            return result

        # Tool version
        r = self.check_tool_update()
        result.update(r)
        if r.get("has_update") and not silent:
            self._print(
                f"\n[bold green]✓ New version available: v{r['new_version']}[/bold green]\n"
                f"  Install: [cyan]{r['install_cmd']}[/cyan]\n"
            )
        elif not silent:
            self._print(f"[green]✓ Kryphorix v{self._cur_ver} is up to date.[/green]")

        # OWASP
        try:
            owasp = self.fetch_owasp()
            result["owasp_loaded"] = True
            if not silent:
                year = next(iter(owasp.values()), {}).get("id", "")
                self._print(f"[green]✓ OWASP Top 10 dataset loaded ({year.split(':')[-1] if ':' in year else 'current'}).[/green]")
        except Exception:
            result["owasp_loaded"] = False

        return result

    def apply_update(self):
        """Attempt in-place update."""
        self._print("[cyan]Checking for git repository...[/cyan]")

        # Git-based update — verify remote is the official repository
        if (self._root / ".git").exists():
            try:
                # Check remote URL before pulling (prevent supply-chain attacks)
                remote_r = subprocess.run(
                    ["git", "remote", "get-url", "origin"],
                    cwd=str(self._root),
                    capture_output=True, text=True, timeout=15
                )
                remote_url = remote_r.stdout.strip()
                # Only allow official or empty (local dev) remotes
                ALLOWED_REMOTE_PATTERNS = [
                    "github.com/ademohmustapha/kryphorix",
                    "gitlab.com/ademohmustapha/kryphorix",
                    "pypi.org",
                ]
                if remote_url and not any(p in remote_url for p in ALLOWED_REMOTE_PATTERNS):
                    self._print(f"[yellow]Git remote '{remote_url}' is not an official "
                                f"Kryphorix repository. Skipping git pull.[/yellow]")
                else:
                    r = subprocess.run(
                        ["git", "pull", "--ff-only"],
                        cwd=str(self._root),
                        capture_output=True, text=True, timeout=60
                    )
                    if r.returncode == 0:
                        self._print("[bold green]✓ Updated via git pull.[/bold green]")
                        self.refresh_os_compat()
                        self.refresh_dependencies()
                        return True
                    else:
                        self._print(f"[yellow]git pull failed: {r.stderr[:100]}[/yellow]")
            except Exception:
                pass

        # pip update
        self._print("[cyan]Attempting pip update...[/cyan]")
        try:
            from core.bootstrap import get_pip_flags as _gpf
        except Exception:
            def _gpf(): return []
        flags = _gpf()
        cmd   = [sys.executable, "-m", "pip", "install", "--upgrade"] + flags + ["kryphorix"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                self._print("[bold green]✓ Updated via pip.[/bold green]")
                self.refresh_os_compat()
                return True
        except Exception:
            pass

        self._print(
            "[yellow]Automatic update unavailable. Manual update:[/yellow]\n"
            "  [cyan]pip install --upgrade kryphorix[/cyan]\n"
            "  or: https://github.com/ademohmustapha/kryphorix"
        )
        return False
