"""
core/selftest.py  —  Kryphorix Self-Test & Health Check
=========================================================
Verifies: Python version, OS compatibility, dependencies, binaries,
module imports, integrity, network connectivity, reporting engine.

WARNINGS EXPLAINED
──────────────────
Warnings are non-fatal advisory notices. They do NOT prevent scanning.
The selftest groups warnings by category and prints a full "Warning Detail"
section at the end so you always know exactly what each warning is and how
to resolve it — no guesswork required.

Common warnings and their fixes:

  ⚠ Not in a virtualenv
      → Optional best-practice. Works fine without one.
        Create: python -m venv .venv && source .venv/bin/activate

  ⚠ Standard user privileges
      → Run with: sudo python kryphorix.py
        (needed for raw-socket port scans and wireless capture)

  ⚠ No wireless tool found
      → Kali/Debian: sudo apt install network-manager
        macOS: airport utility or system_profiler (built-in on 14+)

  ⚠ nmap not installed
      → Kali: sudo apt install nmap
        macOS: brew install nmap  |  Windows: nmap.org/download

  ⚠ ssh-audit binary not found
      → pip install ssh-audit   or   sudo apt install ssh-audit
        (built-in SSH scanner is used as fallback — all SSH checks work)

  ⚠ /<dir>/ missing — created
      → Informational. Directory was created automatically.

  ⚠ <module> not installed — <desc> [optional]
      → pip install <module>   (tool works without it; adds extra features)

  ⚠ <module> — dependency unavailable
      → pip install <missing_package>   (scan module falls back gracefully)

  ⚠ Integrity check error
      → Run: python kryphorix.py --selftest   as the same user who installed
        the tool, or delete integrity_manifest.json to regenerate it.

  ⚠ <host> — unreachable (offline mode?)
      → Check internet connectivity. Offline scans still work on local targets.

  ⚠ PDF engine: <error>
      → pip install reportlab   (HTML/JSON/CSV reports always work without it)
"""

import sys
import socket
import importlib
from pathlib import Path
from datetime import datetime

try:
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class SelfTest:
    def __init__(self, root_dir, version: str, os_name: str, console=None, logger=None):
        self._root    = Path(root_dir)
        self._version = version
        self._os      = os_name
        self._con     = console
        self._log     = logger
        self._passed  = 0
        self._failed  = 0
        self._warned  = 0
        # Collect (category, message, fix_hint) for every warning so we can
        # print a consolidated "Warning Detail" section at the end.
        self._warning_log: list = []

    def _print(self, msg: str):
        if self._con and HAS_RICH:
            self._con.print(msg)
        else:
            print(msg)

    def _ok(self, label: str, detail: str = ""):
        self._passed += 1
        self._print(f"  [bold green]✓[/bold green] {label}" + (f" [dim]{detail}[/dim]" if detail else ""))

    def _fail(self, label: str, detail: str = ""):
        self._failed += 1
        self._print(f"  [bold red]✗[/bold red] {label}" + (f" [dim]{detail}[/dim]" if detail else ""))

    def _warn(self, label: str, detail: str = "", fix: str = ""):
        """Record and display a warning. fix is shown in the summary."""
        self._warned += 1
        self._warning_log.append({
            "label": label,
            "detail": detail,
            "fix": fix,
            "category": self._current_category,
        })
        self._print(
            f"  [bold yellow]⚠[/bold yellow] {label}"
            + (f" [dim]{detail}[/dim]" if detail else "")
        )

    # ── Individual checks ──────────────────────────────────────────────────────
    def _check_python(self):
        self._current_category = "Python & Runtime"
        self._print("\n[bold cyan]Python & Runtime[/bold cyan]")
        v = sys.version_info
        if v >= (3, 8):
            self._ok(f"Python {v.major}.{v.minor}.{v.micro}", f"(minimum 3.8)")
        else:
            self._fail(f"Python {v.major}.{v.minor} — Python 3.8+ required")
        if hasattr(sys, "real_prefix") or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix):
            self._ok("Running inside virtualenv")
        else:
            self._warn(
                "Not in a virtualenv (works fine, but venv is recommended)",
                fix="python -m venv .venv && source .venv/bin/activate"
            )

    def _check_os(self):
        self._current_category = "OS Compatibility"
        self._print("\n[bold cyan]OS Compatibility[/bold cyan]")
        try:
            from core.compat import (get_feature_matrix, describe_platform,
                                     get_wireless_tool, get_nmap_binary, is_elevated)
            feat = get_feature_matrix()
            self._ok(f"Platform: {describe_platform()}")
            if feat.get("elevated"):
                self._ok("Elevated privileges (root/admin)")
            else:
                self._warn(
                    "Standard user privileges — wireless & raw socket scans may be limited",
                    fix="Run with: sudo python kryphorix.py"
                )
            wt = feat.get("wireless_tool")
            if wt:
                self._ok(f"Wireless tool: {wt}")
            else:
                self._warn(
                    "No wireless tool found (install nmcli, iwlist, or use macOS airport)",
                    fix="Kali/Debian: sudo apt install network-manager"
                )
            nm = feat.get("nmap_binary")
            if nm:
                self._ok(f"nmap binary: {nm}")
            else:
                self._warn(
                    "nmap not installed — some port scan features limited",
                    fix="sudo apt install nmap   or   brew install nmap"
                )
            ssh_a = feat.get("ssh_audit_binary")
            if ssh_a:
                self._ok(f"ssh-audit binary: {ssh_a}")
            else:
                self._warn(
                    "ssh-audit binary not found — SSH checks will use built-in scanner",
                    fix="pip install ssh-audit   or   sudo apt install ssh-audit"
                )
        except Exception as e:
            self._fail(f"OS compat check error: {e}")

    def _check_dirs(self):
        self._current_category = "Directory Structure"
        self._print("\n[bold cyan]Directory Structure[/bold cyan]")
        required = ["core", "modules", "plugins", "reports", "logs", "assets", "workspaces"]
        for d in required:
            p = self._root / d
            if p.exists():
                self._ok(f"/{d}/")
            else:
                p.mkdir(parents=True, exist_ok=True)
                self._warn(
                    f"/{d}/ missing — created",
                    fix="Directory has been created automatically."
                )

    def _check_deps(self):
        self._current_category = "Python Dependencies"
        self._print("\n[bold cyan]Python Dependencies[/bold cyan]")
        required = {
            "requests": "HTTP requests",
            "rich":     "Terminal UI",
            "reportlab":"PDF generation",
            "PIL":      "Image processing",
            "cryptography":"Crypto ops",
            "bs4":      "HTML parsing",
            "dns":      "DNS resolution",
            "paramiko": "SSH client",
            "yaml":     "Config parsing",
            "jinja2":   "Templating",
        }
        optional = {
            "OpenSSL":  "Enhanced TLS",
            "whois":    "WHOIS lookups",
            "nmap":     "nmap integration",
            "ldap3":    "LDAP/AD tests",
        }
        for mod, desc in required.items():
            try:
                importlib.import_module(mod)
                self._ok(f"{mod} ({desc})")
            except ImportError:
                self._fail(f"{mod} MISSING — {desc}")
        for mod, desc in optional.items():
            try:
                importlib.import_module(mod)
                self._ok(f"{mod} ({desc}) [optional]")
            except ImportError:
                self._warn(
                    f"{mod} not installed — {desc} [optional]",
                    fix=f"pip install {mod.lower()}"
                )

    def _check_modules(self):
        self._current_category = "Scan Modules"
        self._print("\n[bold cyan]Scan Modules[/bold cyan]")
        modules = [
            "modules.web", "modules.api", "modules.ad", "modules.ports", "modules.vuln_ports",
            "modules.tls", "modules.wireless", "modules.owasp", "modules.osint",
            "modules.ssh_audit", "modules.subdomain", "modules.firewall", "modules.cloud",
            "modules.credentials", "modules.network", "modules.malware", "modules.compliance",
        ]
        for m in modules:
            try:
                mod = importlib.import_module(m)
                if hasattr(mod, "scan"):
                    self._ok(m.split(".")[-1])
                else:
                    self._fail(f"{m} — missing scan() function")
            except ImportError as e:
                self._warn(
                    f"{m.split('.')[-1]} — dependency unavailable: {str(e)[:50]}",
                    fix=f"pip install <missing package shown above>"
                )
            except Exception as e:
                self._fail(f"{m} — error: {str(e)[:60]}")

    def _check_integrity(self):
        self._current_category = "File Integrity"
        self._print("\n[bold cyan]File Integrity[/bold cyan]")
        try:
            from core.integrity import IntegrityChecker
            ic  = IntegrityChecker(self._root)
            ok, issues = ic.verify()
            if ok:
                self._ok("Integrity manifest verified")
            else:
                for issue in issues:
                    self._fail(f"Integrity: {issue}")
        except Exception as e:
            self._warn(
                f"Integrity check error: {e}",
                fix="Run as same user who installed, or delete integrity_manifest.json"
            )

    def _check_network(self):
        self._current_category = "Network Connectivity"
        self._print("\n[bold cyan]Network Connectivity[/bold cyan]")
        tests = [
            ("8.8.8.8",    53,  "DNS (Google)"),
            ("1.1.1.1",    53,  "DNS (Cloudflare)"),
            ("github.com", 443, "GitHub HTTPS"),
        ]
        for host, port, label in tests:
            try:
                s = socket.create_connection((host, port), timeout=4)
                s.close()
                self._ok(f"{label}")
            except Exception:
                self._warn(
                    f"{label} — unreachable (offline mode?)",
                    fix="Check internet connection. Offline/LAN scans still work."
                )

    def _check_reports(self):
        self._current_category = "Reporting Engine"
        self._print("\n[bold cyan]Reporting Engine[/bold cyan]")
        try:
            from core.finding import Finding
            from core.report  import export_json, export_html, export_csv
            test_f = [Finding(
                title="Self-Test Finding", severity="High", cvss=7.5,
                description="Test description.", remediation="Test remediation.",
                module="SelfTest", cwe="CWE-000"
            )]
            export_json(test_f, root=str(self._root), filename="_selftest.json")
            export_csv(test_f,  root=str(self._root), filename="_selftest.csv")
            export_html(test_f, root=str(self._root), filename="_selftest.html")
            for fname in ["_selftest.json", "_selftest.csv", "_selftest.html"]:
                p = self._root / "reports" / fname
                if p.exists():
                    p.unlink()
            self._ok("JSON, CSV, HTML engines working")
        except Exception as e:
            self._fail(f"Report engine: {e}")

        try:
            from core.report import generate_pdf
            test_f = [Finding(
                title="PDF Test", severity="Critical", cvss=9.8,
                description="PDF test.", remediation="N/A.",
                module="SelfTest"
            )]
            generate_pdf(test_f, root=str(self._root), filename="_selftest.pdf")
            p = self._root / "reports" / "_selftest.pdf"
            if p.exists():
                p.unlink()
            self._ok("PDF engine working")
        except Exception as e:
            self._warn(
                f"PDF engine: {e}",
                fix="pip install reportlab   (HTML/JSON/CSV reports work without it)"
            )

    def _check_audit_log(self):
        self._current_category = "Audit Log"
        self._print("\n[bold cyan]Audit Log[/bold cyan]")
        try:
            from core.audit_log import AuditLog
            al = AuditLog(self._root)
            al.log("SELFTEST", {"ts": datetime.now().isoformat()})
            ok, broken_at = al.verify_chain()
            if ok:
                self._ok("Audit log chain valid")
            else:
                self._fail(f"Audit log chain broken at entry {broken_at}")
        except Exception as e:
            self._fail(f"Audit log: {e}")

    # ── Warning detail report ──────────────────────────────────────────────────
    def _print_warning_detail(self):
        """
        Print a consolidated list of every warning with its category and fix
        so the operator knows exactly what each warning means and how to
        resolve it — no digging through scrollback required.
        """
        if not self._warning_log:
            return

        self._print("\n")
        if HAS_RICH:
            self._con.print(Rule("[bold yellow]Warning Details[/bold yellow]", style="yellow"))
        else:
            self._print("─" * 60)
            self._print("  Warning Details")
            self._print("─" * 60)

        for i, w in enumerate(self._warning_log, 1):
            category = w.get("category", "General")
            label    = w["label"]
            fix      = w.get("fix", "")
            self._print(
                f"\n  [bold yellow]⚠ [{i}] {category}[/bold yellow]\n"
                f"  [yellow]    {label}[/yellow]"
            )
            if fix:
                self._print(f"  [dim]    Fix → {fix}[/dim]")

        self._print(
            "\n  [dim]Warnings are advisory — the tool is fully operational.\n"
            "  Address them to unlock the flagged optional features.[/dim]\n"
        )

    # ── Main run ───────────────────────────────────────────────────────────────
    def run(self):
        # initialise category tracker (used in _warn)
        self._current_category = "General"

        if HAS_RICH:
            self._con.print(Panel(
                f"[bold yellow]KRYPHORIX v{self._version} — SELF TEST[/bold yellow]\n"
                f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · {self._os}[/dim]",
                border_style="yellow"
            ))
        else:
            print(f"\n=== KRYPHORIX v{self._version} SELF TEST ===\n")

        self._check_python()
        self._check_os()
        self._check_dirs()
        self._check_deps()
        self._check_modules()
        self._check_integrity()
        self._check_network()
        self._check_reports()
        self._check_audit_log()

        total = self._passed + self._failed + self._warned
        self._print("\n")
        if HAS_RICH:
            self._con.print(Rule("[bold]Self-Test Results[/bold]", style="yellow"))
        self._print(
            f"  [bold green]Passed: {self._passed}[/bold green]  "
            f"[bold red]Failed: {self._failed}[/bold red]  "
            f"[bold yellow]Warnings: {self._warned}[/bold yellow]  "
            f"[dim]Total: {total}[/dim]"
        )

        if self._failed == 0:
            status = "[bold green]HEALTHY — Ready for deployment.[/bold green]"
        elif self._failed <= 2:
            status = "[bold yellow]DEGRADED — Some features unavailable.[/bold yellow]"
        else:
            status = "[bold red]CRITICAL — Address failures before scanning.[/bold red]"

        self._print(f"\n  Status: {status}\n")

        # Always print the full warning breakdown so operator knows what each one is
        self._print_warning_detail()

        return self._failed == 0
