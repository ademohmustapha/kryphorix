#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║    ██╗  ██╗██████╗ ██╗   ██╗██████╗ ██╗  ██╗ ██████╗ ██████╗ ██╗██╗  ██╗      ║
║    ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗██║  ██║██╔═══██╗██╔══██╗██║╚██╗██╔╝      ║
║    █████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝███████║██║   ██║██████╔╝██║ ╚███╔╝       ║
║    ██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║██║   ██║██╔══██╗██║ ██╔██╗       ║
║    ██║  ██╗██║  ██║   ██║   ██║     ██║  ██║╚██████╔╝██║  ██║██║██╔╝ ██╗      ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝    ║
║                                                                                  ║
║       Elite Cyber Security Assessment Suite  v2.0.0  |  2026 Edition           ║
║   Kali Linux · Windows · macOS  ·  Cross-Platform  ·  Auto-Adaptive            ║
╚══════════════════════════════════════════════════════════════════════════════════╝

LEGAL NOTICE:
  Authorised security testing and educational use ONLY.
  By running this tool you confirm you have explicit written authorisation
  to test the specified targets. Misuse is illegal.
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 0 — Absolute stdlib only. No third-party imports yet.
# ─────────────────────────────────────────────────────────────────────────────
import sys
import os
import platform

TOOL_VERSION = "2.0.0"
TOOL_NAME    = "Kryphorix"

# Python gate
if sys.version_info < (3, 8):
    sys.exit(f"[FATAL] Python 3.8+ required. Got {sys.version.split()[0]}")

# Add tool root to sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 1 — OS compatibility detection (stdlib only)
# ─────────────────────────────────────────────────────────────────────────────
from core.compat import (
    OS_NAME, IS_WINDOWS, IS_MACOS, IS_LINUX, IS_KALI,
    is_elevated, describe_platform, PY_VER_STR,
)

# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 2 — Smart dependency bootstrap
# ─────────────────────────────────────────────────────────────────────────────
from core.bootstrap import run as bootstrap_run

print(f"\n[*] Kryphorix v{TOOL_VERSION} starting on {describe_platform()}")
_deps_ok, _missing_opt = bootstrap_run(verbose=True)

if not _deps_ok:
    print("[!] Critical dependencies missing. Some features will be unavailable.")

# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 3 — Full imports (safe after bootstrap)
# ─────────────────────────────────────────────────────────────────────────────
import re
import argparse
import signal
import threading
import getpass
import json
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ipaddress
import importlib

try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.table   import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.prompt  import Confirm, Prompt
    from rich.text    import Text
    from rich.rule    import Rule
    from rich.columns import Columns
    from rich         import box
    from colorama     import init as colorama_init
    colorama_init(autoreset=True)
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    sys.exit("[FATAL] 'rich' and 'colorama' are required. Run: pip install rich colorama")

# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 4 — Internal core imports
# ─────────────────────────────────────────────────────────────────────────────
from core.finding   import Finding
from core.findings  import FindingsManager
from core.report    import generate_pdf, export_json, export_html, export_csv
from core.updater   import UpdateManager
from core.logger    import get_logger
from core.integrity import IntegrityChecker
from core.audit_log import AuditLog
from core.selftest  import SelfTest
from core.config    import Config
from core.workspace import WorkspaceManager

console = Console()
logger  = get_logger(ROOT_DIR)
audit   = AuditLog(ROOT_DIR)
cfg     = Config(ROOT_DIR)

# Ensure directories exist
for d in ["reports","logs","assets","workspaces","plugins","profiles"]:
    Path(ROOT_DIR, d).mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
MODULE_REGISTRY = {
    "web":         "modules.web",
    "api":         "modules.api",
    "ad":          "modules.ad",
    "ports":       "modules.ports",
    "vuln_ports":  "modules.vuln_ports",
    "tls":         "modules.tls",
    "wireless":    "modules.wireless",
    "owasp":       "modules.owasp",
    "osint":       "modules.osint",
    "ssh":         "modules.ssh_audit",
    "subdomain":   "modules.subdomain",
    "firewall":    "modules.firewall",
    "cloud":       "modules.cloud",
    "credentials": "modules.credentials",
    "network":     "modules.network",
    "malware":     "modules.malware",
    "compliance":  "modules.compliance",
}

_MOD_CACHE: dict = {}


def load_module(name: str):
    # FIXED: Only cache successful imports.
    # Previously, failed imports were cached as None, permanently preventing
    # any subsequent retry (e.g., after the user installs a missing dependency
    # or the transient error resolves). Now failures are NOT cached — each call
    # to load_module() for a failed module retries the import fresh.
    if name in _MOD_CACHE and _MOD_CACHE[name] is not None:
        return _MOD_CACHE[name]
    mod_path = MODULE_REGISTRY.get(name)
    if not mod_path:
        return None  # Unknown module name — no cache entry
    try:
        mod = importlib.import_module(mod_path)
        fn  = getattr(mod, "scan", None)
        _MOD_CACHE[name] = fn   # Only cache on success
        return fn
    except Exception as e:
        logger.warning(f"Module '{name}' unavailable: {e}")
        # Do NOT cache None — allow retry on next call
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
SEV_ORDER  = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
SEV_COLORS = {
    "Critical": "bold white on red",
    "High":     "bold red",
    "Medium":   "bold yellow",
    "Low":      "bold green",
    "Info":     "bold blue",
}


_ALLOWED_SCHEMES = ("http://", "https://")
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_safe_host(host: str) -> bool:
    """Return True if host is not a private/loopback address (SSRF prevention)."""
    try:
        addr = ipaddress.ip_address(host)
        return not any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        # It's a hostname — DNS resolution happens at scan time; we do a basic format check
        if re.match(r"^[a-zA-Z0-9._\-]+$", host) and len(host) < 256:
            return True
        return False


def _url(t: str) -> str:
    t = t.strip()
    if not t.startswith(_ALLOWED_SCHEMES):
        t = "https://" + t
    parsed = urlparse(t)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme!r}")
    return t

def _host(t: str) -> str:
    h = re.sub(r"https?://","",t).split("/")[0].split(":")[0].strip()
    # Basic sanity check
    if not re.match(r"^[a-zA-Z0-9._\-]+$", h) or len(h) > 255:
        raise ValueError(f"Invalid host: {h!r}")
    return h

def _targets(val: str) -> list:
    return [v.strip() for v in val.split(",") if v.strip()]

def _tag(findings: list, module: str) -> list:
    for f in findings:
        if not getattr(f,"module",None) or f.module in ("Unknown",""):
            f.module = module
    return findings

def _inp(prompt: str, default: str = "") -> str:
    return console.input(f"[cyan]{prompt}[/cyan]").strip() or default


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────
def show_banner():
    platform_str = describe_platform()
    priv_badge   = ("[bold green]✓ Root/Admin[/bold green]" if is_elevated()
                    else "[yellow]Standard User[/yellow]")
    console.print(f"""[bold cyan]
  ██╗  ██╗██████╗ ██╗   ██╗██████╗ ██╗  ██╗ ██████╗ ██████╗ ██╗██╗  ██╗
  ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗██║  ██║██╔═══██╗██╔══██╗██║╚██╗██╔╝
  █████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝███████║██║   ██║██████╔╝██║ ╚███╔╝
  ██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║██║   ██║██╔══██╗██║ ██╔██╗
  ██║  ██╗██║  ██║   ██║   ██║     ██║  ██║╚██████╔╝██║  ██║██║██╔╝ ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝[/bold cyan]
[bold white]            Elite Cyber Security Assessment Suite  v{TOOL_VERSION}[/bold white]
[dim]  {platform_str}  |  Privileges: {priv_badge}[/dim]""")
    console.print(Panel(
        "[bold red]⚠  AUTHORISED USE ONLY  ⚠[/bold red]\n"
        "[dim]Unauthorised use is illegal.[/dim]",
        border_style="red", expand=False
    ), justify="center")

    # ── Authorisation gate ──────────────────────────────────────────────────
    # Interactive mode: prompt once per installation.
    # Non-TTY / CI mode: requires --accept-terms flag explicitly — silent bypass is not allowed.
    import sys as _sys
    _accept_terms = "--accept-terms" in _sys.argv

    if not _sys.stdin.isatty() and not _accept_terms:
        console.print(
            "\n[bold red]ERROR: Non-interactive mode detected.[/bold red]\n"
            "  Kryphorix requires explicit authorisation confirmation in non-TTY/CI environments.\n"
            "  Re-run with [bold]--accept-terms[/bold] to confirm you have written authorisation:\n\n"
            "    [dim]python kryphorix.py --full target.com --accept-terms --output json[/dim]\n\n"
            "  [dim]Unauthorised scanning is illegal. Kryphorix will not run silently.[/dim]"
        )
        raise SystemExit(1)

    if _sys.stdin.isatty():
        _consent_file = Path.home() / ".kryphorix" / ".consent_accepted"
        if not _consent_file.exists():
            console.print()
            console.print("[bold yellow]AUTHORISATION REQUIRED[/bold yellow]")
            console.print("  Before using Kryphorix you must confirm you have explicit")
            console.print("  [bold]written authorisation[/bold] from the target system owner.")
            console.print("  Scanning systems without authorisation is illegal in most jurisdictions.")
            console.print()
            try:
                answer = input("  Type 'I AGREE' to confirm authorisation, or Ctrl+C to exit: ").strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[red]Aborted.[/red]")
                raise SystemExit(0)
            if answer != "I AGREE":
                console.print("[red]Authorisation not confirmed. Exiting.[/red]")
                raise SystemExit(1)
            _consent_file.parent.mkdir(parents=True, exist_ok=True)
            _consent_file.write_text("accepted\n")
            console.print("[green]Authorisation confirmed. Consent recorded.[/green]\n")
    # ── End authorisation gate ──────────────────────────────────────────────
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  DISPLAY SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
def display_summary(findings: list, title: str = "Scan Results"):
    if not findings:
        console.print("\n[bold green]✓ No findings recorded.[/bold green]\n")
        return

    srt = sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 0), reverse=True)
    tbl = Table(
        title=f"[bold]{title}[/bold]",
        show_lines=True, box=box.DOUBLE_EDGE,
        border_style="cyan", header_style="bold cyan",
        expand=True, highlight=True
    )
    tbl.add_column("Sev",    justify="center", min_width=8)
    tbl.add_column("Module", min_width=10, max_width=14)
    tbl.add_column("Title",  min_width=30, max_width=45)
    tbl.add_column("CVSS",   justify="center", min_width=5)
    tbl.add_column("CWE/CVE",justify="center", min_width=12)
    tbl.add_column("Description", min_width=35)
    tbl.add_column("Remediation", min_width=35)

    for f in srt:
        col     = SEV_COLORS.get(f.severity,"white")
        cvss    = f"{f.cvss:.1f}" if f.cvss else "-"
        cwe_cve = "/".join(filter(None,[f.cwe,f.cve]))[:20]
        tbl.add_row(
            Text(f.severity, style=col),
            f.module,
            f.title[:50],
            cvss,
            cwe_cve,
            (f.description[:130] + "…") if len(f.description)>130 else f.description,
            (f.remediation[:130] + "…") if len(f.remediation)>130 else f.remediation,
        )
    console.print(tbl)

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    console.print()
    console.print(Rule("[bold]Severity Breakdown[/bold]", style="cyan"))
    for sev, col in SEV_COLORS.items():
        n = counts.get(sev, 0)
        if n:
            bar = "█" * min(n, 60)
            console.print(f"  [{col}]{sev:10}[/{col}] [{col}]{bar}[/{col}] {n}")
    risk_color = {
        "Critical": "bold red", "High": "red",
        "Medium": "yellow", "Low": "green", "Info": "blue"
    }
    risk = ("Critical" if counts.get("Critical",0) else
            "High"     if counts.get("High",0)     else
            "Medium"   if counts.get("Medium",0)   else
            "Low"      if counts.get("Low",0)       else "Info")
    total  = len(findings)
    c_h    = counts.get("Critical",0) + counts.get("High",0)
    console.print(
        f"\n  Total: [bold]{total}[/bold]  │  "
        f"Critical+High: [bold red]{c_h}[/bold red]  │  "
        f"Risk: [{risk_color[risk]}]{risk}[/{risk_color[risk]}]\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_module(label: str, fn, targets: list, extra: dict = None) -> list:
    if fn is None:
        console.print(f"  [yellow]⚠ '{label}' unavailable (missing dependency)[/yellow]")
        return []
    results = []
    extra   = extra or {}
    # Inject proxy and stealth from config
    if cfg.proxy:     extra.setdefault("proxy",   cfg.proxy)
    if cfg.stealth:   extra.setdefault("stealth",  True)
    extra.setdefault("timeout", cfg.timeout)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console, transient=True
    ) as prog:
        task = prog.add_task(f"  [cyan]{label}[/cyan]", total=len(targets))
        for t in targets:
            try:
                out = fn(t, **extra)
                results += _tag(out or [], label)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.error(f"[{label}] {t}: {e}")
            prog.advance(task)

    crits = sum(1 for r in results if r.severity in ("Critical","High"))
    line  = f"  [green]✓[/green] [bold]{label}[/bold]: {len(results)} finding(s)"
    if crits:
        line += f"  [bold red]({crits} critical/high)[/bold red]"
    console.print(line)
    return results


def _save_reports(findings: list, targets: list, fmts: list):
    if not findings:
        return
    for fmt in fmts:
        try:
            if fmt == "pdf":
                generate_pdf(findings, targets=targets, root=ROOT_DIR)
            elif fmt == "json":
                export_json(findings, targets=targets, root=ROOT_DIR)
            elif fmt == "html":
                export_html(findings, targets=targets, root=ROOT_DIR)
            elif fmt == "csv":
                export_csv(findings, root=ROOT_DIR)
        except Exception as e:
            logger.error(f"Report [{fmt}]: {e}")
    console.print(f"[bold green]  ✓ Reports → /reports/  [{', '.join(fmts)}][/bold green]")


def _report_prompt(findings: list, targets: list):
    if findings and Confirm.ask("\n[cyan]Generate reports?[/cyan]", default=True):
        fmts = ["pdf","json"]
        _save_reports(findings, targets, fmts)


# ─────────────────────────────────────────────────────────────────────────────
#  FULL SCAN
# ─────────────────────────────────────────────────────────────────────────────
def full_scan(target: str, fmts: list = None, ad_user: str = None,
              ad_pass: str = None) -> list:
    fmts = fmts or ["pdf","json","html","csv"]
    url  = _url(target)
    host = _host(target)
    console.print(Panel(
        f"[bold magenta]◆ FULL COMPREHENSIVE SCAN ◆[/bold magenta]\n"
        f"[dim]Target: {target}[/dim]" +
        (f"\n[dim]Proxy: {cfg.proxy}[/dim]" if cfg.proxy else ""),
        border_style="magenta"
    ))
    audit.log("FULL_SCAN_START", {"target": target})

    # (label, mod_key, target, extra)
    tasks = [
        ("Web",         "web",         url,  {}),
        ("API",         "api",         url,  {}),
        ("Ports",       "ports",       host, {}),
        ("VulnPorts",   "vuln_ports",  host, {}),
        ("TLS",         "tls",         host, {}),
        ("Wireless",    "wireless",    "local", {}),
        ("OWASP",       "owasp",       url,  {}),
        ("OSINT",       "osint",       host, {}),
        ("Subdomain",   "subdomain",   host, {}),
        ("SSH",         "ssh",         host, {}),
        ("Firewall",    "firewall",    url,  {}),
        ("Cloud",       "cloud",       url,  {}),
        ("Credentials", "credentials", url,  {}),
        ("Malware",     "malware",     url,  {}),
        ("Network",     "network",     host, {}),
        ("Compliance",  "compliance",  url,  {"standard":"all"}),
    ]
    if ad_user:
        tasks.append(("AD", "ad", host,
                      {"username": ad_user, "password": ad_pass}))

    all_findings = []
    console.print(Rule("[bold magenta]Executing All Modules in Parallel[/bold magenta]",
                       style="magenta"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console
    ) as prog:
        master = prog.add_task("[magenta]Overall...", total=len(tasks))
        with ThreadPoolExecutor(max_workers=6) as ex:
            fut_map = {}
            for label, mod_key, tgt, kw in tasks:
                fn = load_module(mod_key)
                if fn:
                    # Inject global settings
                    kw.setdefault("proxy",   cfg.proxy)
                    kw.setdefault("stealth", cfg.stealth)
                    kw.setdefault("timeout", cfg.timeout)
                    fut = ex.submit(fn, tgt, **{k:v for k,v in kw.items() if v is not None})
                    fut_map[fut] = label
            for fut in as_completed(fut_map):
                label = fut_map[fut]
                try:
                    res = _tag(fut.result() or [], label)
                    all_findings += res
                    c = sum(1 for r in res if r.severity in ("Critical","High"))
                    if c:
                        prog.console.print(f"  [bold red]! {label}: {c} critical/high[/bold red]")
                except Exception as e:
                    logger.error(f"[Full][{label}]: {e}")
                prog.advance(master)

    console.print(Rule("[bold magenta]Full Scan Complete[/bold magenta]", style="magenta"))
    display_summary(all_findings, title=f"Full Scan — {target}")
    _save_reports(all_findings, [target], fmts)
    audit.log("FULL_SCAN_END", {"target": target, "total": len(all_findings)})
    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
#  MENU
# ─────────────────────────────────────────────────────────────────────────────
MENU = [
    ("1",  "Web Application Scan",           "web",    "cyan"),
    ("2",  "API Security Assessment",         "api",    "cyan"),
    ("3",  "Active Directory Pentest",        "ad",     "cyan"),
    ("4",  "Port Scan + CVE Map",            "ports",   "cyan"),
    ("5",  "TLS / SSL Deep Audit",           "tls",    "cyan"),
    ("6",  "Wireless Network Audit",         "wireless","cyan"),
    ("7",  "OWASP Top 10 (Auto-Updated)",    "owasp",  "cyan"),
    ("8",  "OSINT Reconnaissance",           "osint",  "cyan"),
    ("9",  "SSH Configuration Audit",        "ssh",    "cyan"),
    ("10", "Subdomain Enumeration",          "subdomain","cyan"),
    ("11", "Firewall & WAF Detection",       "firewall","cyan"),
    ("12", "Cloud Misconfiguration Scan",    "cloud",  "cyan"),
    ("13", "Credential & Secret Audit",      "credentials",  "cyan"),
    ("14", "Network Infrastructure Scan",    "network","cyan"),
    ("15", "Malware / Webshell Detection",   "malware","cyan"),
    ("16", "Compliance: PCI/HIPAA/ISO/NIST","compliance","cyan"),
    ("17", "Full Comprehensive Scan",        "full",   "bold magenta"),
    ("18", "Self-Test / Health Check",       "test",   "bold yellow"),
    ("19", "Check / Apply Updates",          "update", "bold green"),
    ("20", "Workspace Manager",              "ws",     "dim cyan"),
    ("21", "View Recent Reports",            "reports","dim cyan"),
    ("0",  "Exit",                           "exit",   "red"),
]


def _draw_menu():
    half = len(MENU)//2
    def _col(items):
        t = Table(box=None, show_header=False, padding=(0,1), expand=True)
        t.add_column("K", style="bold", min_width=4)
        t.add_column("Label")
        for key,label,_,color in items:
            t.add_row(f"[{color}]{key}[/{color}]",
                      f"[{color}]{label}[/{color}]")
        return t
    console.print(Panel(
        Columns([_col(MENU[:half]), _col(MENU[half:])]),
        title=f"[bold cyan]╔  KRYPHORIX v{TOOL_VERSION} — MAIN MENU  ╗[/bold cyan]",
        border_style="cyan",
    ))


def menu_mode():
    show_banner()
    # Background update check
    threading.Thread(
        target=lambda: UpdateManager(ROOT_DIR, TOOL_VERSION, console, logger)
                       .check(silent=True),
        daemon=True
    ).start()

    while True:
        _draw_menu()
        ch = _inp("→ Select (0–21): ")

        if ch == "0":
            console.print("\n[bold green]Goodbye. Stay secure. 🔒[/bold green]\n")
            audit.log("SESSION_END", {})
            break

        elif ch == "1":
            u = _inp("Target URL: "); u = _url(u) if u else ""
            if not u: continue
            f = run_module("Web", load_module("web"), [u])
            display_summary(f); _report_prompt(f, [u])

        elif ch == "2":
            u = _inp("API base URL: "); u = _url(u) if u else ""
            if not u: continue
            f = run_module("API", load_module("api"), [u])
            display_summary(f); _report_prompt(f, [u])

        elif ch == "3":
            h = _inp("Domain Controller IP/hostname: ")
            if not h: continue
            user = _inp("Username (blank=anonymous): ") or None
            # Always use getpass to avoid password in shell history/process list
            pwd  = getpass.getpass("AD Password (input hidden): ") if user else None
            dom  = _inp("Domain (e.g. corp.local, blank=skip): ") or None
            fn   = load_module("ad")
            f = run_module("AD",
                lambda t, **kw: fn(t, username=user, password=pwd, domain=dom) if fn else [],
                [h])
            display_summary(f); _report_prompt(f, [h])

        elif ch == "4":
            hs = _targets(_inp("Host(s)/IP(s), comma-separated: "))
            if not hs: continue
            f  = run_module("Ports",    load_module("ports"),     hs)
            f += run_module("VulnPorts",load_module("vuln_ports"),hs)
            display_summary(f); _report_prompt(f, hs)

        elif ch == "5":
            hs = _targets(_inp("Hostname(s): "))
            if not hs: continue
            f = run_module("TLS", load_module("tls"), hs)
            display_summary(f); _report_prompt(f, hs)

        elif ch == "6":
            if not is_elevated():
                console.print("[yellow]⚠ Wireless may need root/admin privileges.[/yellow]")
                if not Confirm.ask("Continue anyway?", default=True): continue
            f = run_module("Wireless", load_module("wireless"), ["local"])
            display_summary(f); _report_prompt(f, ["local"])

        elif ch == "7":
            u = _inp("URL for OWASP scan: "); u = _url(u) if u else ""
            if not u: continue
            f = run_module("OWASP", load_module("owasp"), [u])
            display_summary(f); _report_prompt(f, [u])

        elif ch == "8":
            t = _inp("Domain/IP for OSINT: ")
            if not t: continue
            f = run_module("OSINT", load_module("osint"), [t])
            display_summary(f); _report_prompt(f, [t])

        elif ch == "9":
            h = _inp("SSH host (host or host:port): ")
            if not h: continue
            f = run_module("SSH", load_module("ssh"), [h])
            display_summary(f); _report_prompt(f, [h])

        elif ch == "10":
            d = _inp("Root domain (e.g. example.com): ")
            if not d: continue
            f = run_module("Subdomain", load_module("subdomain"), [d])
            display_summary(f); _report_prompt(f, [d])

        elif ch == "11":
            t = _inp("Host/URL: ")
            if not t: continue
            f = run_module("Firewall", load_module("firewall"), [_url(t)])
            display_summary(f); _report_prompt(f, [t])

        elif ch == "12":
            t = _inp("Domain/URL: ")
            if not t: continue
            f = run_module("Cloud", load_module("cloud"), [_url(t)])
            display_summary(f); _report_prompt(f, [t])

        elif ch == "13":
            t = _inp("Target URL/host: ")
            if not t: continue
            wl = _inp("Wordlist path (blank=built-in): ") or None
            fn = load_module("credentials")
            f  = run_module("Credentials",
                lambda tgt, **kw: fn(tgt, wordlist=wl) if fn else [],
                [_url(t)])
            display_summary(f); _report_prompt(f, [t])

        elif ch == "14":
            hs = _targets(_inp("Host(s)/IP(s): "))
            if not hs: continue
            f = run_module("Network", load_module("network"), hs)
            display_summary(f); _report_prompt(f, hs)

        elif ch == "15":
            u = _inp("URL: "); u = _url(u) if u else ""
            if not u: continue
            f = run_module("Malware", load_module("malware"), [u])
            display_summary(f); _report_prompt(f, [u])

        elif ch == "16":
            t = _inp("Target URL/host: ")
            if not t: continue
            std = Prompt.ask("[cyan]Standard[/cyan]",
                             choices=["pci","hipaa","iso27001","nist","all"], default="all")
            fn  = load_module("compliance")
            f   = run_module("Compliance",
                lambda tgt, **kw: fn(tgt, standard=std) if fn else [],
                [_url(t)])
            display_summary(f); _report_prompt(f, [t])

        elif ch == "17":
            t    = _inp("Primary target: ")
            user = _inp("AD username (blank=skip AD): ") or None
            pwd  = getpass.getpass("AD password: ") if user else None
            full_scan(t, ad_user=user, ad_pass=pwd)

        elif ch == "18":
            st = SelfTest(ROOT_DIR, TOOL_VERSION, OS_NAME, console, logger)
            st.run()

        elif ch == "19":
            um = UpdateManager(ROOT_DIR, TOOL_VERSION, console, logger)
            res = um.check()
            if res.get("has_update"):
                if Confirm.ask(f"[cyan]Update to v{res['new_version']}?[/cyan]", default=True):
                    um.apply_update()
            else:
                console.print("[green]✓ Kryphorix is up to date.[/green]")

        elif ch == "20":
            ws = WorkspaceManager(ROOT_DIR, console)
            ws.interactive()

        elif ch == "21":
            rdir = Path(ROOT_DIR) / "reports"
            files = sorted(rdir.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True) \
                    if rdir.exists() else []
            if not files:
                console.print("[yellow]No reports found.[/yellow]")
            else:
                tbl = Table(title="Recent Reports", box=box.SIMPLE, border_style="cyan")
                tbl.add_column("#", min_width=3)
                tbl.add_column("Filename", min_width=45)
                tbl.add_column("Size", justify="right")
                tbl.add_column("Date")
                ext_col = {".pdf":"red",".html":"cyan",".json":"yellow",".csv":"green"}
                for i,f in enumerate(files[:25],1):
                    col = ext_col.get(f.suffix,"white")
                    sz  = f"{f.stat().st_size//1024} KB"
                    dt  = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    tbl.add_row(str(i), f"[{col}]{f.name}[/{col}]", sz, dt)
                console.print(tbl)

        else:
            console.print("[red]Invalid selection.[/red]")

        console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  CLI MODE
# ─────────────────────────────────────────────────────────────────────────────
def cli_mode(args):
    audit.log("CLI_START", {k:v for k,v in vars(args).items() if v})
    findings     = []
    targets_used = []
    fmts         = _targets(getattr(args,"output","pdf,json"))

    def _r(label, mod_key, tgts, **kw):
        fn = load_module(mod_key)
        return run_module(label, fn, tgts, kw or None)

    if getattr(args,"web",None):
        ts = _targets(args.web); targets_used += ts
        findings += _r("Web","web",[_url(t) for t in ts])
    if getattr(args,"api",None):
        ts = _targets(args.api); targets_used += ts
        findings += _r("API","api",[_url(t) for t in ts])
    if getattr(args,"ad",None):
        ts = _targets(args.ad); targets_used += ts
        fn = load_module("ad")
        for h in ts:
            findings += _tag(
                fn(h, username=getattr(args,"ad_user",None),
                   password=getattr(args,"ad_pass",None),
                   domain=getattr(args,"ad_domain",None)) if fn else [],
                "AD")
    if getattr(args,"ports",None):
        ts = _targets(args.ports); targets_used += ts
        findings += _r("Ports","ports",ts)
        findings += _r("VulnPorts","vuln_ports",ts)
    if getattr(args,"tls",None):
        ts = _targets(args.tls); targets_used += ts
        findings += _r("TLS","tls",ts)
    if getattr(args,"wifi",False):
        findings += _r("Wireless","wireless",["local"])
    if getattr(args,"owasp",None):
        ts = _targets(args.owasp); targets_used += ts
        findings += _r("OWASP","owasp",[_url(t) for t in ts])
    if getattr(args,"osint",None):
        ts = _targets(args.osint); targets_used += ts
        findings += _r("OSINT","osint",ts)
    if getattr(args,"ssh",None):
        ts = _targets(args.ssh); targets_used += ts
        findings += _r("SSH","ssh",ts)
    if getattr(args,"subdomain",None):
        ts = _targets(args.subdomain); targets_used += ts
        findings += _r("Subdomain","subdomain",ts)
    if getattr(args,"firewall",None):
        ts = _targets(args.firewall); targets_used += ts
        findings += _r("Firewall","firewall",[_url(t) for t in ts])
    if getattr(args,"cloud",None):
        ts = _targets(args.cloud); targets_used += ts
        findings += _r("Cloud","cloud",[_url(t) for t in ts])
    if getattr(args,"creds",None):
        ts = _targets(args.creds); targets_used += ts
        fn = load_module("credentials")
        wl = getattr(args,"wordlist",None)
        for h in [_url(t) for t in ts]:
            findings += _tag(fn(h,wordlist=wl) if fn else [], "Credentials")
    if getattr(args,"network",None):
        ts = _targets(args.network); targets_used += ts
        findings += _r("Network","network",ts)
    if getattr(args,"malware",None):
        ts = _targets(args.malware); targets_used += ts
        findings += _r("Malware","malware",[_url(t) for t in ts])
    if getattr(args,"compliance",None):
        ts = _targets(args.compliance); targets_used += ts
        std = getattr(args,"standard","all")
        fn  = load_module("compliance")
        for h in [_url(t) for t in ts]:
            findings += _tag(fn(h,standard=std) if fn else [], "Compliance")
    if getattr(args,"full",None):
        return full_scan(
            args.full, fmts=fmts,
            ad_user=getattr(args,"ad_user",None),
            ad_pass=getattr(args,"ad_pass",None),
        )

    display_summary(findings)
    _save_reports(findings, targets_used, fmts)
    audit.log("CLI_END", {"total":len(findings)})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kryphorix",
        description=f"Kryphorix v{TOOL_VERSION} — Elite Cyber Security Assessment Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python kryphorix.py                                         # Interactive menu
  python kryphorix.py --web https://target.com               # Web app scan
  python kryphorix.py --full target.com                      # All 17 modules
  python kryphorix.py --ports 10.0.0.1 --tls target.com     # Port + TLS
  python kryphorix.py --ad 10.0.0.1 --ad-user admin \\
                      --ad-pass Pass123 --ad-domain corp.local
  python kryphorix.py --owasp https://target.com             # OWASP Top 10
  python kryphorix.py --proxy http://127.0.0.1:8080 \\
                      --web https://target.com               # Burp Suite proxy
  python kryphorix.py --stealth --ports 10.0.0.1            # Stealth mode
  python kryphorix.py --selftest                             # Health check
  python kryphorix.py --update                               # Update tool+OWASP
  python kryphorix.py --full target.com --output pdf,html,json,csv
        """
    )
    s = p.add_argument_group("Scan Modules")
    s.add_argument("--web",         metavar="URL[s]",  help="Web application scan")
    s.add_argument("--api",         metavar="URL[s]",  help="API security assessment")
    s.add_argument("--ad",          metavar="HOST[s]", help="Active Directory pentest")
    s.add_argument("--ad-user",     metavar="USER",    dest="ad_user")
    s.add_argument("--ad-pass",     metavar="PASS",    dest="ad_pass")
    s.add_argument("--ad-domain",   metavar="DOMAIN",  dest="ad_domain")
    s.add_argument("--ports",       metavar="HOST[s]", help="Port scan + CVE map")
    s.add_argument("--tls",         metavar="HOST[s]", help="TLS/SSL deep audit")
    s.add_argument("--wifi",        action="store_true", help="Wireless network scan")
    s.add_argument("--owasp",       metavar="URL[s]",  help="OWASP Top 10 automated")
    s.add_argument("--osint",       metavar="TARGET",  help="OSINT reconnaissance")
    s.add_argument("--ssh",         metavar="HOST[s]", help="SSH configuration audit")
    s.add_argument("--subdomain",   metavar="DOMAIN",  help="Subdomain enumeration")
    s.add_argument("--firewall",    metavar="TARGET",  help="Firewall & WAF detection")
    s.add_argument("--cloud",       metavar="TARGET",  help="Cloud misconfiguration scan")
    s.add_argument("--creds",       metavar="TARGET",  help="Credential & secret audit")
    s.add_argument("--wordlist",    metavar="FILE",    help="Wordlist for credential tests")
    s.add_argument("--network",     metavar="HOST[s]", help="Network infrastructure scan")
    s.add_argument("--malware",     metavar="URL[s]",  help="Malware/webshell detection")
    s.add_argument("--compliance",  metavar="TARGET",  help="Compliance assessment")
    s.add_argument("--standard",    metavar="STD",     default="all",
                   choices=["pci","hipaa","iso27001","nist","all"])
    s.add_argument("--full",        metavar="TARGET",  help="Run ALL modules")

    o = p.add_argument_group("Network & Behaviour")
    o.add_argument("--output",      default="pdf,json",
                   help="Report formats: pdf,json,html,csv  (default: pdf,json)")
    o.add_argument("--proxy",       metavar="URL",
                   help="HTTP(S) proxy  e.g. http://127.0.0.1:8080  (Burp Suite etc.)")
    o.add_argument("--stealth",     action="store_true",
                   help="Stealth mode: slower, lower-noise scanning")
    o.add_argument("--threads",     type=int,   default=None, help="Thread count override")
    o.add_argument("--timeout",     type=int,   default=None, help="Per-request timeout (s)")

    u = p.add_argument_group("Utility")
    u.add_argument("--update",      action="store_true", help="Check & apply updates")
    u.add_argument("--selftest",    action="store_true", help="Self-test / health check")
    u.add_argument("--workspace",   metavar="NAME",      help="Load named workspace")
    u.add_argument("--accept-terms", action="store_true", dest="accept_terms",
                   help="Required in non-interactive/CI mode. Confirms written authorisation for the target.")
    u.add_argument("--version",     action="version",
                   version=f"Kryphorix v{TOOL_VERSION}")
    return p


# ─────────────────────────────────────────────────────────────────────────────
#  SIGNAL HANDLING
# ─────────────────────────────────────────────────────────────────────────────
def _graceful_exit(sig, frame):
    sig_name = "CTRL+C (SIGINT)" if sig == signal.SIGINT else "SIGTERM"
    console.print(f"\n\n[bold yellow]⚡ {sig_name} — exiting cleanly...[/bold yellow]")
    audit.log("SHUTDOWN", {"signal": sig_name})
    sys.exit(0)

signal.signal(signal.SIGINT,  _graceful_exit)
signal.signal(signal.SIGTERM, _graceful_exit)   # Handle container/systemd shutdown


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()

    # Apply CLI overrides to config
    if getattr(args, "threads", None):  cfg.set("threads",     args.threads)
    if getattr(args, "timeout", None):  cfg.set("timeout",     args.timeout)
    if getattr(args, "stealth", False): cfg.set("stealth_mode", True)
    if getattr(args, "proxy",   None):
        cfg.set("proxy", args.proxy)
        os.environ["HTTP_PROXY"]  = args.proxy
        os.environ["HTTPS_PROXY"] = args.proxy

    # Integrity check
    ic  = IntegrityChecker(ROOT_DIR)
    ok, issues = ic.verify()
    if not ok:
        console.print("[bold red]⚠ INTEGRITY FAILURES:[/bold red]")
        for issue in issues:
            console.print(f"  [red]• {issue}[/red]")
        if not Confirm.ask("Files may be tampered. Continue?", default=False):
            sys.exit(1)

    # Utilities first (before banner for selftest/update)
    if getattr(args, "selftest", False):
        show_banner()
        st = SelfTest(ROOT_DIR, TOOL_VERSION, OS_NAME, console, logger)
        sys.exit(0 if st.run() else 1)

    if getattr(args, "update", False):
        show_banner()
        um = UpdateManager(ROOT_DIR, TOOL_VERSION, console, logger)
        res = um.check()
        if res.get("has_update"):
            um.apply_update()
        sys.exit(0)

    # Workspace restore
    if getattr(args, "workspace", None):
        ws   = WorkspaceManager(ROOT_DIR, console)
        data = ws.load(args.workspace)
        if data:
            console.print(f"[cyan]Resumed workspace: {data.get('name')}[/cyan]")

    # Dispatch
    if len(sys.argv) == 1:
        menu_mode()
    else:
        show_banner()
        cli_mode(args)
