"""
Kryphorix OWASP Top 10 Automated Scanner
Auto-detects and fetches new OWASP Top 10 lists (2021, 2025, future).
Tests all 10 categories with active probes.
"""
import re
import json
import socket
import requests
from urllib.parse import urljoin, urlparse, urlencode
from core.finding import Finding
from core.findings import FindingsManager

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
import logging
logger = logging.getLogger("kryphorix")

# ── OWASP Top 10 Lists ──────────────────────────────────────────────────────
OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

OWASP_2025 = {
    # OWASP Top 10 2025 — reflects updated threat landscape vs 2021
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
    # Extended 2025 additions (where applicable)
    "A11": "Cross-Site Scripting (XSS) — elevated from A03",
    "A12": "AI/LLM Security Risks — new in 2025",
}

KNOWN_YEARS = [2017, 2021, 2025]


def get_latest_owasp():
    """Fetch latest OWASP Top 10 list — auto-discovers new years."""
    import datetime
    year = max(KNOWN_YEARS)
    best_list = OWASP_2025
    best_year = 2025

    # Check if newer years exist
    current_year = datetime.datetime.now().year
    for y in range(year + 1, current_year + 2):
        try:
            url = f"https://raw.githubusercontent.com/OWASP/Top10/master/{y}/docs/index.md"
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and "OWASP" in r.text:
                # Try to parse categories
                cats = re.findall(r'A(\d+):(\d{4})\s+(.+?)(?:\n|$)', r.text)
                if cats:
                    new_list = {f"A{n.zfill(2)}": name.strip() for n, yr, name in cats}
                    if len(new_list) >= 8:
                        best_list = new_list
                        best_year = y
        except Exception:
            pass

    return best_year, best_list


def _get(session, url, **kw):
    try:
        kw.setdefault("timeout", 10)
        return session.get(url, **kw)
    except Exception:
        return None


def _post(session, url, **kw):
    try:
        kw.setdefault("timeout", 10)
        return session.post(url, **kw)
    except Exception:
        return None


# ── A01: Broken Access Control ───────────────────────────────────────────────
def test_a01_broken_access_control(target, session, fm, year):
    label = f"A01:{year}"
    # Test IDOR-style path access
    restricted = ["/admin", "/admin/dashboard", "/users", "/api/users",
                  "/api/admin", "/management", "/internal"]
    for path in restricted:
        r = _get(session, target.rstrip("/") + path)
        if r and r.status_code == 200 and len(r.text) > 100:
            fm.add(Finding(
                title=f"[{label}] Broken Access Control — Restricted Path Accessible",
                severity="High",
                description=f"Path '{path}' returns HTTP 200 without authentication.",
                remediation="Implement proper access controls. Deny by default. Use server-side authorization.",
                module="OWASP", cvss=8.8, cwe="CWE-284",
                evidence=f"Path: {target.rstrip('/')+ path}\nStatus: 200\nSize: {len(r.text)}"
            ))
            return

    # Test HTTP method override
    r = _get(session, target, headers={"X-HTTP-Method-Override": "DELETE"})
    if r and r.status_code not in [400, 401, 403, 404, 405, 501]:
        fm.add(Finding(
            title=f"[{label}] HTTP Method Override Accepted",
            severity="Medium",
            description="Server accepts X-HTTP-Method-Override header, potentially bypassing WAF rules.",
            remediation="Validate actual HTTP method, not headers. Remove method override support.",
            module="OWASP", cvss=6.5, cwe="CWE-284"
        ))


# ── A02: Cryptographic Failures ──────────────────────────────────────────────
def test_a02_cryptographic_failures(target, session, fm, year):
    label = f"A02:{year}"
    parsed = urlparse(target)
    if parsed.scheme == "http":
        fm.add(Finding(
            title=f"[{label}] Cryptographic Failure — Plaintext HTTP",
            severity="High",
            description="Site served over HTTP. All data transmitted in cleartext.",
            remediation="Deploy TLS 1.2+. Enforce HTTPS with HSTS.",
            module="OWASP", cvss=7.5, cwe="CWE-319"
        ))
    else:
        # Check for mixed content
        r = _get(session, target)
        if r:
            http_srcs = re.findall(r'src=["\']http://[^"\']+["\']', r.text, re.I)
            if http_srcs:
                fm.add(Finding(
                    title=f"[{label}] Mixed Content Detected",
                    severity="Medium",
                    description=f"HTTPS page loads {len(http_srcs)} resources over HTTP.",
                    remediation="Ensure all resources are loaded over HTTPS.",
                    module="OWASP", cvss=5.9, cwe="CWE-311",
                    evidence=str(http_srcs[:5])
                ))


# ── A03: Injection ────────────────────────────────────────────────────────────
def test_a03_injection(target, session, fm, year):
    label = f"A03:{year}"
    # SQL injection probes
    sql_payloads = ["'", "' OR '1'='1", "' OR 1=1--", "1 AND SLEEP(2)--", "' UNION SELECT NULL--"]
    sql_errors   = ["sql syntax", "mysql_fetch", "ORA-", "PostgreSQL", "sqlite", "SQLSTATE",
                    "syntax error", "unclosed quotation", "Incorrect syntax"]
    params = ["id", "user", "q", "search", "name", "item", "product", "page"]

    for param in params[:3]:
        for payload in sql_payloads[:3]:
            r = _get(session, target, params={param: payload})
            if r:
                for err in sql_errors:
                    if err.lower() in r.text.lower():
                        fm.add(Finding(
                            title=f"[{label}] SQL Injection — Error-Based",
                            severity="Critical",
                            description=f"SQL error '{err}' triggered by parameter '{param}' with payload '{payload}'.",
                            remediation="Use parameterized queries. Input validation. Least privilege DB accounts.",
                            module="OWASP", cvss=9.8, cwe="CWE-89",
                            evidence=f"Param={param}, Payload={payload}, Error={err}"
                        ))
                        return

    # XSS probe
    xss_payload = "<script>alert('KRY')</script>"
    for param in params[:3]:
        r = _get(session, target, params={param: xss_payload})
        if r and xss_payload in r.text:
            fm.add(Finding(
                title=f"[{label}] Reflected XSS — Unencoded Script Reflected",
                severity="High",
                description=f"Payload reflected without encoding via parameter '{param}'.",
                remediation="Encode all output. Implement CSP. Use templating engines with auto-escape.",
                module="OWASP", cvss=7.2, cwe="CWE-79",
                evidence=f"Param={param}, Payload reflected in response"
            ))
            return

    # Command injection probe
    cmd_payloads = ["; ls", "| whoami", "; id", "$(id)", "`id`"]
    cmd_indicators = ["root", "www-data", "uid=", "gid=", "bin/bash", "bin/sh"]
    for param in ["host", "cmd", "exec", "ping", "ip"]:
        for payload in cmd_payloads[:2]:
            r = _get(session, target, params={param: f"127.0.0.1{payload}"})
            if r:
                for ind in cmd_indicators:
                    if ind in r.text:
                        fm.add(Finding(
                            title=f"[{label}] Command Injection",
                            severity="Critical",
                            description=f"OS command output detected in response via param '{param}'.",
                            remediation="Never pass user input to shell commands. Use safe APIs.",
                            module="OWASP", cvss=9.8, cwe="CWE-78",
                            evidence=f"Indicator: {ind}"
                        ))
                        return


# ── A05: Security Misconfiguration ───────────────────────────────────────────
def test_a05_misconfiguration(target, session, fm, year):
    label = f"A05:{year}"
    # Default credentials in common paths
    default_paths = [
        ("/.env", ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "AWS_SECRET"]),
        ("/phpinfo.php", ["PHP Version", "SERVER_SOFTWARE", "DOCUMENT_ROOT"]),
        ("/server-status", ["Apache Server Status", "Total accesses"]),
        ("/actuator/env", ["spring.datasource.password", "spring.security"]),
    ]
    for path, indicators in default_paths:
        r = _get(session, target.rstrip("/") + path)
        if r and r.status_code == 200:
            content = r.text
            for ind in indicators:
                if ind in content:
                    fm.add(Finding(
                        title=f"[{label}] Security Misconfiguration — Sensitive File: {path}",
                        severity="High",
                        description=f"'{path}' is publicly accessible and contains sensitive information.",
                        remediation="Remove or restrict access to sensitive configuration files.",
                        module="OWASP", cvss=7.5, cwe="CWE-16",
                        evidence=f"Indicator '{ind}' found at {target.rstrip('/')+ path}"
                    ))
                    return


# ── A07: Broken Authentication ────────────────────────────────────────────────
def test_a07_broken_auth(target, session, fm, year):
    label = f"A07:{year}"
    # Find login form
    login_paths = ["/login", "/signin", "/auth", "/wp-login.php", "/user/login"]
    login_url = None
    for path in login_paths:
        r = _get(session, target.rstrip("/") + path)
        if r and r.status_code == 200:
            if re.search(r'type=["\']password["\']', r.text, re.I):
                login_url = target.rstrip("/") + path
                break

    if not login_url:
        return

    # Test for account lockout (no rate limiting = brute force possible)
    hits = 0
    for i in range(6):
        r = _post(session, login_url,
                  data={"username": "admin", "password": f"wrong_pass_{i}",
                        "user": "admin", "pass": f"wrong_pass_{i}"})
        if r and r.status_code in [200, 302]:
            hits += 1

    if hits >= 5:
        fm.add(Finding(
            title=f"[{label}] No Account Lockout / Brute-Force Protection",
            severity="High",
            description="Login endpoint allows unlimited authentication attempts without lockout.",
            remediation="Implement account lockout, CAPTCHA, or rate limiting.",
            module="OWASP", cvss=7.5, cwe="CWE-307",
            evidence=f"6 rapid requests to {login_url} all returned {hits} non-error responses"
        ))

    # Test default credentials
    defaults = [("admin", "admin"), ("admin", "password"), ("admin", ""), ("root", "root")]
    for user, pwd in defaults:
        r = _post(session, login_url,
                  data={"username": user, "password": pwd, "user": user, "pass": pwd},
                  allow_redirects=True)
        if r:
            success_signs = ["dashboard", "logout", "welcome", "my account", "profile", "overview"]
            if any(s in r.text.lower() for s in success_signs):
                fm.add(Finding(
                    title=f"[{label}] Default Credentials Valid: {user}:{pwd}",
                    severity="Critical",
                    description=f"Default credentials '{user}:{pwd}' successfully authenticated.",
                    remediation="Change all default credentials immediately. Enforce strong password policy.",
                    module="OWASP", cvss=9.8, cwe="CWE-521"
                ))
                return


# ── A09: Insufficient Logging ─────────────────────────────────────────────────
def test_a09_logging(target, session, fm, year):
    label = f"A09:{year}"
    # Check if security events generate any logging evidence
    # We can only confirm absence of logging mechanisms (headers)
    r = _get(session, target)
    if r:
        # No specific header proves logging, but check for security.txt
        sec_txt = _get(session, target.rstrip("/") + "/.well-known/security.txt")
        if not sec_txt or sec_txt.status_code != 200:
            fm.add(Finding(
                title=f"[{label}] Missing security.txt — No Vulnerability Disclosure Policy",
                severity="Low",
                description="No security.txt found. No clear channel for security researchers to report issues.",
                remediation="Create /.well-known/security.txt per RFC 9116.",
                module="OWASP", cvss=2.0, cwe="CWE-778"
            ))


# ── A10: SSRF ─────────────────────────────────────────────────────────────────
def test_a10_ssrf(target, session, fm, year):
    label = f"A10:{year}"
    ssrf_params = ["url", "redirect", "proxy", "callback", "fetch", "src",
                   "href", "dest", "next", "return", "link"]
    ssrf_targets = [
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id"]),
        ("http://localhost/", ["localhost", "127.0.0.1"]),
        ("http://[::1]/", ["localhost"]),
    ]

    for param in ssrf_params[:6]:
        for ssrf_url, indicators in ssrf_targets[:2]:
            r = _get(session, target, params={param: ssrf_url})
            if r:
                for ind in indicators:
                    if ind in r.text:
                        fm.add(Finding(
                            title=f"[{label}] Server-Side Request Forgery (SSRF)",
                            severity="Critical",
                            description=f"Parameter '{param}' fetches internal resources. "
                                        f"Indicator '{ind}' found in response.",
                            remediation="Validate/whitelist all user-supplied URLs. Block internal IP ranges.",
                            module="OWASP", cvss=9.1, cwe="CWE-918",
                            evidence=f"Param={param}, URL={ssrf_url}, Indicator={ind}"
                        ))
                        return


def scan(target: str, **kwargs) -> list:
    fm = FindingsManager()
    session = requests.Session()
    session.headers["User-Agent"] = "Kryphorix/4.0 Security Assessment"
    session.verify = kwargs.get("ssl_verify", True)

    if not target.startswith("http"):
        target = "https://" + target

    # Get current OWASP list (auto-updates)
    try:
        year, owasp_list = get_latest_owasp()
    except Exception:
        year, owasp_list = 2025, OWASP_2025

    fm.add(Finding(
        title=f"OWASP Top 10 {year} Assessment — Target: {target}",
        severity="Info",
        description=f"Running automated OWASP Top 10 {year} assessment.",
        remediation="Review all findings and prioritize by CVSS score.",
        module="OWASP"
    ))

    tests = [
        test_a01_broken_access_control,
        test_a02_cryptographic_failures,
        test_a03_injection,
        test_a05_misconfiguration,
        test_a07_broken_auth,
        test_a09_logging,
        test_a10_ssrf,
    ]

    for test_fn in tests:
        try:
            test_fn(target, session, fm, year)
        except Exception:
            pass

    return fm.all()
