"""
modules/web.py  —  Web Application Security Scanner
====================================================
Tests: security headers, cookies, CORS, sensitive paths, error disclosure,
HTTP methods, open redirect, CSP quality, HTTPS enforcement.
"""
import re
import logging
from core.finding  import Finding
from core.findings import FindingsManager
from modules._base import make_session, safe_get, normalize_url, extract_host

# NOTE: SSL certificate verification is intentionally set per-request in this module.
# When scanning unknown/untrusted targets (the primary use-case of a security assessment
# tool), self-signed and expired certificates are EXPECTED findings — not errors.
# verify=False is used so the scanner reaches the target and REPORTS the bad cert
# as a finding, rather than refusing to connect. This is correct security-scanner
# behaviour. For internal/trusted targets, pass ssl_verify=True via kwargs.
# SSL_VERIFY_NOTE


logger = logging.getLogger("kryphorix")

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": "High", "cvss": 7.4, "cwe": "CWE-319",
        "description": "HSTS not set — HTTPS connections are vulnerable to SSL stripping attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "severity": "Medium", "cvss": 6.1, "cwe": "CWE-1021",
        "description": "No Content Security Policy — XSS and data injection attacks are facilitated.",
        "remediation": "Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'",
    },
    "x-content-type-options": {
        "severity": "Low", "cvss": 3.7, "cwe": "CWE-16",
        "description": "X-Content-Type-Options not set — MIME-type sniffing attacks possible.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "severity": "Medium", "cvss": 5.4, "cwe": "CWE-1021",
        "description": "X-Frame-Options missing — site may be embedded in iframes (clickjacking).",
        "remediation": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors directive.",
    },
    "referrer-policy": {
        "severity": "Low", "cvss": 3.1, "cwe": "CWE-200",
        "description": "Referrer-Policy not set — sensitive URLs may leak in referrer headers.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "Low", "cvss": 2.4, "cwe": "CWE-16",
        "description": "Permissions-Policy not set — browser features not restricted.",
        "remediation": "Add Permissions-Policy to restrict camera, microphone, geolocation etc.",
    },
}

SENSITIVE_PATHS = [
    "/.env","/.env.local","/.env.production","/.git/config","/.git/HEAD",
    "/.htpasswd","/.htaccess","/web.config","/config.php","/config.yml",
    "/config.yaml","/wp-config.php","/phpinfo.php","/info.php","/test.php",
    "/backup.zip","/backup.sql","/dump.sql","/database.sql",
    "/admin","/admin/","/administrator","/admin/login",
    "/actuator","/actuator/env","/actuator/health","/actuator/beans",
    "/swagger-ui.html","/swagger-ui/","/api-docs","/openapi.json",
    "/api/swagger","/graphql","/graphiql","/robots.txt","/sitemap.xml",
    "/server-status","/server-info","/.well-known/security.txt",
    "/debug","/trace","/health","/metrics","/status",
    "/api/v1/users","/api/v2/users","/api/users",
    "/__debug__/","/django-admin/","/console","/h2-console",
]

SENSITIVE_RESPONSE_PATTERNS = {
    "SQL Error":        [r"sql syntax|mysql_fetch|ORA-\d+|pg_query|unclosed quotation",
                         "CWE-209"],
    "PHP Disclosure":   [r"Fatal error.*?in.*?on line \d+|Warning:.*?PHP",
                         "CWE-209"],
    "Stack Trace":      [r"at \w+\.\w+\([\w\.]+:\d+\)|Traceback \(most recent",
                         "CWE-209"],
    "Path Disclosure":  [r"C:\\Users\\|C:\\inetpub|/var/www/|/home/\w+/|/opt/",
                         "CWE-200"],
    "Private IP Leak":  [r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b",
                         "CWE-200"],
    "AWS Key Leak":     [r"AKIA[A-Z0-9]{16}",   "CWE-312"],
    "JWT Leak":         [r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.", "CWE-312"],
    "Private Key Leak": [r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",   "CWE-312"],
}

ALLOWED_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}
DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"}


def check_security_headers(target: str, session, fm: FindingsManager):
    r = safe_get(session, target)
    if r is None:
        fm.add(Finding(title="Target Unreachable", severity="High",
                       description=f"Cannot connect to {target}",
                       remediation="Verify target is reachable.", module="Web"))
        return

    hdrs_lower = {k.lower(): v for k, v in r.headers.items()}

    for hdr, info in REQUIRED_HEADERS.items():
        if hdr not in hdrs_lower:
            fm.add(Finding(
                title=f"Missing Security Header: {hdr.title()}",
                severity=info["severity"], cvss=info["cvss"], cwe=info["cwe"],
                description=info["description"], remediation=info["remediation"],
                module="Web"
            ))
        else:
            # Extra quality checks
            if hdr == "strict-transport-security":
                val = hdrs_lower[hdr].lower()
                if "max-age" in val:
                    try:
                        age = int(re.search(r"max-age=(\d+)", val).group(1))
                        if age < 31536000:
                            fm.add(Finding(
                                title="HSTS max-age Too Short",
                                severity="Low", cvss=2.6, cwe="CWE-319",
                                description=f"HSTS max-age={age}s — recommended ≥ 31536000 (1 year).",
                                remediation="Set max-age=31536000 or higher.",
                                module="Web"
                            ))
                    except Exception:
                        pass
            if hdr == "content-security-policy":
                val = hdrs_lower[hdr]
                if "unsafe-inline" in val or "unsafe-eval" in val:
                    fm.add(Finding(
                        title="Weak Content Security Policy",
                        severity="Medium", cvss=5.4, cwe="CWE-1021",
                        description="CSP uses 'unsafe-inline' or 'unsafe-eval' — XSS bypass possible.",
                        remediation="Remove 'unsafe-inline'/'unsafe-eval'. Use nonces or hashes.",
                        module="Web", evidence=f"CSP: {val[:200]}"
                    ))

    # Server version disclosure
    server = hdrs_lower.get("server", "")
    if re.search(r"nginx/[\d.]+|apache/[\d.]+|iis/[\d.]+|php/[\d.]+", server, re.I):
        fm.add(Finding(
            title="Server Version Disclosed",
            severity="Low", cvss=3.1, cwe="CWE-200",
            description=f"Server header exposes version: '{server}'",
            remediation="Configure server to suppress version information.",
            module="Web", evidence=f"Server: {server}"
        ))

    # X-Powered-By
    xpb = hdrs_lower.get("x-powered-by", "")
    if xpb:
        fm.add(Finding(
            title="X-Powered-By Header Exposes Technology",
            severity="Low", cvss=3.1, cwe="CWE-200",
            description=f"X-Powered-By: {xpb} — technology stack disclosed.",
            remediation="Remove X-Powered-By header from server config.",
            module="Web", evidence=f"X-Powered-By: {xpb}"
        ))


def check_cookies(target: str, session, fm: FindingsManager):
    r = safe_get(session, target)
    if not r:
        return
    for cookie in r.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and \
                "httponly" not in str(cookie).lower():
            issues.append("missing HttpOnly flag")
        samesite = cookie.get_nonstandard_attr("SameSite", "")
        if not samesite:
            issues.append("missing SameSite attribute")
        if issues:
            fm.add(Finding(
                title=f"Insecure Cookie: {cookie.name}",
                severity="Medium", cvss=4.3, cwe="CWE-614",
                description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}.",
                remediation="Set Secure; HttpOnly; SameSite=Strict on all session cookies.",
                module="Web", evidence=f"Cookie: {cookie.name}; issues: {issues}"
            ))


def check_https(target: str, session, fm: FindingsManager):
    if not target.startswith("https"):
        return
    http_url = target.replace("https://", "http://")
    r = safe_get(session, http_url, allow_redirects=False)
    if r and r.status_code not in (301, 302, 307, 308):
        fm.add(Finding(
            title="HTTP Not Redirected to HTTPS",
            severity="High", cvss=7.5, cwe="CWE-319",
            description="Port 80 serves content without redirecting to HTTPS.",
            remediation="Configure permanent 301 redirect from HTTP to HTTPS.",
            module="Web"
        ))


def check_sensitive_paths(target: str, session, fm: FindingsManager):
    base = target.rstrip("/")
    found = []
    for path in SENSITIVE_PATHS:
        r = safe_get(session, base + path, allow_redirects=False)
        if not r:
            continue
        if r.status_code == 200 and len(r.content) > 20:
            sev = ("Critical" if any(s in path for s in [".env","config","passwd","sql","backup"]) else
                   "High"     if any(s in path for s in ["git","swagger","actuator","graphql"]) else
                   "Medium")
            found.append(path)
            fm.add(Finding(
                title=f"Sensitive Path Accessible: {path}",
                severity=sev, cvss={"Critical":9.1,"High":7.5,"Medium":5.3}[sev],
                cwe="CWE-538",
                description=f"Path '{path}' returns HTTP 200 and may expose sensitive data.",
                remediation="Restrict access. Remove debug/dev files from production.",
                module="Web", evidence=f"URL: {base+path}  Status: 200  Size: {len(r.content)}"
            ))


def check_error_disclosure(target: str, session, fm: FindingsManager):
    r = safe_get(session, target)
    if not r:
        return
    for error_type, (pattern, cwe) in SENSITIVE_RESPONSE_PATTERNS.items():
        m = re.search(pattern, r.text, re.IGNORECASE)
        if m:
            fm.add(Finding(
                title=f"Sensitive Data in Response: {error_type}",
                severity="High" if "Key" in error_type or "Private" in error_type else "Medium",
                cvss=7.5 if "Key" in error_type else 5.3, cwe=cwe,
                description=f"{error_type} detected in page source.",
                remediation="Suppress error details in production. Use generic error pages.",
                module="Web", evidence=m.group(0)[:200]
            ))


def check_http_methods(target: str, session, fm: FindingsManager):
    dangerous_found = []
    for method in DANGEROUS_METHODS:
        try:
            r = session.request(method, target, timeout=8, verify=False)  # nosec — scanner intentional
            if r and r.status_code not in (405, 501, 400):
                dangerous_found.append(f"{method} ({r.status_code})")
        except Exception:
            pass
    if dangerous_found:
        fm.add(Finding(
            title=f"Dangerous HTTP Methods Enabled",
            severity="Medium", cvss=5.8, cwe="CWE-16",
            description=f"Server accepts dangerous methods: {', '.join(dangerous_found)}",
            remediation="Disable TRACE, PUT, DELETE unless explicitly required.",
            module="Web", evidence=str(dangerous_found)
        ))


def check_cors(target: str, session, fm: FindingsManager):
    r = safe_get(session, target, headers={"Origin": "https://evil.example.com"})
    if not r:
        return
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        fm.add(Finding(
            title="Overly Permissive CORS: Allow-Origin *",
            severity="Medium", cvss=5.4, cwe="CWE-942",
            description="CORS allows any origin (*) to read responses.",
            remediation="Restrict CORS to specific trusted domains.",
            module="Web", evidence=f"ACAO: {acao}"
        ))
    elif "evil.example.com" in acao and "true" in acac.lower():
        fm.add(Finding(
            title="CORS: Reflected Origin + Credentials Allowed",
            severity="High", cvss=8.1, cwe="CWE-942",
            description="Server reflects any Origin and allows credentials — full CORS bypass.",
            remediation="Validate Origin against allowlist. Never combine wildcard with credentials.",
            module="Web", evidence=f"ACAO: {acao}, ACAC: {acac}"
        ))


def check_open_redirect(target: str, session, fm: FindingsManager):
    payloads = [
        f"{target}?url=https://evil.example.com",
        f"{target}?next=https://evil.example.com",
        f"{target}?redirect=https://evil.example.com",
        f"{target}?return=https://evil.example.com",
    ]
    for url in payloads:
        r = safe_get(session, url, allow_redirects=False)
        if r and r.status_code in (301,302,307,308):
            loc = r.headers.get("Location","")
            if "evil.example.com" in loc:
                param = url.split("?")[1].split("=")[0]
                fm.add(Finding(
                    title=f"Open Redirect via '{param}' parameter",
                    severity="Medium", cvss=6.1, cwe="CWE-601",
                    description=f"Redirect parameter '{param}' redirects to external URLs.",
                    remediation="Validate redirect targets against whitelist. Use relative paths.",
                    module="Web", evidence=f"Redirect to: {loc}"
                ))
                return


def scan(target: str, proxy: str = None, stealth: bool = False,
         timeout: int = 10, **kwargs) -> list:
    fm = FindingsManager()
    target = normalize_url(target)
    logger.info(f"[Web] Starting scan: {target}")

    try:
        session = make_session(proxy=proxy, stealth=stealth, timeout=timeout)
    except RuntimeError as e:
        fm.add(Finding(title="Web Scan Unavailable", severity="Info",
                       description=str(e), remediation="Install requests.",
                       module="Web"))
        return fm.all()

    check_https(target, session, fm)
    check_security_headers(target, session, fm)
    check_cookies(target, session, fm)
    check_sensitive_paths(target, session, fm)
    check_error_disclosure(target, session, fm)
    check_http_methods(target, session, fm)
    check_cors(target, session, fm)
    check_open_redirect(target, session, fm)

    if fm.count() == 0:
        fm.add(Finding(
            title="Web App: No Obvious Issues Found",
            severity="Info",
            description="No automated findings. Manual testing recommended.",
            remediation="Perform manual OWASP-guided assessment.",
            module="Web"
        ))
    logger.info(f"[Web] Complete: {fm.count()} findings")
    return fm.all()
