"""Kryphorix Credential & Password Audit — exposed secrets, default creds, HIBP."""
import re
import requests
import hashlib
from core.finding import Finding
from core.findings import FindingsManager
from modules._base import normalize_url

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
import logging
logger = logging.getLogger("kryphorix")

SECRET_PATTERNS = {
    "AWS Access Key":   r'AKIA[A-Z0-9]{16}',
    "AWS Secret Key":   r'(?:aws_secret|AWS_SECRET)[^=\n]*=[^"\n]*([A-Za-z0-9/+=]{40})',
    "Private Key":      r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    "Generic API Key":  r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
    "JWT Token":        r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.',
    "GitHub Token":     r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
    "Slack Token":      r'xox[baprs]-[A-Za-z0-9-]{10,}',
    "Google API Key":   r'AIza[0-9A-Za-z_\-]{35}',
    "Stripe Key":       r'sk_live_[A-Za-z0-9]{24,}',
    "SendGrid Key":     r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
    "Basic Auth URL":   r'https?://[^:]+:[^@]+@',
    "DB Connection":    r'(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s"\']+',
    "Password Literal": r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
}

SENSITIVE_FILES = [
    "/.env","/.env.local","/.env.production","/.env.backup","/.env.development",
    "/config.php","/config.yml","/config.yaml","/config.json",
    "/wp-config.php","/settings.py","/application.properties",
    "/.git/config","/.htpasswd","/web.config","/credentials.xml",
    "/backup.sql","/dump.sql","/database.sql","/.aws/credentials",
    "/secrets.yaml","/vault.json","/docker-compose.yml","/docker-compose.yaml",
    "/Dockerfile","/.npmrc","/.pypirc","/composer.json",
    "/package.json","/yarn.lock","/Gemfile",
]

DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","admin123"),("admin",""),
    ("root","root"),("root","toor"),("root","password"),("root",""),
    ("test","test"),("guest","guest"),("demo","demo"),
    ("admin","12345"),("admin","123456"),("admin","qwerty"),
    ("admin","letmein"),("admin","admin@123"),
    ("superadmin","superadmin"),("administrator","administrator"),
    ("administrator","password"),("user","user"),("user","password"),
]


def _get(session, url, **kw):
    try:
        kw.setdefault("timeout", 8)
        # ssl_verify defaults to True; caller can override via session.verify
        return session.get(url, **kw)
    except Exception:
        return None


def check_page_secrets(target, session, fm):
    r = _get(session, target)
    if not r:
        return
    body = r.text
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            # Redact
            redacted = [m[:4] + "***" + m[-4:] if len(m) > 8 else "***" for m in matches[:2]]
            fm.add(Finding(
                title=f"Secret Exposed in Page: {secret_type}",
                severity="Critical", cvss=9.8, cwe="CWE-312",
                description=f"Sensitive {secret_type} found in page source.",
                remediation="Remove secrets from source. Use environment variables and secrets managers.",
                module="Credentials",
                evidence=f"Type: {secret_type}\nRedacted samples: {redacted}"
            ))


def check_sensitive_files(target, session, fm):
    base = target.rstrip("/")
    for path in SENSITIVE_FILES:
        r = _get(session, base + path)
        if not r or r.status_code != 200 or len(r.text) < 5:
            continue
        # Check for credential-like content
        if any(kw in r.text.lower() for kw in
               ["password","secret","key","token","database","credential","host","user"]):
            # Redact values before storing
            redacted = re.sub(
                r'(password|secret|key|token)\s*[=:]\s*\S+',
                r'\1 = [REDACTED]',
                r.text[:300], flags=re.IGNORECASE
            )
            sev = "Critical" if any(s in path for s in [".env","config","credentials",".aws",
                                                          ".htpasswd","backup.sql"]) else "High"
            fm.add(Finding(
                title=f"Sensitive File Exposed: {path}",
                severity=sev, cvss=9.8, cwe="CWE-538",
                description=f"File '{path}' is publicly accessible and contains credentials.",
                remediation="Block access via web server config. Remove from web root.",
                module="Credentials",
                evidence=f"URL: {base+path}\nContent (redacted): {redacted}"
            ))


def check_default_creds(target, session, fm):
    login_url = None
    for path in ["/login","/admin/login","/wp-login.php","/admin","/signin","/auth"]:
        r = _get(session, target.rstrip("/") + path)
        if r and r.status_code == 200 and re.search(r'type=["\']password["\']', r.text, re.I):
            login_url = target.rstrip("/") + path
            break
    if not login_url:
        return

    import time as _time
    for user, pwd in DEFAULT_CREDS[:5]:  # Limit attempts to avoid triggering lockout
        try:
            _time.sleep(0.3)  # Gentle pacing to avoid rate-limit lockout
            r = session.post(login_url,
                             data={"username": user, "password": pwd,
                                   "user": user, "pass": pwd,
                                   "email": f"{user}@test.com"},
                             timeout=8, allow_redirects=True)
            if r:
                success = any(s in r.text.lower() for s in
                              ["dashboard","logout","welcome","my account","profile","overview"])
                fail = any(f in r.text.lower() for f in
                           ["invalid","incorrect","wrong","failed","error"])
                if success and not fail:
                    fm.add(Finding(
                        title=f"Default Credentials Work: {user}:{pwd}",
                        severity="Critical", cvss=9.8, cwe="CWE-521",
                        description=f"Default credentials '{user}:{pwd}' authenticated successfully.",
                        remediation="Change default credentials immediately. Enforce strong passwords.",
                        module="Credentials"
                    ))
                    return
        except Exception:
            continue


def check_hibp(domain, fm, api_key: str = None):
    """Check HaveIBeenPwned for known breaches.

    HIBP API v3 requires an API key for breach search. Without a key,
    only public breach list (no domain filtering) is available.
    Set HIBP_API_KEY environment variable or pass api_key parameter.
    """
    import os as _os
    key = api_key or _os.environ.get("HIBP_API_KEY", "")
    headers = {"User-Agent": "Kryphorix/4.0 Security Assessment"}
    if key:
        headers["hibp-api-key"] = key
    try:
        r = requests.get("https://haveibeenpwned.com/api/v3/breaches",
                         headers=headers, timeout=10)
        if r.status_code == 401:
            logger.info("[Credentials] HIBP API key required. Set HIBP_API_KEY env var.")
            return
        if r.status_code == 429:
            logger.warning("[Credentials] HIBP rate limited.")
            return
        if r.status_code == 200:
            breaches = r.json()
            domain_breaches = [b for b in breaches
                               if domain.lower() in b.get("Domain", "").lower()]
            if domain_breaches:
                names = [b.get("Name", "") for b in domain_breaches]
                fm.add(Finding(
                    title=f"Domain in {len(domain_breaches)} Known Data Breach(es)",
                    severity="High", cvss=8.1, cwe="CWE-359",
                    description=f"Domain involved in: {', '.join(names)}",
                    remediation="Force password resets. Enable MFA. Conduct security review.",
                    module="Credentials",
                    evidence=f"Breaches: {names}"
                ))
    except Exception:
        pass


def scan(target: str, wordlist: str = None, **kwargs) -> list:
    fm = FindingsManager()
    try:
        target = normalize_url(target)
    except ValueError as e:
        fm.add(Finding(title="Invalid Target", severity="Info", description=str(e),
                       remediation="Provide a valid URL or hostname.", module="Credentials"))
        return fm.all()
    domain = target.replace("https://","").replace("http://","").split("/")[0]

    session = requests.Session()
    session.headers["User-Agent"] = "Kryphorix/4.0 Security Scanner"
    # SSL verification on by default; disable only if explicitly requested
    session.verify = kwargs.get("ssl_verify", True)

    check_page_secrets(target, session, fm)
    check_sensitive_files(target, session, fm)
    check_default_creds(target, session, fm)
    check_hibp(domain, fm)

    return fm.all()
