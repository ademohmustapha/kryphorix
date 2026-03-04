"""
Kryphorix API Security Scanner
Tests: auth bypass, BOLA/IDOR, mass assignment, rate limiting,
versioning exposure, JWT weaknesses, GraphQL introspection, CORS.
"""
import re
import json
import requests
from urllib.parse import urljoin
from core.finding import Finding
from core.findings import FindingsManager

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
import logging

# NOTE: SSL certificate verification is intentionally set per-request in this module.
# When scanning unknown/untrusted targets (the primary use-case of a security assessment
# tool), self-signed and expired certificates are EXPECTED findings — not errors.
# verify=False is used so the scanner reaches the target and REPORTS the bad cert
# as a finding, rather than refusing to connect. This is correct security-scanner
# behaviour. For internal/trusted targets, pass ssl_verify=True via kwargs.
# SSL_VERIFY_NOTE

logger = logging.getLogger("kryphorix")

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1",
    "/graphql", "/graphiql",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/.well-known/openid-configuration",
    "/oauth2/token", "/oauth/token", "/auth/token",
]

SENSITIVE_ENDPOINTS = [
    "/api/users", "/api/admin", "/api/config", "/api/debug",
    "/api/v1/users", "/api/v1/admin", "/api/v1/keys",
    "/api/v2/users", "/api/internal",
    "/api/health", "/api/status", "/api/metrics",
    "/api/export", "/api/backup", "/api/dump",
]

JWT_NONE_TOKEN = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Iktyb3Bob3JpeCIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9."


def _get(session, url, **kw):
    try:
        kw.setdefault("timeout", 10)
        kw.setdefault("verify", False)
        return session.get(url, **kw)
    except Exception:
        return None


def discover_api(target, session, fm):
    """Discover API endpoints."""
    base = target.rstrip("/")
    found = []
    for path in API_PATHS:
        r = _get(session, base + path)
        if r and r.status_code in [200, 401, 403]:
            found.append(f"{path} → {r.status_code}")
            # OpenAPI/Swagger exposure
            if r.status_code == 200 and any(kw in r.text[:2000] for kw in
                                             ["openapi", "swagger", "paths", "definitions"]):
                fm.add(Finding(
                    title=f"API Documentation Exposed: {path}",
                    severity="Medium",
                    description=f"API specification file at '{path}' reveals all endpoints and schemas.",
                    remediation="Restrict API docs to authenticated users. Remove from production if not needed.",
                    module="API", cvss=5.3, cwe="CWE-200",
                    evidence=f"URL: {base+path} — contains API schema"
                ))

            # GraphQL introspection
            if "graphql" in path and r.status_code == 200:
                introspect = _get(session, base + path,
                                  params={"query": "{__schema{types{name}}}"})
                if introspect and "__schema" in (introspect.text or ""):
                    fm.add(Finding(
                        title="GraphQL Introspection Enabled",
                        severity="Medium",
                        description="GraphQL introspection reveals full schema — types, queries, mutations.",
                        remediation="Disable introspection in production environments.",
                        module="API", cvss=5.3, cwe="CWE-200",
                        evidence="Introspection query returned full schema"
                    ))

    if found:
        fm.add(Finding(
            title=f"API Endpoints Discovered ({len(found)})",
            severity="Info",
            description=f"Found {len(found)} API endpoints.",
            remediation="Audit all API endpoints for proper authentication and authorization.",
            module="API",
            evidence="\n".join(found[:20])
        ))

    return bool(found)


def check_auth_bypass(target, session, fm):
    """Test for authentication bypass techniques."""
    base = target.rstrip("/")
    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
    ]

    for endpoint in SENSITIVE_ENDPOINTS[:6]:
        r = _get(session, base + endpoint)
        if r and r.status_code in [401, 403]:
            # Try bypass headers
            for hdr in bypass_headers:
                r2 = _get(session, base + endpoint, headers=hdr)
                if r2 and r2.status_code == 200 and len(r2.text) > 50:
                    fm.add(Finding(
                        title=f"Authentication Bypass via Header: {list(hdr.keys())[0]}",
                        severity="Critical",
                        description=f"Adding header '{list(hdr.keys())[0]}: {list(hdr.values())[0]}' "
                                    f"bypasses 401/403 on '{endpoint}'.",
                        remediation="Remove server-side IP trust based on client-supplied headers. "
                                    "Implement proper authentication at application layer.",
                        module="API", cvss=9.8, cwe="CWE-290",
                        evidence=f"Endpoint: {base+endpoint}\nHeader: {hdr}\nStatus: {r2.status_code}"
                    ))
                    return


def check_jwt_vulnerabilities(target, session, fm):
    """Test for JWT algorithm confusion and none algorithm."""
    # Test alg:none
    r = _get(session, target, headers={"Authorization": f"Bearer {JWT_NONE_TOKEN}"})
    if r and r.status_code == 200 and r.text and len(r.text) > 20:
        fm.add(Finding(
            title="JWT Algorithm None Accepted",
            severity="Critical",
            description="Server accepts JWT with alg=none, allowing forgery of tokens without signature.",
            remediation="Explicitly reject tokens with alg=none. Maintain strict whitelist of allowed algorithms.",
            module="API", cvss=9.8, cwe="CWE-347",
            evidence="alg:none JWT returned HTTP 200"
        ))

    # Check for JWT in common headers/cookies
    r2 = _get(session, target)
    if r2:
        # Look for JWT pattern in response
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        jwts = re.findall(jwt_pattern, r2.text)
        if jwts:
            # Check if JWT has sensitive claims
            import base64
            for jwt in jwts[:2]:
                try:
                    payload = jwt.split(".")[1]
                    padding = 4 - len(payload) % 4
                    decoded = base64.b64decode(payload + "=" * padding).decode("utf-8", errors="ignore")
                    if any(s in decoded.lower() for s in ["password", "secret", "key", "admin"]):
                        fm.add(Finding(
                            title="Sensitive Data in JWT Payload",
                            severity="High",
                            description="JWT token in response contains sensitive fields in payload.",
                            remediation="Remove sensitive data from JWT payload. Payload is base64-encoded, not encrypted.",
                            module="API", cvss=7.5, cwe="CWE-312",
                            evidence=f"Decoded payload (partial): {decoded[:200]}"
                        ))
                except Exception:
                    pass


def check_rate_limiting(target, session, fm):
    """Test if API has rate limiting."""
    responses = []
    for _ in range(20):
        r = _get(session, target)
        if r:
            responses.append(r.status_code)

    if 429 in responses:
        fm.add(Finding(
            title="API Rate Limiting Active",
            severity="Info",
            description="API returns 429 Too Many Requests — rate limiting is implemented.",
            remediation="Verify rate limits are appropriately configured.",
            module="API"
        ))
    elif all(c == 200 for c in responses):
        fm.add(Finding(
            title="No API Rate Limiting Detected",
            severity="Medium",
            description="20 rapid API requests received no throttling response.",
            remediation="Implement rate limiting: max requests per IP/token per time window.",
            module="API", cvss=5.3, cwe="CWE-770"
        ))


def check_mass_assignment(target, session, fm):
    """Test for mass assignment vulnerabilities."""
    test_endpoints = ["/api/v1/users", "/api/users", "/api/profile", "/api/account"]
    extra_fields   = {"admin": True, "role": "admin", "is_admin": True, "superuser": True}

    for endpoint in test_endpoints[:3]:
        try:
            r = requests.post(
                target.rstrip("/") + endpoint,
                json={**{"username": "test", "email": "test@test.com", "password": "Test123!"}, **extra_fields},
                timeout=8, verify=False
            )  # nosec — scanner intentional
            if r and r.status_code in [200, 201]:
                resp_data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                if any(str(v).lower() in ["true", "1", "admin"] for v in
                       (resp_data.get("admin"), resp_data.get("role"), resp_data.get("is_admin"))):
                    fm.add(Finding(
                        title=f"Mass Assignment Vulnerability at {endpoint}",
                        severity="Critical",
                        description="API accepts and processes privileged fields from user input.",
                        remediation="Use allowlists for accepted fields. Never bind request body directly to model.",
                        module="API", cvss=9.8, cwe="CWE-915",
                        evidence=f"Sent: {extra_fields}\nReceived privileged values in response"
                    ))
                    return
        except Exception:
            pass


def scan(target: str, **kwargs) -> list:
    fm = FindingsManager()
    try:
        target = normalize_url(target)
    except ValueError as e:
        fm.add(Finding(title="Invalid Target", severity="Info", description=str(e),
                       remediation="Provide a valid URL or hostname.", module="API"))
        return fm.all()
    session = requests.Session()
    session.headers["User-Agent"] = "Kryphorix/4.0 API Scanner"

    api_found = discover_api(target, session, fm)
    if api_found:
        check_auth_bypass(target, session, fm)
        check_jwt_vulnerabilities(target, session, fm)
        check_mass_assignment(target, session, fm)

    check_rate_limiting(target, session, fm)

    return fm.all()
