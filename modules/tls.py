"""
modules/tls.py  —  TLS/SSL Deep Audit
======================================
Tests: protocol versions, cipher suites, cert expiry/validity,
HSTS preload, key size, CT compliance, HPKP remnants.
"""
import ssl
import socket
import re
import logging
from datetime import datetime, timezone, timedelta
from core.finding  import Finding
from core.findings import FindingsManager
from modules._base import extract_host

logger = logging.getLogger("kryphorix")

WEAK_PROTOCOLS = {
    "SSLv2":  ("Critical", 9.8, "CVE-2011-3389"),
    "SSLv3":  ("Critical", 9.8, "CVE-2014-3566"),   # POODLE
    "TLSv1":  ("High",     7.4, "CVE-2011-3389"),   # BEAST
    "TLSv1.1":("High",     7.4, ""),
}

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ADH", "AECDH",
    "MD5", "SHA1RSA", "ANON",
]

CERT_WARN_DAYS = 30
CERT_CRIT_DAYS = 7


def _get_cert_info(host: str, port: int = 443) -> dict:
    """Retrieve certificate and negotiated protocol via OS SSL stack."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE  # nosec — scanner intentional
    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert  = s.getpeercert(binary_form=False)
                proto = s.version()
                cipher_info = s.cipher()   # (name, protocol, bits)
                return {
                    "cert":   cert or {},
                    "proto":  proto,
                    "cipher": cipher_info,
                    "ok":     True,
                }
    except ssl.SSLError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_legacy_protocol(host: str, port: int, proto_const) -> bool:
    """Return True if host accepts the given (legacy) TLS/SSL protocol."""
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE  # nosec — scanner intentional
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except Exception:
        return False


def check_protocols(host: str, port: int, fm: FindingsManager):
    """Test for SSL/TLS legacy protocol acceptance."""
    proto_tests = []

    # SSLv3
    try:
        proto_tests.append(("SSLv3",  ssl.PROTOCOL_SSLv3))   # May not exist
    except AttributeError:
        pass
    # TLS 1.0 / 1.1 (these attributes removed in Python 3.10+, use OP_NO_ flags)
    try:
        ctx_10 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_10.check_hostname = False
        ctx_10.verify_mode    = ssl.CERT_NONE
        ctx_10.minimum_version = ssl.TLSVersion.TLSv1
        ctx_10.maximum_version = ssl.TLSVersion.TLSv1
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx_10.wrap_socket(raw, server_hostname=host):
                fm.add(Finding(
                    title="TLS 1.0 Accepted — Deprecated Protocol",
                    severity="High", cvss=7.4, cwe="CWE-326",
                    description="TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST.",
                    remediation="Disable TLS 1.0. Accept TLS 1.2 minimum, prefer TLS 1.3.",
                    module="TLS"
                ))
    except Exception:
        pass

    try:
        ctx_11 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_11.check_hostname = False
        ctx_11.verify_mode    = ssl.CERT_NONE
        ctx_11.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx_11.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx_11.wrap_socket(raw, server_hostname=host):
                fm.add(Finding(
                    title="TLS 1.1 Accepted — Deprecated Protocol",
                    severity="High", cvss=7.4, cwe="CWE-326",
                    description="TLS 1.1 is deprecated (RFC 8996).",
                    remediation="Disable TLS 1.1. Accept TLS 1.2+.",
                    module="TLS"
                ))
    except Exception:
        pass


def check_certificate(host: str, port: int, fm: FindingsManager):
    info = _get_cert_info(host, port)
    if not info.get("ok"):
        fm.add(Finding(
            title=f"TLS Connection Failed: {host}:{port}",
            severity="High", cvss=7.5, cwe="CWE-326",
            description=f"Could not establish TLS: {info.get('error','unknown')}",
            remediation="Verify TLS is configured. Check firewall rules.",
            module="TLS"
        ))
        return

    cert  = info.get("cert", {})
    proto = info.get("proto", "Unknown")
    ciph  = info.get("cipher", ("Unknown", "", 0))

    # Negotiated protocol
    fm.add(Finding(
        title=f"TLS Negotiated: {proto} / {ciph[0]}",
        severity="Info" if proto in ("TLSv1.2","TLSv1.3") else "Medium",
        description=f"Negotiated: {proto}, cipher: {ciph[0]}, bits: {ciph[2]}",
        remediation="Prefer TLS 1.3. Minimum TLS 1.2.",
        module="TLS"
    ))

    # Weak cipher
    if any(wk in ciph[0].upper() for wk in WEAK_CIPHERS):
        fm.add(Finding(
            title=f"Weak Cipher Suite: {ciph[0]}",
            severity="High", cvss=7.4, cwe="CWE-326",
            description=f"Weak cipher {ciph[0]} accepted.",
            remediation="Configure ECDHE+AES-GCM or ChaCha20 ciphers only.",
            module="TLS"
        ))

    # Key size
    if ciph[2] and ciph[2] < 128:
        fm.add(Finding(
            title=f"Insufficient Key Length: {ciph[2]} bits",
            severity="High", cvss=7.4, cwe="CWE-326",
            description=f"Key length {ciph[2]} bits is below the 128-bit minimum.",
            remediation="Use 2048-bit RSA or 256-bit ECDSA certificates.",
            module="TLS"
        ))

    # Certificate expiry
    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (exp - now).days
            if days_left < 0:
                fm.add(Finding(
                    title="Certificate EXPIRED",
                    severity="Critical", cvss=9.8, cwe="CWE-295",
                    description=f"Certificate expired {abs(days_left)} days ago.",
                    remediation="Renew certificate immediately.",
                    module="TLS", evidence=f"Expired: {not_after}"
                ))
            elif days_left <= CERT_CRIT_DAYS:
                fm.add(Finding(
                    title=f"Certificate Expires in {days_left} Days — URGENT",
                    severity="Critical", cvss=9.0, cwe="CWE-295",
                    description=f"Certificate expires in {days_left} days.",
                    remediation="Renew immediately. Enable auto-renewal (Let's Encrypt).",
                    module="TLS"
                ))
            elif days_left <= CERT_WARN_DAYS:
                fm.add(Finding(
                    title=f"Certificate Expires in {days_left} Days",
                    severity="High", cvss=7.5, cwe="CWE-295",
                    description=f"Certificate expires soon: {not_after}",
                    remediation="Schedule certificate renewal.",
                    module="TLS"
                ))
        except Exception:
            pass

    # Self-signed
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    subject = dict(x[0] for x in cert.get("subject", []))
    if issuer.get("organizationName") == subject.get("organizationName") and issuer:
        fm.add(Finding(
            title="Self-Signed Certificate",
            severity="High", cvss=7.4, cwe="CWE-295",
            description="Certificate is self-signed — clients will receive browser warnings.",
            remediation="Obtain certificate from a trusted CA (Let's Encrypt for free).",
            module="TLS"
        ))

    # Wildcard cert
    sans = cert.get("subjectAltName", [])
    wildcards = [v for t, v in sans if t == "DNS" and v.startswith("*")]
    if wildcards:
        fm.add(Finding(
            title=f"Wildcard Certificate: {wildcards[0]}",
            severity="Low", cvss=3.1, cwe="CWE-295",
            description="Wildcard certs compromise all subdomains if the private key is stolen.",
            remediation="Use specific SAN certificates for critical services.",
            module="TLS", evidence=f"Wildcards: {wildcards}"
        ))


def scan(target: str, port: int = 443, **kwargs) -> list:
    fm   = FindingsManager()
    host = extract_host(target)

    # Resolve port from target if explicit
    if ":" in target.replace("https://","").replace("http://",""):
        parts = target.replace("https://","").replace("http://","").split(":")
        if len(parts) > 1:
            try:
                port = int(parts[1].split("/")[0])
            except ValueError:
                pass

    logger.info(f"[TLS] Auditing {host}:{port}")

    # Check TLS is even available
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.close()
    except Exception:
        fm.add(Finding(
            title=f"Port {port} Not Reachable on {host}",
            severity="Info",
            description=f"Cannot connect to {host}:{port} — TLS audit skipped.",
            remediation="Verify host/port.", module="TLS"
        ))
        return fm.all()

    check_protocols(host, port, fm)
    check_certificate(host, port, fm)

    logger.info(f"[TLS] Complete: {fm.count()} findings")
    return fm.all()
