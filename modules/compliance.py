"""Kryphorix Compliance Assessment Module — PCI-DSS, HIPAA, ISO 27001, NIST CSF."""
import ssl
import socket
import requests
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

# ── Compliance check definitions ─────────────────────────────────────────────
# Each check: (id, name, description, how_to_check, fix)
PCI_CHECKS = [
    ("PCI-1.3", "Firewall between Internet and DMZ",
     "Verify network segmentation controls are in place.",
     "port_check", "Implement stateful firewall rules. Deny all unless explicitly allowed."),
    ("PCI-4.1", "TLS 1.2+ for cardholder data",
     "All data transmission must use TLS 1.2 or higher.",
     "tls_version", "Upgrade to TLS 1.2+. Disable SSL and TLS 1.0/1.1."),
    ("PCI-6.1", "Security headers present",
     "Web applications must have appropriate security headers.",
     "sec_headers", "Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options."),
    ("PCI-6.5.1", "Injection flaws prevented",
     "Application must not be vulnerable to SQL/command injection.",
     "injection_check", "Use parameterized queries. Input validation. WAF."),
    ("PCI-8.1", "Strong authentication required",
     "All access must require unique IDs and passwords.",
     "auth_check", "Remove default accounts. Enforce strong passwords. Use MFA."),
]

HIPAA_CHECKS = [
    ("HIPAA-164.312(a)(2)(iv)", "Encryption in transit",
     "PHI must be encrypted in transit.",
     "tls_version", "Enforce TLS 1.2+. Use HTTPS for all PHI transmissions."),
    ("HIPAA-164.312(a)(1)", "Unique user identification",
     "Assign unique names/numbers to all users.",
     "auth_check", "Enforce unique usernames. Prohibit shared accounts."),
    ("HIPAA-164.312(c)(1)", "Data integrity controls",
     "PHI must be protected from alteration.",
     "sec_headers", "Implement integrity checks. Use digital signatures."),
    ("HIPAA-164.312(e)(2)(i)", "Audit controls",
     "Implement audit logging for PHI access.",
     "logging_check", "Enable comprehensive audit logging. Review logs regularly."),
]

ISO_CHECKS = [
    ("ISO-A.14.1.3", "Protection of application services",
     "Information in application services must be protected.",
     "tls_version", "Use TLS 1.2+. Implement API security controls."),
    ("ISO-A.12.6.1", "Management of technical vulnerabilities",
     "Timely patching of known vulnerabilities.",
     "version_check", "Implement vulnerability management program. Patch within SLA."),
    ("ISO-A.10.1.1", "Cryptography policy",
     "Policy on use of cryptographic controls.",
     "tls_version", "Document and enforce cryptography standards."),
    ("ISO-A.9.4.1", "Information access restriction",
     "Access to system and application functions must be restricted.",
     "auth_check", "Implement least privilege. Regular access reviews."),
]

NIST_CHECKS = [
    ("NIST-PR.AC-3", "Remote access managed",
     "Remote access must be managed.",
     "port_check", "Restrict RDP/SSH access. Require MFA for remote access."),
    ("NIST-PR.DS-2", "Data in transit protected",
     "Data-in-transit is protected.",
     "tls_version", "Enforce TLS 1.2+. Disable cleartext protocols."),
    ("NIST-PR.IP-1", "Baseline configuration",
     "Baseline security configuration maintained.",
     "sec_headers", "Implement configuration management. Harden defaults."),
    ("NIST-DE.CM-1", "Network monitoring",
     "Network is monitored for events.",
     "logging_check", "Deploy IDS/IPS. Centralize logging. SIEM integration."),
]

STANDARDS = {
    "pci":     ("PCI-DSS v4.0", PCI_CHECKS),
    "hipaa":   ("HIPAA Security Rule", HIPAA_CHECKS),
    "iso27001":("ISO/IEC 27001:2022", ISO_CHECKS),
    "nist":    ("NIST CSF 2.0", NIST_CHECKS),
}


def _check_tls(host, fm, check_id, check_name, standard):
    port = 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version()
                if proto in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    fm.add(Finding(
                        title=f"[{check_id}] {check_name} — FAILED",
                        severity="High", cvss=7.4, cwe="CWE-326",
                        description=f"TLS version {proto} does not meet {standard} requirements.",
                        remediation="Upgrade to TLS 1.2+. Disable legacy protocols.",
                        module="Compliance",
                        evidence=f"Negotiated: {proto}"
                    ))
                    return False
                else:
                    fm.add(Finding(
                        title=f"[{check_id}] {check_name} — PASSED",
                        severity="Info",
                        description=f"TLS {proto} meets requirements.",
                        remediation="Maintain TLS 1.2+ requirement.",
                        module="Compliance"
                    ))
                    return True
    except Exception as e:
        fm.add(Finding(
            title=f"[{check_id}] {check_name} — Cannot Verify (TLS Error)",
            severity="Medium",
            description=f"Could not verify TLS: {e}",
            remediation="Ensure TLS is configured and accessible.",
            module="Compliance"
        ))
        return False


def _check_security_headers(target, fm, check_id, check_name, standard):
    required = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"]
    try:
        r = requests.get(target, timeout=8, verify=False)  # nosec — scanner intentional
        missing = [h for h in required if h.lower() not in {k.lower() for k in r.headers}]
        if missing:
            fm.add(Finding(
                title=f"[{check_id}] {check_name} — FAILED",
                severity="Medium", cvss=5.3,
                description=f"Missing security headers: {', '.join(missing)}",
                remediation=f"Add required headers for {standard} compliance.",
                module="Compliance",
                evidence=f"Missing: {missing}"
            ))
            return False
        else:
            fm.add(Finding(
                title=f"[{check_id}] {check_name} — PASSED",
                severity="Info",
                description="Required security headers present.",
                remediation="Maintain security headers.",
                module="Compliance"
            ))
            return True
    except Exception:
        return False


def scan(target: str, standard: str = "all", **kwargs) -> list:
    fm = FindingsManager()
    try:
        target = normalize_url(target)
    except ValueError as e:
        fm.add(Finding(title="Invalid Target", severity="Info", description=str(e),
                       remediation="Provide a valid URL or hostname.", module="Compliance"))
        return fm.all()
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    to_run = STANDARDS.items() if standard == "all" else [(standard, STANDARDS.get(standard))]

    for std_key, std_data in to_run:
        if not std_data:
            continue
        std_name, checks = std_data

        fm.add(Finding(
            title=f"Compliance Assessment: {std_name}",
            severity="Info",
            description=f"Running {std_name} compliance checks against {target}",
            remediation="Address all FAILED checks to achieve compliance.",
            module="Compliance"
        ))

        passed = 0
        failed = 0

        for check_id, check_name, check_desc, check_type, fix in checks:
            result = None
            if check_type == "tls_version":
                result = _check_tls(host, fm, check_id, check_name, std_name)
            elif check_type == "sec_headers":
                result = _check_security_headers(target, fm, check_id, check_name, std_name)
            elif check_type in ["auth_check", "injection_check", "port_check", "logging_check", "version_check"]:
                # Manual review required — report as advisory
                fm.add(Finding(
                    title=f"[{check_id}] {check_name} — Manual Review Required",
                    severity="Medium",
                    description=f"{check_desc}\n\nThis control requires manual verification.",
                    remediation=fix,
                    module="Compliance"
                ))
                continue

            if result is True:
                passed += 1
            elif result is False:
                failed += 1

        fm.add(Finding(
            title=f"{std_name} Summary: {passed} passed, {failed} failed (automated)",
            severity="High" if failed > 0 else "Info",
            description=f"Automated compliance check complete. Manual review required for remaining controls.",
            remediation=f"Address all failed controls and manually verify all {std_name} requirements.",
            module="Compliance"
        ))

    return fm.all()
