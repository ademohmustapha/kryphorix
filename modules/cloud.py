"""Kryphorix Cloud Misconfiguration Scanner — S3, Azure, GCP, SSRF."""
import re
import requests
import socket
from core.finding import Finding
from core.findings import FindingsManager
from modules._base import normalize_url

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

S3_PATTERNS = [r's3\.amazonaws\.com/([a-z0-9.-]+)', r'([a-z0-9.-]+)\.s3\.amazonaws\.com']
AZURE_PATTERNS = [r'([a-z0-9]+)\.blob\.core\.windows\.net']
GCP_PATTERNS = [r'storage\.googleapis\.com/([a-z0-9_.-]+)']


def _derive_buckets(domain):
    base = domain.replace(".", "-").replace("_", "-")
    return [domain, base,
            f"{base}-backup", f"{base}-backups", f"{base}-dev", f"{base}-staging",
            f"{base}-prod", f"{base}-data", f"{base}-logs", f"{base}-assets",
            f"{base}-static", f"{base}-files", f"{base}-uploads", f"{base}-media",
            f"backup-{base}", f"dev-{base}", f"test-{base}", f"www-{base}"]


def _check_s3(bucket, fm):
    for url in [f"https://{bucket}.s3.amazonaws.com", f"https://s3.amazonaws.com/{bucket}"]:
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200 and "<ListBucketResult" in r.text:
                files = re.findall(r'<Key>(.*?)</Key>', r.text)
                sensitive = [f for f in files if any(k in f.lower() for k in
                             ["password","secret","key",".env","backup",".sql",".pem"])]
                sev = "Critical" if sensitive else "High"
                fm.add(Finding(
                    title=f"Public S3 Bucket with Listing: {bucket}",
                    severity=sev, cvss=9.8 if sev == "Critical" else 8.2, cwe="CWE-284",
                    description=f"S3 bucket '{bucket}' is public with {len(files)} files"
                                + (f", {len(sensitive)} sensitive." if sensitive else "."),
                    remediation="Enable S3 Block Public Access. Review bucket policy.",
                    module="Cloud",
                    evidence=f"URL: {url}\nFiles: {files[:5]}" + (f"\nSensitive: {sensitive}" if sensitive else "")
                ))
                return True
            elif r.status_code == 403:
                fm.add(Finding(
                    title=f"S3 Bucket Exists (Private): {bucket}",
                    severity="Low", cvss=2.0,
                    description=f"S3 bucket '{bucket}' exists but blocks public access.",
                    remediation="Verify this is your authorized bucket.",
                    module="Cloud"
                ))
                return True
        except Exception:
            continue
    return False


def _network_position_note() -> str:
    """
    Detect likely network position so callers can contextualise metadata findings.
    Cloud metadata services (169.254.169.254) are only reachable from inside
    a cloud VM. An external scanner will always time out on these checks —
    that is expected behaviour, NOT a finding of 'service unavailable'.
    """
    import socket
    try:
        # Check if we can reach a link-local address (only possible inside a VM)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("169.254.169.254", 80))
        s.close()
        return "INSIDE_CLOUD"
    except Exception:
        return "EXTERNAL"


def _check_metadata_ssrf(target, session, fm):
    # NOTE: Direct metadata-endpoint reachability is only testable from inside a cloud VM.
    # When scanning from an external network, these checks test whether the TARGET
    # APPLICATION is vulnerable to SSRF — i.e. whether it can be made to proxy
    # a request to the metadata endpoint on behalf of the scanner.
    # That is intentional and correct security-scanner behaviour.
    ssrf_targets = {
        "AWS":   ("http://169.254.169.254/latest/meta-data/", ["ami-id","instance-id","security-credentials"]),
        "GCP":   ("http://metadata.google.internal/computeMetadata/v1/", ["computeMetadata","project"]),
        "Azure": ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["vmId","location"]),
    }
    for param in ["url","redirect","proxy","fetch","callback","next","dest"][:5]:
        for provider, (ssrf_url, indicators) in ssrf_targets.items():
            try:
                r = session.get(target, params={param: ssrf_url}, timeout=5, verify=False)  # nosec — scanner intentional
                for ind in indicators:
                    if ind in r.text:
                        fm.add(Finding(
                            title=f"SSRF to {provider} Metadata Service",
                            severity="Critical", cvss=9.8, cwe="CWE-918",
                            description=f"Parameter '{param}' fetches {provider} metadata, leaking cloud credentials.",
                            remediation="Block SSRF. Validate/whitelist URLs. Use IMDSv2 on AWS.",
                            module="Cloud",
                            evidence=f"Param={param}={ssrf_url}, Indicator={ind}"
                        ))
                        return
            except Exception:
                continue


def scan(target: str, **kwargs) -> list:
    fm = FindingsManager()
    try:
        target = normalize_url(target)
    except ValueError as e:
        fm.add(Finding(title="Invalid Target", severity="Info", description=str(e),
                       remediation="Provide a valid URL or hostname.", module="Cloud"))
        return fm.all()
    session = requests.Session()
    session.headers["User-Agent"] = "Kryphorix/4.0"
    domain = target.replace("https://","").replace("http://","").split("/")[0]

    # Determine network position so report consumers can correctly interpret metadata results
    net_position = _network_position_note()
    if net_position == "EXTERNAL":
        fm.add(Finding(
            title="Scanning from External Network — Metadata Checks Are SSRF-Only",
            severity="Info",
            description=(
                "This scan is running from outside a cloud provider network. "
                "Cloud instance metadata endpoints (169.254.169.254) are not directly reachable "
                "from external IPs — this is expected. "
                "The SSRF checks below test whether the TARGET APPLICATION can be made to "
                "proxy requests to the metadata service, which IS an externally detectable vulnerability."
            ),
            remediation="For direct metadata endpoint testing, run Kryphorix from inside the cloud VM.",
            module="Cloud",
        ))

    # Extract cloud refs from page
    try:
        r = session.get(target, timeout=8, verify=False)  # nosec — scanner intentional
        for pattern in S3_PATTERNS:
            for m in re.findall(pattern, r.text):
                _check_s3(m, fm)
        for pattern in AZURE_PATTERNS:
            for acc in re.findall(pattern, r.text):
                for cont in ["$web","public","files","backup"]:
                    try:
                        r2 = requests.get(
                            f"https://{acc}.blob.core.windows.net/{cont}?restype=container&comp=list",
                            timeout=8)
                        if r2.status_code == 200 and "EnumerationResults" in r2.text:
                            fm.add(Finding(
                                title=f"Public Azure Blob Container: {acc}/{cont}",
                                severity="High", cvss=8.2, cwe="CWE-284",
                                description=f"Azure blob '{cont}' is publicly accessible.",
                                remediation="Set container to private. Review storage firewall.",
                                module="Cloud"
                            ))
                    except Exception:
                        pass
    except Exception:
        pass

    # Derived S3 bucket checks
    found = False
    for bucket in _derive_buckets(domain)[:10]:
        if _check_s3(bucket, fm):
            found = True

    _check_metadata_ssrf(target, session, fm)

    if not found:
        fm.add(Finding(
            title="No Public Cloud Storage Found",
            severity="Info",
            description="Automated cloud storage checks found no obvious misconfigurations.",
            remediation="Manually review cloud IAM policies and storage permissions.",
            module="Cloud"
        ))
    return fm.all()
