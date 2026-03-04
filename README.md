# KRYPHORIX v2.0.0 — Elite Cyber Security Assessment Suite

**Real-world deployable penetration testing framework. No setup. No config. Just run.**

Kali Linux · macOS · Windows 10/11 · Python 3.8–3.13+ · Auto-Adaptive

---

## Quick Start

```bash
# Linux / macOS
chmod +x kryphorix.sh
./kryphorix.sh                                    # Interactive menu
./kryphorix.sh --web https://target.com           # Web scan
./kryphorix.sh --full target.com                  # All 17 modules

# Windows
kryphorix.bat
kryphorix.bat --web https://target.com

# Direct Python (any OS)
python kryphorix.py
python kryphorix.py --full target.com
```

**Dependencies auto-install on first run** — no manual pip install needed.

---

## 17 Security Modules

| # | Module | Coverage |
|---|--------|----------|
| 1 | **Web Application** | Security headers, cookies, CORS, sensitive paths, error disclosure, open redirect |
| 2 | **API Security** | Auth bypass, JWT flaws, mass assignment, GraphQL, rate limiting, Swagger exposure |
| 3 | **Active Directory** | SMB signing, null sessions, LDAP anon bind, Kerberos AS-REP, WinRM, zone transfer |
| 4 | **Port Scanner + CVE Map** | Multi-threaded TCP, nmap integration, 100+ service CVE database, stealth mode |
| 5 | **TLS / SSL Audit** | Protocol versions, ciphers, cert expiry, HSTS, key size, self-signed |
| 6 | **Wireless** | WEP/WPA/WPA2/WPA3, open networks, rogue APs, default SSIDs — cross-platform |
| 7 | **OWASP Top 10** | All 10 categories (2021/2025, auto-updated annually) with active probes |
| 8 | **OSINT Recon** | WHOIS, DNS, SPF/DMARC, zone transfer, Shodan, cert transparency |
| 9 | **SSH Audit** | Version CVE check, weak algorithms, password auth, ssh-audit integration |
| 10 | **Subdomain Enum** | DNS brute force (500 wordlist) + cert transparency + takeover detection |
| 11 | **Firewall / WAF** | 13 WAF signatures, bypass testing, rate limiting detection |
| 12 | **Cloud Security** | S3 public buckets, Azure blobs, GCP storage, SSRF to metadata endpoints |
| 13 | **Credential Audit** | Exposed secrets in source, sensitive files, default creds, HIBP |
| 14 | **Network Infra** | SNMP community strings, NFS, TFTP, rsync, UPnP |
| 15 | **Malware Detection** | Webshell patterns, malicious JS, crypto miners, file upload testing |
| 16 | **Compliance** | PCI-DSS v4.0, HIPAA, ISO 27001:2022, NIST CSF 2.0 |
| 17 | **Full Scan** | All 17 modules in parallel, comprehensive PDF+JSON+HTML+CSV report |

---

## Usage Examples

```bash
# Single module
python kryphorix.py --web https://example.com
python kryphorix.py --ports 192.168.1.100
python kryphorix.py --tls example.com
python kryphorix.py --ad 10.0.0.1 --ad-user admin --ad-pass Pass123 --ad-domain corp.local

# Multiple modules
python kryphorix.py --web https://example.com --owasp https://example.com --tls example.com

# Full scan — all 17 modules
python kryphorix.py --full https://example.com

# Proxy integration (Burp Suite, ZAP, etc.)
python kryphorix.py --proxy http://127.0.0.1:8080 --web https://example.com

# Stealth mode (slower, quieter)
python kryphorix.py --stealth --ports 10.0.0.1

# Compliance check
python kryphorix.py --compliance https://example.com --standard pci

# Report formats
python kryphorix.py --full target.com --output pdf,json,html,csv

# Utilities
python kryphorix.py --selftest         # Health check
python kryphorix.py --update           # Update tool + OWASP lists
python kryphorix.py --workspace prod   # Resume saved scan session
```

---

## Cross-Platform Compatibility

| Feature | Kali Linux | Ubuntu/Debian | macOS | Windows |
|---------|-----------|---------------|-------|---------|
| All scan modules | ✓ | ✓ | ✓ | ✓ |
| Wireless scan | ✓ nmcli/iwlist | ✓ | ✓ airport/system_profiler | ✓ netsh |
| PDF reports | ✓ | ✓ | ✓ | ✓ |
| Auto-install deps | ✓ (PEP 668 aware) | ✓ | ✓ Homebrew | ✓ |
| Launcher script | kryphorix.sh | kryphorix.sh | kryphorix.sh | kryphorix.bat |
| Root optional | ✓ | ✓ | ✓ | ✓ |

### macOS 14+ (Sonoma and beyond)
The `airport` binary was removed in macOS 14. Kryphorix automatically detects this and uses `system_profiler SPAirPortDataType` instead.

### Python 3.12+ / PEP 668
Operating systems that mark Python as "externally managed" (Kali 2024+, Ubuntu 23.04+, Homebrew Python 3.12+) are fully supported. The bootstrap system detects this at runtime and uses `--break-system-packages` automatically, or falls back to `--user` install.

---

## Security Architecture

- **File Integrity Verification** — SHA-256 manifest checked on every startup
- **Tamper-Evident Audit Log** — Chain-hashed JSONL log of all operations
- **Session Workspaces** — Save/resume any scan with `--workspace NAME`
- **Stealth Mode** — Throttled scanning for sensitive engagements
- **Proxy Support** — Full HTTP(S) proxy for traffic inspection

---

## Requirements

- Python 3.8+ (3.11+ recommended)
- No root required for most modules
- Root/sudo recommended for: wireless, raw socket scans

**All Python dependencies auto-install on first run.**

Optional system tools (enhance capabilities if installed):
- `nmap` — Enhanced port scanning
- `ssh-audit` — Deep SSH analysis  
- `nmcli` / `iwlist` — Wireless scanning (Linux)

---

## Plugin System

Add custom modules as `plugins/plugin_mycheck.py`:

```python
from core.finding import Finding

def scan(target: str) -> list:
    findings = []
    # ... your custom check ...
    findings.append(Finding(
        title="Custom Finding",
        severity="Medium",
        description="Description of the issue.",
        remediation="How to fix it.",
        module="Custom"
    ))
    return findings
```

Plugins auto-discovered on startup. No registration needed.

---

## Legal Notice

**AUTHORISED USE ONLY.** Using Kryphorix against systems you do not own or have explicit written permission to test is illegal in most jurisdictions. The authors accept no liability for misuse.

---

*Kryphorix v2.0.0 — Elite Cyber Security Assessment Suite — 2026*
