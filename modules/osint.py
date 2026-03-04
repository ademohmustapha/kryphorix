"""Kryphorix OSINT Reconnaissance — WHOIS, DNS, Shodan, CT logs, breach check."""
import socket
import re
import json
import requests
from core.finding import Finding
from core.findings import FindingsManager

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
import logging
logger = logging.getLogger("kryphorix")

try:
    import dns.resolver, dns.query, dns.zone
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def _clean(target):
    return target.replace("https://", "").replace("http://", "").split("/")[0]


def whois_rdap(domain, fm):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
            expiry = events.get("expiration", "Unknown")
            fm.add(Finding(
                title="WHOIS/RDAP Registration Data",
                severity="Info",
                description=f"Domain registered. Expiry: {expiry}",
                remediation="Enable WHOIS privacy. Monitor renewal.",
                module="OSINT",
                evidence=json.dumps({"expiry": expiry, "events": events}, default=str)[:400]
            ))
    except Exception:
        pass


def dns_enum(domain, fm):
    if not HAS_DNS:
        # Fallback using socket
        try:
            ip = socket.gethostbyname(domain)
            fm.add(Finding(
                title=f"DNS A Record: {domain} → {ip}",
                severity="Info",
                description=f"Domain resolves to {ip}",
                remediation="Review DNS records for unintended exposure.",
                module="OSINT"
            ))
        except Exception:
            pass
        return

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    dns_data = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            dns_data[rtype] = [str(r) for r in answers]
        except Exception:
            continue

    # Zone transfer
    for ns in dns_data.get("NS", [])[:3]:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns.rstrip("."), domain, timeout=5))
            fm.add(Finding(
                title="DNS Zone Transfer Allowed",
                severity="Critical",
                description=f"Nameserver {ns} allows AXFR — full DNS exposed.",
                remediation="Restrict zone transfers to authorized secondaries.",
                module="OSINT", cvss=9.8, cwe="CWE-200",
                evidence=f"Zone transfer from {ns}"
            ))
        except Exception:
            pass

    # SPF/DMARC
    txts = dns_data.get("TXT", [])
    if not any("v=spf1" in t for t in txts):
        fm.add(Finding(
            title="Missing SPF Record",
            severity="Medium",
            description="No SPF record. Domain can be spoofed in email.",
            remediation="Add SPF TXT record.",
            module="OSINT", cvss=5.3, cwe="CWE-183"
        ))
    has_dmarc = False
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        has_dmarc = any("v=DMARC1" in str(r) for r in dmarc)
    except Exception:
        pass
    if not has_dmarc:
        fm.add(Finding(
            title="Missing DMARC Record",
            severity="Medium",
            description="No DMARC policy. Email spoofing likely to succeed.",
            remediation="Add DMARC TXT record with p=reject policy.",
            module="OSINT", cvss=5.3, cwe="CWE-183"
        ))

    if dns_data:
        fm.add(Finding(
            title=f"DNS Enumeration — {len(dns_data)} Record Types Found",
            severity="Info",
            description="DNS records enumerated.",
            remediation="Review for unintended exposure.",
            module="OSINT",
            evidence=json.dumps(dns_data, indent=2)[:600]
        ))


def shodan_passive(ip, fm):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulns", [])
            ports = data.get("ports", [])
            if vulns:
                fm.add(Finding(
                    title=f"Shodan: {len(vulns)} Known CVEs on {ip}",
                    severity="Critical",
                    description=f"Shodan database shows {len(vulns)} CVEs for this IP.",
                    remediation="Patch all CVEs immediately. Review exposed services.",
                    module="OSINT", cvss=9.0,
                    evidence=f"CVEs: {', '.join(vulns[:10])}\nPorts: {ports}"
                ))
            elif ports:
                fm.add(Finding(
                    title=f"Shodan: {len(ports)} Indexed Ports on {ip}",
                    severity="Medium",
                    description=f"Shodan has {len(ports)} ports indexed for {ip}.",
                    remediation="Review all indexed ports and close unnecessary ones.",
                    module="OSINT", cvss=4.0,
                    evidence=f"Ports: {ports}"
                ))
    except Exception:
        pass


def cert_transparency(domain, fm):
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=12)
        if r.status_code == 200:
            subs = set()
            for cert in r.json()[:200]:
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") and name != domain:
                        subs.add(name)
            if subs:
                fm.add(Finding(
                    title=f"Certificate Transparency: {len(subs)} Subdomains",
                    severity="Info",
                    description="CT logs reveal historical subdomains.",
                    remediation="Audit all subdomains. Secure or decommission unused ones.",
                    module="OSINT",
                    evidence="\n".join(sorted(subs)[:30])
                ))
    except Exception:
        pass


def scan(target: str, **kwargs) -> list:
    fm = FindingsManager()
    domain = _clean(target)
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = domain

    whois_rdap(domain, fm)
    dns_enum(domain, fm)
    shodan_passive(ip, fm)
    cert_transparency(domain, fm)
    return fm.all()
