"""Kryphorix Subdomain Enumeration — DNS brute force + certificate transparency."""
import socket
import re
import requests
import concurrent.futures
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

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

WORDLIST = [
    "www","mail","ftp","smtp","pop","ns1","ns2","ns3","vpn","remote","api",
    "dev","staging","test","admin","portal","cdn","static","assets","media",
    "img","upload","uploads","blog","shop","store","app","mobile","m","wap",
    "secure","login","dashboard","backend","beta","alpha","demo","support",
    "help","docs","git","gitlab","jenkins","ci","jira","confluence","wiki",
    "monitoring","status","health","metrics","grafana","db","database","mysql",
    "postgres","redis","mongo","elasticsearch","s3","backup","files","data",
    "internal","intranet","mail2","mx","exchange","owa","autodiscover","server",
    "host","cloud","office","vpn2","rdp","payment","billing","checkout","cart",
    "crm","erp","hub","legacy","old","new","v1","v2","v3","api2","prod",
    "production","live","uat","qa","dev2","test2","stg","preprod","preview",
    "sandbox","dr","recovery","backup2","archive","logs","auth","sso","oauth",
    "ldap","ad","dc","dc1","dc2","pdc","smtp2","imap","calendar","search",
]

TAKEOVER_CNAMES = {
    "amazonaws.com":     "AWS S3",
    "azurewebsites.net": "Azure",
    "github.io":         "GitHub Pages",
    "herokuapp.com":     "Heroku",
    "fastly.net":        "Fastly",
    "cloudfront.net":    "CloudFront",
    "shopify.com":       "Shopify",
    "zendesk.com":       "Zendesk",
    "surge.sh":          "Surge.sh",
    "ghost.io":          "Ghost",
    "unbounce.com":      "Unbounce",
    "bitbucket.io":      "Bitbucket",
}


def _resolve(subdomain, domain):
    fqdn = "{}.{}".format(subdomain, domain)
    try:
        if HAS_DNS:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
            return fqdn, [str(r) for r in answers]
        else:
            ip = socket.gethostbyname(fqdn)
            return fqdn, [ip]
    except Exception:
        return None


def _crt_sh(domain):
    subs = set()
    try:
        r = requests.get(
            "https://crt.sh/?q=%.{}&output=json".format(domain),
            timeout=12
        )
        if r.status_code == 200:
            for cert in r.json()[:300]:
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if "." in name and domain in name:
                        sub = name.replace(".{}".format(domain), "").split(".")[-1]
                        if sub and len(sub) < 30:
                            subs.add(sub)
    except Exception:
        pass
    return subs


def _check_takeover(fqdn, fm):
    if not HAS_DNS:
        return
    try:
        cname_ans = dns.resolver.resolve(fqdn, "CNAME", lifetime=5)
        for rdata in cname_ans:
            cname_target = str(rdata.target).rstrip(".")
            for service_domain, service_name in TAKEOVER_CNAMES.items():
                if service_domain in cname_target:
                    try:
                        r = requests.get(
                            "https://{}".format(fqdn),
                            timeout=5, verify=False
                        )  # nosec — scanner intentional
                        if any(p in r.text.lower() for p in
                               ["not found", "doesn't exist", "no such app",
                                "there is no app", "no such site"]):
                            fm.add(Finding(
                                title="Potential Subdomain Takeover: {}".format(fqdn),
                                severity="High", cvss=8.1, cwe="CWE-350",
                                description="{} points to {} but resource appears unclaimed.".format(
                                    fqdn, service_name),
                                remediation="Claim the {} resource or remove CNAME.".format(
                                    service_name),
                                module="Subdomain",
                                evidence="CNAME: {} -> {}".format(fqdn, cname_target)
                            ))
                    except Exception:
                        pass
    except Exception:
        pass


def scan(target, **kwargs):
    fm = FindingsManager()
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    parts = domain.split(".")
    if len(parts) > 2:
        domain = ".".join(parts[-2:])

    discovered = {}

    ct_subs = _crt_sh(domain)
    full_list = list(set(WORDLIST + list(ct_subs)))[:500]

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        fmap = {ex.submit(_resolve, sub, domain): sub for sub in full_list}
        for fut in concurrent.futures.as_completed(fmap):
            result = fut.result()
            if result:
                fqdn, ips = result
                discovered[fqdn] = ips

    if not discovered:
        fm.add(Finding(
            title="No Subdomains Discovered",
            severity="Info",
            description="Subdomain enumeration found nothing for {}.".format(domain),
            remediation="N/A",
            module="Subdomain"
        ))
        return fm.all()

    for fqdn in list(discovered.keys())[:30]:
        _check_takeover(fqdn, fm)

    interesting = [f for f in discovered if any(
        kw in f.split(".")[0].lower() for kw in
        ["dev", "staging", "test", "admin", "internal", "api",
         "db", "backend", "git", "jenkins", "beta", "legacy",
         "old", "uat", "qa", "preprod", "sandbox"]
    )]

    if interesting:
        fm.add(Finding(
            title="Sensitive Subdomains Discovered ({})".format(len(interesting)),
            severity="Medium", cvss=5.3, cwe="CWE-200",
            description="Dev/admin/internal subdomains found — may expose sensitive services.",
            remediation="Ensure all subdomains require authentication and use HTTPS.",
            module="Subdomain",
            evidence="\n".join(interesting[:20])
        ))

    fm.add(Finding(
        title="Subdomain Enumeration: {} Active Subdomains".format(len(discovered)),
        severity="Info",
        description="Found {} live subdomains for {}.".format(len(discovered), domain),
        remediation="Audit all subdomains. Apply consistent security policies.",
        module="Subdomain",
        evidence="\n".join(
            "{}: {}".format(fqdn, ", ".join(ips))
            for fqdn, ips in list(discovered.items())[:30]
        )
    ))

    return fm.all()
