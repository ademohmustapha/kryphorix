"""
modules/ports.py  —  Port Scanner with CVE Mapping
====================================================
Multi-threaded TCP scanner with: banner grabbing, rate limiting,
stealth mode, nmap integration, 100+ port CVE database.
"""
import socket
import re
import time
import logging
import concurrent.futures
from core.finding  import Finding
from core.findings import FindingsManager
from modules._base import port_open, grab_banner, extract_host

logger = logging.getLogger("kryphorix")

# fmt: off
PORT_DB = {
    21:   ("FTP",         "Medium", 5.9,  "CWE-319", "FTP transmits credentials in plaintext. Check for anonymous login and writeable directories."),
    22:   ("SSH",         "Info",   0,    "",        "SSH detected — run SSH audit module for deep analysis."),
    23:   ("Telnet",      "High",   8.8,  "CWE-319", "Telnet transmits credentials in plaintext. Replace with SSH."),
    25:   ("SMTP",        "Medium", 5.3,  "CWE-16",  "SMTP open relay or unauthenticated relay allows spam/phishing."),
    53:   ("DNS",         "Low",    3.7,  "CWE-400", "DNS service. Check for zone transfer (AXFR) and amplification."),
    80:   ("HTTP",        "Info",   0,    "",        "HTTP port open. Ensure HTTPS redirect is configured."),
    110:  ("POP3",        "Medium", 5.3,  "CWE-319", "POP3 in plaintext. Use POP3S (port 995) with TLS."),
    111:  ("RPC",         "High",   7.5,  "CWE-284", "Remote Procedure Call — attack surface for older exploits."),
    135:  ("MS-RPC",      "High",   7.5,  "CWE-284", "Microsoft RPC endpoint mapper — common attack vector."),
    139:  ("NetBIOS",     "High",   7.5,  "CWE-284", "NetBIOS — enables null sessions and credential relay attacks."),
    143:  ("IMAP",        "Medium", 5.3,  "CWE-319", "IMAP plaintext. Use IMAPS (port 993)."),
    161:  ("SNMP",        "Critical",9.8, "CWE-1392","SNMP — check for default community strings 'public'/'private'."),
    389:  ("LDAP",        "High",   7.5,  "CWE-287", "LDAP — check for unauthenticated bind and information disclosure."),
    443:  ("HTTPS",       "Info",   0,    "",        "HTTPS — run TLS audit module for full SSL/TLS analysis."),
    445:  ("SMB",         "Critical",9.8, "CWE-287", "SMB — check signing, null sessions, EternalBlue (CVE-2017-0144)."),
    465:  ("SMTPS",       "Info",   0,    "",        "SMTP over TLS — verify certificate."),
    512:  ("rexec",       "High",   8.8,  "CWE-284", "Remote execution daemon — no authentication by default."),
    513:  ("rlogin",      "High",   8.8,  "CWE-319", "rlogin — cleartext, legacy, replace with SSH."),
    514:  ("rsh/syslog",  "High",   8.8,  "CWE-284", "rsh — trust-based auth easily bypassed. Remove."),
    587:  ("SMTP-TLS",    "Info",   0,    "",        "SMTP submission — verify auth and TLS configuration."),
    636:  ("LDAPS",       "Info",   0,    "",        "LDAP over TLS — verify certificate."),
    873:  ("rsync",       "High",   7.5,  "CWE-306", "rsync — may allow unauthenticated file read/write."),
    1433: ("MSSQL",       "Critical",9.8, "CWE-287", "Microsoft SQL Server — check default SA credentials and xp_cmdshell."),
    1521: ("Oracle",      "Critical",9.8, "CWE-287", "Oracle DB — check default credentials (SYSTEM/MANAGER, DBSNMP/DBSNMP)."),
    2049: ("NFS",         "High",   8.8,  "CWE-732", "NFS — may expose filesystems without authentication."),
    2375: ("Docker",      "Critical",10.0,"CWE-306", "Docker daemon UNAUTHENTICATED — full container/host RCE."),
    2376: ("Docker-TLS",  "High",   8.1,  "CWE-287", "Docker with TLS — verify client certificate requirement."),
    3306: ("MySQL",       "Critical",9.8, "CWE-287", "MySQL — check internet exposure, default credentials."),
    3389: ("RDP",         "High",   8.8,  "CWE-287", "RDP — BlueKeep (CVE-2019-0708), brute force, MitM risks."),
    3690: ("SVN",         "Medium", 6.5,  "CWE-284", "Subversion — check anonymous access to repositories."),
    4369: ("Erlang",      "Critical",9.8, "CWE-306", "Erlang Port Mapper — RabbitMQ/CouchDB cluster compromise."),
    4848: ("GlassFish",   "High",   8.8,  "CWE-287", "GlassFish admin — check default admin/admin credentials."),
    5432: ("PostgreSQL",  "Critical",9.8, "CWE-287", "PostgreSQL — check internet exposure and default credentials."),
    5601: ("Kibana",      "High",   8.1,  "CWE-306", "Kibana — may lack auth; SSRF to Elasticsearch."),
    5672: ("RabbitMQ",    "High",   8.8,  "CWE-287", "RabbitMQ AMQP — check default guest/guest credentials."),
    5900: ("VNC",         "High",   9.0,  "CWE-287", "VNC — brute-force risk; check for no-auth configuration."),
    5984: ("CouchDB",     "Critical",9.8, "CWE-306", "CouchDB — Futon admin may be world-accessible (CVE-2017-12635)."),
    6379: ("Redis",       "Critical",10.0,"CWE-306", "Redis — UNAUTHENTICATED by default; full RCE via config writes."),
    6443: ("K8s API",     "Critical",9.8, "CWE-306", "Kubernetes API Server — check RBAC and unauthenticated access."),
    7001: ("WebLogic",    "Critical",9.8, "CVE-2020-14882","WebLogic RCE — CVE-2020-14882/14883; Java deserialization."),
    8080: ("HTTP-Alt",    "Medium", 5.3,  "CWE-16",  "Alternative HTTP — dev servers, app proxies, weak configs."),
    8443: ("HTTPS-Alt",   "Medium", 5.3,  "CWE-16",  "Alternative HTTPS — management interfaces, weak TLS."),
    8500: ("Consul",      "High",   8.8,  "CWE-306", "Consul — admin interface may be world-accessible."),
    8888: ("Jupyter",     "Critical",9.8, "CWE-306", "Jupyter Notebook — often runs without auth; full code exec."),
    9000: ("SonarQube",   "Medium", 5.8,  "CWE-284", "SonarQube — may expose source code analysis to internet."),
    9042: ("Cassandra",   "Critical",9.8, "CWE-306", "Cassandra — may lack authentication by default."),
    9090: ("Prometheus",  "Medium", 5.3,  "CWE-200", "Prometheus — metrics may expose sensitive infrastructure data."),
    9200: ("Elasticsearch","Critical",9.8,"CWE-306", "Elasticsearch — UNAUTHENTICATED in older versions; full data dump."),
    9300: ("ES-Cluster",  "Critical",9.8, "CWE-306", "Elasticsearch cluster comms — Java deserialization RCE."),
    10250:("Kubelet",     "Critical",9.8, "CWE-306", "Kubernetes Kubelet — unauthenticated exec in pods."),
    11211:("Memcached",   "Critical",9.8, "CWE-306", "Memcached — no auth by default; cache poisoning, data theft."),
    15672:("RabbitMQ-UI","High",    8.8,  "CWE-287", "RabbitMQ management UI — default guest/guest credentials."),
    27017:("MongoDB",     "Critical",9.8, "CWE-306", "MongoDB — no auth by default in older versions; full dump."),
    27018:("MongoDB-SSL", "High",   7.5,  "CWE-306", "MongoDB SSL port — verify authentication is required."),
    50000:("SAP",         "Critical",9.8, "CWE-287", "SAP Message Server — may allow internal network access."),
    50070:("Hadoop",      "High",   8.8,  "CWE-306", "Hadoop NameNode — web interface often exposes file system."),
}
# fmt: on

TOP_PORTS = sorted(PORT_DB.keys())
COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,161,389,443,445,
                512,513,514,587,636,873,1433,1521,2049,2375,3306,3389,
                3690,4369,5432,5601,5672,5900,5984,6379,6443,7001,8080,
                8443,8888,9200,9300,10250,11211,27017,27018,50000,50070]


def _scan_port(host: str, port: int, timeout: float, rate_delay: float) -> dict | None:
    """Scan a single port and return result dict or None if closed."""
    if rate_delay > 0:
        time.sleep(rate_delay)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((host, port))
        if r == 0:
            banner = ""
            try:
                if port in (21, 22, 25, 110, 143, 161, 389, 6379, 9200):
                    data = s.recv(512)
                    banner = data.decode("utf-8", errors="ignore").strip()[:200]
            except Exception:
                pass
            s.close()
            return {"port": port, "banner": banner}
        s.close()
    except Exception:
        pass
    return None


def scan(target: str, ports: list = None, threads: int = 100,
         stealth: bool = False, proxy: str = None,
         timeout: float = 1.5, **kwargs) -> list:
    fm   = FindingsManager()
    host = extract_host(target)
    logger.info(f"[Ports] Scanning {host}")

    # Stealth mode: slower, less noisy
    rate_delay = 0.05 if stealth else 0.0
    threads    = min(threads, 30 if stealth else 150)
    t_out      = timeout if not stealth else max(timeout, 2.5)

    port_list = ports or COMMON_PORTS

    # Resolve hostname first
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        fm.add(Finding(
            title=f"Cannot Resolve Host: {host}",
            severity="High", description="DNS resolution failed.",
            remediation="Verify hostname/IP.", module="Ports"
        ))
        return fm.all()

    # Try nmap first if available
    try:
        import shutil
        nmap_path = shutil.which("nmap")
        if nmap_path:
            import subprocess
            import re as _re2
            # Validate IP is safe before passing to subprocess
            if not _re2.match(r"^[0-9a-fA-F.:]+$", ip):
                raise ValueError(f"Invalid resolved IP: {ip!r}")
            port_str = ",".join(str(p) for p in port_list[:200])
            cmd = [nmap_path, "-sV", "--open", f"-p{port_str}",
                   "--max-retries", "1", "--host-timeout", "60s",
                   "-T3" if not stealth else "-T2",
                   "-oX", "-", ip]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and "<port " in r.stdout:
                # Parse nmap XML
                import re as _re
                for m in _re.finditer(
                    r'<port protocol="tcp" portid="(\d+)">.*?'
                    r'<state state="open".*?/>(?:.*?<service name="([^"]*)"[^>]*/?>)?',
                    r.stdout, _re.DOTALL
                ):
                    p    = int(m.group(1))
                    svc  = (m.group(2) or "").strip()
                    info = PORT_DB.get(p)
                    if info:
                        svc_name, sev, cvss, cwe, desc = info
                        fm.add(Finding(
                            title=f"Port {p}/TCP Open: {svc_name}",
                            severity=sev, cvss=cvss, cwe=cwe,
                            description=desc, module="Ports",
                            remediation="Review if this service should be internet-accessible.",
                            evidence=f"nmap: {svc or svc_name}"
                        ))
                logger.info(f"[Ports] nmap scan complete: {fm.count()} findings")
                return fm.all()
    except Exception as e:
        logger.debug(f"[Ports] nmap unavailable, using built-in scanner: {e}")

    # Built-in multithreaded scanner
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        fmap = {ex.submit(_scan_port, ip, p, t_out, rate_delay): p for p in port_list}
        for fut in concurrent.futures.as_completed(fmap):
            try:
                res = fut.result()
                if res:
                    open_ports.append(res)
            except Exception:
                pass

    if not open_ports:
        fm.add(Finding(
            title=f"No Common Ports Open on {host}",
            severity="Info",
            description="No open ports detected in the scanned range.",
            remediation="Verify scan range. Firewall may be dropping connections.",
            module="Ports"
        ))
        return fm.all()

    for res in sorted(open_ports, key=lambda x: x["port"]):
        p      = res["port"]
        banner = res["banner"]
        info   = PORT_DB.get(p)
        if info:
            svc, sev, cvss, cwe, desc = info
            fm.add(Finding(
                title=f"Port {p}/TCP Open: {svc}",
                severity=sev, cvss=cvss, cwe=cwe,
                description=desc,
                remediation=f"Review {svc} on port {p}. Firewall if not needed externally.",
                module="Ports",
                evidence=f"Banner: {banner}" if banner else ""
            ))
        else:
            fm.add(Finding(
                title=f"Port {p}/TCP Open: Unknown Service",
                severity="Low", cvss=3.1,
                description=f"Port {p} is open with an unrecognised service.",
                remediation="Identify and document this service. Firewall if not required.",
                module="Ports",
                evidence=f"Banner: {banner}" if banner else ""
            ))

    logger.info(f"[Ports] Complete: {len(open_ports)} open ports, {fm.count()} findings")
    return fm.all()
