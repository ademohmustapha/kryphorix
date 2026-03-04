"""
Kryphorix Vulnerability Port Mapper
Maps open ports to CVEs, MITRE ATT&CK techniques, and exploitation guidance.
"""
import socket
import concurrent.futures
from core.finding import Finding
from core.findings import FindingsManager

# CVE → (description, cvss, exploit_info, mitre_technique, remediation)
CVE_DATABASE = {
    "CVE-2017-0144": (
        "EternalBlue — SMBv1 RCE (WannaCry/NotPetya)",
        10.0,
        "Exploitable via Metasploit module exploit/windows/smb/ms17_010_eternalblue. "
        "Used by WannaCry ransomware to propagate across networks.",
        "T1210 Exploitation of Remote Services",
        "Disable SMBv1 immediately. Apply MS17-010. Block port 445 at perimeter."
    ),
    "CVE-2017-0145": (
        "EternalRomance — SMBv1 RCE",
        9.8,
        "Metasploit: exploit/windows/smb/ms17_010_psexec",
        "T1210",
        "Apply MS17-010. Disable SMBv1."
    ),
    "CVE-2020-0796": (
        "SMBGhost — SMBv3.1.1 Remote Code Execution",
        10.0,
        "Heap overflow in SMBv3 compression. PoC exploits exist publicly.",
        "T1210",
        "Apply KB4551762. Disable SMBv3 compression if patch cannot be applied immediately."
    ),
    "CVE-2019-0708": (
        "BlueKeep — RDP Pre-Auth RCE (unauthenticated)",
        9.8,
        "Wormable vulnerability in RDP. Metasploit module available. "
        "Can lead to full SYSTEM compromise without credentials.",
        "T1210",
        "Apply KB4499175/KB4499180. Disable RDP if not required. Enable NLA."
    ),
    "CVE-2019-1181": (
        "DejaBlue — RDP RCE (Windows 10/Server 2019)",
        9.8,
        "Similar to BlueKeep but affects newer Windows versions.",
        "T1210",
        "Apply August 2019 cumulative updates."
    ),
    "CVE-2019-11043": (
        "PHP-FPM RCE via Nginx fastcgi_pass misconfiguration",
        9.8,
        "phuip-fpizdam tool can exploit this remotely with a single request.",
        "T1190",
        "Update PHP-FPM. Fix Nginx PATH_INFO regex."
    ),
    "CVE-2020-14882": (
        "Oracle WebLogic RCE (unauthenticated)",
        9.8,
        "Trivially exploitable with a single HTTP GET request to /console/css/%252E%252E/...",
        "T1190",
        "Apply Oracle CPU October 2020. Restrict admin console access."
    ),
    "CVE-2022-0543": (
        "Redis Lua Sandbox Escape RCE",
        10.0,
        "Allows RCE via Lua scripting in Redis. Used by Muhstik botnet.",
        "T1190",
        "Update Redis. Enable requirepass. Bind to 127.0.0.1 only."
    ),
    "CVE-2021-22005": (
        "VMware vCenter Arbitrary File Upload RCE",
        9.8,
        "Single HTTP POST request can upload a JSP shell. Widely exploited.",
        "T1190",
        "Apply VMSA-2021-0020 immediately."
    ),
    "CVE-2019-7609": (
        "Kibana Timelion RCE",
        8.1,
        "Prototype pollution in Timelion allows server-side JavaScript execution.",
        "T1190",
        "Update Kibana to 6.6.1+. Disable Timelion if not required."
    ),
    "CVE-2019-5736": (
        "Docker runc Container Escape",
        8.6,
        "Allows container to overwrite host runc binary → full host compromise.",
        "T1611",
        "Update Docker Engine. Do not run untrusted containers."
    ),
    "CVE-2021-22145": (
        "Elasticsearch Stack Overflow Memory Disclosure",
        6.5,
        "Memory disclosure can leak sensitive cluster data.",
        "T1530",
        "Update Elasticsearch. Enable security features (TLS + authentication)."
    ),
    "CVE-2019-15681": (
        "LibVNCServer Heap Buffer Overflow",
        9.8,
        "Remote code execution via malformed VNC message.",
        "T1210",
        "Update VNC server. Require authentication. Firewall port 5900."
    ),
    "CVE-2012-2122": (
        "MySQL Authentication Bypass",
        5.1,
        "Timing attack allows bypassing password auth in ~256 attempts.",
        "T1110",
        "Update MySQL. Restrict network access."
    ),
    "CVE-2020-1350": (
        "SIGRed — Windows DNS Server RCE (wormable)",
        10.0,
        "Malicious DNS response triggers heap overflow. Wormable via default DNS.",
        "T1210",
        "Apply KB4569509. Restrict DNS to authoritative/recursive as needed."
    ),
    "CVE-2020-0618": (
        "MSSQL Reporting Services RCE",
        8.8,
        "Authenticated deserialization RCE in SQL Server Reporting Services.",
        "T1210",
        "Apply January 2020 MSSQL cumulative update."
    ),
    "CVE-2019-2386": (
        "MongoDB Unauthorized Access",
        5.3,
        "MongoDB instances exposed without authentication. Direct data access.",
        "T1530",
        "Enable MongoDB authentication. Bind to localhost. Use network ACLs."
    ),
    "CVE-2021-34535": (
        "RDP Client RCE (reverse direction)",
        8.8,
        "Malicious RDP server can execute code on connecting client.",
        "T1210",
        "Apply August 2021 cumulative updates."
    ),
    "CVE-2021-42278": (
        "Active Directory sAMAccountName Spoofing → Privilege Escalation",
        8.8,
        "Allows low-privileged users to impersonate Domain Controllers → DCSync.",
        "T1078",
        "Apply KB5008102. Audit machine account creation rights."
    ),
    "CVE-2017-6742": (
        "Cisco IOS SNMP RCE",
        8.8,
        "Malformed SNMP packet triggers remote code execution on Cisco IOS.",
        "T1498",
        "Apply cisco-sa-20170629-snmp. Use SNMPv3 with authentication."
    ),
    "CVE-2020-10001": (
        "CUPS Integer Overflow",
        8.4,
        "IPP crafted request can trigger memory corruption in cupsd.",
        "T1210",
        "Update CUPS. Restrict port 631 to localhost."
    ),
}

# Port → CVE mapping
PORT_TO_CVE = {
    445:   ["CVE-2017-0144", "CVE-2017-0145", "CVE-2020-0796"],
    3389:  ["CVE-2019-0708", "CVE-2019-1181", "CVE-2021-34535"],
    9200:  ["CVE-2021-22145"],
    9000:  ["CVE-2019-11043"],
    7001:  ["CVE-2020-14882"],
    6379:  ["CVE-2022-0543"],
    902:   ["CVE-2021-22005"],
    5601:  ["CVE-2019-7609"],
    2375:  ["CVE-2019-5736"],
    3306:  ["CVE-2012-2122"],
    27017: ["CVE-2019-2386"],
    5900:  ["CVE-2019-15681"],
    53:    ["CVE-2020-1350"],
    1433:  ["CVE-2020-0618"],
    88:    ["CVE-2021-42278"],
    161:   ["CVE-2017-6742"],
    631:   ["CVE-2020-10001"],
}

# Dangerous combinations (pairs of open ports indicating high risk)
DANGEROUS_COMBOS = [
    ({445, 3389},   "SMB + RDP open — High ransomware/lateral movement risk"),
    ({445, 139},    "SMB + NetBIOS — Active Directory attack surface"),
    ({6379, 2375},  "Redis + Docker API — Likely cryptomining/container escape risk"),
    ({9200, 5601},  "Elasticsearch + Kibana — Data store exposed without auth likely"),
    ({3306, 1433, 5432, 27017}, "Multiple database ports open — Significant data breach risk"),
    ({5900, 3389},  "VNC + RDP — Multiple remote access ports (minimal segmentation)"),
]


def _check_port_open(host: str, port: int) -> bool:
    try:
        s = socket.socket()
        s.settimeout(1.5)
        r = s.connect_ex((host, port))
        s.close()
        return r == 0
    except Exception:
        return False


def scan(target: str, **kwargs) -> list:
    fm = FindingsManager()
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    # Quick scan of all CVE-mapped ports
    all_ports = list(set(PORT_TO_CVE.keys()))

    open_ports = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        fmap = {ex.submit(_check_port_open, ip, p): p for p in all_ports}
        for fut in concurrent.futures.as_completed(fmap):
            p = fmap[fut]
            try:
                if fut.result():
                    open_ports.add(p)
            except Exception:
                pass

    if not open_ports:
        return fm.all()

    # Per-CVE findings
    for port in sorted(open_ports):
        cves = PORT_TO_CVE.get(port, [])
        for cve_id in cves:
            info = CVE_DATABASE.get(cve_id)
            if not info:
                continue
            desc, cvss, exploit, mitre, fix = info
            fm.add(Finding(
                title=f"[{cve_id}] {desc.split('—')[0].strip()} (Port {port})",
                severity="Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium",
                description=f"{desc}\n\nExploitation: {exploit}\nMITRE: {mitre}",
                remediation=fix,
                module="VulnPorts",
                cvss=cvss,
                cve=cve_id,
                cwe="CWE-119",
                evidence=f"Port {port} is open on {ip}. CVE: {cve_id}"
            ))

    # Dangerous combination checks
    for port_set, message in DANGEROUS_COMBOS:
        if port_set.issubset(open_ports) or (len(port_set) >= 3 and len(port_set & open_ports) >= 2):
            actual = port_set & open_ports
            fm.add(Finding(
                title=f"Dangerous Port Combination Detected: {', '.join(str(p) for p in sorted(actual))}",
                severity="Critical",
                description=message,
                remediation="Apply network segmentation. Firewall unnecessary ports. Review exposure.",
                module="VulnPorts",
                cvss=9.0,
                evidence=f"Open ports in combination: {sorted(actual)}"
            ))

    return fm.all()
