"""Kryphorix Network Infrastructure Scanner — SNMP, routing, network services."""
import socket
import struct
import concurrent.futures
from core.finding import Finding
from core.findings import FindingsManager

NETWORK_SERVICES = {
    161:  ("SNMP",       "Critical", "SNMP often has default community strings 'public'/'private'"),
    162:  ("SNMP-Trap",  "Medium",   "SNMP trap receiver"),
    69:   ("TFTP",       "High",     "TFTP — no authentication, file read/write possible"),
    111:  ("RPC",        "High",     "Remote Procedure Call — legacy attack surface"),
    512:  ("rexec",      "High",     "Remote execution daemon"),
    513:  ("rlogin",     "High",     "rlogin — cleartext credentials"),
    514:  ("rsh/syslog", "High",     "rsh or syslog — legacy protocols"),
    2049: ("NFS",        "High",     "NFS — may expose filesystems without auth"),
    873:  ("rsync",      "High",     "rsync — may allow unauthenticated file access"),
    1900: ("UPnP",       "Medium",   "UPnP — can expose internal network to SSRF"),
    5353: ("mDNS",       "Low",      "Multicast DNS — device enumeration"),
    123:  ("NTP",        "Low",      "NTP — amplification DDoS possible"),
    500:  ("IKE/IPSec",  "Medium",   "VPN service fingerprinting"),
    4500: ("NAT-T",      "Low",      "IPSec NAT traversal"),
}

SNMP_COMMUNITIES = ["public", "private", "community", "admin", "manager",
                    "cisco", "snmpd", "default", "all", "internal"]


def _port_open(host: str, port: int, proto="tcp", timeout: float = 1.5) -> bool:
    try:
        if proto == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        if proto == "tcp":
            r = s.connect_ex((host, port))
            s.close()
            return r == 0
        else:
            # UDP: send and wait for response
            s.sendto(b"\x00", (host, port))
            try:
                s.recv(64)
                s.close()
                return True
            except Exception:
                s.close()
                return False
    except Exception:
        return False


def _snmp_community_test(host: str, community: str) -> bool:
    """Send SNMP v1 GET for sysDescr and check for valid response."""
    try:
        # Build SNMPv1 GET sysDescr OID 1.3.6.1.2.1.1.1.0
        community_bytes = community.encode()
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        null = bytes([0x05, 0x00])
        varbind = bytes([0x30, len(oid) + len(null)]) + oid + null
        varbindlist = bytes([0x30, len(varbind)]) + varbind

        req_id = bytes([0x02, 0x01, 0x01])
        error = bytes([0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
        pdu = bytes([0xa0, len(req_id) + len(error) + len(varbindlist)]) + req_id + error + varbindlist

        community_tlv = bytes([0x04, len(community_bytes)]) + community_bytes
        version = bytes([0x02, 0x01, 0x00])  # v1

        seq_content = version + community_tlv + pdu
        packet = bytes([0x30, len(seq_content)]) + seq_content

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(packet, (host, 161))
        resp, _ = s.recvfrom(1024)
        s.close()

        # If we get a response with the community string, it worked
        return community.encode() in resp and len(resp) > 20
    except Exception:
        return False


def check_snmp(host, fm):
    if not _port_open(host, 161, "udp"):
        return
    for community in SNMP_COMMUNITIES:
        if _snmp_community_test(host, community):
            fm.add(Finding(
                title=f"SNMP Default Community String: '{community}'",
                severity="Critical", cvss=9.8, cwe="CWE-1392",
                description=f"SNMP community string '{community}' is accepted. "
                            "Full network device configuration can be read/written.",
                remediation="Change all SNMP community strings. Use SNMPv3 with auth+privacy. "
                            "Restrict SNMP to management networks.",
                module="Network",
                evidence=f"Host: {host}, Community: {community}"
            ))
            return

    fm.add(Finding(
        title="SNMP Port Open — Community String Hardened",
        severity="Medium", cvss=4.0,
        description="SNMP is running but default community strings rejected. "
                    "Still assess SNMPv3 configuration.",
        remediation="Use SNMPv3 exclusively. Restrict SNMP access by IP ACL.",
        module="Network"
    ))


def check_nfs(host, fm):
    if not _port_open(host, 2049):
        return
    fm.add(Finding(
        title="NFS Port 2049 Open",
        severity="High", cvss=8.8, cwe="CWE-732",
        description="NFS exposed. If misconfigured (no_root_squash, world-readable), "
                    "attackers can mount and read/write filesystem.",
        remediation="Restrict NFS exports. Use 'root_squash'. Firewall port 2049.",
        module="Network"
    ))


def check_tftp(host, fm):
    if not _port_open(host, 69, "udp"):
        return
    fm.add(Finding(
        title="TFTP Port 69 Open",
        severity="High", cvss=7.5, cwe="CWE-306",
        description="TFTP has no authentication. Used to steal router configs.",
        remediation="Disable TFTP unless required. Restrict to management VLAN.",
        module="Network"
    ))


def check_upnp(host, fm):
    if not _port_open(host, 1900, "udp"):
        return
    fm.add(Finding(
        title="UPnP Exposed on Internet",
        severity="Medium", cvss=6.5, cwe="CWE-284",
        description="UPnP should not be exposed to internet. Enables port forwarding by malicious clients.",
        remediation="Disable UPnP on internet-facing interfaces.",
        module="Network"
    ))


def check_rsync(host, fm):
    if not _port_open(host, 873):
        return
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, 873))
        banner = s.recv(128).decode("utf-8", errors="ignore")
        # Try anonymous list
        s.send(b"\n")
        modules = s.recv(1024).decode("utf-8", errors="ignore")
        s.close()
        if "@" in modules or "." in modules:
            fm.add(Finding(
                title="rsync Allows Unauthenticated Access",
                severity="Critical", cvss=9.1, cwe="CWE-306",
                description=f"rsync lists modules without authentication: {modules[:200]}",
                remediation="Add 'auth users' and 'secrets file' to rsyncd.conf. "
                            "Restrict access by IP.",
                module="Network",
                evidence=f"Modules: {modules[:300]}"
            ))
    except Exception:
        fm.add(Finding(
            title="rsync Port 873 Open",
            severity="High", cvss=7.5, cwe="CWE-306",
            description="rsync is accessible. Assess if authentication is required.",
            remediation="Require authentication. Restrict to authorized IPs.",
            module="Network"
        ))


def scan(target: str, **kwargs) -> list:
    fm = FindingsManager()
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    # Quick scan of network service ports
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        fmap = {ex.submit(_port_open, ip, p): p for p in NETWORK_SERVICES}
        for fut in concurrent.futures.as_completed(fmap):
            p = fmap[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass

    for port in open_ports:
        service, severity, desc = NETWORK_SERVICES[port]
        fm.add(Finding(
            title=f"Network Service Open: {service} (Port {port})",
            severity=severity, cvss={"Critical":9.8,"High":7.5,"Medium":5.3,"Low":3.1}.get(severity,0),
            description=desc,
            remediation=f"Assess if {service} is required. Restrict access to management networks.",
            module="Network"
        ))

    # Specific deep checks
    check_snmp(ip, fm)
    check_nfs(ip, fm)
    check_tftp(ip, fm)
    check_upnp(ip, fm)
    check_rsync(ip, fm)

    if not open_ports:
        fm.add(Finding(
            title="No Network Infrastructure Services Found",
            severity="Info",
            description="No network management services detected in the scanned port range.",
            remediation="N/A",
            module="Network"
        ))

    return fm.all()
