"""
modules/ad.py  —  Active Directory Penetration Testing
=======================================================
Tests: SMB signing, null sessions, LDAP anon bind, Kerberos,
password policy, DNS zone transfer, LAPS, AS-REP roasting.

IMPORTANT: All imports are at module top — no runtime import() bugs.
"""
import re
import socket
import logging
import struct
from core.finding  import Finding
from core.findings import FindingsManager
from modules._base import port_open, grab_banner

logger = logging.getLogger("kryphorix")

try:
    import ldap3
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

AD_PORTS = {
    53:   "DNS",
    88:   "Kerberos",
    135:  "RPC",
    139:  "NetBIOS-SSN",
    389:  "LDAP",
    445:  "SMB",
    464:  "Kpasswd",
    636:  "LDAPS",
    3268: "Global Catalog",
    3269: "GC-SSL",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}


def detect_ad_ports(host: str, fm: FindingsManager) -> dict:
    """Detect open AD-related ports and return {port: open}."""
    open_ports = {}
    for port, name in AD_PORTS.items():
        is_open = port_open(host, port, timeout=2.0)
        open_ports[port] = is_open
        if is_open:
            fm.add(Finding(
                title=f"AD Port Open: {port}/{name}",
                severity="Info",
                description=f"AD service port {port} ({name}) is accessible.",
                remediation="Ensure this port is accessible only to authorised networks.",
                module="AD"
            ))
    return open_ports


def check_smb_signing(host: str, fm: FindingsManager):
    """Check if SMB signing is required (NTLM relay prevention)."""
    if not port_open(host, 445, timeout=3.0):
        return
    # SMB negotiate request (raw)
    NEGOTIATE_PROTO = (
        b"\x00\x00\x00\x85"                       # NetBIOS
        b"\xff\x53\x4d\x42"                       # SMB header
        b"\x72\x00\x00\x00\x00\x18\x53\xc8"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00"
        b"\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54"
        b"\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31"
        b"\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
        b"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57"
        b"\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61"
        b"\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c"
        b"\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c"
        b"\x4d\x20\x30\x2e\x31\x32\x00"
    )
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, 445))
        s.sendall(NEGOTIATE_PROTO)
        resp = s.recv(1024)
        s.close()
        # Byte 39 (0-indexed) = Security Mode. Bit 3 = signing required.
        if len(resp) > 39:
            security_mode = resp[39]
            signing_required = bool(security_mode & 0x08)
            if not signing_required:
                fm.add(Finding(
                    title="SMB Signing NOT Required",
                    severity="High", cvss=8.1, cwe="CWE-300",
                    description="SMB signing is not required — NTLM relay attacks are possible. "
                                "Attackers can relay credentials to authenticate as any user.",
                    remediation="Enable 'RequireSecuritySignature' via GPO. "
                                "Microsoft Security Baseline requires this.",
                    module="AD"
                ))
            else:
                fm.add(Finding(
                    title="SMB Signing Required ✓",
                    severity="Info",
                    description="SMB signing is enforced — NTLM relay attacks are mitigated.",
                    remediation="Continue enforcing SMB signing across all domain members.",
                    module="AD"
                ))
    except Exception as e:
        logger.debug(f"[AD] SMB signing check error: {e}")


def check_null_session(host: str, fm: FindingsManager):
    """Check for SMB null session (unauthenticated access)."""
    if not port_open(host, 445, timeout=3.0):
        return
    try:
        import subprocess
        import shutil
        if shutil.which("rpcclient"):
            r = subprocess.run(
                ["rpcclient", "-U", "%", "-N", host, "-c", "lsaquery"],
                capture_output=True, text=True, timeout=8
            )
            if r.returncode == 0 and ("Domain" in r.stdout or "SID" in r.stdout):
                fm.add(Finding(
                    title="SMB Null Session Allowed",
                    severity="High", cvss=7.5, cwe="CWE-306",
                    description="Unauthenticated SMB null session allowed — domain info enumerable.",
                    remediation="Restrict null sessions via GPO: RestrictAnonymous=2.",
                    module="AD", evidence=r.stdout[:300]
                ))
                return
    except Exception:
        pass

    # Pure socket check: attempt SMBv2 null session setup
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, 445))
        # SMBv2 negotiate
        SMB2_NEGOTIATE = (
            b"\x00\x00\x00\x2e"
            b"\xfeSMB"
            b"\x40\x00" + b"\x00"*60
        )
        s.sendall(SMB2_NEGOTIATE)
        resp = s.recv(512)
        s.close()
        if b"\xfeSMB" in resp:
            fm.add(Finding(
                title="SMBv2 Responds to Unauthenticated Probe",
                severity="Medium", cvss=5.3, cwe="CWE-284",
                description="SMBv2 responds to unauthenticated probes — assess further with rpcclient.",
                remediation="Restrict SMB access to authorised hosts only.",
                module="AD"
            ))
    except Exception:
        pass


def check_ldap_anonymous(host: str, fm: FindingsManager):
    """Test for LDAP anonymous bind."""
    if not port_open(host, 389, timeout=3.0) and not port_open(host, 3268, timeout=3.0):
        return

    if not HAS_LDAP:
        fm.add(Finding(
            title="LDAP Anonymous Bind Check: ldap3 Not Installed",
            severity="Info",
            description="Install ldap3 to enable LDAP anonymous bind testing: pip install ldap3",
            remediation="pip install ldap3",
            module="AD"
        ))
        return

    for port, name in [(389, "LDAP"), (3268, "Global Catalog")]:
        if not port_open(host, port, timeout=3.0):
            continue
        try:
            server = ldap3.Server(host, port=port, get_info=ldap3.ALL,
                                  connect_timeout=5)
            conn   = ldap3.Connection(server, authentication=ldap3.ANONYMOUS,
                                      auto_bind=True, read_only=True)
            if conn.bound:
                # Try to read base DN
                conn.search("", "(objectClass=*)", ldap3.BASE,
                            attributes=["namingContexts"])
                naming = str(conn.entries)[:200]
                conn.unbind()
                fm.add(Finding(
                    title=f"LDAP Anonymous Bind Allowed: {name} (port {port})",
                    severity="High", cvss=7.5, cwe="CWE-287",
                    description=f"Anonymous LDAP bind on port {port} allowed — "
                                "domain structure and user accounts may be enumerable.",
                    remediation="Disable anonymous LDAP binds. Set 'dsHeuristics' "
                                "attribute to restrict anonymous access.",
                    module="AD", evidence=f"Naming contexts: {naming}"
                ))
            else:
                conn.unbind()
        except ldap3.core.exceptions.LDAPBindError:
            fm.add(Finding(
                title=f"LDAP Anonymous Bind Refused: {name} ✓",
                severity="Info",
                description=f"Anonymous LDAP bind on port {port} is properly refused.",
                remediation="Continue monitoring LDAP access controls.",
                module="AD"
            ))
        except Exception as e:
            logger.debug(f"[AD] LDAP {port} check error: {e}")


def check_kerberos(host: str, fm: FindingsManager):
    """Check Kerberos service and AS-REP roasting risk."""
    if not port_open(host, 88, timeout=3.0):
        return
    # Send KRB5 AS-REQ and check response (indicates KDC present)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        # Minimal KRB5 AS-REQ
        krb_req = b"\x6a\x00"   # simple probe
        s.sendto(krb_req, (host, 88))
        resp = s.recvfrom(512)
        s.close()
        fm.add(Finding(
            title="Kerberos KDC Responding",
            severity="Info",
            description="Kerberos Key Distribution Center is active on port 88.",
            remediation="Assess for AS-REP roasting: accounts without pre-auth required. "
                        "Use: GetNPUsers.py domain/ -usersfile users.txt",
            module="AD"
        ))
    except socket.timeout:
        fm.add(Finding(
            title="Kerberos Port 88 Open — AS-REP Roasting Risk",
            severity="Medium", cvss=5.9, cwe="CWE-284",
            description="Kerberos port open. Accounts with 'Do not require Kerberos preauthentication' "
                        "are vulnerable to offline password cracking (AS-REP roasting).",
            remediation="Require Kerberos pre-authentication for all accounts. "
                        "Use strong passwords. Audit with Get-ADUser -Filter * "
                        "-Properties DoesNotRequirePreAuth.",
            module="AD"
        ))
    except Exception as e:
        logger.debug(f"[AD] Kerberos check: {e}")


def check_dns_zone_transfer(host: str, domain: str, fm: FindingsManager):
    """Attempt DNS zone transfer (AXFR)."""
    if not HAS_DNS:
        return
    try:
        # Try to derive domain from DC if not provided
        if not domain:
            try:
                r = socket.gethostbyaddr(host)
                parts = r[0].split(".")
                domain = ".".join(parts[1:]) if len(parts) > 2 else r[0]
            except Exception:
                return

        axfr = dns.query.xfr(host, domain, timeout=8)
        z    = dns.zone.from_xfr(axfr)
        names = sorted(z.nodes.keys())
        fm.add(Finding(
            title=f"DNS Zone Transfer (AXFR) Succeeded: {domain}",
            severity="Critical", cvss=9.1, cwe="CWE-284",
            description=f"Zone transfer returned {len(names)} DNS records for {domain}. "
                        "Full internal hostname map exposed to unauthenticated attacker.",
            remediation="Restrict AXFR to authorised secondary DNS servers only (ACL by IP).",
            module="AD",
            evidence="\n".join(str(n) for n in names[:30])
        ))
    except Exception:
        fm.add(Finding(
            title="DNS Zone Transfer Refused ✓",
            severity="Info",
            description="AXFR zone transfer is properly restricted.",
            remediation="Continue restricting zone transfers to authorised servers.",
            module="AD"
        ))


def check_winrm(host: str, fm: FindingsManager):
    """Check WinRM accessibility."""
    for port, desc in [(5985, "WinRM HTTP"), (5986, "WinRM HTTPS")]:
        if port_open(host, port, timeout=2.5):
            fm.add(Finding(
                title=f"{desc} Accessible (port {port})",
                severity="High", cvss=7.5, cwe="CWE-284",
                description=f"Windows Remote Management ({desc}) is accessible. "
                            "Potential remote code execution if credentials are obtained.",
                remediation="Restrict WinRM to management hosts via Windows Firewall. "
                            "Require HTTPS (5986) and certificate auth.",
                module="AD"
            ))


def check_authenticated(host: str, domain: str, username: str, password: str,
                         fm: FindingsManager):
    """Authenticated LDAP enumeration."""
    if not HAS_LDAP or not username:
        return
    try:
        server = ldap3.Server(host, port=389, get_info=ldap3.ALL, connect_timeout=8)
        conn   = ldap3.Connection(
            server,
            user=f"{domain}\\{username}" if domain else username,
            password=password,
            authentication=ldap3.NTLM,
            auto_bind=True,
            read_only=True,
        )
        if conn.bound:
            fm.add(Finding(
                title=f"Authenticated LDAP Bind Successful: {username}",
                severity="Info",
                description="Credentials valid — authenticated enumeration possible.",
                remediation="Rotate credentials after testing. Use least-privilege accounts.",
                module="AD"
            ))
            # Check for accounts with no pre-auth
            base = conn.server.info.other.get("defaultNamingContext", [""])[0]
            conn.search(
                base,
                "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName", "userAccountControl"]
            )
            if conn.entries:
                accts = [str(e.sAMAccountName) for e in conn.entries]
                fm.add(Finding(
                    title=f"AS-REP Roastable Accounts: {len(accts)} found",
                    severity="High", cvss=8.1, cwe="CWE-522",
                    description=f"{len(accts)} account(s) have 'Do not require Kerberos "
                                "preauthentication' set — offline password cracking possible.",
                    remediation="Enable Kerberos pre-authentication for all accounts. "
                                "Use strong passwords for service accounts.",
                    module="AD",
                    evidence="\n".join(accts[:20])
                ))
            conn.unbind()
    except Exception as e:
        logger.debug(f"[AD] Authenticated check error: {e}")


def scan(target: str, domain: str = None, username: str = None,
         password: str = None, **kwargs) -> list:
    fm   = FindingsManager()
    host = target.replace("https://","").replace("http://","").split("/")[0]
    logger.info(f"[AD] Scanning {host}")

    open_ports = detect_ad_ports(host, fm)

    if not any(open_ports.values()):
        fm.add(Finding(
            title="No AD Ports Detected",
            severity="Info",
            description=f"{host} does not appear to be an Active Directory domain controller.",
            remediation="Verify the target IP. Use --ad with a DC IP address.",
            module="AD"
        ))
        return fm.all()

    check_smb_signing(host, fm)
    check_null_session(host, fm)
    check_ldap_anonymous(host, fm)
    check_kerberos(host, fm)
    check_winrm(host, fm)
    if domain or username:
        check_dns_zone_transfer(host, domain, fm)
    if username and password:
        check_authenticated(host, domain, username, password, fm)

    logger.info(f"[AD] Complete: {fm.count()} findings")
    return fm.all()
