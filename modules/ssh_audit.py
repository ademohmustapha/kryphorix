"""Kryphorix SSH Security Audit — version, algorithms, auth, config."""
import socket
import re
import subprocess
from core.finding import Finding
from core.findings import FindingsManager

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

WEAK_KEXALGS   = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                   "gss-gex-sha1-", "diffie-hellman-group-exchange-sha1"]
WEAK_CIPHERS   = ["arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
                   "cast128-cbc", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
WEAK_MACS      = ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64"]
VULN_VERSIONS  = {
    r"OpenSSH_[1-6]\.": ("Critical", 9.8, "OpenSSH 1–6.x has multiple critical CVEs. Upgrade to 9.x+."),
    r"OpenSSH_7\.":     ("High",     7.5, "OpenSSH 7.x has known vulnerabilities. Upgrade to 9.x+."),
    r"OpenSSH_8\.[01]": ("Medium",   5.0, "OpenSSH 8.0/8.1 has known issues. Consider upgrading."),
    r"dropbear_20[01]": ("High",     7.5, "Dropbear < 2020 has multiple CVEs."),
    r"libssh_0\.[67]":  ("Critical", 9.8, "libssh 0.6/0.7 vulnerable to auth bypass CVE-2018-10933."),
}


def grab_banner(host: str, port: int) -> str:
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner
    except Exception:
        return ""


def scan(target: str, **kwargs) -> list:
    fm = FindingsManager()
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    port = 22
    if ":" in target.split("//")[-1]:
        try:
            port = int(target.split("//")[-1].split(":")[1])
        except Exception:
            pass

    # Check if SSH is open
    s = socket.socket()
    s.settimeout(5)
    if s.connect_ex((host, port)) != 0:
        fm.add(Finding(title=f"SSH Port {port} Not Open", severity="Info",
                       description=f"SSH is not accessible on {host}:{port}.",
                       remediation="N/A", module="SSH"))
        return fm.all()
    s.close()

    banner = grab_banner(host, port)

    # Default port warning
    if port == 22:
        fm.add(Finding(
            title="SSH Running on Default Port 22",
            severity="Low",
            description="Default port 22 makes automated scanning easier.",
            remediation="Consider non-standard port as defense-in-depth (not security substitute).",
            module="SSH", cvss=2.0, evidence=f"Banner: {banner}"
        ))

    # Version check
    for pattern, (severity, cvss, detail) in VULN_VERSIONS.items():
        if re.search(pattern, banner):
            fm.add(Finding(
                title=f"Vulnerable SSH Version: {banner.split()[0] if banner else 'Unknown'}",
                severity=severity, description=detail,
                remediation="Upgrade SSH to latest stable version immediately.",
                module="SSH", cvss=cvss, cwe="CWE-1104", evidence=f"Banner: {banner}"
            ))
            break
    else:
        if banner:
            fm.add(Finding(
                title=f"SSH Version: {banner[:60]}",
                severity="Info",
                description="SSH server version identified.",
                remediation="Keep SSH updated to latest stable release.",
                module="SSH", evidence=banner
            ))

    # Try ssh-audit tool first
    try:
        r = subprocess.run(["ssh-audit", "-n", f"{host}:{port}"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout:
            fail_lines = [l.strip() for l in r.stdout.splitlines()
                         if "[fail]" in l.lower() or "-- fail" in l.lower()]
            warn_lines = [l.strip() for l in r.stdout.splitlines()
                         if "[warn]" in l.lower()]
            if fail_lines:
                fm.add(Finding(
                    title=f"SSH Configuration Failures ({len(fail_lines)} issues)",
                    severity="High",
                    description="ssh-audit found configuration failures.",
                    remediation="Remove weak algorithms. Follow ssh-audit recommendations.",
                    module="SSH", cvss=7.4, cwe="CWE-326",
                    evidence="\n".join(fail_lines[:15])
                ))
            if warn_lines:
                fm.add(Finding(
                    title=f"SSH Configuration Warnings ({len(warn_lines)} issues)",
                    severity="Medium",
                    description="ssh-audit found configuration warnings.",
                    remediation="Address all warnings for hardened SSH configuration.",
                    module="SSH", cvss=5.0, cwe="CWE-326",
                    evidence="\n".join(warn_lines[:15])
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # ssh-audit not installed — use paramiko

    # Paramiko-based checks
    if HAS_PARAMIKO:
        try:
            t = paramiko.Transport((host, port))
            t.start_client(timeout=10)
            sec = t.get_security_options()

            weak_kex = [k for k in list(t._preferred_kex if hasattr(t, '_preferred_kex') else [])
                       if any(w in k for w in WEAK_KEXALGS)]
            weak_cip = [c for c in list(t._preferred_ciphers if hasattr(t, '_preferred_ciphers') else [])
                       if any(w in c for w in WEAK_CIPHERS)]

            if weak_kex:
                fm.add(Finding(
                    title="Weak KEX Algorithms Supported",
                    severity="High",
                    description=f"Weak key exchange: {', '.join(weak_kex)}",
                    remediation="Remove weak KEX. Use curve25519-sha256 and group16/18-sha512.",
                    module="SSH", cvss=7.4, cwe="CWE-326"
                ))
            if weak_cip:
                fm.add(Finding(
                    title="Weak SSH Ciphers Supported",
                    severity="High",
                    description=f"CBC-mode ciphers: {', '.join(weak_cip)}",
                    remediation="Remove CBC ciphers. Use chacha20-poly1305 and AES-GCM.",
                    module="SSH", cvss=7.4, cwe="CWE-326"
                ))
            t.close()
        except Exception:
            pass

        # Check password auth
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(host, port=port, username="kryphorix_noauth_test",
                               password="kryphorix_noauth_test", timeout=5,
                               allow_agent=False, look_for_keys=False)
            except paramiko.AuthenticationException as e:
                err = str(e).lower()
                if "publickey" in err and "password" not in err:
                    fm.add(Finding(
                        title="Password Auth Disabled — Key-Only (Secure)",
                        severity="Info",
                        description="Only public key authentication accepted.",
                        remediation="Maintain this configuration.",
                        module="SSH"
                    ))
                elif "password" in err:
                    fm.add(Finding(
                        title="Password Authentication Enabled",
                        severity="Medium",
                        description="SSH accepts passwords — brute force attacks possible.",
                        remediation="Disable PasswordAuthentication in sshd_config. Use keys only.",
                        module="SSH", cvss=6.5, cwe="CWE-307"
                    ))
            finally:
                client.close()
        except Exception:
            pass

    return fm.all()
