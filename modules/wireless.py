"""
modules/wireless.py  —  Wireless Network Assessment
=====================================================
Cross-platform: Kali/Linux (nmcli/iwlist/iw), macOS (airport/system_profiler),
Windows (netsh). Auto-adapts via compat layer. Handles macOS 14+ airport removal.
"""
import re
import subprocess
import logging
from core.finding  import Finding
from core.findings import FindingsManager
from core.compat   import (get_wireless_tool, IS_LINUX, IS_MACOS, IS_WINDOWS,
                            MACOS_MAJOR, is_elevated, has_binary)

logger = logging.getLogger("kryphorix")


def _run(cmd: list, timeout: int = 20) -> str:
    """Run a shell command and return stdout, empty on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return ""


# ── Linux (nmcli) ─────────────────────────────────────────────────────────────
def _scan_nmcli(fm: FindingsManager) -> list:
    raw = _run(["nmcli", "-t", "-f",
                "SSID,BSSID,MODE,CHAN,RATE,SIGNAL,BARS,SECURITY",
                "device", "wifi", "list"])
    if not raw.strip():
        return []
    networks = []
    for line in raw.splitlines():
        parts = line.split(":")
        if len(parts) < 8:
            continue
        ssid     = parts[0].strip()
        bssid    = parts[1].strip()
        signal   = parts[5].strip()
        security = ":".join(parts[7:]).strip()
        networks.append({"ssid": ssid, "bssid": bssid,
                         "signal": signal, "security": security})
    return networks


# ── Linux (iwlist fallback) ───────────────────────────────────────────────────
def _get_wlan_iface() -> str:
    """Detect wireless interface name across different Linux kernel versions."""
    # Try iw first (modern)
    if has_binary("iw"):
        out = _run(["iw", "dev"])
        m = re.search(r"Interface\s+(\w+)", out)
        if m:
            return m.group(1)
    # Try ip link
    if has_binary("ip"):
        out = _run(["ip", "-o", "link", "show"])
        for line in out.splitlines():
            m = re.search(r"\d+: (\w+):", line)
            if m and re.search(r"wl|wifi|wlan|ath", m.group(1), re.I):
                return m.group(1)
    # Scan /sys/class/net
    import os
    for iface in os.listdir("/sys/class/net") if os.path.exists("/sys/class/net") else []:
        if re.search(r"wl|ath|wlan", iface, re.I):
            return iface
    return "wlan0"  # last resort


def _scan_iwlist(fm: FindingsManager) -> list:
    iface = _get_wlan_iface()
    raw   = _run(["iwlist", iface, "scan"])
    if not raw.strip():
        return []
    networks = []
    current  = {}
    for line in raw.splitlines():
        line = line.strip()
        if "Cell" in line and "Address:" in line:
            if current:
                networks.append(current)
            current = {"bssid": line.split("Address:")[-1].strip(), "ssid": "",
                       "security": "", "signal": ""}
        elif "ESSID:" in line:
            current["ssid"] = line.split("ESSID:")[-1].strip().strip('"')
        elif "Encryption key:on" in line:
            current["security"] = current.get("security", "") + "WEP "
        elif "IE: IEEE 802.11i/WPA2" in line:
            current["security"] = "WPA2"
        elif "IE: WPA Version" in line:
            current["security"] = "WPA"
        elif "Signal level=" in line:
            m = re.search(r"Signal level=(-?\d+)", line)
            current["signal"] = m.group(1) if m else ""
    if current:
        networks.append(current)
    return networks


# ── macOS ─────────────────────────────────────────────────────────────────────
def _scan_macos(fm: FindingsManager) -> list:
    tool = get_wireless_tool()
    networks = []

    if tool and "airport" in str(tool):
        # Classic airport binary (macOS < 14 typically)
        raw = _run([tool, "-s"])
        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 7:
                networks.append({
                    "ssid":     parts[0],
                    "bssid":    parts[1],
                    "signal":   parts[2],
                    "security": parts[-1],
                })

    elif tool == "system_profiler":
        # macOS 14+ — airport removed, use system_profiler
        raw = _run(["system_profiler", "SPAirPortDataType", "-json"])
        try:
            import json
            data = json.loads(raw)
            wifi_data = data.get("SPAirPortDataType", [{}])[0]
            for net in wifi_data.get("spairport_airport_other_local_wireless_networks", []):
                security = net.get("spairport_security_mode", "")
                networks.append({
                    "ssid":     net.get("_name", ""),
                    "bssid":    net.get("spairport_network_bssid", ""),
                    "signal":   str(net.get("spairport_signal_noise", "")),
                    "security": security,
                })
        except Exception as e:
            logger.debug(f"[Wireless] system_profiler parse error: {e}")

    if not networks:
        # Fallback for any macOS version: networksetup
        raw = _run(["networksetup", "-listallhardwareports"])
        # This doesn't give surrounding networks but at least shows the interface
        fm.add(Finding(
            title="Wireless Scan: Limited Data Available",
            severity="Info",
            description="Full wireless scan unavailable on this macOS version without airport tool.",
            remediation="Install macOS airport tool or run 'brew install wireless-tools'.",
            module="Wireless"
        ))

    return networks


# ── Windows ───────────────────────────────────────────────────────────────────
def _scan_windows(fm: FindingsManager) -> list:
    raw = _run(["netsh", "wlan", "show", "networks", "mode=Bssid"])
    networks  = []
    current   = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            if current:
                networks.append(current)
            current = {"ssid": line.split(":", 1)[-1].strip(), "bssid": "",
                       "security": "", "signal": ""}
        elif "BSSID" in line:
            current["bssid"] = line.split(":", 1)[-1].strip()
        elif "Authentication" in line:
            current["security"] = line.split(":", 1)[-1].strip()
        elif "Signal" in line:
            current["signal"] = line.split(":", 1)[-1].strip()
    if current:
        networks.append(current)
    return networks


# ── Analysis ──────────────────────────────────────────────────────────────────
def _analyse_networks(networks: list, fm: FindingsManager):
    if not networks:
        fm.add(Finding(
            title="No Wireless Networks Found",
            severity="Info",
            description="No WiFi networks detected in range or adapter unavailable.",
            remediation="Ensure wireless adapter is enabled. Run with elevated privileges.",
            module="Wireless"
        ))
        return

    fm.add(Finding(
        title=f"{len(networks)} Wireless Networks Detected",
        severity="Info",
        description=f"Discovered {len(networks)} nearby wireless networks.",
        remediation="Document and audit all access points in your environment.",
        module="Wireless",
        evidence="\n".join(f"{n.get('ssid','?')}  {n.get('security','?')}  {n.get('bssid','')}"
                           for n in networks[:20])
    ))

    for net in networks:
        ssid     = net.get("ssid", "").strip()
        security = net.get("security", "").upper()
        bssid    = net.get("bssid", "")

        # Open network
        if not security or security in ("NONE", "OPEN", "--"):
            fm.add(Finding(
                title=f"Open (Unencrypted) Network: '{ssid}'",
                severity="Critical", cvss=9.8, cwe="CWE-311",
                description=f"Network '{ssid}' has NO encryption. All traffic is readable.",
                remediation="Enable WPA3 or WPA2. Never use open networks for sensitive work.",
                module="Wireless", evidence=f"BSSID: {bssid}"
            ))

        # WEP
        elif "WEP" in security:
            fm.add(Finding(
                title=f"WEP Encryption (Crackable in Minutes): '{ssid}'",
                severity="Critical", cvss=9.8, cwe="CWE-326",
                description=f"WEP can be cracked in <5 minutes with Aircrack-ng.",
                remediation="Immediately upgrade to WPA3 or WPA2-AES.",
                module="Wireless", evidence=f"BSSID: {bssid}"
            ))

        # WPA1
        elif re.search(r"\bWPA\b", security) and "WPA2" not in security and "WPA3" not in security:
            fm.add(Finding(
                title=f"WPA1 (Weak): '{ssid}'",
                severity="High", cvss=7.4, cwe="CWE-326",
                description="WPA1 is deprecated and vulnerable to dictionary attacks.",
                remediation="Upgrade to WPA3 or at minimum WPA2-AES.",
                module="Wireless", evidence=f"BSSID: {bssid}"
            ))

        # Default/common SSIDs
        default_ssids = ["linksys","dlink","netgear","TP-Link","Xfinity","HUAWEI",
                         "default","admin","home","wifi","router","2WIRE","ATT",
                         "Verizon","Spectrum","ASUS","Belkin"]
        if any(d.lower() in ssid.lower() for d in default_ssids):
            fm.add(Finding(
                title=f"Default SSID Detected: '{ssid}'",
                severity="Medium", cvss=4.3, cwe="CWE-1392",
                description="Default SSID suggests router may use default credentials.",
                remediation="Change SSID and all default admin credentials.",
                module="Wireless", evidence=f"BSSID: {bssid}"
            ))

        # Hidden SSID (empty SSID string)
        if not ssid or ssid == "<hidden>":
            fm.add(Finding(
                title="Hidden SSID Detected",
                severity="Low", cvss=2.4, cwe="CWE-656",
                description="A hidden network was detected. SSID hiding is security through obscurity.",
                remediation="Hidden SSIDs provide no real security. Use strong WPA3 instead.",
                module="Wireless", evidence=f"BSSID: {bssid}"
            ))


def scan(target: str = "local", **kwargs) -> list:
    fm = FindingsManager()
    logger.info("[Wireless] Starting wireless scan")

    if not is_elevated():
        fm.add(Finding(
            title="Wireless Scan: Elevated Privileges Recommended",
            severity="Info",
            description="Full wireless scanning may require root/admin. Running in limited mode.",
            remediation="Run with sudo (Linux/macOS) or as Administrator (Windows).",
            module="Wireless"
        ))

    networks = []

    if IS_LINUX:
        tool = get_wireless_tool()
        if tool == "nmcli":
            networks = _scan_nmcli(fm)
        elif tool in ("iwlist", None):
            networks = _scan_iwlist(fm)
        elif tool == "iw":
            iface = _get_wlan_iface()
            _run(["iw", iface, "scan"])   # trigger scan
            networks = _scan_iwlist(fm)   # iwlist may still parse

    elif IS_MACOS:
        networks = _scan_macos(fm)

    elif IS_WINDOWS:
        networks = _scan_windows(fm)

    else:
        fm.add(Finding(
            title="Wireless Scan: Unsupported Platform",
            severity="Info",
            description=f"Wireless scanning not implemented for this OS.",
            remediation="Run on Kali Linux, macOS, or Windows.",
            module="Wireless"
        ))
        return fm.all()

    _analyse_networks(networks, fm)
    logger.info(f"[Wireless] Complete: {fm.count()} findings, {len(networks)} networks")
    return fm.all()
