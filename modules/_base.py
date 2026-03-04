"""
modules/_base.py  —  Shared utilities for all Kryphorix scan modules.

Every module imports from here to ensure:
  • Consistent session management with proxy + stealth support
  • OS-aware request headers
  • Structured logging
  • Rate limiting in stealth mode
  • Graceful degradation for missing optional deps
"""
import re
import time
import socket
import logging
from pathlib import Path

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.finding  import Finding
from core.findings import FindingsManager

logger = logging.getLogger("kryphorix")


def make_session(proxy: str = None, user_agent: str = None,
                 stealth: bool = False, timeout: int = 10) -> "requests.Session":
    """
    Create a pre-configured requests Session.
    Handles proxy injection, custom UA, stealth timing, SSL ignore.
    """
    if not HAS_REQUESTS:
        raise RuntimeError("requests library not available")

    s = requests.Session()
    s.verify  = True  # Verify SSL by default; pass ssl_verify=False to override
    s.timeout = timeout
    s.headers.update({
        "User-Agent":      user_agent or "Mozilla/5.0 (X11; Linux x86_64) Kryphorix/2.0",
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection":      "keep-alive",
    })
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def safe_get(session, url: str, timeout: int = 10,
             stealth_delay: float = 0.0, **kw) -> "requests.Response | None":
    """GET with full error handling and optional stealth delay."""
    if stealth_delay > 0:
        time.sleep(stealth_delay)
    try:
        kw.setdefault("timeout", timeout)
        kw.setdefault("verify",  False)
        kw.setdefault("allow_redirects", True)
        return session.get(url, **kw)
    except Exception as e:
        logger.debug(f"GET {url} failed: {type(e).__name__}: {e}")
        return None


def safe_post(session, url: str, data: dict = None, json_data: dict = None,
              timeout: int = 10, **kw) -> "requests.Response | None":
    """POST with full error handling."""
    try:
        kw.setdefault("timeout", timeout)
        kw.setdefault("verify",  False)
        if json_data:
            return session.post(url, json=json_data, **kw)
        return session.post(url, data=data, **kw)
    except Exception as e:
        logger.debug(f"POST {url} failed: {type(e).__name__}: {e}")
        return None


def port_open(host: str, port: int, timeout: float = 1.5, proto: str = "tcp") -> bool:
    """Check if a TCP or UDP port is reachable."""
    try:
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"\x00", (host, port))
            try:
                s.recv(64)
                s.close()
                return True
            except socket.timeout:
                s.close()
                return False   # No ICMP port unreachable = likely filtered
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((host, port))
            s.close()
            return r == 0
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 3.0, send: bytes = b"") -> str:
    """Grab a service banner string."""
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        if send:
            s.send(send)
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner
    except Exception:
        return ""


def normalize_url(target: str) -> str:
    if target and not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def extract_host(target: str) -> str:
    return re.sub(r"https?://", "", target).split("/")[0].split(":")[0]


def validate_target(target: str) -> str:
    """
    Validate and normalise a scan target.
    - Strips whitespace
    - Enforces maximum length (prevents DoS via oversized inputs)
    - Rejects targets containing shell metacharacters
    - Returns the cleaned target string
    Raises ValueError if the target is invalid.
    """
    if not isinstance(target, str):
        raise ValueError(f"Target must be a string, got {type(target).__name__}")
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty")
    if len(target) > 2048:
        raise ValueError(f"Target too long: {len(target)} chars (max 2048)")
    # Reject shell metacharacters
    forbidden = set(';|&`$(){}[]<>\\')
    found = [c for c in target if c in forbidden]
    if found:
        raise ValueError(f"Target contains forbidden characters: {found}")
    return target


def normalize_url(target: str) -> str:
    """Validate and ensure target has http(s) scheme."""
    target = validate_target(target)
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target

