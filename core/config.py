"""
core/config.py  —  Persistent JSON configuration with runtime overrides.
"""
import json
import os
from pathlib import Path

DEFAULTS = {
    "threads":        20,
    "timeout":        10,
    "stealth_mode":   False,
    "aggressive":     False,
    "user_agent":     "Mozilla/5.0 Kryphorix/2.0 Security Assessment",
    "port_range":     "1-1024",
    "top_ports":      True,
    "max_subdomains": 500,
    "ssl_verify":     True,
    "report_formats": ["pdf", "json"],
    "proxy":          None,
    "owasp_cache_dir":"assets",
    "workspace_dir":  "workspaces",
    "version":        "2.0.0",
    "auto_update":    True,
    "rate_limit_rps": 50,      # requests per second for port scan
    "stealth_delay":  0.5,     # seconds between requests in stealth mode
}


class Config:
    def __init__(self, root_dir=None):
        self._root = Path(root_dir) if root_dir else Path.cwd()
        self._path = self._root / "config.json"
        self._data = dict(DEFAULTS)
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                with open(self._path, encoding="utf-8") as f:
                    saved = json.load(f)
                # Only load known keys, new defaults stay
                for k, v in saved.items():
                    if k in DEFAULTS:
                        self._data[k] = v
            except Exception:
                pass

    def save(self):
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception:
            pass

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value):
        self._data[key] = value
        self.save()

    def all(self) -> dict:
        return dict(self._data)

    # Convenience properties
    @property
    def threads(self)     -> int:   return self._data.get("threads", 20)
    @property
    def timeout(self)     -> int:   return self._data.get("timeout", 10)
    @property
    def stealth(self)     -> bool:  return self._data.get("stealth_mode", False)
    @property
    def proxy(self)       -> str:   return self._data.get("proxy")
    @property
    def user_agent(self)  -> str:   return self._data.get("user_agent", "Kryphorix/2.0")
    @property
    def ssl_verify(self)  -> bool:
        # FIXED: fallback was False but DEFAULTS has True — inconsistent.
        # Now fallback explicitly matches DEFAULTS["ssl_verify"] = True.
        return self._data.get("ssl_verify", True)
    @property
    def stealth_delay(self) -> float: return self._data.get("stealth_delay", 0.5)
