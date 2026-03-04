"""
core/audit_log.py  —  Tamper-evident chain-hashed audit log (JSONL).
Each entry includes the SHA-256 hash of the previous entry so any
deletion or modification is immediately detectable.
"""
import json
import hashlib
import hmac
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, root_dir=None):
        self._root  = Path(root_dir) if root_dir else Path.cwd()
        self._path  = self._root / "logs" / "audit.jsonl"
        self._lock  = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._hmac_key = self._load_hmac_key()
        self._prev_hash = self._compute_prev_hash()

    def _load_hmac_key(self) -> bytes:
        """Load or create a persistent HMAC key for audit chain integrity."""
        key_path = self._root / "logs" / ".audit_key"
        if key_path.exists():
            data = key_path.read_bytes()
            if len(data) == 32:
                return data
        key = os.urandom(32)
        key_path.write_bytes(key)
        try:
            key_path.chmod(0o600)
        except Exception:
            pass
        return key

    def _compute_prev_hash(self) -> str:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return hashlib.sha256(b"KRYPHORIX_GENESIS").hexdigest()
        try:
            lines = self._path.read_text(encoding="utf-8").strip().splitlines()
            if lines:
                return json.loads(lines[-1]).get("hash", hashlib.sha256(b"GENESIS").hexdigest())
        except Exception:
            pass
        return hashlib.sha256(b"KRYPHORIX_GENESIS").hexdigest()

    def log(self, event: str, data: dict = None):
        """Append a tamper-evident log entry."""
        with self._lock:
            entry = {
                "ts":    datetime.now(timezone.utc).isoformat(),
                "event": event,
                "pid":   os.getpid(),
                "data":  data or {},
            }
            entry_json    = json.dumps(entry, separators=(",", ":"), default=str)
            chain_input   = (self._prev_hash + entry_json).encode()
            entry["hash"] = hmac.new(self._hmac_key, chain_input, hashlib.sha256).hexdigest()
            line          = json.dumps(entry, default=str) + "\n"
            try:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(line)
                self._prev_hash = entry["hash"]
            except Exception:
                pass

    def verify_chain(self) -> tuple:
        """Verify integrity of audit log chain. Returns (ok, broken_at)."""
        if not self._path.exists():
            return True, None
        try:
            lines = self._path.read_text(encoding="utf-8").strip().splitlines()
            if not lines:
                return True, None
            # Load the HMAC key — must match the key used during log() writes
            key = self._load_hmac_key()
            prev = hashlib.sha256(b"KRYPHORIX_GENESIS").hexdigest()
            for i, line in enumerate(lines):
                entry    = json.loads(line)
                stored   = entry.pop("hash", None)
                # FIX: was using plain hashlib.sha256() — but log() uses hmac.new(key, ...)
                # The chain hash is HMAC-SHA256 keyed with the audit HMAC key, not bare SHA-256.
                entry_j  = json.dumps(entry, separators=(",", ":"), default=str)
                chain_input = (prev + entry_j).encode()
                expected = hmac.new(key, chain_input, hashlib.sha256).hexdigest()
                entry["hash"] = stored   # put back
                if stored != expected:
                    return False, i
                prev = stored
            return True, None
        except Exception as e:
            return False, str(e)
