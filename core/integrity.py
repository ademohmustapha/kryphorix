"""
core/integrity.py  —  SHA-256 manifest-based integrity checker.
"""
import hashlib
import hmac
import json
import os
import threading
from pathlib import Path

MANIFEST_FILE = "integrity_manifest.json"
CRITICAL_FILES = [
    "kryphorix.py",
    "core/finding.py",
    "core/findings.py",
    "core/config.py",
    "core/audit_log.py",
    "core/bootstrap.py",
    "core/compat.py",
    "core/report.py",
    "core/updater.py",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class IntegrityChecker:
    def __init__(self, root_dir=None):
        self._root     = Path(root_dir) if root_dir else Path.cwd()
        self._manifest = self._root / MANIFEST_FILE
        self._lock     = threading.Lock()

    def _hmac_key(self) -> bytes:
        """Derive a per-installation HMAC key from machine-specific data."""
        key_file = self._root / ".integrity_key"
        if key_file.exists():
            return key_file.read_bytes()
        key = os.urandom(32)
        key_file.write_bytes(key)
        try:
            key_file.chmod(0o600)
        except Exception:
            pass
        return key

    def _sign_manifest(self, manifest: dict) -> str:
        """Return HMAC-SHA256 of serialised manifest."""
        data = json.dumps(manifest, sort_keys=True).encode()
        return hmac.new(self._hmac_key(), data, hashlib.sha256).hexdigest()

    def regenerate(self) -> dict:
        """Build (or rebuild) the integrity manifest."""
        manifest = {}
        for rel in CRITICAL_FILES:
            p = self._root / rel
            if p.exists():
                try:
                    manifest[rel] = _sha256(p)
                except Exception:
                    pass
        manifest["_sig"] = self._sign_manifest({k: v for k, v in manifest.items() if not k.startswith("_")})
        with self._lock:
            with open(self._manifest, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        return manifest

    def verify(self) -> tuple:
        """
        Check each critical file against stored hashes.
        Validates HMAC signature first, then individual file hashes.
        Returns (all_ok: bool, issues: list[str])
        """
        if not self._manifest.exists():
            self.regenerate()
            return True, []

        try:
            with open(self._manifest, encoding="utf-8") as f:
                stored = json.load(f)
        except Exception:
            return False, ["Manifest unreadable — possible tampering"]

        # Verify HMAC signature first
        sig = stored.pop("_sig", None)
        if sig:
            expected_sig = self._sign_manifest(stored)
            if not hmac.compare_digest(sig, expected_sig):
                return False, ["Manifest HMAC invalid — manifest may have been tampered"]
        # Put sig back
        if sig:
            stored["_sig"] = sig

        issues = []
        for rel, expected_hash in stored.items():
            if rel.startswith("_"):
                continue
            p = self._root / rel
            if not p.exists():
                issues.append(f"MISSING: {rel}")
                continue
            try:
                actual = _sha256(p)
                if actual != expected_hash:
                    issues.append(f"MODIFIED: {rel}")
            except Exception as e:
                issues.append(f"ERROR reading {rel}: {e}")

        return len(issues) == 0, issues
