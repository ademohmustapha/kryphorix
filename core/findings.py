"""
core/findings.py  —  Thread-safe findings collection with dedup & filtering.
"""
from __future__ import annotations
import threading
from core.finding import Finding


class FindingsManager:
    def __init__(self):
        self._lock     = threading.Lock()
        self._findings: list[Finding] = []
        self._seen:     set  = set()   # deduplication by (title, severity, module)

    def add(self, finding: Finding) -> bool:
        """Add finding; returns False if duplicate was dropped."""
        key = (finding.title.strip()[:80], finding.severity, finding.module)
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._findings.append(finding)
            return True

    def add_all(self, findings: list) -> None:
        for f in (findings or []):
            self.add(f)

    def all(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    def by_severity(self, *severities) -> list[Finding]:
        with self._lock:
            return [f for f in self._findings if f.severity in severities]

    def critical(self)   -> list: return self.by_severity("Critical")
    def high(self)       -> list: return self.by_severity("High")
    def medium(self)     -> list: return self.by_severity("Medium")
    def low(self)        -> list: return self.by_severity("Low")
    def info(self)       -> list: return self.by_severity("Info")
    def critical_high(self) -> list: return self.by_severity("Critical", "High")

    def highest_severity(self) -> str:
        order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        if not self._findings:
            return "None"
        return max(self._findings, key=lambda f: order.get(f.severity, 0)).severity

    def count(self) -> int:
        with self._lock:
            return len(self._findings)

    def summary_dict(self) -> dict:
        findings = self.all()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"total": len(findings), **counts}
