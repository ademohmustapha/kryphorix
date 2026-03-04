"""
core/finding.py  —  Finding data model with full validation.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

_CVSS_RANGES = {
    "Critical": (9.0, 10.0),
    "High":     (7.0,  8.9),
    "Medium":   (4.0,  6.9),
    "Low":      (0.1,  3.9),
    "Info":     (0.0,  0.0),
}


@dataclass
class Finding:
    title:       str
    severity:    str
    description: str
    remediation: str
    module:      str       = "Unknown"
    cvss:        float     = 0.0
    cwe:         str       = ""
    cve:         str       = ""
    evidence:    str       = ""
    impact:      str       = ""
    references:  list      = field(default_factory=list)

    def __post_init__(self):
        # Normalise severity
        cap = self.severity.strip().capitalize()
        if cap not in VALID_SEVERITIES:
            cap = "Info"
        self.severity = cap

        # Clamp / default CVSS
        try:
            self.cvss = float(self.cvss)
        except (TypeError, ValueError):
            self.cvss = 0.0
        self.cvss = round(max(0.0, min(10.0, self.cvss)), 1)

        # Ensure strings
        for attr in ("title","description","remediation","module","cwe","cve","evidence","impact"):
            setattr(self, attr, str(getattr(self, attr, "") or ""))

        if not isinstance(self.references, list):
            self.references = []

    # ── Legacy aliases ─────────────────────────────────────────────────────────
    @property
    def desc(self) -> str:
        return self.description

    @property
    def fix(self) -> str:
        return self.remediation

    # ── Serialisation ──────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "title":       self.title,
            "severity":    self.severity,
            "cvss":        self.cvss,
            "module":      self.module,
            "cwe":         self.cwe,
            "cve":         self.cve,
            "description": self.description,
            "remediation": self.remediation,
            "evidence":    self.evidence,
            "impact":      self.impact,
            "references":  self.references,
        }

    def to_csv_row(self) -> list:
        return [
            self.severity, self.module, self.title, self.cvss,
            self.cwe, self.cve, self.description[:200],
            self.remediation[:200], self.evidence[:200],
        ]

    @property
    def risk_score(self) -> float:
        """Normalised 0-1 risk score combining severity + CVSS."""
        sev_weight = {"Critical": 1.0, "High": 0.8, "Medium": 0.5,
                      "Low": 0.25, "Info": 0.0}
        sw   = sev_weight.get(self.severity, 0)
        cvss = (self.cvss / 10.0) if self.cvss else sw
        return round((sw * 0.6 + cvss * 0.4), 3)
