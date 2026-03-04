"""
core/report.py  —  Kryphorix Professional Reporting Engine
===========================================================
Produces: PDF (primary), HTML (dark-themed), JSON, CSV.
ReportLab is a soft dependency — HTML/JSON/CSV always work without it.
"""

import json
import os
import csv
import re
from datetime import datetime
from pathlib import Path

TOOL_VERSION = "2.0.0"

# ── Severity colour mappings ───────────────────────────────────────────────────
SEV_HEX = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#2ecc71",
    "Info":     "#3498db",
}

HTML_DARK_CSS = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;
      --crit:#c0392b;--high:#e67e22;--med:#f1c40f;--low:#2ecc71;--info:#3498db;}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}
header{background:linear-gradient(135deg,#0a1628,#1a2744);padding:40px 60px;border-bottom:1px solid var(--border)}
header h1{font-size:2.2em;color:#58a6ff;letter-spacing:2px;font-weight:700}
header .meta{margin-top:8px;opacity:.7;font-size:.9em}
.container{max-width:1400px;margin:0 auto;padding:40px 40px}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:20px;margin:30px 0}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;text-align:center;transition:.2s}
.stat-card:hover{transform:translateY(-2px);border-color:#58a6ff}
.stat-card .num{font-size:2.8em;font-weight:700;line-height:1}
.stat-card .label{opacity:.7;margin-top:8px;text-transform:uppercase;letter-spacing:1px;font-size:.8em}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}
h2{margin:40px 0 20px;color:#58a6ff;font-size:1.4em;border-bottom:1px solid var(--border);padding-bottom:10px}
.finding{background:var(--card);border:1px solid var(--border);border-left:4px solid;border-radius:8px;margin:16px 0;padding:20px}
.finding.Critical{border-left-color:var(--crit)}.finding.High{border-left-color:var(--high)}
.finding.Medium{border-left-color:var(--med)}.finding.Low{border-left-color:var(--low)}.finding.Info{border-left-color:var(--info)}
.finding-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.finding-title{font-weight:700;font-size:1.05em}
.badge{padding:4px 12px;border-radius:20px;font-size:.8em;font-weight:700;color:#fff}
.badge.Critical{background:var(--crit)}.badge.High{background:var(--high)}.badge.Medium{background:var(--med);color:#000}
.badge.Low{background:var(--low);color:#000}.badge.Info{background:var(--info)}
.finding-meta{display:flex;gap:16px;margin-bottom:10px;opacity:.7;font-size:.85em}
.finding-body p{margin:8px 0;opacity:.85}
.finding-body .label{font-weight:600;color:#8b949e;font-size:.85em;text-transform:uppercase;letter-spacing:.5px}
.evidence{background:#0d1117;border-radius:6px;padding:12px;margin:8px 0;font-family:'Courier New',monospace;font-size:.85em;overflow-x:auto}
footer{text-align:center;padding:40px;opacity:.4;font-size:.85em;border-top:1px solid var(--border);margin-top:40px}
.risk-bar{height:8px;background:#21262d;border-radius:4px;margin:4px 0}
.risk-fill{height:100%;border-radius:4px}
.legal{background:#1c1c0d;border:1px solid #5a4e00;border-radius:8px;padding:16px;margin:20px 0;font-size:.85em;opacity:.8}
"""


def _ts(fmt: str = "%Y%m%d_%H%M%S") -> str:
    return datetime.now().strftime(fmt)

def _ensure_dir(root) -> Path:
    d = Path(root or ".") / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _sev_count(findings: list) -> dict:
    c = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c

def _sort_findings(findings: list) -> list:
    order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    return sorted(findings, key=lambda f: order.get(f.severity, 0), reverse=True)

def _esc(s: str) -> str:
    """HTML-escape a string."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ── JSON ───────────────────────────────────────────────────────────────────────
def export_json(findings: list, targets: list = None, root=None, filename: str = None) -> str:
    d    = _ensure_dir(root)
    path = d / (filename or f"kryphorix_report_{_ts()}.json")
    data = {
        "tool":      f"Kryphorix v{TOOL_VERSION}",
        "generated": datetime.now().isoformat(),
        "targets":   targets or [],
        "summary":   _sev_count(findings),
        "findings":  [f.to_dict() for f in _sort_findings(findings)],
    }
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"  [JSON] Saved: {path}")
    return str(path)


# ── CSV ────────────────────────────────────────────────────────────────────────
def export_csv(findings: list, root=None, filename: str = None) -> str:
    d    = _ensure_dir(root)
    path = d / (filename or f"kryphorix_report_{_ts()}.csv")
    headers = ["Severity","Module","Title","CVSS","CWE","CVE","Description","Remediation","Evidence"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for finding in _sort_findings(findings):
            w.writerow(finding.to_csv_row())
    print(f"  [CSV]  Saved: {path}")
    return str(path)


# ── HTML ───────────────────────────────────────────────────────────────────────
def export_html(findings: list, targets: list = None, root=None, filename: str = None) -> str:
    d     = _ensure_dir(root)
    path  = d / (filename or f"kryphorix_report_{_ts()}.html")
    counts = _sev_count(findings)
    total  = len(findings)
    risk   = ("Critical" if counts["Critical"] > 0 else "High" if counts["High"] > 0
              else "Medium" if counts["Medium"] > 0 else "Low" if counts["Low"] > 0 else "Clean")

    def _stat(num, label, cls):
        return (f'<div class="stat-card"><div class="num {cls}">{num}</div>'
                f'<div class="label">{label}</div></div>')

    stats_html = "\n".join([
        _stat(total,                  "Total",    ""),
        _stat(counts["Critical"],     "Critical", "critical"),
        _stat(counts["High"],         "High",     "high"),
        _stat(counts["Medium"],       "Medium",   "medium"),
        _stat(counts["Low"],          "Low",      "low"),
        _stat(counts["Info"],         "Info",     "info"),
        _stat(risk,                   "Risk",     risk.lower()),
    ])

    findings_html = ""
    for f in _sort_findings(findings):
        cvss_bar = ""
        if f.cvss > 0:
            pct   = f.cvss * 10
            color = SEV_HEX.get(f.severity, "#888")
            cvss_bar = (f'<div class="risk-bar"><div class="risk-fill" '
                        f'style="width:{pct}%;background:{color}"></div></div>')

        ev_html = ""
        if f.evidence:
            ev_html = f'<div class="evidence">{_esc(f.evidence[:500])}</div>'

        meta_parts = []
        if f.cvss > 0:     meta_parts.append(f"CVSS: {f.cvss:.1f}")
        if f.cwe:          meta_parts.append(f"CWE: {f.cwe}")
        if f.cve:          meta_parts.append(f"CVE: {f.cve}")
        if f.module:       meta_parts.append(f"Module: {f.module}")

        findings_html += f"""
        <div class="finding {_esc(f.severity)}">
          <div class="finding-header">
            <div class="finding-title">{_esc(f.title)}</div>
            <span class="badge {_esc(f.severity)}">{_esc(f.severity)}</span>
          </div>
          {cvss_bar}
          <div class="finding-meta">{' &nbsp;·&nbsp; '.join(meta_parts)}</div>
          <div class="finding-body">
            <p><span class="label">Description</span><br>{_esc(f.description)}</p>
            <p><span class="label">Remediation</span><br>{_esc(f.remediation)}</p>
            {ev_html}
          </div>
        </div>"""

    tgt_str = ", ".join(targets or []) or "N/A"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Kryphorix Security Report — {_ts('%Y-%m-%d %H:%M')}</title>
  <style>{HTML_DARK_CSS}</style>
</head>
<body>
<header>
  <h1>🔐 KRYPHORIX v{TOOL_VERSION}</h1>
  <div class="meta">
    Security Assessment Report &nbsp;·&nbsp;
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;·&nbsp;
    Target(s): {_esc(tgt_str)}
  </div>
</header>
<div class="container">
  <div class="legal">⚠ CONFIDENTIAL — This report contains sensitive security information.
  Handle in accordance with your organisation's data classification policy.</div>

  <h2>Executive Summary</h2>
  <div class="summary-grid">{stats_html}</div>

  <h2>Findings ({total})</h2>
  {findings_html if findings_html else '<p style="opacity:.5">No findings recorded.</p>'}
</div>
<footer>
  Kryphorix v{TOOL_VERSION} · Elite Cyber Security Assessment Suite ·
  {datetime.now().strftime('%Y')} · CONFIDENTIAL
</footer>
</body></html>"""

    path.write_text(html, encoding="utf-8")
    print(f"  [HTML] Saved: {path}")
    return str(path)


# ── PDF ────────────────────────────────────────────────────────────────────────
def generate_pdf(findings: list, targets: list = None, root=None, filename: str = None) -> str:
    """Generate professional PDF. Gracefully falls back to HTML if reportlab unavailable."""
    d    = _ensure_dir(root)
    path = d / (filename or f"kryphorix_report_{_ts()}.pdf")

    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, PageBreak, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        # Graceful fallback: produce HTML with .pdf in the name hint
        print("  [PDF]  reportlab unavailable — producing HTML instead")
        html_path = export_html(findings, targets=targets, root=root,
                                filename=str(path.stem) + ".html")
        return html_path

    doc = SimpleDocTemplate(
        str(path), pagesize=landscape(A4),
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm,  bottomMargin=1.5*cm,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Title2",  fontSize=22, textColor=colors.HexColor("#1a3a5c"),
                               fontName="Helvetica-Bold", spaceAfter=6, alignment=TA_CENTER))
    styles.add(ParagraphStyle("SubTitle",fontSize=11, textColor=colors.HexColor("#666"),
                               fontName="Helvetica",     spaceAfter=4, alignment=TA_CENTER))
    styles.add(ParagraphStyle("SH",      fontSize=13, textColor=colors.HexColor("#1a3a5c"),
                               fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle("Body",    fontSize=8,  leading=11, wordWrap="LTR"))
    styles.add(ParagraphStyle("Bold8",   fontSize=8,  fontName="Helvetica-Bold"))

    SEV_COLORS_PDF = {
        "Critical": colors.HexColor("#c0392b"),
        "High":     colors.HexColor("#e67e22"),
        "Medium":   colors.HexColor("#f39c12"),
        "Low":      colors.HexColor("#27ae60"),
        "Info":     colors.HexColor("#2980b9"),
    }

    counts   = _sev_count(findings)
    total    = len(findings)
    tgt_str  = ", ".join(targets or []) or "N/A"

    story = []

    # ── Cover ──────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("KRYPHORIX", styles["Title2"]))
    story.append(Paragraph(f"Elite Cyber Security Assessment Suite v{TOOL_VERSION}", styles["SubTitle"]))
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a3a5c")))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(f"Target(s): {tgt_str}", styles["SubTitle"]))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["SubTitle"]))
    story.append(Spacer(1, 1.5*cm))

    # ── Summary table ──────────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["SH"]))
    sum_data = [["Metric", "Count"]]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        sum_data.append([sev, str(counts.get(sev, 0))])
    sum_data.append(["TOTAL", str(total)])

    sum_tbl = Table(sum_data, colWidths=[6*cm, 4*cm])
    sum_style = TableStyle([
        ("BACKGROUND",   (0,0), (-1,0),  colors.HexColor("#1a3a5c")),
        ("TEXTCOLOR",    (0,0), (-1,0),  colors.white),
        ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("GRID",         (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS",(0,1),(-1,-2),[colors.HexColor("#f7f8fa"), colors.white]),
        ("BACKGROUND",   (0,-1),(-1,-1), colors.HexColor("#eaf2ff")),
        ("FONTNAME",     (0,-1),(-1,-1), "Helvetica-Bold"),
        ("ALIGN",        (1,0), (1,-1),  "CENTER"),
    ])
    for i, sev in enumerate(["Critical","High","Medium","Low","Info"], 1):
        if counts.get(sev, 0) > 0:
            sum_style.add("TEXTCOLOR", (0,i), (0,i), SEV_COLORS_PDF[sev])
            sum_style.add("FONTNAME",  (0,i), (0,i), "Helvetica-Bold")
    sum_tbl.setStyle(sum_style)
    story.append(sum_tbl)
    story.append(PageBreak())

    # ── Findings table ─────────────────────────────────────────────────────────
    story.append(Paragraph(f"Detailed Findings ({total})", styles["SH"]))

    col_widths = [2.5*cm, 8*cm, 2*cm, 1.5*cm, 8*cm, 8*cm]
    tbl_data = [["Severity","Title","Module","CVSS","Description","Remediation"]]

    for f in _sort_findings(findings):
        desc_p = Paragraph(f.description[:250], styles["Body"])
        fix_p  = Paragraph(f.remediation[:200], styles["Body"])
        tbl_data.append([
            Paragraph(f.severity, styles["Bold8"]),
            Paragraph(f.title[:80],  styles["Bold8"]),
            Paragraph(f.module,      styles["Body"]),
            f"{f.cvss:.1f}" if f.cvss else "-",
            desc_p,
            fix_p,
        ])

    findings_tbl = Table(tbl_data, colWidths=col_widths, repeatRows=1)
    tbl_style = [
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#1a3a5c")),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#dddddd")),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.HexColor("#f7f8fa"), colors.white]),
        ("LEADING",       (0,0), (-1,-1), 10),
    ]
    for i, f in enumerate(_sort_findings(findings), 1):
        tbl_style.append(
            ("TEXTCOLOR", (0,i), (0,i), SEV_COLORS_PDF.get(f.severity, colors.black))
        )
    findings_tbl.setStyle(TableStyle(tbl_style))
    story.append(findings_tbl)

    # ── Footer ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"CONFIDENTIAL — Kryphorix v{TOOL_VERSION} — "
        f"{datetime.now().strftime('%Y')} — Authorised security testing only.",
        styles["SubTitle"]
    ))

    doc.build(story)
    print(f"  [PDF]  Saved: {path}")
    return str(path)
