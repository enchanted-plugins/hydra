#!/usr/bin/env python3
"""
Security Report Generator
Generates dark-themed HTML report from audit.jsonl data.
Background: #0A0A0A, Surface: #141414, following @enchanter-ai report standard.

Usage:
    python3 report-gen.py <audit_jsonl_path> [output_html_path]
"""

import json
import os
import sys
from collections import Counter
from datetime import datetime


def load_audit_events(audit_path):
    """Load events from audit.jsonl file."""
    events = []
    try:
        with open(audit_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except (OSError, IOError):
        pass
    return events


def aggregate_events(events):
    """Aggregate events by type and severity."""
    severity_counts = Counter()
    event_types = Counter()
    files_scanned = set()
    cwe_counts = Counter()
    findings_by_file = {}

    for event in events:
        event_type = event.get("event", "unknown")
        event_types[event_type] += 1

        severity = event.get("severity", "")
        if severity:
            severity_counts[severity] += 1

        file_path = event.get("file", "")
        if file_path:
            files_scanned.add(file_path)
            if file_path not in findings_by_file:
                findings_by_file[file_path] = []
            findings_by_file[file_path].append(event)

        cwe = event.get("cwe", "")
        if cwe:
            cwe_counts[cwe] += 1

    return {
        "total_events": len(events),
        "severity_counts": dict(severity_counts),
        "event_types": dict(event_types),
        "files_scanned": len(files_scanned),
        "cwe_counts": dict(cwe_counts),
        "findings_by_file": findings_by_file,
    }


def severity_bar(label, count, total, color):
    """Generate an HTML severity bar."""
    pct = (count / total * 100) if total > 0 else 0
    return f'''<div style="margin-bottom:8px;">
    <div style="display:flex;justify-content:space-between;margin-bottom:2px;">
      <span style="color:{color};font-weight:600;">{label}</span>
      <span style="color:#8b949e;">{count}</span>
    </div>
    <div style="background:#1c1c1c;border-radius:4px;height:8px;overflow:hidden;">
      <div style="background:{color};height:100%;width:{pct:.1f}%;border-radius:4px;"></div>
    </div>
  </div>'''


def generate_html(audit_path, stats):
    """Generate dark-themed HTML report."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    sc = stats["severity_counts"]
    total_findings = sum(sc.values())

    severity_colors = {
        "critical": "#f85149",
        "high": "#d29922",
        "medium": "#58a6ff",
        "low": "#8b949e",
        "info": "#484f58",
    }

    bars = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sc.get(sev, 0)
        color = severity_colors.get(sev, "#8b949e")
        bars += severity_bar(sev.upper(), count, total_findings, color)

    # CWE pills
    cwe_pills = ""
    for cwe, count in sorted(stats["cwe_counts"].items(), key=lambda x: -x[1])[:10]:
        cwe_pills += f'<span style="display:inline-block;padding:2px 8px;margin:2px;background:#1c2333;border-radius:12px;font-size:11px;color:#58a6ff;">{cwe} ({count})</span>'

    # Top files
    top_files = ""
    sorted_files = sorted(stats["findings_by_file"].items(), key=lambda x: -len(x[1]))[:10]
    for fpath, findings in sorted_files:
        short = os.path.basename(fpath)
        top_files += f'<div style="padding:4px 0;border-bottom:1px solid #1c1c1c;font-size:12px;"><span style="color:#e6edf3;">{short}</span> <span style="color:#8b949e;">— {len(findings)} finding(s)</span></div>'

    # Determine overall verdict
    critical = sc.get("critical", 0)
    high = sc.get("high", 0)
    if critical > 0:
        verdict_color = "#f85149"
        verdict_text = "CRITICAL — Secrets or dangerous vulnerabilities found. Immediate action required."
    elif high > 0:
        verdict_color = "#d29922"
        verdict_text = "WARNING — High-severity issues found. Review before deploying."
    elif total_findings > 0:
        verdict_color = "#58a6ff"
        verdict_text = "CAUTION — Minor issues found. Review at your convenience."
    else:
        verdict_color = "#3fb950"
        verdict_text = "CLEAN — No security issues detected."

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hydra Security Report</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0A0A0A; color:#e6edf3; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; font-size:13px; line-height:1.5; }}
  .brand-bar {{ height:3px; background:#f85149; }}
  .container {{ max-width:800px; margin:0 auto; padding:32px 24px; }}
  h1 {{ font-size:24px; margin-bottom:4px; }}
  h1 span {{ color:#8b949e; font-size:12px; font-weight:400; margin-left:8px; }}
  .subtitle {{ color:#484f58; font-size:11px; margin-bottom:24px; }}
  .card {{ background:#141414; border:1px solid rgba(255,255,255,0.04); border-radius:8px; padding:20px; margin-bottom:16px; }}
  .card h2 {{ font-size:14px; margin-bottom:12px; color:#8b949e; text-transform:uppercase; letter-spacing:0.5px; }}
  .verdict {{ padding:12px 16px; border-radius:8px; margin-bottom:16px; border-left:3px solid {verdict_color}; background:#141414; }}
  .verdict-text {{ color:{verdict_color}; font-weight:600; }}
  .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; }}
  .stat {{ background:#141414; border:1px solid rgba(255,255,255,0.04); border-radius:8px; padding:12px; text-align:center; }}
  .stat-value {{ font-size:24px; font-weight:700; color:#e6edf3; }}
  .stat-label {{ font-size:10px; color:#8b949e; text-transform:uppercase; letter-spacing:0.5px; }}
  .footer {{ margin-top:32px; padding-top:12px; border-top:1px solid rgba(255,255,255,0.04); font-size:10px; color:#484f58; display:flex; justify-content:space-between; }}
</style>
</head>
<body>
<div class="brand-bar"></div>
<div class="container">
  <h1>Hydra <span>Security Report</span></h1>
  <div class="subtitle">Generated {now} — source: {os.path.basename(audit_path)}</div>

  <div class="verdict">
    <span class="verdict-text">{verdict_text}</span>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-value">{total_findings}</div><div class="stat-label">Findings</div></div>
    <div class="stat"><div class="stat-value" style="color:#f85149;">{critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-value">{stats["files_scanned"]}</div><div class="stat-label">Files</div></div>
    <div class="stat"><div class="stat-value">{stats["total_events"]}</div><div class="stat-label">Events</div></div>
  </div>

  <div class="card">
    <h2>Severity Distribution</h2>
    {bars}
  </div>

  <div class="card">
    <h2>CWE Coverage</h2>
    {cwe_pills if cwe_pills else '<span style="color:#484f58;">No CWE-mapped findings</span>'}
  </div>

  <div class="card">
    <h2>Top Files</h2>
    {top_files if top_files else '<span style="color:#484f58;">No file-specific findings</span>'}
  </div>

  <div class="footer">
    <span>Hydra v1.0.0 — @enchanter-ai</span>
    <span>{now}</span>
  </div>
</div>
</body>
</html>'''

    return html


def main():
    if len(sys.argv) < 2:
        print("Usage: report-gen.py <audit_jsonl_path> [output_html_path]", file=sys.stderr)
        sys.exit(1)

    audit_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/hydra-report.html"

    events = load_audit_events(audit_path)
    stats = aggregate_events(events)
    html = generate_html(audit_path, stats)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(json.dumps({"report": output_path, "stats": stats}, indent=2))


if __name__ == "__main__":
    main()
