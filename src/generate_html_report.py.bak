#!/usr/bin/env python3
"""
generate_html_report.py

Robust HTML aggregator for OWASP_Automation.

Features:
- Loads all JSON files from reports/raw/
- Normalizes `status` across reports (handles strings, numbers, missing)
- Maps numeric HTTP-like codes to PASS/WARN/FAIL/ERROR
- Produces a clean HTML dashboard with a donut chart and table
- Tolerant to malformed or partial report files
"""

import os
import json
import datetime
import pandas as pd
import plotly.express as px
from jinja2 import Environment, FileSystemLoader, select_autoescape

RAW_DIR = "reports/raw"
AGG_DIR = "reports/aggregated"
OUTPUT_FILE = os.path.join(AGG_DIR, "owasp_report.html")


def load_json_file(path):
    """Safely load a JSON file, returning a dict even on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        return {"_parse_error": str(e)}


def normalize_status(raw_status):
    """
    Normalize a raw `status` value into one of:
      PASS, WARN, FAIL, ERROR, UNKNOWN

    Acceptable inputs:
      - strings like "pass", "Warn", "FAIL" -> normalized to uppercase
      - numeric codes (e.g., 200, 404) -> mapped to categories
      - missing/None/empty -> UNKNOWN
    """
    if raw_status is None:
        return "UNKNOWN"

    # If it's a dict with status field, unwrap (defensive)
    if isinstance(raw_status, dict) and "status" in raw_status:
        raw_status = raw_status["status"]

    # If it's numeric (int/float) or numeric string, classify by ranges
    try:
        # allow numeric strings like "200"
        num = int(raw_status)
        if 100 <= num < 300:
            return "PASS"
        if 300 <= num < 400:
            return "WARN"
        if 400 <= num < 500:
            return "FAIL"
        if num >= 500:
            return "ERROR"
    except Exception:
        pass

    # If it's a string, trim and uppercase it
    if isinstance(raw_status, str):
        s = raw_status.strip().upper()
        if s == "":
            return "UNKNOWN"
        # common synonyms mapping (helpful if scripts use varied words)
        if s in ("OK", "200", "SUCCESS", "PASSED"):
            return "PASS"
        if s in ("WARN", "WARNING", "CAUTION"):
            return "WARN"
        if s in ("FAIL", "FAILED", "VULNERABLE", "ERROR"):
            return "FAIL" if "FAIL" in s else ("ERROR" if "ERROR" in s else s)
        # If it's already PASS/WARN/FAIL/ERROR, return directly
        if s in ("PASS", "WARN", "FAIL", "ERROR", "UNKNOWN"):
            return s
        # For other words (e.g., "rate_limited"), classify as WARN
        if any(k in s for k in ("RATE", "LIMIT", "THROTTLE", "LIMITED")):
            return "WARN"
        # default to WARN for anything unclear but present
        return "WARN"

    # For unknown types fallback
    return "UNKNOWN"


def load_reports():
    """Read raw JSON reports and create a normalized list of report dicts."""
    reports = []
    if not os.path.isdir(RAW_DIR):
        return reports

    for fname in sorted(os.listdir(RAW_DIR)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(RAW_DIR, fname)
        raw = load_json_file(path)

        # If file failed to parse, mark error
        if "_parse_error" in raw:
            reports.append({
                "check_name": fname.replace("_report.json", ""),
                "status": "ERROR",
                "num_findings": 0,
                "path": path,
                "error": f"parse_error: {raw.get('_parse_error')}",
                "raw": raw
            })
            continue

        # Try common keys for check name
        check_name = raw.get("check_name") or raw.get("name") or fname.replace("_report.json", "")

        # Determine findings array length defensively
        findings = raw.get("findings", [])
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            # If singular or dict, convert to list
            findings = [findings]

        # Normalize status value (robust)
        raw_status = raw.get("status")
        status = normalize_status(raw_status)

        reports.append({
            "check_name": check_name,
            "status": status,
            "num_findings": len(findings),
            "path": path,
            "error": raw.get("error", ""),
            "raw": raw
        })

    return reports


def build_summary_df(reports):
    """Return a pandas DataFrame from normalized reports list."""
    if not reports:
        return pd.DataFrame(columns=["check_name", "status", "num_findings", "path"])
    df = pd.DataFrame(reports)
    return df


def make_chart(df):
    """Return Plotly HTML snippet for status distribution (or None)."""
    if df.empty:
        return None

    counts = df["status"].value_counts().reindex(["PASS", "WARN", "FAIL", "ERROR", "UNKNOWN"], fill_value=0)
    summary = counts.reset_index()
    summary.columns = ["status", "count"]
    fig = px.pie(
        summary,
        names="status",
        values="count",
        hole=0.5,
        color="status",
        color_discrete_map={
            "PASS": "#4CAF50",
            "WARN": "#FFB74D",
            "FAIL": "#F44336",
            "ERROR": "#9C27B0",
            "UNKNOWN": "#9E9E9E",
        },
        title="OWASP Check Status Distribution"
    )
    fig.update_layout(margin=dict(l=0, r=0, t=30, b=0), showlegend=True)
    return fig.to_html(full_html=False, include_plotlyjs="cdn")


def render_html(df, chart_html):
    """Render final HTML using Jinja2 template embedded here."""
    env = Environment(loader=FileSystemLoader(searchpath="./"), autoescape=select_autoescape(["html", "xml"]))

    template = env.from_string("""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>OWASP Automation Report</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 30px; background:#f7f9fb; color:#222; }
    header { margin-bottom: 20px; }
    table { border-collapse: collapse; width:100%; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,0.08); }
    th, td { padding: 12px 10px; border-bottom:1px solid #eee; text-align:left; }
    th { background:#2f3e46; color:#fff; font-weight:600; }
    tr:nth-child(even) td { background:#fbfdff; }
    .PASS { color:#1b8a1b; font-weight:700; }
    .WARN { color:#b06a00; font-weight:700; }
    .FAIL { color:#c23131; font-weight:700; }
    .ERROR { color:#8e44ad; font-weight:700; }
    .UNKNOWN { color:#777; font-weight:700; }
    .container { max-width:1200px; margin:auto; }
    .left { float:left; width:60%; }
    .right { float:right; width:36%; }
    .clearfix::after { content:''; display:table; clear:both; }
    footer { margin-top: 30px; color:#666; font-size:13px; text-align:center;}
    a.raw-link { color:#2a6fdb; text-decoration:none; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>OWASP Security Automation Report</h1>
      <p>Generated: {{ generated }}</p>
    </header>

    <div class="clearfix">
      <div class="left">
        <table>
          <thead>
            <tr><th>Check</th><th>Status</th><th>Findings</th><th>Raw JSON</th></tr>
          </thead>
          <tbody>
            {% for r in rows %}
            <tr>
              <td>{{ r.check_name }}</td>
              <td class="{{ r.status }}">{{ r.status }}</td>
              <td>{{ r.num_findings }}</td>
              <td><a class="raw-link" href="../raw/{{ r.check_name }}_report.json" target="_blank">Open</a></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="right">
        <h3>Overall Status</h3>
        {{ chart_html | safe }}
        <p style="margin-top:10px">Pass: {{ counts.PASS }} &nbsp; | &nbsp; Warn: {{ counts.WARN }} &nbsp; | &nbsp; Fail: {{ counts.FAIL }}</p>
      </div>
    </div>

    <footer>
      <p>OWASP_Automation Framework • {{ generated }}</p>
    </footer>
  </div>
</body>
</html>
""")

    # compute counts for display
    counts = {
        "PASS": int((df["status"] == "PASS").sum()) if not df.empty else 0,
        "WARN": int((df["status"] == "WARN").sum()) if not df.empty else 0,
        "FAIL": int((df["status"] == "FAIL").sum()) if not df.empty else 0
    }

    html = template.render(rows=df.to_dict(orient="records"), chart_html=chart_html, generated=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"), counts=counts)
    return html


def main():
    if not os.path.isdir(RAW_DIR):
        print(f"No raw reports directory found: {RAW_DIR}")
        return

    os.makedirs(AGG_DIR, exist_ok=True)

    reports = load_reports()
    df = build_summary_df(reports)
    chart_html = make_chart(df)
    html = render_html(df, chart_html)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"✅ HTML report generated at: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
