#!/usr/bin/env python3
"""
generate_html_report.py
-------------------------------------------------
Simple, responsive, client-ready OWASP report dashboard.

Key goals:
- Minimal dependencies (only jinja2; Plotly via CDN)
- Robust status normalization (string/number/None)
- Robust findings parsing (list/dict/missing)
- Clear, readable layout with mobile support
- Export buttons for CSV/JSON of the visible data
- Backward-compatible with your existing *_report.json files

Input directory : reports/raw/
Output file     : reports/aggregated/owasp_report.html
"""

import os
import json
import datetime
from typing import Any, Dict, List, Tuple
from jinja2 import Environment, BaseLoader, select_autoescape

RAW_DIR = "reports/raw"
AGG_DIR = "reports/aggregated"
OUT_FILE = os.path.join(AGG_DIR, "owasp_report.html")


# -------------------------------
# Helpers: status & severity
# -------------------------------
def normalize_status(raw_status: Any) -> str:
    """
    Map arbitrary status to PASS/WARN/FAIL/ERROR/UNKNOWN.

    Handles:
    - ints (HTTP-like): 2xx=PASS, 3xx=WARN, 4xx=FAIL, 5xx=ERROR
    - strings (case-insensitive)
    - None/missing
    """
    if raw_status is None:
        return "UNKNOWN"

    # unwrap nested {"status": "..."} if present
    if isinstance(raw_status, dict) and "status" in raw_status:
        raw_status = raw_status["status"]

    # numeric (or numeric string)
    try:
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

    # strings
    if isinstance(raw_status, str):
        s = raw_status.strip().upper()
        if s in ("PASS", "WARN", "FAIL", "ERROR", "UNKNOWN"):
            return s
        if s in ("OK", "SUCCESS", "PASSED"):
            return "PASS"
        if s in ("WARNING", "CAUTION"):
            return "WARN"
        if "RATE_LIMIT" in s or "RATE" in s:
            return "WARN"
        if "ERROR" in s:
            return "ERROR"
        if "FAIL" in s or "VULNERABLE" in s:
            return "FAIL"
        if s.isdigit():
            # If string digit slipped through
            return normalize_status(int(s))
        return "WARN"  # conservative default for non-empty strings

    return "UNKNOWN"


def normalize_severity(raw: Any) -> str:
    """
    Map arbitrary severity strings to HIGH/MEDIUM/LOW/INFO.
    Default to INFO if missing/unknown.
    """
    if not isinstance(raw, str):
        return "INFO"
    s = raw.strip().upper()
    if s in ("HIGH", "MEDIUM", "LOW", "INFO"):
        return s
    if s in ("CRITICAL", "SEVERE"):
        return "HIGH"
    if s in ("MODERATE"):
        return "MEDIUM"
    if s in ("MINOR",):
        return "LOW"
    return "INFO"


def display_name_from_file(filename: str) -> str:
    """
    Convert 'cookie_scan_report.json' -> 'Cookie Scan'
    """
    base = filename.replace("_report.json", "")
    parts = base.split("_")
    return " ".join(p.capitalize() for p in parts)


# -------------------------------
# Load & shape data
# -------------------------------
def safe_load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {"_parse_error": str(e), "path": path}


def coerce_findings(raw_findings: Any) -> List[Dict[str, Any]]:
    """
    Ensure findings is a list of dicts.
    - If dict, wrap in list.
    - If None/missing, return []
    - If list of non-dicts, coerce to dict with 'detail'
    """
    if raw_findings is None:
        return []
    if isinstance(raw_findings, dict):
        return [raw_findings]
    if isinstance(raw_findings, list):
        out = []
        for item in raw_findings:
            if isinstance(item, dict):
                out.append(item)
            else:
                out.append({"detail": str(item)})
        return out
    # fallback
    return [{"detail": str(raw_findings)}]


def summarize_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = normalize_severity(f.get("severity", "INFO"))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def collect_reports() -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """
    Read all *_report.json from RAW_DIR and shape into a unified list.
    Also compute overall status counts for the pie chart.
    """
    reports: List[Dict[str, Any]] = []
    status_counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "ERROR": 0, "UNKNOWN": 0}

    if not os.path.isdir(RAW_DIR):
        return reports, status_counts

    for fname in sorted(os.listdir(RAW_DIR)):
        if not fname.endswith("_report.json"):
            continue
        path = os.path.join(RAW_DIR, fname)
        data = safe_load_json(path)

        if "_parse_error" in data:
            check_name = display_name_from_file(fname)
            report = {
                "file": fname,
                "check_name": check_name,
                "status": "ERROR",
                "summary": f"parse_error: {data['_parse_error']}",
                "findings": [{"detail": f"Parse error for {fname}", "severity": "HIGH"}],
                "sev_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "raw_relpath": f"../raw/{fname}",
                "timestamp": None,
            }
            status_counts["ERROR"] += 1
            reports.append(report)
            continue

        # tolerant field extraction
        check_name = data.get("check_name") or display_name_from_file(fname)
        raw_status = data.get("status")
        status = normalize_status(raw_status)

        summary = data.get("summary", "")
        findings = coerce_findings(data.get("findings"))
        sev_counts = summarize_severities(findings)

        timestamp = data.get("timestamp") or data.get("time") or data.get("created_at")
        raw_relpath = f"../raw/{fname}"

        report = {
            "file": fname,
            "check_name": check_name,
            "status": status,
            "summary": summary,
            "findings": findings,
            "sev_counts": sev_counts,
            "raw_relpath": raw_relpath,
            "timestamp": timestamp,
        }

        status_counts[status] = status_counts.get(status, 0) + 1
        reports.append(report)

    return reports, status_counts


# -------------------------------
# Template (inline)
# -------------------------------
TEMPLATE_HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>OWASP Security Automation Report</title>
<link rel="preconnect" href="https://cdn.plot.ly">
<style>
  :root{
    --bg:#0f172a;           /* slate-900 */
    --panel:#111827;        /* gray-900 */
    --panel-2:#0b1220;      /* deep panel */
    --muted:#94a3b8;        /* slate-400 */
    --text:#e5e7eb;         /* gray-200 */
    --accent:#60a5fa;       /* blue-400 */
    --pass:#22c55e;         /* green-500 */
    --warn:#f59e0b;         /* amber-500 */
    --fail:#ef4444;         /* red-500 */
    --error:#a855f7;        /* violet-500 */
    --unknown:#9ca3af;      /* gray-400 */
    --border:#1f2937;       /* gray-800 */
    --chip:#1f2937;         /* gray-800 */
  }
  *{box-sizing:border-box}
  body{
    margin:0; background:linear-gradient(160deg,#0b1220 0%, #0f172a 40%, #0b1220 100%);
    color:var(--text); font:14px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;
    padding:24px;
  }
  .container{max-width:1200px; margin:0 auto;}
  header{display:flex; flex-wrap:wrap; gap:16px; align-items:center; justify-content:space-between; margin-bottom:16px;}
  .title h1{margin:0; font-size:22px; font-weight:700}
  .title .sub{color:var(--muted); font-size:12px}
  .toolbar{display:flex; gap:8px; flex-wrap:wrap}
  button.btn{
    background:var(--panel); color:var(--text);
    border:1px solid var(--border); padding:8px 12px; border-radius:10px;
    cursor:pointer; transition:all .15s;
  }
  button.btn:hover{transform:translateY(-1px); border-color:#334155}
  .grid{display:grid; grid-template-columns: 1fr 300px; gap:16px;}
  @media (max-width: 960px){ .grid{grid-template-columns:1fr} }

  .card{background:linear-gradient(160deg,var(--panel) 0%, var(--panel-2) 100%);
        border:1px solid var(--border); border-radius:14px; padding:14px;}

  /* Table */
  table{width:100%; border-collapse:separate; border-spacing:0; overflow:hidden;}
  thead th{
    text-align:left; font-size:12px; letter-spacing:.02em; color:var(--muted);
    padding:10px 10px; border-bottom:1px solid var(--border); background:transparent; position:sticky; top:0;
  }
  tbody td{padding:12px 10px; border-bottom:1px solid var(--border); vertical-align:top;}
  tr:hover td{background:rgba(148,163,184,.05)}
  .status{font-weight:700; padding:2px 8px; border-radius:999px; display:inline-block}
  .PASS{color:var(--pass); background:rgba(34,197,94,.1)}
  .WARN{color:var(--warn); background:rgba(245,158,11,.12)}
  .FAIL{color:var(--fail); background:rgba(239,68,68,.12)}
  .ERROR{color:var(--error); background:rgba(168,85,247,.12)}
  .UNKNOWN{color:var(--unknown); background:rgba(156,163,175,.12)}

  .sev {display:inline-flex; align-items:center; gap:6px; flex-wrap:wrap}
  .chip{
    font-size:11px; color:var(--text); background:var(--chip); border:1px solid var(--border);
    padding:2px 8px; border-radius:999px;
  }
  .chip.HIGH{border-color:rgba(239,68,68,.6); color:var(--fail)}
  .chip.MEDIUM{border-color:rgba(245,158,11,.6); color:var(--warn)}
  .chip.LOW{border-color:rgba(34,197,94,.6); color:var(--pass)}
  .chip.INFO{border-color:#334155; color:#cbd5e1}

  .link{color:#93c5fd; text-decoration:none}
  .link:hover{text-decoration:underline}

  /* Findings details */
  details{background:rgba(2,6,23,.35); border:1px solid var(--border); border-radius:10px; padding:10px; }
  details + details{margin-top:10px}
  summary{cursor:pointer; color:#c7d2fe; font-weight:600; outline:none}
  .finding{margin-top:8px; padding:10px; border:1px dashed #334155; border-radius:8px; background:rgba(15,23,42,.35)}
  .k{color:#94a3b8}
  pre{white-space:pre-wrap; margin:8px 0; color:#e2e8f0}
  .muted{color:var(--muted); font-size:12px}

  /* Sidebar card */
  .legend .row{display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px dashed #1f2937}
  .legend .row:last-child{border-bottom:0}

  footer{margin-top:14px; color:var(--muted); font-size:12px; text-align:center}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="title">
      <h1>OWASP Security Automation Report</h1>
      <div class="sub">Generated: {{ generated }}</div>
    </div>
    <div class="toolbar">
      <button class="btn" id="exportCsvBtn">Export CSV</button>
      <button class="btn" id="exportJsonBtn">Export JSON</button>
    </div>
  </header>

  <div class="grid">
    <!-- Main Table -->
    <section class="card">
      <table id="resultsTable">
        <thead>
          <tr>
            <th style="width:26%">Check</th>
            <th style="width:12%">Status</th>
            <th style="width:18%">Findings</th>
            <th style="width:30%">Summary</th>
            <th style="width:14%">Raw</th>
          </tr>
        </thead>
        <tbody>
          {% for r in reports %}
          <tr>
            <td>
              <div style="font-weight:600">{{ r.check_name }}</div>
              {% if r.timestamp %}
                <div class="muted">Run at: {{ r.timestamp }}</div>
              {% endif %}
              {% if r.findings and r.findings|length > 0 %}
                <details>
                  <summary>View Findings ({{ r.findings|length }})</summary>
                  {% for f in r.findings %}
                    <div class="finding">
                      {% if f.severity %}
                        <div class="chip {{ f.severity | upper }}">{{ f.severity | upper }}</div>
                      {% endif %}
                      {% if f.message %}
                        <div><span class="k">Message:</span> {{ f.message }}</div>
                      {% endif %}
                      {% if f.detail %}
                        <div><span class="k">Detail:</span> {{ f.detail }}</div>
                      {% endif %}
                      {% if f.issue %}
                        <div><span class="k">Issue:</span> {{ f.issue }}</div>
                      {% endif %}
                      {% if f.recommendation %}
                        <div><span class="k">Recommendation:</span> {{ f.recommendation }}</div>
                      {% endif %}
                      {% if f.expected %}
                        <div><span class="k">Expected:</span> {{ f.expected }}</div>
                      {% endif %}
                      {% if f.actual is defined %}
                        <div><span class="k">Actual:</span> {{ f.actual }}</div>
                      {% endif %}
                      {% if f.url %}
                        <div><span class="k">URL:</span> <a class="link" href="{{ f.url }}" target="_blank" rel="noopener">{{ f.url }}</a></div>
                      {% endif %}
                      {% if f.endpoint %}
                        <div><span class="k">Endpoint:</span> {{ f.endpoint }}</div>
                      {% endif %}
                      {% if f.params %}
                        <div><span class="k">Params:</span> <pre>{{ f.params | tojson(indent=2) }}</pre></div>
                      {% endif %}
                    </div>
                  {% endfor %}
                </details>
              {% endif %}
            </td>
            <td>
              <span class="status {{ r.status }}">{{ r.status }}</span>
            </td>
            <td>
              <div class="sev">
                <span class="chip HIGH">HIGH: {{ r.sev_counts.HIGH }}</span>
                <span class="chip MEDIUM">MED: {{ r.sev_counts.MEDIUM }}</span>
                <span class="chip LOW">LOW: {{ r.sev_counts.LOW }}</span>
                <span class="chip INFO">INFO: {{ r.sev_counts.INFO }}</span>
              </div>
            </td>
            <td>{{ r.summary }}</td>
            <td><a class="link" href="{{ r.raw_relpath }}" target="_blank" rel="noopener">View JSON</a></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>

    <!-- Sidebar: Pie + Legend -->
    <aside class="card">
      <div id="pie" style="height:280px;"></div>
      <div class="legend">
        <div class="row"><span>PASS</span><span>{{ status_counts.PASS }}</span></div>
        <div class="row"><span>WARN</span><span>{{ status_counts.WARN }}</span></div>
        <div class="row"><span>FAIL</span><span>{{ status_counts.FAIL }}</span></div>
        <div class="row"><span>ERROR</span><span>{{ status_counts.ERROR }}</span></div>
        <div class="row"><span>UNKNOWN</span><span>{{ status_counts.UNKNOWN }}</span></div>
      </div>
    </aside>
  </div>

  <footer>
    OWASP_Automation • {{ generated }}
  </footer>
</div>

<!-- Plotly Pie (via CDN) -->
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<script>
  // Data for pie chart from server
  const statusCounts = {{ status_counts | tojson }};
  const pieData = [{
    values: [statusCounts.PASS, statusCounts.WARN, statusCounts.FAIL, statusCounts.ERROR, statusCounts.UNKNOWN],
    labels: ['PASS', 'WARN', 'FAIL', 'ERROR', 'UNKNOWN'],
    type: 'pie',
    hole: .55,
    textinfo: 'label+value',
    marker: { colors: ['#22c55e','#f59e0b','#ef4444','#a855f7','#9ca3af'] }
  }];
  Plotly.newPlot('pie', pieData, {
    paper_bgcolor: 'rgba(0,0,0,0)',
    plot_bgcolor : 'rgba(0,0,0,0)',
    margin:{l:0,r:0,t:0,b:0},
    showlegend:false
  }, {displayModeBar:false});

  // Current table data for export (exactly what's rendered)
  const exported = {{ reports | tojson }};

  // Export CSV
  document.getElementById('exportCsvBtn').addEventListener('click', () => {
    const rows = [];
    rows.push(['Check','Status','High','Medium','Low','Info','Summary','Raw']);
    exported.forEach(r => {
      rows.push([
        r.check_name,
        r.status,
        r.sev_counts.HIGH || 0,
        r.sev_counts.MEDIUM || 0,
        r.sev_counts.LOW || 0,
        r.sev_counts.INFO || 0,
        (r.summary || '').replace(/\n+/g,' ').trim(),
        r.raw_relpath
      ]);
      // add each finding as sub-rows for clarity
      if (Array.isArray(r.findings)) {
        r.findings.forEach((f, idx) => {
          const sev = (f.severity || 'INFO').toUpperCase();
          const msg = f.message || f.issue || f.detail || '';
          rows.push([`  - Finding ${idx+1}`, sev, '', '', '', '', msg, '']);
        });
      }
    });
    const csv = rows.map(r => r.map(x => `"${String(x).replace(/"/g,'""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], {type:'text/csv;charset=utf-8;'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = "owasp_report.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // Export JSON (the same shaped data you see)
  document.getElementById('exportJsonBtn').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(exported, null, 2)], {type:'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = "owasp_report.json";
    a.click();
    URL.revokeObjectURL(a.href);
  });
</script>
</body>
</html>
"""


def render_html(reports: List[Dict[str, Any]], status_counts: Dict[str, int]) -> str:
    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(["html", "xml"])
    )
    template = env.from_string(TEMPLATE_HTML)
    html = template.render(
        reports=reports,
        status_counts=status_counts,
        generated=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%SZ"),
    )
    return html


def main():
    os.makedirs(AGG_DIR, exist_ok=True)
    reports, status_counts = collect_reports()
    html = render_html(reports, status_counts)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"✅ OWASP Dashboard generated successfully at: {OUT_FILE}")


if __name__ == "__main__":
    main()
