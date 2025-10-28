#!/usr/bin/env python3
"""
debug_mode_check.py
------------------------------------------------
OWASP Check: Verify that debug mode is disabled in production servers.

Enhanced version:
✅ Scans multiple endpoints (/, /login, /api, /admin, etc.)
✅ Detects debug headers and body leaks
✅ Reports per-endpoint results with severity levels
✅ Compatible with your existing reporting + HTML dashboard
"""

import os
import re
import json
import argparse
import datetime
import requests

# ------------------------------------------------------
# Known debug indicators (framework signatures)
# ------------------------------------------------------
DEBUG_PATTERNS = {
    "Flask": re.compile(r"werkzeug|flask debug|debugger pin", re.I),
    "Django": re.compile(r"technical details|django version|request information", re.I),
    "Laravel": re.compile(r"laravel|Whoops! There was an error", re.I),
    "ASP.NET": re.compile(r"stack trace|aspxerrorpath", re.I),
    "PHP": re.compile(r"Fatal error|Notice: Undefined|Warning:", re.I),
    "Node/Express": re.compile(r"expressjs|node\.js", re.I),
    "Generic": re.compile(r"traceback|exception in thread|error on line|500 Internal Server Error", re.I)
}


def check_debug_signatures(content):
    """Return list of framework patterns detected in response body."""
    findings = []
    for name, pattern in DEBUG_PATTERNS.items():
        if re.search(pattern, content):
            findings.append(f"{name} debug indicator detected in response body")
    return findings


def check_headers_for_debug(headers):
    """Check headers for debug keywords or dev banners."""
    findings = []
    for key, value in headers.items():
        if any(k in key.lower() for k in ["debug", "werkzeug", "trace"]):
            findings.append(f"Header {key}: {value}")
        elif any(v in str(value).lower() for v in ["debug", "werkzeug", "trace", "development"]):
            findings.append(f"Header {key}: {value}")
    return findings


def analyze_single_endpoint(base_url, endpoint):
    """Send request to a single endpoint and return findings."""
    full_url = base_url.rstrip("/") + endpoint
    entry = {"endpoint": full_url, "status_code": None, "findings": []}

    try:
        resp = requests.get(full_url, timeout=10)
        entry["status_code"] = resp.status_code

        # Skip if site unreachable
        if resp.status_code >= 500:
            entry["findings"].append({
                "message": f"Server returned {resp.status_code} error.",
                "severity": "Medium",
                "recommendation": "Ensure internal errors do not leak debug details."
            })
            return entry

        # Check headers + body
        header_issues = check_headers_for_debug(resp.headers)
        body_issues = check_debug_signatures(resp.text)

        for issue in header_issues:
            entry["findings"].append({
                "message": issue,
                "severity": "High",
                "recommendation": "Remove debug or diagnostic headers from production responses."
            })

        for issue in body_issues:
            entry["findings"].append({
                "message": issue,
                "severity": "High",
                "recommendation": "Disable debug mode and stack trace display."
            })

        if not entry["findings"]:
            entry["findings"].append({
                "message": "No debug indicators found.",
                "severity": "Low",
                "recommendation": "Debug mode appears safely disabled."
            })

    except requests.exceptions.RequestException as e:
        entry["findings"].append({
            "message": f"Connection error: {e}",
            "severity": "High",
            "recommendation": "Ensure endpoint is reachable and secured."
        })

    return entry


def analyze_debug_mode(base_url, endpoints, output_file):
    """Scan multiple endpoints and consolidate report."""
    results = {
        "check_name": "debug_mode_check",
        "status": "PASS",
        "timestamp": datetime.datetime.now().isoformat(),
        "summary": "",
        "findings": []
    }

    print(f"🔍 Checking debug mode across {len(endpoints)} endpoints for: {base_url}")

    all_findings = []
    fail_count = 0

    for ep in endpoints:
        endpoint_result = analyze_single_endpoint(base_url, ep)
        all_findings.append(endpoint_result)
        # escalate status if any high-severity issue
        if any(f["severity"] == "High" for f in endpoint_result["findings"]):
            fail_count += 1

    # Determine overall status
    if fail_count > 0:
        results["status"] = "FAIL"
        results["summary"] = f"Debug indicators found on {fail_count} of {len(endpoints)} endpoints."
    else:
        results["status"] = "PASS"
        results["summary"] = f"No debug indicators detected across {len(endpoints)} endpoints."

    results["findings"] = all_findings

    # Save JSON report
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"✅ Debug mode check completed. Report saved at: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OWASP Check: Debug Mode Disabled Verification (multi-endpoint)")
    parser.add_argument("--target", required=True, help="Base target URL (e.g. https://example.com)")
    parser.add_argument("--endpoints", nargs="*", default=["/", "/login", "/api", "/admin", "/debug", "/status"],
                        help="Endpoints to scan for debug indicators")
    args = parser.parse_args()

    analyze_debug_mode(args.target, args.endpoints, "reports/raw/debug_mode_report.json")
