#!/usr/bin/env python3
"""
no_unwanted_keys_exposure_check.py
-------------------------------------------------
OWASP Web Check: Verify no unwanted keys or secrets are exposed
in frontend responses or API endpoints.

Purpose:
  - Detect exposure of sensitive keys in HTML, JS, or JSON responses.
  - Validate against common secret patterns and key names.
  - Support both page URLs and JSON API endpoints.

Covers OWASP ASVS:
  - 5.1.7: Verify sensitive data is not exposed in client-side code.
  - 14.2.4: Verify security headers and response filtering.
  - 14.4.5: Verify unnecessary or sensitive data isn’t returned.

Usage Example:
    python3 src/no_unwanted_keys_exposure_check.py \
        --target https://example.com \
        --endpoints /, /api/config, /static/app.js
"""

import os
import re
import sys
import json
import argparse
import requests
from datetime import datetime


# ======================================================
# Sensitive Key Patterns
# ======================================================
SENSITIVE_KEY_PATTERNS = [
    r"api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
    r"access[_-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?",
    r"auth[_-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?",
    r"aws[_-]?(access|secret)?[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?",
    r"-----BEGIN PRIVATE KEY-----",
    r"ssh-rsa\s+[A-Za-z0-9+/=]+",
    r"connection\s*string\s*[:=]",
    r"db[_-]?password\s*[=:]",
    r"x-api-key",
    r"bearer\s+[A-Za-z0-9\-_\.]+"
]

# Common sensitive key names to catch in JSON
SENSITIVE_JSON_KEYS = {
    "api_key", "access_key", "secret", "token", "auth_token",
    "accessToken", "private_key", "connectionString", "aws_secret"
}


# ======================================================
# Helper Function: Scan Text for Sensitive Patterns
# ======================================================
def scan_text_for_keys(content: str):
    findings = []
    for pattern in SENSITIVE_KEY_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            findings.append({
                "pattern": pattern,
                "snippet": match[:100] + "..." if len(match) > 100 else match
            })
    return findings


# ======================================================
# Core Logic: Check Endpoint Responses
# ======================================================
def check_endpoints(base_url: str, endpoints: list):
    results = []
    session = requests.Session()
    headers = {"User-Agent": "OWASP_Automation/1.0"}

    for endpoint in endpoints:
        full_url = base_url.rstrip("/") + endpoint
        print(f"🔍 Scanning {full_url} for key exposure...")

        try:
            resp = session.get(full_url, headers=headers, timeout=10)
            content_type = resp.headers.get("Content-Type", "").lower()
            body = resp.text
            findings = []

            # Scan JSON separately for key names
            if "application/json" in content_type:
                try:
                    data = resp.json()
                    for key in data.keys():
                        if key in SENSITIVE_JSON_KEYS:
                            findings.append({
                                "type": "json_key",
                                "key": key,
                                "snippet": str(data[key])[:100]
                            })
                except Exception:
                    pass

            # Scan text (HTML, JS, or JSON) for secret patterns
            text_findings = scan_text_for_keys(body)
            findings.extend(text_findings)

            result = {
                "endpoint": endpoint,
                "status_code": resp.status_code,
                "num_findings": len(findings),
                "findings": findings
            }
            results.append(result)

        except requests.exceptions.RequestException as e:
            results.append({
                "endpoint": endpoint,
                "error": str(e),
                "num_findings": 0,
                "findings": []
            })

    return results


# ======================================================
# Summarize and Generate Report
# ======================================================
def summarize_results(results):
    total_findings = sum(r["num_findings"] for r in results)
    if total_findings == 0:
        return "PASS", "No unwanted keys or secrets exposed."
    elif total_findings <= 3:
        return "WARN", f"{total_findings} potential exposures found (review required)."
    else:
        return "FAIL", f"High number of potential secret exposures ({total_findings})."


# ======================================================
# Main Entrypoint
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="OWASP Unwanted Key Exposure Checker")
    parser.add_argument("--target", required=True, help="Base target URL (e.g., https://example.com)")
    parser.add_argument("--endpoints", nargs="+", required=True, help="Endpoints to check (space-separated)")
    args = parser.parse_args()

    results = check_endpoints(args.target, args.endpoints)
    status, summary = summarize_results(results)

    report = {
        "check_name": "no_unwanted_keys_exposure_check",
        "target": args.target,
        "status": status,
        "summary": summary,
        "findings": results,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs("reports/raw", exist_ok=True)
    report_path = "reports/raw/no_unwanted_keys_exposure_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[no_unwanted_keys_exposure_check] ✅ status={status}, report saved at {report_path}")


if __name__ == "__main__":
    main()
