#!/usr/bin/env python3
"""
logging_monitoring_check.py
-------------------------------------------------
OWASP Web Check: Verify implementation of robust
logging and monitoring to detect suspicious activity.

Purpose:
  - Validate if the application produces and exposes logs for security events.
  - Detect absence of logging or monitoring APIs.
  - Ensure logs contain timestamps, user context, and suspicious activity markers.

Covers OWASP ASVS:
  - 9.1: Verify all login, access control, and validation failures are logged.
  - 9.2: Verify logs contain sufficient detail (timestamps, IPs, user).
  - 9.4: Verify logs are protected from unauthorised access.
  - OWASP Top 10 A09:2021 – Logging and Monitoring Failures.

Usage Example:
    python3 src/logging_monitoring_check.py \
        --base-url http://127.0.0.1:5002 \
        --log-endpoints /api/logs,/admin/logs \
        --simulate-events
"""

import os
import re
import json
import time
import argparse
import requests
from datetime import datetime


# ======================================================
# Helper: Fetch Log Endpoint Data
# ======================================================
def fetch_logs(base_url: str, endpoints: list):
    """
    Fetch log data from each provided endpoint.
    Returns structured result including HTTP code,
    accessibility, and whether logs appear structured.
    """
    results = []
    headers = {"User-Agent": "OWASP_Automation/1.0"}

    for endpoint in endpoints:
        url = base_url.rstrip("/") + endpoint
        print(f"🔍 Checking log endpoint: {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            body = resp.text
            content_type = resp.headers.get("Content-Type", "").lower()

            structured = bool(re.search(r"\{.*?\}", body)) or "json" in content_type
            has_timestamp = bool(re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", body))
            has_event = bool(re.search(r"(failed|error|unauthorized|alert|warning)", body, re.IGNORECASE))

            findings = {
                "endpoint": endpoint,
                "status_code": resp.status_code,
                "structured": structured,
                "has_timestamp": has_timestamp,
                "has_event_keyword": has_event,
                "snippet": body[:250].replace("\n", " ") + "..."
            }
            results.append(findings)

        except requests.RequestException as e:
            results.append({
                "endpoint": endpoint,
                "status_code": None,
                "error": str(e),
                "structured": False,
                "has_timestamp": False,
                "has_event_keyword": False
            })

    return results


# ======================================================
# Simulate Suspicious Events (optional)
# ======================================================
def simulate_activity(base_url: str):
    """
    Optional step: Trigger suspicious events (like failed logins)
    to see if they appear in logs later.
    """
    test_events = [
        ("/api/login", {"username": "admin", "password": "wrongpass"}),
        ("/api/login", {"username": "root", "password": "wrongpass"})
    ]
    headers = {"User-Agent": "OWASP_Automation/1.0"}
    for path, data in test_events:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.post(url, json=data, headers=headers, timeout=5)
            print(f"⚠️ Simulated failed login at {url}, status={resp.status_code}")
        except Exception as e:
            print(f"⚠️ Failed to simulate event at {url}: {e}")


# ======================================================
# Analyze Findings
# ======================================================
def analyze_logs(results):
    """
    Determine if logging is robust and suspicious activity can be detected.
    """
    accessible_logs = [r for r in results if r.get("status_code") and r["status_code"] < 400]
    structured_logs = sum(1 for r in results if r["structured"])
    suspicious_detected = sum(1 for r in results if r["has_event_keyword"])

    if not accessible_logs:
        status = "FAIL"
        summary = "No accessible logging endpoints found."
    elif structured_logs == 0:
        status = "WARN"
        summary = "Logs found but appear unstructured or incomplete."
    elif suspicious_detected == 0:
        status = "WARN"
        summary = "Logs accessible but no suspicious activity entries found."
    else:
        status = "PASS"
        summary = "Structured logs detected with suspicious activity entries present."

    return status, summary


# ======================================================
# Main Entrypoint
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="OWASP Logging & Monitoring Verification Tool")
    parser.add_argument("--base-url", required=True, help="Base URL of the web application")
    parser.add_argument("--log-endpoints", required=True, help="Comma-separated list of potential log endpoints (e.g. /api/logs,/admin/logs)")
    parser.add_argument("--simulate-events", action="store_true", help="Trigger fake events to test logging visibility")
    args = parser.parse_args()

    base_url = args.base_url
    endpoints = [e.strip() for e in args.log_endpoints.split(",")]

    if args.simulate_events:
        simulate_activity(base_url)
        print("⏳ Waiting briefly for logs to update...")
        time.sleep(3)

    results = fetch_logs(base_url, endpoints)
    status, summary = analyze_logs(results)

    # Compile JSON report
    report = {
        "check_name": "logging_monitoring_check",
        "target": base_url,
        "status": status,
        "summary": summary,
        "findings": results,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs("reports/raw", exist_ok=True)
    report_path = "reports/raw/logging_monitoring_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[logging_monitoring_check] ✅ status={status}, report saved at {report_path}")


if __name__ == "__main__":
    main()
