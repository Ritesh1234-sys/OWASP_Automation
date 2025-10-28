#!/usr/bin/env python3
"""
login_throttling_check.py
-------------------------------------------------
OWASP Web Check: Verify implementation of throttling
on CMS or API login endpoints.

Purpose:
  - Detect absence or weakness of login throttling / rate limiting.
  - Identify whether multiple rapid login attempts are allowed.
  - Determine if server enforces 429, lockout, or delay after threshold.

Covers OWASP ASVS:
  - 2.8.2: Verify login attempts are rate limited.
  - 14.4.4: Verify performance and resource exhaustion protections.

Usage Example:
    python3 src/login_throttling_check.py \
        --target https://example.com/api/login \
        --username admin \
        --password wrongpass \
        --attempts 15 \
        --delay 0.3
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime


# ======================================================
# Helper: Perform Login Attempt
# ======================================================
def attempt_login(target, username, password, use_json, headers):
    """
    Send one login attempt to the target endpoint.

    Supports:
    - Form-based login (application/x-www-form-urlencoded)
    - JSON-based login (application/json)
    """
    try:
        if use_json:
            payload = {"username": username, "password": password}
            resp = requests.post(target, json=payload, headers=headers, timeout=10)
        else:
            payload = {"username": username, "password": password}
            resp = requests.post(target, data=payload, headers=headers, timeout=10)

        return {
            "status_code": resp.status_code,
            "latency": round(resp.elapsed.total_seconds(), 3),
            "text_snippet": resp.text[:200]
        }

    except requests.exceptions.RequestException as e:
        return {"status_code": None, "latency": None, "error": str(e)}


# ======================================================
# Core Throttling Logic
# ======================================================
def check_throttling(target, username, password, attempts, delay, use_json):
    """
    Run multiple consecutive login attempts and observe:
      - 429 Too Many Requests responses
      - Increasing latency per attempt
      - Connection drops or lockouts

    Classifies:
      - PASS: Throttling observed (429 or clear blocking)
      - WARN: Slight delay/soft throttling
      - FAIL: No throttling (all attempts accepted rapidly)
    """
    headers = {"User-Agent": "OWASP_Automation/1.0"}
    results = []

    print(f"🚀 Sending {attempts} login attempts to {target}...")

    for i in range(1, attempts + 1):
        result = attempt_login(target, username, password, use_json, headers)
        result["attempt"] = i
        results.append(result)

        print(f"  Attempt {i}: status={result.get('status_code')} latency={result.get('latency')}s")

        time.sleep(delay)

    # --------------------------------------------------
    # Analyze Results
    # --------------------------------------------------
    latencies = [r["latency"] for r in results if r.get("latency") is not None]
    status_codes = [r["status_code"] for r in results if r.get("status_code")]

    if not latencies:
        return "ERROR", "No responses received (endpoint unreachable).", results

    avg_latency = sum(latencies) / len(latencies)
    latency_trend = "increasing" if len(latencies) > 3 and latencies[-1] > latencies[0] * 1.5 else "stable"
    has_429 = any(code == 429 for code in status_codes)
    fail_codes = sum(1 for code in status_codes if code and code >= 500)

    # Determine throttling behaviour
    if has_429:
        status = "PASS"
        summary = f"Throttling enforced — received HTTP 429 after {len(status_codes)} attempts."
    elif latency_trend == "increasing" or fail_codes > 0:
        status = "WARN"
        summary = f"Potential soft throttling detected (latency trend={latency_trend}, failures={fail_codes})."
    else:
        status = "FAIL"
        summary = "No throttling observed — multiple login attempts allowed rapidly."

    return status, summary, results


# ======================================================
# JSON Report Generator
# ======================================================
def generate_report(target, username, status, summary, results):
    """
    Create structured JSON report with key metrics.
    """
    findings = []
    for r in results:
        entry = {
            "attempt": r["attempt"],
            "status_code": r.get("status_code"),
            "latency": r.get("latency"),
            "detail": r.get("error") or r.get("text_snippet"),
            "severity": (
                "HIGH" if status == "FAIL" else
                "MEDIUM" if status == "WARN" else
                "LOW"
            )
        }
        findings.append(entry)

    report = {
        "check_name": "login_throttling_check",
        "target": target,
        "username_tested": username,
        "status": status,
        "summary": summary,
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs("reports/raw", exist_ok=True)
    report_path = "reports/raw/login_throttling_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[login_throttling_check] ✅ status={status}, report saved at {report_path}")


# ======================================================
# Main Entrypoint
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="OWASP Login Throttling Checker")
    parser.add_argument("--target", required=True, help="Login endpoint URL")
    parser.add_argument("--username", required=True, help="Username to test")
    parser.add_argument("--password", required=True, help="Password to test (use invalid one)")
    parser.add_argument("--attempts", type=int, default=10, help="Number of consecutive attempts")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between attempts (seconds)")
    parser.add_argument("--use-json", action="store_true", help="Send credentials as JSON instead of form data")
    args = parser.parse_args()

    status, summary, results = check_throttling(
        target=args.target,
        username=args.username,
        password=args.password,
        attempts=args.attempts,
        delay=args.delay,
        use_json=args.use_json
    )
    generate_report(args.target, args.username, status, summary, results)


if __name__ == "__main__":
    main()
