#!/usr/bin/env python3
"""
response_data_scanner.py - Detect sensitive data exposure in HTTP responses

Purpose:
  - Send a request to a target URL.
  - Inspect response body and headers for potential leaks of sensitive data
    such as passwords, API keys, access tokens, JWTs, credit card numbers, or emails.
  - Complements cookie_scanner.py for full coverage of OWASP Sensitive Data Exposure.

Usage:
  python3 src/response_data_scanner.py --target http://127.0.0.1:5002/set_cookies_demo
Output:
  reports/raw/response_data_report.json
"""

import re
import requests
import json
import argparse
import os

# Define simple regex patterns to look for sensitive information
PATTERNS = {
    "email": re.compile(r"[\w\.-]+@[\w\.-]+\.\w+"),
    "api_key": re.compile(r"(?i)(api[_-]?key|x-api-key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]?"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "access_token": re.compile(r"(?i)(access[_-]?token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{10,}['\"]?"),
    "password": re.compile(r"(?i)(password|pwd)['\"]?\s*[:=]\s*['\"][^'\"<>]{4,}['\"]?"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
}

parser = argparse.ArgumentParser(description="Scan responses for sensitive data exposure.")
parser.add_argument("--target", required=True, help="URL to scan (e.g. http://127.0.0.1:5002/)")
args = parser.parse_args()

TARGET = args.target

def scan_response(url):
    """Fetch URL and inspect body and headers for sensitive data patterns."""
    print(f"Scanning response of {url} ...")

    try:
        r = requests.get(url, timeout=10)
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        return {"url": url, "error": str(e)}

    findings = []
    body = r.text
    headers = " ".join(f"{k}: {v}" for k, v in r.headers.items())

    # Search both body and headers
    combined_text = headers + "\n" + body

    for name, pattern in PATTERNS.items():
        matches = pattern.findall(combined_text)
        if matches:
            findings.append({
                "pattern": name,
                "count": len(matches),
                "examples": matches[:3]  # limit to 3 examples
            })

    result = {
        "url": url,
        "status": r.status_code,
        "content_length": len(body),
        "findings": findings
    }
    return result

if __name__ == "__main__":
    report = scan_response(TARGET)
    os.makedirs("reports/raw", exist_ok=True)
    with open("reports/raw/response_data_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("✅ Scan complete. Report saved at reports/raw/response_data_report.json")
