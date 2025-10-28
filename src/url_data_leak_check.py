#!/usr/bin/env python3
"""
url_data_leak_check.py
---------------------------------------------------------
OWASP Check: Verify critical information is not shared through the URL.

Purpose:
  - Detect sensitive data in query parameters or fragments
  - Identify tokens, passwords, API keys, PII in URLs
  - Works on static URLs or those dynamically loaded from HTML or API responses

OWASP Reference:
  - ASVS 5.3.2, 10.4.1 – Sensitive data must not be transmitted via URLs

Usage Example:
  python3 src/url_data_leak_check.py \
      --target https://example.com/dashboard \
      --max-depth 2 \
      --sensitive-keys password,token,apikey,auth,session,email

Output:
  - JSON report saved at reports/raw/url_data_leak_report.json
"""

import os
import re
import json
import time
import argparse
import urllib.parse
import requests
from bs4 import BeautifulSoup
from datetime import datetime


# ======================================================
# 🔍 Sensitive Key Patterns
# ======================================================
DEFAULT_SENSITIVE_KEYS = [
    "password", "passwd", "pwd", "secret", "token",
    "auth", "session", "jwt", "api_key", "key",
    "creditcard", "email", "ssn", "dob"
]


# ======================================================
# 🧠 Helper: Detect sensitive data in a URL
# ======================================================
def detect_sensitive_data_in_url(url: str, sensitive_keys=None):
    """
    Parse the given URL and return a list of suspicious parameters.
    """
    sensitive_keys = sensitive_keys or DEFAULT_SENSITIVE_KEYS
    findings = []

    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    for key, values in query.items():
        for s_key in sensitive_keys:
            if s_key.lower() in key.lower():
                findings.append({
                    "parameter": key,
                    "value": values,
                    "issue": f"Possible sensitive data in query string (key '{key}')"
                })
    return findings


# ======================================================
# 🧩 Helper: Extract all links from an HTML page
# ======================================================
def extract_links(html_content, base_url):
    soup = BeautifulSoup(html_content, "html.parser")
    links = []
    for tag in soup.find_all(["a", "link", "script", "iframe", "img", "form"]):
        attr = "href" if tag.name != "form" else "action"
        url = tag.get(attr)
        if not url:
            continue
        full_url = urllib.parse.urljoin(base_url, url)
        links.append(full_url)
    return list(set(links))


# ======================================================
# ⚙️ Core Scan Function
# ======================================================
def scan_url_for_data_leak(base_url, max_depth, sensitive_keys):
    """
    Recursively crawl a limited number of pages and inspect URLs for sensitive data.
    """
    visited = set()
    to_visit = [base_url]
    findings = []

    session = requests.Session()
    session.headers.update({"User-Agent": "OWASP_Automation/URLLeakChecker/1.0"})

    for depth in range(max_depth):
        new_links = []
        for url in list(to_visit):
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = session.get(url, timeout=10)
                # Analyze this URL itself
                url_findings = detect_sensitive_data_in_url(url, sensitive_keys)
                if url_findings:
                    findings.extend([{
                        "source": url,
                        "type": "url_param",
                        "details": f"{len(url_findings)} suspicious query parameters found.",
                        "examples": url_findings
                    }])

                # Analyze potential redirects
                if resp.history:
                    for hist in resp.history:
                        hist_findings = detect_sensitive_data_in_url(hist.url, sensitive_keys)
                        if hist_findings:
                            findings.extend([{
                                "source": hist.url,
                                "type": "redirect_url",
                                "details": "Sensitive data found in redirect URL.",
                                "examples": hist_findings
                            }])

                # Extract and analyze embedded links
                if "text/html" in resp.headers.get("Content-Type", ""):
                    child_links = extract_links(resp.text, url)
                    for child in child_links:
                        f = detect_sensitive_data_in_url(child, sensitive_keys)
                        if f:
                            findings.extend([{
                                "source": url,
                                "type": "embedded_link",
                                "details": f"Sensitive data in embedded URL: {child}",
                                "examples": f
                            }])
                    new_links.extend(child_links)
            except Exception as e:
                findings.append({
                    "source": url,
                    "type": "error",
                    "details": f"Error fetching URL: {e}"
                })
        to_visit = [link for link in new_links if link not in visited]
        time.sleep(1)  # respectful crawling delay

    return findings


# ======================================================
# 📊 Summarize & Save Report
# ======================================================
def summarize_findings(findings):
    """
    Derive a status from findings:
      - PASS = no issues
      - WARN = found suspicious URLs but not critical
      - FAIL = found clear sensitive data indicators
    """
    if not findings:
        return "PASS", "No sensitive data found in URLs."

    # Count criticals
    critical_count = sum(1 for f in findings if "password" in json.dumps(f).lower() or "token" in json.dumps(f).lower())
    if critical_count > 0:
        return "FAIL", f"{critical_count} URLs contain potential critical data exposure."
    return "WARN", f"{len(findings)} URLs contain parameters that may hold sensitive data."


# ======================================================
# 🚀 Main Entrypoint
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="OWASP - Verify critical information not shared in URL.")
    parser.add_argument("--target", required=True, help="Base URL of the application (e.g. https://example.com)")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth (default=2)")
    parser.add_argument("--sensitive-keys", default=",".join(DEFAULT_SENSITIVE_KEYS),
                        help="Comma-separated list of sensitive keys to look for.")
    parser.add_argument("--report-path", default="reports/raw/url_data_leak_report.json",
                        help="Where to save the report.")
    args = parser.parse_args()

    sensitive_keys = [x.strip().lower() for x in args.sensitive_keys.split(",") if x.strip()]
    print(f"🔍 Scanning {args.target} for URL data leaks...")

    findings = scan_url_for_data_leak(args.target, args.max_depth, sensitive_keys)
    status, summary = summarize_findings(findings)

    report = {
        "check_name": "url_data_leak_check",
        "target": args.target,
        "status": status,
        "summary": summary,
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs(os.path.dirname(args.report_path), exist_ok=True)
    with open(args.report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[url_data_leak_check] ✅ status={status}, report saved at {args.report_path}")


if __name__ == "__main__":
    main()
