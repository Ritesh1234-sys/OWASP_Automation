#!/usr/bin/env python3
"""
subdomain_enumeration_check.py
-------------------------------------------------
OWASP Web Check: Verify available subdomains.

GOAL:
  • Identify public or internal subdomains for the given domain.
  • Detect potentially sensitive, forgotten, or misconfigured ones.
  • Ensure that only legitimate subdomains are accessible.

Covers OWASP ASVS:
  - V1.2.4: Verify that the system minimizes exposed endpoints.
  - V14.1.2: Verify that staging/test environments are not publicly accessible.

OUTPUT:
  → JSON report: reports/raw/subdomain_enumeration_report.json
"""

import os
import json
import argparse
import socket
import dns.resolver
import requests
from datetime import datetime

# ================================================================
# 1️⃣ Common subdomain wordlist
# ================================================================
# This list can be extended or loaded from a file in data/subdomains.txt
COMMON_SUBDOMAINS = [
    "www", "api", "admin", "portal", "dev", "stage", "staging", "test", "uat",
    "mail", "ftp", "beta", "dashboard", "cms", "internal", "app", "secure",
    "api-dev", "sandbox", "old", "backup"
]

# ================================================================
# 2️⃣ Utility functions
# ================================================================
def resolve_subdomain(domain: str, dns_servers=None):
    """
    Attempt to resolve a subdomain using custom or default DNS servers.
    Returns: (resolved_ip, status)
    """
    resolver = dns.resolver.Resolver()
    if dns_servers:
        resolver.nameservers = dns_servers

    try:
        answer = resolver.resolve(domain, "A")
        return str(answer[0]), "RESOLVED"
    except dns.resolver.NXDOMAIN:
        return None, "NOT_FOUND"
    except dns.resolver.Timeout:
        return None, "TIMEOUT"
    except Exception as e:
        return None, f"ERROR: {e}"


def check_http_status(url: str):
    """Send a HEAD request to check HTTP reachability of the subdomain."""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code
    except requests.exceptions.SSLError:
        return "SSL_ERROR"
    except requests.exceptions.ConnectionError:
        return "CONN_ERROR"
    except Exception:
        return "UNKNOWN"


def classify_severity(subdomain, ip, status_code):
    """
    Assign a severity based on what was found.
      - High: Exposed staging/test/internal domains.
      - Medium: Accessible subdomains that respond unexpectedly.
      - Info: Normal subdomains (e.g., www/api).
    """
    lower = subdomain.lower()
    if any(x in lower for x in ["stage", "test", "dev", "uat", "backup", "old", "internal"]):
        return "HIGH"
    if isinstance(status_code, int) and (200 <= status_code < 400):
        return "MEDIUM"
    return "INFO"


# ================================================================
# 3️⃣ Core logic
# ================================================================
def enumerate_subdomains(target_domain, dns_servers=None):
    """
    Enumerate potential subdomains for a given domain.
    - Resolves DNS.
    - Checks HTTP reachability.
    - Categorizes findings.
    """
    findings = []
    dns_servers_list = dns_servers.split(",") if dns_servers else None

    print(f"🔍 Starting subdomain enumeration for {target_domain}")
    print(f"🧭 Using {len(COMMON_SUBDOMAINS)} common subdomain prefixes")

    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{target_domain}"
        ip, dns_status = resolve_subdomain(fqdn, dns_servers_list)

        if dns_status != "RESOLVED":
            continue  # skip unresolvable ones

        for protocol in ["https", "http"]:
            url = f"{protocol}://{fqdn}"
            status_code = check_http_status(url)
            severity = classify_severity(fqdn, ip, status_code)

            findings.append({
                "subdomain": fqdn,
                "ip": ip,
                "protocol": protocol,
                "status_code": status_code,
                "severity": severity,
                "detail": f"Subdomain reachable ({protocol.upper()} {status_code})"
                           if isinstance(status_code, int)
                           else f"Connection error ({status_code})"
            })

    return findings


# ================================================================
# 4️⃣ Summarization helper
# ================================================================
def summarize(findings):
    """Compute summary and final status."""
    if not findings:
        return "PASS", "No accessible subdomains detected."

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    med = sum(1 for f in findings if f["severity"] == "MEDIUM")

    if high > 0:
        status = "FAIL"
        summary = f"{high} high-risk subdomains detected."
    elif med > 0:
        status = "WARN"
        summary = f"{med} medium-risk subdomains detected."
    else:
        status = "PASS"
        summary = "All subdomains are safe or expected."

    return status, summary


# ================================================================
# 5️⃣ Main entry point
# ================================================================
def main():
    parser = argparse.ArgumentParser(description="OWASP: Verify available subdomains")
    parser.add_argument("--target-domain", required=True, help="Primary domain to check (e.g., example.com)")
    parser.add_argument("--dns-servers", help="Comma-separated list of DNS servers (optional)")
    args = parser.parse_args()

    domain = args.target_domain.strip()

    # Perform enumeration
    findings = enumerate_subdomains(domain, args.dns_servers)
    status, summary = summarize(findings)

    # Build JSON report
    report = {
        "check_name": "subdomain_enumeration_check",
        "target_domain": domain,
        "status": status,
        "summary": summary,
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs("reports/raw", exist_ok=True)
    out_path = "reports/raw/subdomain_enumeration_report.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[subdomain_enumeration_check] ✅ status={status}, findings={len(findings)}, saved: {out_path}")


if __name__ == "__main__":
    main()
