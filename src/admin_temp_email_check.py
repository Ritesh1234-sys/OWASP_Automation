#!/usr/bin/env python3
"""
admin_temp_email_check.py
-------------------------------------------------
OWASP Web Check: Verify that admin accounts cannot
be created using temporary/disposable email addresses.

GOAL:
  • Ensure the application does not allow admin registrations
    using disposable or temporary email addresses.

OWASP ASVS Mapping:
  - V2.1.2: Verify that all email addresses are validated.
  - V4.1.3: Verify that administrative accounts cannot be created
             with untrusted or disposable email addresses.

OUTPUT:
  → JSON report saved to reports/raw/admin_temp_email_report.json
"""

import os
import json
import argparse
import requests
from datetime import datetime

# ================================================================
# 1️⃣  Known disposable domains
# ================================================================
# You can extend this list or even dynamically fetch from a GitHub source.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "guerrillamail.com", "10minutemail.com",
    "trashmail.com", "yopmail.com", "getnada.com", "tempinbox.com",
    "dispostable.com", "fakeinbox.com", "maildrop.cc"
}


# ================================================================
# 2️⃣  Utility helpers
# ================================================================
def is_disposable(email: str) -> bool:
    """Check if an email belongs to a known disposable domain."""
    try:
        domain = email.split("@")[1].lower().strip()
        return domain in DISPOSABLE_DOMAINS
    except Exception:
        return False


def add_finding(findings, issue, severity, detail, evidence=None):
    """Append a structured finding to the report list."""
    findings.append({
        "issue": issue,
        "severity": severity,
        "detail": detail,
        "evidence": evidence or {}
    })


def classify_overall(findings):
    """
    Determine overall test status with robust fallback logic.
    - FAIL  → If any HIGH severity issues exist
    - WARN  → If any MEDIUM issues or partial failures
    - UNKNOWN → If every request failed
    - PASS  → All fine or only INFO findings
    """
    if not findings:
        return "UNKNOWN"

    severities = {f["severity"] for f in findings}
    total = len(findings)
    errors = sum(1 for f in findings if f["issue"] == "request_error")

    if "HIGH" in severities:
        return "FAIL"
    if "MEDIUM" in severities:
        return "WARN"
    if errors == total:
        return "UNKNOWN"
    if errors > 0:
        return "WARN"
    return "PASS"


# ================================================================
# 3️⃣  Core test logic
# ================================================================
def test_admin_creation(target_url, emails, field_name="email"):
    """
    Run the actual validation logic.
    For each email:
      - Send a POST to admin registration endpoint.
      - Detect if disposable domains are improperly accepted.
    """
    findings = []
    session = requests.Session()
    headers = {"User-Agent": "OWASP_Automation/1.0"}

    for email in emails:
        disposable = is_disposable(email)
        payload = {field_name: email}

        try:
            # Perform POST request to the registration endpoint
            response = session.post(target_url, data=payload, headers=headers, timeout=10)
            status = response.status_code
            body = response.text.lower() if response.text else ""

            # CASE 1: Disposable accepted → High risk
            if disposable and 200 <= status < 300:
                add_finding(
                    findings,
                    "disposable_email_accepted",
                    "HIGH",
                    f"Disposable email '{email}' was accepted (HTTP {status}).",
                    {"email": email, "status": status}
                )

            # CASE 2: Disposable email not clearly rejected → Potential medium issue
            elif disposable and ("invalid" not in body and "not allowed" not in body and status < 400):
                add_finding(
                    findings,
                    "weak_disposable_validation",
                    "MEDIUM",
                    f"Disposable email '{email}' may not be properly validated (status={status}).",
                    {"email": email, "status": status, "body_snippet": body[:120]}
                )

            # CASE 3: Valid email rejected → low false-positive issue
            elif not disposable and 400 <= status < 500:
                add_finding(
                    findings,
                    "false_rejection_valid_email",
                    "LOW",
                    f"Valid email '{email}' was rejected (HTTP {status}).",
                    {"email": email, "status": status}
                )

            # CASE 4: Everything handled properly
            else:
                add_finding(
                    findings,
                    "email_validation_passed",
                    "INFO",
                    f"Email '{email}' handled appropriately (HTTP {status}).",
                    {"email": email, "status": status}
                )

        except Exception as e:
            # Network / server issues get logged as WARN
            add_finding(
                findings,
                "request_error",
                "WARN",
                f"Could not connect to {target_url} for '{email}'. Server may be unreachable.",
                {"email": email, "error": str(e)}
            )

    return findings


# ================================================================
# 4️⃣  Main Entry Point
# ================================================================
def main():
    parser = argparse.ArgumentParser(
        description="OWASP: Verify that admin accounts cannot use temporary email domains."
    )
    parser.add_argument("--target", required=True, help="Target admin registration endpoint URL.")
    parser.add_argument("--emails-file", required=True, help="File with test email addresses.")
    parser.add_argument("--field-name", default="email", help="Email field name in the form (default: email).")
    args = parser.parse_args()

    target = args.target.strip()
    emails_path = args.emails_file

    # Load test emails
    if not os.path.exists(emails_path):
        print(f"❌ Test emails file not found: {emails_path}")
        return

    with open(emails_path, "r", encoding="utf-8") as f:
        emails = [line.strip() for line in f if line.strip()]

    print(f"🔍 Running admin temporary email validation on {target}")
    print(f"📧 Loaded {len(emails)} test emails")

    # Run the main checks
    findings = test_admin_creation(target, emails, field_name=args.field_name)
    status = classify_overall(findings)

    # Summarize counts by severity
    summary_counts = {lvl: sum(1 for f in findings if f["severity"] == lvl)
                      for lvl in ["HIGH", "MEDIUM", "LOW", "WARN", "INFO"]}
    summary_text = ", ".join([f"{lvl}: {count}" for lvl, count in summary_counts.items() if count > 0]) or "No findings."

    # Build final report
    report = {
        "check_name": "admin_temp_email_check",
        "target": target,
        "status": status,
        "summary": f"{summary_text}",
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs("reports/raw", exist_ok=True)
    out_path = "reports/raw/admin_temp_email_report.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[admin_temp_email_check] ✅ status={status}, findings={len(findings)}, saved: {out_path}")


if __name__ == "__main__":
    main()
