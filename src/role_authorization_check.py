#!/usr/bin/env python3
"""
role_authorization_check.py

Purpose:
  - Programmatically verify that roles cannot access endpoints/features
    they are not authorized for (RBAC checks).
  - Designed to integrate with the existing OWASP automation framework:
    - Reads role credentials from `data/roles.json`
    - Reads endpoints and allowed_roles from `data/restricted_endpoints.json`
    - Writes a JSON report to `reports/raw/role_authorization_report.json`

Features:
  - Supports Bearer token (Authorization header) and cookie-based auth.
  - Supports GET/POST/PUT/DELETE (method per endpoint entry).
  - Tolerant to relative endpoints (prepends role's base_url).
  - Produces a clear JSON report with `status`, `summary`, `findings`, `timestamp`.

Usage (example):
  python3 src/role_authorization_check.py \
    --roles-file data/roles.json \
    --restricted-file data/restricted_endpoints.json
"""

import argparse
import json
import os
import sys
import requests
from datetime import datetime, timezone

# Default output path for this check's report
OUT_PATH = "reports/raw/role_authorization_report.json"
TIMEOUT = 10  # seconds for HTTP requests


def load_json(path):
    """Read JSON from file and return parsed object (or raise)."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_full_url(base_url, endpoint):
    """
    Combine a base URL and an endpoint which may be an absolute URL or a relative path.
    Examples:
      base_url="http://127.0.0.1:5002", endpoint="/admin"
      => "http://127.0.0.1:5002/admin"

      endpoint can also be "https://api.example.com/admin" and will be returned as-is.
    """
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    # Ensure base_url does not end with slash to avoid double-slash
    return base_url.rstrip("/") + "/" + endpoint.lstrip("/")


def prepare_request_headers(role_creds):
    """
    Build headers for a role:
      - If role_creds contains 'token', use Authorization: Bearer <token>
      - If role_creds contains 'extra_headers' (dict), include them too
    """
    headers = {}
    token = role_creds.get("token") or role_creds.get("access_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    extra = role_creds.get("extra_headers") or {}
    if isinstance(extra, dict):
        headers.update(extra)
    return headers


def prepare_request_cookies(role_creds):
    """
    Build cookies dict if role_creds has cookie-based auth (e.g., 'cookie_name' / 'cookie_value'
    or 'cookies' dict). Returns dict suitable for `requests`.
    """
    if "cookies" in role_creds and isinstance(role_creds["cookies"], dict):
        return role_creds["cookies"]
    # legacy fields: cookie_name + cookie_value
    if role_creds.get("cookie_name") and role_creds.get("cookie_value"):
        return {role_creds["cookie_name"]: role_creds["cookie_value"]}
    return {}


def call_endpoint(method, url, headers=None, cookies=None, data=None, json_body=None):
    """
    Perform the HTTP request using `requests`. Returns a dict with:
      - status_code (int) if request succeeded
      - text (str) response body (first 800 chars)
      - elapsed (float) seconds
    On exceptions, returns dict with 'error' key.
    """
    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            cookies=cookies or {},
            data=data,
            json=json_body,
            timeout=TIMEOUT,
        )
        return {
            "status_code": resp.status_code,
            "text": resp.text[:800],
            "elapsed": resp.elapsed.total_seconds(),
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {"error": str(e)}


def is_accessible(response_info):
    """
    Decide whether a response indicates 'access' (i.e., the role could reach the endpoint).
    We consider HTTP 2xx and 3xx as accessible. Adjust as needed.
    """
    if "error" in response_info:
        return False
    sc = response_info.get("status_code", 0)
    return 200 <= sc < 400


def run_checks(roles, restricted):
    """
    Main runner:
      - roles: dict mapping role_name -> role_creds
      - restricted: list of restriction entries (endpoint, allowed_roles, optional method, payload)
    Returns:
      - results: list of individual attempt records
      - findings: list of detected violations (strings/dicts)
    """
    results = []
    findings = []
    vulnerable = False

    # Build a flat list of endpoints from `restricted`
    for rule in restricted:
        endpoint = rule.get("endpoint")
        allowed_roles = rule.get("allowed_roles", [])
        method = rule.get("method", "GET").upper()
        # Optional payloads for POST/PUT
        payload = rule.get("payload")
        json_body = rule.get("json")

        for role_name, role_creds in roles.items():
            base_url = role_creds.get("base_url", "").strip() or ""
            url = build_full_url(base_url, endpoint) if base_url else endpoint
            headers = prepare_request_headers(role_creds)
            cookies = prepare_request_cookies(role_creds)

            # Perform the request
            resp_info = call_endpoint(method, url, headers=headers, cookies=cookies, data=payload, json_body=json_body)

            accessible = is_accessible(resp_info)

            # Record attempt
            rec = {
                "role": role_name,
                "endpoint": endpoint,
                "full_url": url,
                "method": method,
                "status_code": resp_info.get("status_code") if "status_code" in resp_info else None,
                "accessible": accessible,
                "error": resp_info.get("error", ""),
                "elapsed": resp_info.get("elapsed", None),
            }
            results.append(rec)

            # If role is NOT allowed but endpoint is accessible -> violation
            if role_name not in allowed_roles and accessible:
                vulnerable = True
                findings.append({
                    "type": "Access Control Violation",
                    "role": role_name,
                    "endpoint": endpoint,
                    "full_url": url,
                    "method": method,
                    "status_code": resp_info.get("status_code"),
                    "detail": f"Role '{role_name}' accessed restricted endpoint '{endpoint}' ({method}) with HTTP {resp_info.get('status_code')}"
                })

    status = "VULNERABLE" if vulnerable else "SECURE"
    return results, findings, status


def write_report(results, findings, status, summary):
    """Write the normalized report JSON to OUT_PATH."""
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    report = {
        "check_name": "role_authorization_check",
        "status": status,
        "summary": summary,
        "findings": findings,
        "attempts": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"✅ Report written to: {OUT_PATH}")


def parse_args():
    p = argparse.ArgumentParser(description="Role authorization (RBAC) check")
    p.add_argument("--roles-file", required=True, help="JSON file with role credentials (data/roles.json)")
    p.add_argument("--restricted-file", required=True, help="JSON file with restricted endpoints (data/restricted_endpoints.json)")
    return p.parse_args()


def main():
    args = parse_args()

    try:
        roles = load_json(args.roles_file)
    except Exception as e:
        print(f"❌ Failed to read roles file: {e}")
        sys.exit(1)

    try:
        restricted = load_json(args.restricted_file)
    except Exception as e:
        print(f"❌ Failed to read restricted file: {e}")
        sys.exit(1)

    # Informative message
    print(f"🔍 Running RBAC tests: {len(roles)} roles x {len(restricted)} endpoints...")

    # Run the tests
    results, findings, status = run_checks(roles, restricted)

    # Short summary text (human readable)
    if status == "VULNERABLE":
        summary = f"Access control violations detected: {len(findings)}"
    else:
        summary = "No unauthorized access detected."

    # Write report
    write_report(results, findings, status, summary)

    # Print quick console summary
    print(f"[role_authorization_check] status={status} findings={len(findings)} attempts={len(results)}")


if __name__ == "__main__":
    main()
