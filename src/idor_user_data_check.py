#!/usr/bin/env python3
"""
idor_user_data_check.py

Purpose:
  - Verify that authenticated users cannot access another user's private data.
  - Detects IDOR / broken object-level authorization where user A can access user B's resources.
  - Integrates with existing framework: reads users from data/users.json,
    reads endpoints to test from data/idor_endpoints.json, writes a JSON report
    to reports/raw/idor_user_data_report.json

High-level algorithm:
  - Load list of user accounts (each with an ID and authentication token or cookies).
  - For each endpoint pattern (e.g. /api/users/{user_id}/profile), substitute a "target" user_id
    (victim) and attempt to access it with each *other* user credentials.
  - If a user other than the owner gets a 2xx or 3xx response, that's a potential IDOR.
  - Record attempts and findings, write structured JSON report.

Notes:
  - Supports Bearer tokens (Authorization header) and cookie-based auth.
  - Supports GET/POST/PUT/DELETE and optional json/payload for POST/PUT.
  - Timeout and heuristics are conservative; tune TIMEOUT if required.
"""

import argparse
import json
import os
import sys
import requests
from datetime import datetime, timezone

OUT_PATH = "reports/raw/idor_user_data_report.json"
TIMEOUT = 12  # seconds per request


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_url(base_url, endpoint_pattern, user_id_value):
    """
    Replace placeholder {user_id} in endpoint_pattern with user_id_value.
    If endpoint_pattern is absolute URL, still substitute.
    Example:
       base_url = "http://127.0.0.1:5002"
       endpoint_pattern = "/api/users/{user_id}/profile"
       user_id_value = "alice123"
    -> "http://127.0.0.1:5002/api/users/alice123/profile"
    """
    endpoint = endpoint_pattern.replace("{user_id}", str(user_id_value))
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    if not base_url:
        return endpoint
    return base_url.rstrip("/") + "/" + endpoint.lstrip("/")


def prepare_headers(user):
    """Return headers for user credentials (Bearer token + any extras)."""
    headers = {}
    token = user.get("token") or user.get("access_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    extra = user.get("extra_headers") or {}
    if isinstance(extra, dict):
        headers.update(extra)
    return headers


def prepare_cookies(user):
    """Return cookies dict for user if provided."""
    if "cookies" in user and isinstance(user["cookies"], dict):
        return user["cookies"]
    if user.get("cookie_name") and user.get("cookie_value"):
        return {user["cookie_name"]: user["cookie_value"]}
    return {}


def do_request(method, url, headers=None, cookies=None, json_body=None, data=None):
    """Perform HTTP request and return normalized response info."""
    try:
        resp = requests.request(method=method.upper(), url=url, headers=headers or {}, cookies=cookies or {},
                                json=json_body, data=data, timeout=TIMEOUT)
        return {
            "status_code": resp.status_code,
            "text_snippet": resp.text[:1000],
            "elapsed": resp.elapsed.total_seconds(),
            "headers": dict(resp.headers)
        }
    except Exception as e:
        return {"error": str(e)}


def is_access_allowed(resp_info):
    """
    Heuristic: Treat 2xx and 3xx as access allowed.
    If you want to treat certain 3xx (redirect to login) as not allowed,
    refine this function.
    """
    if "error" in resp_info:
        return False
    sc = resp_info.get("status_code", 0) or 0
    return 200 <= sc < 400


def run_idor_tests(users, endpoints):
    """
    - users: dict mapping username -> {user_id, base_url, token/cookies}
    - endpoints: list of endpoint rule objects
    Returns:
      - attempts: list of attempts (who requested what, response)
      - findings: list of discovered IDORs
    """
    attempts = []
    findings = []
    vulnerable = False

    # Build list of user identifiers to test (owner candidates)
    user_items = []
    for username, info in users.items():
        # Required: info must include `user_id` — the resource identifier used in endpoints
        uid = info.get("user_id")
        if uid is None:
            print(f"⚠️ Warning: user '{username}' missing 'user_id' field — skipping")
            continue
        user_items.append((username, uid, info))

    # For each endpoint pattern, test cross-access
    for rule in endpoints:
        endpoint_pattern = rule.get("endpoint")
        method = rule.get("method", "GET").upper()
        json_body = rule.get("json")
        payload = rule.get("payload")
        # Which base_url to use? We'll prefer user-specific base_url (each account may use same base)
        for owner_username, owner_user_id, owner_info in user_items:
            # target url = resource owned by owner_user_id
            # Now attempt to access that target with every other user (attacker)
            for attacker_username, attacker_user_id, attacker_info in user_items:
                # Skip owner accessing their own resource (we only want cross-user tests)
                if attacker_username == owner_username:
                    continue

                base_url = attacker_info.get("base_url") or owner_info.get("base_url") or ""
                url = build_url(base_url, endpoint_pattern, owner_user_id)
                headers = prepare_headers(attacker_info)
                cookies = prepare_cookies(attacker_info)

                resp = do_request(method, url, headers=headers, cookies=cookies, json_body=json_body, data=payload)

                allowed = is_access_allowed(resp)

                attempt = {
                    "endpoint_pattern": endpoint_pattern,
                    "target_owner": owner_username,
                    "target_user_id": owner_user_id,
                    "attacker": attacker_username,
                    "attacker_user_id": attacker_user_id,
                    "full_url": url,
                    "method": method,
                    "status_code": resp.get("status_code"),
                    "error": resp.get("error", ""),
                    "allowed": allowed,
                    "elapsed": resp.get("elapsed")
                }
                attempts.append(attempt)

                # If attacker is not owner and access is allowed -> potential IDOR
                if allowed:
                    vulnerable = True
                    findings.append({
                        "type": "IDOR",
                        "owner": owner_username,
                        "owner_user_id": owner_user_id,
                        "attacker": attacker_username,
                        "attacker_user_id": attacker_user_id,
                        "endpoint_pattern": endpoint_pattern,
                        "full_url": url,
                        "status_code": resp.get("status_code"),
                        "detail": f"User '{attacker_username}' could access resource for '{owner_username}' at '{url}' (HTTP {resp.get('status_code')})"
                    })

    status = "VULNERABLE" if vulnerable else "SECURE"
    return attempts, findings, status


def write_report(attempts, findings, status, summary):
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    report = {
        "check_name": "idor_user_data_check",
        "status": status,
        "summary": summary,
        "findings": findings,
        "attempts": attempts,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"✅ Report written: {OUT_PATH}")


def parse_args():
    p = argparse.ArgumentParser(description="IDOR / Cross-user data access check")
    p.add_argument("--users-file", required=True, help="JSON file mapping user accounts (data/users.json)")
    p.add_argument("--endpoints-file", required=True, help="JSON file listing endpoints with {user_id} placeholder (data/idor_endpoints.json)")
    return p.parse_args()


def main():
    args = parse_args()

    try:
        users = load_json(args.users_file)
    except Exception as e:
        print(f"❌ Failed to read users file: {e}")
        sys.exit(1)

    try:
        endpoints = load_json(args.endpoints_file)
    except Exception as e:
        print(f"❌ Failed to read endpoints file: {e}")
        sys.exit(1)

    print(f"🔎 Running IDOR tests: {len(users)} accounts x {len(endpoints)} endpoints ...")

    attempts, findings, status = run_idor_tests(users, endpoints)

    summary = f"IDORs found: {len(findings)}" if findings else "No cross-user data access detected."
    write_report(attempts, findings, status, summary)

    print(f"[idor_user_data_check] status={status} findings={len(findings)} attempts={len(attempts)}")


if __name__ == "__main__":
    main()
