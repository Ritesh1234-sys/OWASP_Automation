#!/usr/bin/env python3
"""
activity_log_check.py

Enhanced OWASP automation check:
Verify whether user activity logs are stored promptly and accurately.

New Features:
  ✅ Timestamp validation: confirms logs appear within MAX_DELAY_SECONDS
  ✅ Log freshness score: % of timely vs delayed logs
  ✅ Comprehensive findings: missing, delayed, and found logs

Expected input:
  - data/activity_check_config.json (defines users, actions, and log endpoint)
Output:
  - reports/raw/activity_log_report.json
"""

import argparse
import json
import os
import sys
import time
import requests
from datetime import datetime, timezone

# Configurable constants
OUT_PATH = "reports/raw/activity_log_report.json"
TIMEOUT = 10  # seconds per request
DELAY_BETWEEN_ACTIONS = 2  # wait before checking logs
MAX_DELAY_SECONDS = 5  # acceptable delay between action and log creation


# ---------------------------
# Utility functions
# ---------------------------

def load_json(path):
    """Safely load a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def prepare_headers(user):
    """Build authorization headers for a user."""
    headers = {}
    token = user.get("token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if "extra_headers" in user and isinstance(user["extra_headers"], dict):
        headers.update(user["extra_headers"])
    return headers


def prepare_cookies(user):
    """Return cookie dict for user if provided."""
    if "cookies" in user and isinstance(user["cookies"], dict):
        return user["cookies"]
    return {}


def perform_action(action, user):
    """
    Simulate a user activity (login, update, logout, etc.)
    Returns metadata for the attempt (status_code, time, duration).
    """
    url = action.get("url")
    method = action.get("method", "GET").upper()
    json_body = action.get("json")
    payload = action.get("payload")

    headers = prepare_headers(user)
    cookies = prepare_cookies(user)

    try:
        start = datetime.now(timezone.utc)
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            json=json_body,
            data=payload,
            timeout=TIMEOUT,
        )
        end = datetime.now(timezone.utc)
        return {
            "url": url,
            "method": method,
            "status_code": resp.status_code,
            "elapsed": resp.elapsed.total_seconds(),
            "action_time": start.isoformat(),
            "completed_time": end.isoformat(),
        }
    except Exception as e:
        return {"url": url, "method": method, "error": str(e), "action_time": datetime.now(timezone.utc).isoformat()}


def parse_timestamp(ts_str):
    """Convert ISO timestamp string to datetime object safely."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def query_activity_log(log_endpoint, user, action_keyword=None):
    """
    Fetch the user's activity logs from the log endpoint.
    Returns tuple (found: bool, recent_logs: list)
    """
    headers = prepare_headers(user)
    cookies = prepare_cookies(user)

    try:
        resp = requests.get(log_endpoint, headers=headers, cookies=cookies, timeout=TIMEOUT)
        if resp.status_code != 200:
            return False, []

        data = resp.json() if "application/json" in resp.headers.get("Content-Type", "") else {}
        logs = data.get("data", data) if isinstance(data, dict) else data

        if not isinstance(logs, list):
            return False, []

        # Filter to recent logs matching keyword
        if action_keyword:
            logs = [log for log in logs if action_keyword.lower() in json.dumps(log).lower()]
        return bool(logs), logs
    except Exception:
        return False, []


# ---------------------------
# Core logic
# ---------------------------

def run_check(config):
    findings = []
    attempts = []
    total_actions = 0
    missing_logs = 0
    delayed_logs = 0

    users = config.get("users", {})
    actions = config.get("actions", [])
    log_endpoint_pattern = config.get("activity_log_endpoint")

    for username, user in users.items():
        print(f"🔍 Testing activity logging for user: {username}")

        for action in actions:
            total_actions += 1

            # Replace {username} placeholder if present
            url = action["url"].replace("{username}", username)
            keyword = action.get("keyword", action["url"])

            # 1️⃣ Perform the action
            result = perform_action({"url": url, **action}, user)
            attempts.append({**result, "user": username})

            # 2️⃣ Wait for logs to be recorded
            time.sleep(DELAY_BETWEEN_ACTIONS)

            # 3️⃣ Query logs for this user
            log_url = log_endpoint_pattern.replace("{username}", username)
            found, logs = query_activity_log(log_url, user, keyword)

            # 4️⃣ Analyze results
            if not found:
                missing_logs += 1
                findings.append({
                    "user": username,
                    "action_url": url,
                    "detail": f"❌ No activity log found for action '{keyword}'",
                    "expected_log_url": log_url
                })
                continue

            # Check timestamps
            action_time = parse_timestamp(result["action_time"])
            log_times = []

            for log in logs:
                log_time_str = log.get("timestamp") or log.get("time") or log.get("created_at")
                if log_time_str:
                    parsed = parse_timestamp(log_time_str)
                    if parsed:
                        log_times.append(parsed)

            if not log_times:
                missing_logs += 1
                findings.append({
                    "user": username,
                    "action_url": url,
                    "detail": f"⚠️ Log found but no timestamp field detected in entries",
                    "expected_log_url": log_url
                })
                continue

            # Calculate delay between action and first log entry
            min_delay = min((lt - action_time).total_seconds() for lt in log_times if lt > action_time)

            if min_delay > MAX_DELAY_SECONDS:
                delayed_logs += 1
                findings.append({
                    "user": username,
                    "action_url": url,
                    "detail": f"⚠️ Log detected but delayed by {min_delay:.2f}s (>{MAX_DELAY_SECONDS}s)",
                    "expected_log_url": log_url
                })
            else:
                findings.append({
                    "user": username,
                    "action_url": url,
                    "detail": f"✅ Log found promptly ({min_delay:.2f}s delay)",
                    "expected_log_url": log_url
                })

    # ---------------------------
    # Aggregate summary
    # ---------------------------
    timely_logs = total_actions - missing_logs - delayed_logs
    freshness_score = round((timely_logs / total_actions) * 100, 2) if total_actions else 0

    if missing_logs > 0:
        status = "MISSING_LOGS"
    elif delayed_logs > 0:
        status = "DELAYED_LOGS"
    else:
        status = "SECURE"

    summary = (
        f"Timely logs: {timely_logs}/{total_actions} "
        f"({freshness_score}%) | Missing: {missing_logs}, Delayed: {delayed_logs}"
    )

    return findings, attempts, status, summary, freshness_score


# ---------------------------
# Report writing
# ---------------------------

def write_report(findings, attempts, status, summary, freshness_score):
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    report = {
        "check_name": "activity_log_check",
        "status": status,
        "summary": summary,
        "freshness_score": freshness_score,
        "findings": findings,
        "attempts": attempts,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"✅ Report written: {OUT_PATH}")


def parse_args():
    p = argparse.ArgumentParser(description="Verify if user activity logs are stored and timely.")
    p.add_argument("--config-file", required=True, help="Path to config JSON (actions + users)")
    return p.parse_args()


def main():
    args = parse_args()
    try:
        config = load_json(args.config_file)
    except Exception as e:
        print(f"❌ Failed to load config file: {e}")
        sys.exit(1)

    findings, attempts, status, summary, score = run_check(config)
    write_report(findings, attempts, status, summary, score)
    print(f"[activity_log_check] status={status} | {summary}")


if __name__ == "__main__":
    main()
