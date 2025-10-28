#!/usr/bin/env python3
"""
account_lockout_check.py

OWASP-style automation check:
"Verify if the user account is locked or blocked after multiple failed login attempts."

Behaviour:
 - Configurable (target login URL, username, known-correct-password,
   list of bad passwords, number of attempts, delay between attempts).
 - Performs a baseline successful login (if credentials provided).
 - Performs N failed-login attempts using bad passwords.
 - Re-checks login with the correct password to detect lockout.
 - Detects lockout using:
     * HTTP status codes (defaults: 403, 429)
     * Response body heuristics (e.g., "account locked", "too many attempts")
     * The correct-login turning from success -> failure after attempts
 - Generates a JSON report at reports/raw/account_lockout_report.json

Safety:
 - Uses delays between attempts to avoid accidental DoS
 - Non-destructive: attempts login only (no account deletion / modification)
 - Respect legal/ethical policies — only run on systems you own or are authorised to test.

Example usage:
 python3 src/account_lockout_check.py \
   --target http://127.0.0.1:5001/login \
   --username alice \
   --correct-password correcthorsebatterystaple \
   --bad-passwords data/bad_passwords.txt \
   --attempts 8 \
   --delay 1

Output:
 - JSON report saved to reports/raw/account_lockout_report.json
"""

from __future__ import annotations
import argparse
import json
import os
import time
import datetime
from typing import List, Dict, Any, Optional
import requests

# -------------------------
# DEFAULTS / CONFIG
# -------------------------
DEFAULT_BAD_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin", "password1"
]
DEFAULT_LOCK_STATUS_CODES = [403, 429]  # common codes indicating blocked/ratelimited
DEFAULT_LOCK_STRINGS = [
    "account locked", "too many attempts", "temporarily locked", "too many login attempts",
    "account disabled", "locked due to", "try again later"
]

REPORT_PATH = "reports/raw/account_lockout_report.json"


# -------------------------
# Helpers
# -------------------------
def load_bad_passwords(path: Optional[str]) -> List[str]:
    """Load bad passwords from a file, fallback to default list."""
    if not path:
        return DEFAULT_BAD_PASSWORDS.copy()
    if not os.path.isfile(path):
        return DEFAULT_BAD_PASSWORDS.copy()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        return lines if lines else DEFAULT_BAD_PASSWORDS.copy()
    except Exception:
        return DEFAULT_BAD_PASSWORDS.copy()


def safe_post(session: requests.Session, url: str, data: dict, json_body: Optional[dict],
              headers: dict, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Perform a POST and return a normalized dict with:
      - status_code (int or None)
      - text (string or error message)
      - elapsed (seconds float)
      - ok (bool)
    """
    try:
        start = time.time()
        if json_body is not None:
            resp = session.post(url, json=json_body, headers=headers, timeout=timeout)
        else:
            resp = session.post(url, data=data, headers=headers, timeout=timeout)
        elapsed = time.time() - start
        return {
            "status_code": resp.status_code,
            "text": resp.text[:4000],  # keep payload reasonably limited
            "elapsed": elapsed,
            "ok": resp.ok,
            "headers": dict(resp.headers)
        }
    except requests.RequestException as e:
        return {
            "status_code": None,
            "text": str(e),
            "elapsed": 0.0,
            "ok": False,
            "headers": {}
        }


def detect_lock_from_response(resp: Dict[str, Any],
                              lock_status_codes: List[int],
                              lock_strings: List[str]) -> Optional[Dict[str, Any]]:
    """
    Inspect a response dict and decide whether it indicates a lock/rate limit.
    Returns a dict of detection details if locked, else None.
    """
    sc = resp.get("status_code")
    txt = (resp.get("text") or "").lower()

    # Status code check
    if sc is not None and sc in lock_status_codes:
        return {"method": "status_code", "status_code": sc, "reason": "status code in lock list"}

    # Text heuristics check
    for phrase in lock_strings:
        if phrase in txt:
            return {"method": "body_phrase", "phrase": phrase}

    # Not obviously locked
    return None


# -------------------------
# Core check flow
# -------------------------
def run_lockout_check(target: str,
                      username: str,
                      correct_password: Optional[str],
                      bad_passwords: List[str],
                      attempts: int,
                      delay: float,
                      username_field: str,
                      password_field: str,
                      use_json: bool,
                      headers: Dict[str, str],
                      lock_status_codes: List[int],
                      lock_strings: List[str],
                      timeout: float = 10.0) -> Dict[str, Any]:
    """
    Execute the lockout test and return a structured report dict.
    """

    session = requests.Session()
    session.headers.update({"User-Agent": "OWASP_Automation/AccountLockoutCheck/1.0"})
    # allow user-supplied headers to override UA / others
    session.headers.update(headers or {})

    now = datetime.datetime.utcnow().isoformat() + "Z"
    report = {
        "check_name": "account_lockout_check",
        "target": target,
        "username": username,
        "attempts_configured": attempts,
        "attempt_delay_seconds": delay,
        "timestamp": now,
        "initial_login": None,
        "failed_attempts": [],
        "post_attempt_login": None,
        "lock_detected": False,
        "lock_details": None,
        "summary": "",
    }

    # Prepare payload templates (form data or JSON)
    def build_payload(user: str, pwd: str):
        if use_json:
            return None, {username_field: user, password_field: pwd}
        else:
            return {username_field: user, password_field: pwd}, None

    # -------------------------
    # Step 0: baseline correct login (if provided)
    # -------------------------
    if correct_password:
        data, json_body = build_payload(username, correct_password)
        report["initial_login"] = safe_post(session, target, data, json_body, headers, timeout=timeout)
    else:
        report["initial_login"] = {"status_code": None, "text": "no-correct-password-provided", "ok": False}

    # NOTE: if the baseline login fails, we still proceed, but we mark this and interpret accordingly.
    baseline_ok = bool(report["initial_login"].get("ok"))

    # -------------------------
    # Step 1: perform repeated failed attempts
    # -------------------------
    for i in range(attempts):
        bad_pwd = bad_passwords[i % len(bad_passwords)]
        data, json_body = build_payload(username, bad_pwd)
        resp = safe_post(session, target, data, json_body, headers, timeout=timeout)
        # record attempt
        attempt_entry = {
            "attempt": i + 1,
            "password_used": bad_pwd,
            "status_code": resp.get("status_code"),
            "ok": resp.get("ok"),
            "elapsed": resp.get("elapsed"),
            "text_snippet": (resp.get("text") or "")[:1000]
        }
        report["failed_attempts"].append(attempt_entry)

        # quick heuristic detection: if any response indicates immediate lock, stop
        detection = detect_lock_from_response(resp, lock_status_codes, lock_strings)
        if detection:
            report["lock_detected"] = True
            report["lock_details"] = {
                "when_attempt": i + 1,
                "detection": detection,
                "evidence": attempt_entry
            }
            # stop further attempts (locked detected early)
            break

        # respectful pause between attempts
        time.sleep(delay)

    # -------------------------
    # Step 2: try correct login again to confirm lock state
    # -------------------------
    if correct_password:
        data, json_body = build_payload(username, correct_password)
        post_resp = safe_post(session, target, data, json_body, headers, timeout=timeout)
        report["post_attempt_login"] = post_resp
        # detect lock using same heuristic
        detection = detect_lock_from_response(post_resp, lock_status_codes, lock_strings)
        if detection:
            report["lock_detected"] = True
            report["lock_details"] = report.get("lock_details") or {}
            report["lock_details"].update({
                "post_attempt_detection": detection,
                "post_attempt_evidence": {
                    "status_code": post_resp.get("status_code"),
                    "text_snippet": (post_resp.get("text") or "")[:1000]
                }
            })
    else:
        report["post_attempt_login"] = {"status_code": None, "text": "no-correct-password-provided", "ok": False}

    # -------------------------
    # Step 3: final status decision and summary
    # -------------------------
    if report["lock_detected"]:
        status = "PASS"
        summary = ("An account lockout or blocking behaviour was detected for "
                   f"user '{username}'. See lock_details for evidence.")
    else:
        # If baseline succeeded but post-attempt login failed -> WARN
        if baseline_ok and not bool(report["post_attempt_login"].get("ok")):
            status = "WARN"
            summary = ("Baseline login succeeded earlier but failed after failed-attempt burst. "
                       "This might indicate soft-rate-limiting or other interference; manual check recommended.")
        else:
            status = "FAIL"
            summary = ("No account lockout detected — the user can still login after repeated failed attempts. "
                       "This could indicate lack of account lockout policy or it may be enforced by different protections (e.g., CAPTCHA, IP block).")

    report["status"] = status
    report["summary"] = summary

    return report


# -------------------------
# CLI Entrypoint
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Account lockout detection check (OWASP-style).")
    parser.add_argument("--target", required=True, help="Login endpoint URL (e.g., https://example.com/login)")
    parser.add_argument("--username", required=True, help="Username to test (must be valid account you control)")
    parser.add_argument("--correct-password", default=None,
                        help="Known good password for the account (optional but recommended).")
    parser.add_argument("--bad-passwords", default=None,
                        help="Path to newline-separated file of incorrect passwords (optional).")
    parser.add_argument("--attempts", type=int, default=5, help="Number of failed login attempts to simulate.")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay in seconds between attempts (default 1s).")
    parser.add_argument("--username-field", default="username", help="Form/json field name for username.")
    parser.add_argument("--password-field", default="password", help="Form/json field name for password.")
    parser.add_argument("--use-json", action="store_true", help="Send login as JSON instead of form-encoded data.")
    parser.add_argument("--header", action="append", default=[],
                        help="Custom header to include (multiple allowed). Format: 'Name: value'")
    parser.add_argument("--lock-status-codes", default="403,429", help="Comma-separated status codes that indicate locking.")
    parser.add_argument("--lock-strings", default=",".join(DEFAULT_LOCK_STRINGS),
                        help="Comma-separated phrases that indicate lockout in response body (case-insensitive).")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout seconds per request.")
    parser.add_argument("--report-path", default=REPORT_PATH, help="Path to save JSON report.")
    args = parser.parse_args()

    # Build headers dict
    hdrs = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()

    bad_pw_list = load_bad_passwords(args.bad_passwords)
    lock_status_codes = [int(x) for x in args.lock_status_codes.split(",") if x.strip().isdigit()]
    lock_strings = [x.strip().lower() for x in args.lock_strings.split(",") if x.strip()]

    # Run the check
    report = run_lockout_check(
        target=args.target,
        username=args.username,
        correct_password=args.correct_password,
        bad_passwords=bad_pw_list,
        attempts=args.attempts,
        delay=args.delay,
        username_field=args.username_field,
        password_field=args.password_field,
        use_json=args.use_json,
        headers=hdrs,
        lock_status_codes=lock_status_codes,
        lock_strings=lock_strings,
        timeout=args.timeout
    )

    # Ensure output dir exists and write report
    os.makedirs(os.path.dirname(args.report_path) or "reports/raw", exist_ok=True)
    with open(args.report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # Print summary and location
    print(f"[account_lockout_check] Status: {report['status']} - {report['summary']}")
    print(f"Report written: {args.report_path}")


if __name__ == "__main__":
    main()
