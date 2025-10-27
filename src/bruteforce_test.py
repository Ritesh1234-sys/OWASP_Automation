#!/usr/bin/env python3
"""
====================================================
FILE: bruteforce_test.py
PURPOSE:
    This script tries multiple password and OTP combinations 
    against a login endpoint (like the demo in flask_login_otp.py).

    It helps verify if a system correctly blocks brute-force 
    attacks using:
      - rate limiting (HTTP 429)
      - account lockout (HTTP 403)
      - progressive delay or blocking

USAGE:
    python3 src/bruteforce_test.py \
        --target http://127.0.0.1:5001 \
        --username alice \
        --password-file data/pwlist.txt \
        --otp-file data/otplist.txt \
        --delay 0.2

OUTPUT:
    JSON report is saved to: reports/raw/bruteforce_report.json
====================================================
"""
import requests
import time
import json
import argparse
import os

# -------------------------
# CLI SETUP
# -------------------------
# argparse lets users run this script with command-line flags.
parser = argparse.ArgumentParser(description="Brute-force / rate-limit test client")
parser.add_argument("--target", help="Base URL of target (default is http://127.0.0.1:5001)")
parser.add_argument("--username", help="Username to test", default="alice")
parser.add_argument("--password-file", help="File containing passwords to try")
parser.add_argument("--otp-file", help="File containing OTPs to try")
parser.add_argument("--delay", type=float, help="Delay between attempts (seconds)", default=0.2)
parser.add_argument("--max-attempts", type=int, help="Maximum attempts per test", default=50)
args = parser.parse_args()

# Default test URL if user doesn’t specify
TARGET_BASE = args.target or "http://127.0.0.1:5001"
LOGIN_PATH = "/login"
OTP_PATH = "/otp"
USERNAME = args.username
DELAY = args.delay
MAX_ATTEMPTS = args.max_attempts

# -------------------------
# READ PASSWORD AND OTP LISTS
# -------------------------
def load_list_from_file(path, fallback):
    """Reads passwords/OTPs from a file, or uses defaults if not found."""
    if path and os.path.exists(path):
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return fallback

PASSWORDS = load_list_from_file(args.password_file, ["wrong1", "wrong2", "correcthorsebatterystaple"])
OTPS = load_list_from_file(args.otp_file, ["000000", "111111", "123456"])

# -------------------------
# REPORT STRUCTURE
# -------------------------
report = {
    "login_attempts": [],
    "otp_attempts": [],
    "observations": []
}
ip_throttle_detected = False

# -------------------------
# LOGIN REQUEST FUNCTION
# -------------------------
def attempt_login(username, password):
    """Sends one login request with username and password."""
    url = TARGET_BASE + LOGIN_PATH
    payload = {"username": username, "password": password}
    start = time.time()
    try:
        r = requests.post(url, json=payload, timeout=10)
        elapsed = time.time() - start
        return r.status_code, r.json(), elapsed
    except Exception as e:
        return None, {"error": str(e)}, 0

# -------------------------
# OTP REQUEST FUNCTION
# -------------------------
def attempt_otp(username, otp):
    """Sends one OTP verification request."""
    url = TARGET_BASE + OTP_PATH
    payload = {"username": username, "otp": otp}
    start = time.time()
    try:
        r = requests.post(url, json=payload, timeout=10)
        elapsed = time.time() - start
        return r.status_code, r.json(), elapsed
    except Exception as e:
        return None, {"error": str(e)}, 0

# -------------------------
# RESPONSE ANALYSIS
# -------------------------
def analyze_response(action, status, body, elapsed):
    """Categorises each server response for reporting."""
    global ip_throttle_detected

    if status == 429:
        ip_throttle_detected = True
        report["observations"].append((action, "rate_limited", body))
        return "rate_limited"

    if status in (401, 400):
        report["observations"].append((action, "failed", body))
        return "failed"

    if status == 403:
        if "locked_until" in str(body):
            report["observations"].append((action, "account_locked", body))
            return "account_locked"
        report["observations"].append((action, "forbidden", body))
        return "forbidden"

    if status == 200:
        report["observations"].append((action, "success", body))
        return "success"

    report["observations"].append((action, "unknown", {"status": status, "body": body, "elapsed": elapsed}))
    return "unknown"

# -------------------------
# LOGIN TEST LOOP
# -------------------------
def run_login_test():
    """Tries passwords from list until lockout or success."""
    print(f"=== Running login brute-force test against {TARGET_BASE} ===")
    for i, pwd in enumerate(PASSWORDS * 3):
        if i >= MAX_ATTEMPTS:
            break
        status, body, elapsed = attempt_login(USERNAME, pwd)
        outcome = analyze_response("login", status, body, elapsed)
        print(f"[{i+1}] password='{pwd}' => {status} {outcome} (time={elapsed:.2f}s)")
        time.sleep(DELAY)
        if outcome in ("account_locked", "rate_limited"):
            print("Protection triggered:", outcome)
            break

# -------------------------
# OTP TEST LOOP
# -------------------------
def run_otp_test():
    """Tries multiple OTPs to test OTP brute-force prevention."""
    print(f"=== Running OTP brute-force test against {TARGET_BASE} ===")
    for i, otp in enumerate(OTPS * 5):
        if i >= MAX_ATTEMPTS:
            break
        status, body, elapsed = attempt_otp(USERNAME, otp)
        outcome = analyze_response("otp", status, body, elapsed)
        print(f"[{i+1}] otp='{otp}' => {status} {outcome} (time={elapsed:.2f}s)")
        time.sleep(DELAY)
        if outcome in ("account_locked", "rate_limited"):
            print("Protection triggered:", outcome)
            break

# -------------------------
# SUMMARY & SAVE REPORT
# -------------------------
def summarize():
    """Prints a summary and saves it to JSON."""
    print("\n=== Summary ===")
    print(f"Total login attempts: {len(report['login_attempts'])}")
    print(f"Total OTP attempts: {len(report['otp_attempts'])}")

    if ip_throttle_detected:
        print("✅ Rate limiting detected — protection is working.")
    else:
        print("⚠️  No rate limiting detected (increase attempt rate to confirm).")

    os.makedirs("reports/raw", exist_ok=True)
    with open("reports/raw/bruteforce_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("Report saved to reports/raw/bruteforce_report.json")

# -------------------------
# MAIN PROGRAM
# -------------------------
if __name__ == "__main__":
    run_login_test()
    run_otp_test()
    summarize()
