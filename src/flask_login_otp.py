#!/usr/bin/env python3
"""
====================================================
FILE: flask_login_otp.py
PURPOSE: 
    This is a small, local Flask-based web server 
    that imitates a login + OTP verification system. 

    It helps us test how well our automation scripts 
    detect rate limiting and brute-force protection.

HOW TO USE:
    1. Activate your virtual environment:
       $ source venv/bin/activate

    2. Start this server:
       $ python3 src/flask_login_otp.py

    3. It will run at: http://127.0.0.1:5001

    Then you can run the "bruteforce_test.py" script 
    against it to test your automation.

----------------------------------------------------
"""
from flask import Flask, request, jsonify, make_response
import time
import threading

# ---------------------------------------------------
# STEP 1: Create the Flask app
# ---------------------------------------------------
# Flask is a lightweight Python web framework.
# It lets us create simple web APIs for testing quickly.
app = Flask(__name__)

# ---------------------------------------------------
# STEP 2: Define our dummy users (for testing only)
# ---------------------------------------------------
# These are fake accounts used for testing brute-force.
# Do NOT use any real usernames or passwords here.
USERS = {
    "alice": {"password": "correcthorsebatterystaple", "otp": "123456"},
    "bob":   {"password": "hunter2", "otp": "654321"},
}

# ---------------------------------------------------
# STEP 3: Define system protection rules
# ---------------------------------------------------
# These values simulate protection mechanisms in a real app.
# You can adjust them to test different scenarios.
MAX_FAILED = 5            # Lock account after 5 failed attempts
LOCKOUT_SECONDS = 60      # Keep account locked for 60 seconds
RATE_LIMIT_WINDOW = 10    # Time window for rate limit (10 sec)
RATE_LIMIT_MAX = 10       # Max 10 requests allowed in 10 seconds

# ---------------------------------------------------
# STEP 4: Temporary storage (memory only)
# ---------------------------------------------------
# These dictionaries keep track of login attempts and rate limits.
# In a real system, this would be stored in a database or Redis.
IP_RATE_LIMIT = {}   # Tracks requests per IP
FAILED_COUNTS = {}   # Tracks failed login attempts per user
OTP_ATTEMPTS = {}    # Tracks failed OTP attempts per user

lock = threading.Lock()  # Lock to make updates thread-safe


# ---------------------------------------------------
# HELPER FUNCTION: Count requests per IP
# ---------------------------------------------------
def increment_ip_requests(ip):
    """Keeps count of how many times a user (by IP) has made requests recently."""
    now = time.time()
    arr = IP_RATE_LIMIT.setdefault(ip, [])
    arr.append(now)
    # Remove old requests outside the time window
    while arr and arr[0] < now - RATE_LIMIT_WINDOW:
        arr.pop(0)
    return len(arr)


# ---------------------------------------------------
# HELPER FUNCTION: Check if account is locked
# ---------------------------------------------------
def is_locked(username):
    """Returns True if this user account is currently locked."""
    rec = FAILED_COUNTS.get(username)
    if not rec:
        return False
    return time.time() < rec.get("locked_until", 0)


# ---------------------------------------------------
# HELPER FUNCTION: Record a failed login
# ---------------------------------------------------
def register_failed(username):
    """Adds a failed attempt for a user. Locks the account if needed."""
    rec = FAILED_COUNTS.setdefault(username, {"count": 0, "locked_until": 0})
    rec["count"] += 1
    if rec["count"] >= MAX_FAILED:
        rec["locked_until"] = time.time() + LOCKOUT_SECONDS
        rec["count"] = 0  # Reset counter after locking


# ---------------------------------------------------
# HELPER FUNCTION: Reset failed count
# ---------------------------------------------------
def reset_failed(username):
    """Clears all failure data for this user (after successful login)."""
    FAILED_COUNTS.pop(username, None)


# ---------------------------------------------------
# ENDPOINT 1: /login
# ---------------------------------------------------
# This endpoint mimics a normal login process.
# It accepts JSON with "username" and "password".
# Responses:
#   - 200 OK if password is correct (asks for OTP)
#   - 401 Unauthorized for invalid credentials
#   - 403 Forbidden if account locked
#   - 429 Too Many Requests if rate limit hit
@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr or request.environ.get("HTTP_X_FORWARDED_FOR", "unknown")

    # Check if this IP has sent too many requests
    nreq = increment_ip_requests(ip)
    if nreq > RATE_LIMIT_MAX:
        return make_response(jsonify({"error": "rate_limited", "detail": "Too many requests"}), 429)

    # Get login data from user
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "missing_fields"}), 400

    # Security trick: Don’t reveal if username exists
    if username not in USERS:
        time.sleep(0.2)  # Delay to slow down brute-force guessing
        return jsonify({"error": "invalid_credentials"}), 401

    # If account locked, block login
    if is_locked(username):
        return jsonify({"error": "account_locked", "locked_until": FAILED_COUNTS[username]["locked_until"]}), 403

    # If correct password:
    if USERS[username]["password"] == password:
        reset_failed(username)
        return jsonify({"status": "ok", "next": "otp_required", "message": "Enter OTP"}), 200
    else:
        # Wrong password → increment fail count
        with lock:
            register_failed(username)
        rec = FAILED_COUNTS.get(username, {"count": 0})
        delay = 0.1 * rec.get("count", 0)  # Progressive delay after each failure
        time.sleep(delay)
        return jsonify({"error": "invalid_credentials"}), 401


# ---------------------------------------------------
# ENDPOINT 2: /otp
# ---------------------------------------------------
# This endpoint mimics the second authentication step (OTP verification).
# It accepts "username" and "otp".
# After too many wrong attempts, user is locked.
@app.route("/otp", methods=["POST"])
def otp():
    ip = request.remote_addr or request.environ.get("HTTP_X_FORWARDED_FOR", "unknown")
    nreq = increment_ip_requests(ip)
    if nreq > RATE_LIMIT_MAX:
        return make_response(jsonify({"error": "rate_limited", "detail": "Too many requests"}), 429)

    data = request.json or {}
    username = data.get("username")
    otp = data.get("otp")
    if not username or not otp:
        return jsonify({"error": "missing_fields"}), 400

    if is_locked(username):
        return jsonify({"error": "account_locked", "locked_until": FAILED_COUNTS[username]["locked_until"]}), 403

    expected = USERS.get(username, {}).get("otp")

    # If correct OTP → success
    if expected and otp == expected:
        OTP_ATTEMPTS.pop(username, None)
        FAILED_COUNTS.pop(username, None)
        return jsonify({"status": "ok", "message": "Authenticated"}), 200
    else:
        # Wrong OTP → count attempts
        arr = OTP_ATTEMPTS.setdefault(username, [])
        arr.append(time.time())
        # Keep only attempts within the last 5 minutes
        window = 300
        arr = [t for t in arr if t > time.time() - window]
        OTP_ATTEMPTS[username] = arr

        # If too many OTP failures → lock user
        threshold = 5
        if len(arr) >= threshold:
            FAILED_COUNTS.setdefault(username, {"count": 0, "locked_until": time.time() + LOCKOUT_SECONDS})
            return jsonify({"error": "otp_lock", "locked_until": FAILED_COUNTS[username]["locked_until"]}), 403
        return jsonify({"error": "invalid_otp"}), 401


# ---------------------------------------------------
# ENDPOINT 3: /status
# ---------------------------------------------------
# This is a helper endpoint for debugging.
# It shows what’s currently stored in memory:
# failed logins, OTP attempts, and IP request counts.
@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "failed_counts": FAILED_COUNTS,
        "otp_attempts": OTP_ATTEMPTS,
        "ip_rate": IP_RATE_LIMIT
    })


# ---------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------
# Flask runs this if you execute "python3 src/flask_login_otp.py"
if __name__ == "__main__":
    # Run local server on port 5001
    app.run(port=5001, debug=True)
