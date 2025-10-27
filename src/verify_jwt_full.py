#!/usr/bin/env python3
"""
verify_jwt_full.py
===================
Purpose:
    Verifies JSON Web Tokens (JWT) for expiration, lifetime policy,
    and signature validity. Aligned with OWASP ASVS 2.7: "Verify token expiration policy".

Usage:
    python3 src/verify_jwt_full.py --token-file data/token.txt

Output:
    Prints validation summary and saves structured JSON report to reports/raw/jwt_verify_report.json
"""

import argparse
import json
import jwt
import time
import os
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, DecodeError

# --------------------------------------
# CLI arguments
# --------------------------------------
parser = argparse.ArgumentParser(description="Verify JWT expiration and signature validity.")
parser.add_argument("--token-file", required=True, help="Path to file containing a single JWT.")
args = parser.parse_args()

# --------------------------------------
# Load token from file
# --------------------------------------
if not os.path.exists(args.token_file):
    print(f"❌ Token file not found: {args.token_file}")
    exit(1)

with open(args.token_file, "r") as f:
    token = f.read().strip()

# --------------------------------------
# Decode header and payload safely
# --------------------------------------
try:
    payload = jwt.decode(token, options={"verify_signature": False})
    header = jwt.get_unverified_header(token)
except DecodeError:
    print("❌ Invalid JWT structure — unable to decode token.")
    exit(1)

# --------------------------------------
# Extract claims
# --------------------------------------
issued_at = payload.get("iat")
expires_at = payload.get("exp")
now = int(time.time())

results = {
    "header": header,
    "payload": payload,
    "validation": {},
}

# --------------------------------------
# 1️⃣ Expiration Policy Validation
# --------------------------------------
if expires_at:
    lifetime = (expires_at - issued_at) if issued_at else None
    results["validation"].update({
        "issued_at": issued_at,
        "expires_at": expires_at,
        "current_time": now,
        "expired": now > expires_at,
        "token_lifetime_seconds": lifetime
    })

    if now > expires_at:
        print("⛔ Token is expired.")
    else:
        print("✅ Token is still valid.")
        if lifetime and lifetime > 3600:
            print(f"⚠️ Token lifetime too long: {lifetime} seconds (recommended ≤ 3600s)")
else:
    print("⚠️ No expiration ('exp') claim found.")
    results["validation"]["expires_at"] = None

# --------------------------------------
# 2️⃣ Signature Verification (optional)
# --------------------------------------
secret_path = "data/secret.txt"
if os.path.exists(secret_path):
    with open(secret_path, "r") as f:
        secret = f.read().strip()
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
        print("✅ Signature is valid.")
        results["validation"]["signature_valid"] = True
    except InvalidSignatureError:
        print("❌ Invalid signature — token may have been tampered.")
        results["validation"]["signature_valid"] = False
    except ExpiredSignatureError:
        print("❌ Signature valid but token is expired.")
        results["validation"]["signature_valid"] = True
else:
    print("⚠️ Secret key not found — skipping signature verification.")
    results["validation"]["signature_valid"] = None

# --------------------------------------
# 3️⃣ Save JSON report
# --------------------------------------
os.makedirs("reports/raw", exist_ok=True)
output_path = "reports/raw/jwt_verify_report.json"
with open(output_path, "w") as out:
    json.dump(results, out, indent=4)

print(f"📄 JWT validation report saved: {output_path}")
