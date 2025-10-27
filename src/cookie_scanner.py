#!/usr/bin/env python3
"""
cookie_scanner.py - Scan Set-Cookie headers and cookie values for insecure attributes or sensitive content

Full path: src/cookie_scanner.py

PURPOSE:
  - Fetch a URL and analyze its Set-Cookie headers.
  - Detect insecure cookie attributes (missing Secure/HttpOnly/SameSite).
  - Heuristically detect sensitive data in cookie values (JWTs, emails, long base64 strings, possible credit card numbers).
  - Save a structured JSON report to reports/raw/cookie_scan_report.json.

NOTES:
  - Some servers send multiple Set-Cookie headers. Those headers can include commas
    inside attribute values (e.g. Expires=Mon, 27 Oct 2025 11:48:21 GMT). Naively
    splitting on commas will break parsing. This script uses a robust method to
    extract individual Set-Cookie headers safely.
  - This is a local testing tool. Do not use against targets you do not have permission to test.
  - The file includes clear, beginner-friendly comments so your team can understand and extend it.
"""
import requests
import re
import json
import argparse
import os
from http import cookies as http_cookies

# -------------------------
# Patterns to detect sensitive values inside cookie values
# -------------------------
# JWT structure: header.payload.signature -> three base64-url parts
JWT_RE = re.compile(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$')
# Simple email pattern
EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
# Credit-card like pattern (13-16 digits with optional separators)
CC_RE = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
# Long base64 blobs (likely encoded sensitive content)
BASE64_RE = re.compile(r'^[A-Za-z0-9+/=]{40,}$')

# -------------------------
# CLI: target URL and options
# -------------------------
parser = argparse.ArgumentParser(description="Scan cookies for insecure attributes & sensitive content")
parser.add_argument("--target", help="Full URL to call (example: http://127.0.0.1:5002/set_cookies_demo)", required=True)
parser.add_argument("--insecure-ok", action="store_true", help="Treat insecure cookie flags as informational (no 'issue')")
args = parser.parse_args()

TARGET = args.target
INSECURE_OK = args.insecure_ok

# -------------------------
# Helpers: parse one Set-Cookie header
# -------------------------
def analyze_cookie_header(raw_header):
    """
    Parse a single Set-Cookie header string into components.

    Returns:
      {
        "name": <cookie name>,
        "value": <cookie value>,
        "attrs": {attr_name: attr_value_or_true, ...},
        "raw": <original header>
      }
    """
    parts = [p.strip() for p in raw_header.split(";")]
    if not parts:
        return None

    # first part should be name=value
    name_val = parts[0]
    if "=" not in name_val:
        return None
    name, value = name_val.split("=", 1)

    attrs = {}
    for token in parts[1:]:
        if "=" in token:
            k, v = token.split("=", 1)
            attrs[k.lower()] = v
        else:
            # flags like Secure or HttpOnly
            attrs[token.lower()] = True

    return {"name": name, "value": value, "attrs": attrs, "raw": raw_header}

# -------------------------
# Heuristic checks for cookie values
# -------------------------
def sensitive_checks(value):
    """Return a list of findings for suspicious cookie values."""
    findings = []
    if value is None:
        return findings
    v = value.strip()
    if JWT_RE.match(v):
        findings.append("value_looks_like_jwt")
    if EMAIL_RE.search(v):
        findings.append("value_contains_email")
    if CC_RE.search(v):
        findings.append("value_contains_possible_creditcard")
    if BASE64_RE.match(v):
        findings.append("value_looks_like_long_base64_blob")
    if len(v) > 200:
        findings.append("value_excessive_length")
    return findings

# -------------------------
# Check cookie attributes for missing best-practices
# -------------------------
def check_cookie_attrs(parsed):
    """Return a list of attribute-related findings for a parsed cookie."""
    findings = []
    attrs = parsed.get("attrs", {})

    # HttpOnly prevents JS access to cookie
    if "httponly" not in attrs:
        findings.append("missing_httponly")

    # Secure ensures cookies sent only over HTTPS
    if "secure" not in attrs:
        findings.append("missing_secure")

    # SameSite mitigates some CSRF attacks
    samesite = attrs.get("samesite")
    if samesite is None:
        findings.append("missing_samesite")
    else:
        try:
            if isinstance(samesite, str) and samesite.lower() == "none":
                findings.append("samesite_none_requires_secure")
        except Exception:
            pass

    # Excessive max-age (example threshold: > 90 days)
    max_age = attrs.get("max-age")
    if max_age:
        try:
            ma = int(max_age)
            if ma > 60 * 60 * 24 * 90:
                findings.append("excessive_max_age")
        except ValueError:
            # non-integer max-age - ignore but could flag if desired
            pass

    return findings

# -------------------------
# Robust extraction of Set-Cookie headers
# -------------------------
def extract_set_cookie_headers(response):
    """
    Return a list of individual Set-Cookie header strings.

    Some HTTP stacks concatenate multiple Set-Cookie headers into one header value.
    We use several strategies:
      1) If raw.headers.get_all('Set-Cookie') is available (urllib3), use it.
      2) Else, obtain response.headers.get('Set-Cookie') and split safely:
         - We split on ", " only when it is followed by a cookie-name-looking token
           (letters/digits/underscore/hyphen) and an equals sign. This avoids splitting
           inside Expires values which contain commas.
    """
    raw_headers = []

    # Strategy 1: try to use get_all from the underlying urllib3 headers (preferred)
    try:
        if hasattr(response, "raw") and hasattr(response.raw, "headers") and hasattr(response.raw.headers, "get_all"):
            # urllib3 exposes get_all('Set-Cookie') which returns a list
            raw_headers = response.raw.headers.get_all("Set-Cookie") or []
    except Exception:
        raw_headers = []

    # Strategy 2: fallback - requests headers may expose a single string
    if not raw_headers:
        sc_header = response.headers.get("Set-Cookie")
        if sc_header:
            # Split only on comma-space sequences that are followed by a token that looks like "name="
            # This pattern avoids splitting inside dates like: Expires=Mon, 27 Oct 2025 11:48:21 GMT
            parts = re.split(r', (?=[A-Za-z0-9_\-]+=[^;]+)', sc_header)
            raw_headers = [p.strip() for p in parts if p.strip()]

    return raw_headers

# -------------------------
# Core scanning logic
# -------------------------
def scan(target):
    """
    Fetch the target and analyze cookies. Returns a structured dict.
    """
    print(f"Scanning {target} ...")

    try:
        r = requests.get(target, timeout=10)
    except Exception as e:
        print("ERROR: request failed:", e)
        return {"url": target, "error": str(e)}

    out = {
        "url": target,
        "status_code": r.status_code,
        "cookies_found": [],
        "findings": []
    }

    # Get all Set-Cookie header values robustly
    raw_headers = extract_set_cookie_headers(r)

    # If no headers found, try to see if requests parsed cookies into r.cookies
    if not raw_headers and r.cookies:
        # Convert requests' CookieJar entries into simple cookie objects
        for c in r.cookies:
            parsed = {"name": c.name, "value": c.value, "attrs": {"domain": c.domain, "path": c.path, "secure": c.secure}, "raw": f"{c.name}={c.value}"}
            out["cookies_found"].append(parsed)
            # value checks
            for issue in sensitive_checks(parsed["value"]):
                out["findings"].append({"cookie": parsed["name"], "issue": issue, "type": "sensitive_value"})
            # attr checks
            for issue in check_cookie_attrs(parsed):
                level = "info" if INSECURE_OK else "issue"
                out["findings"].append({"cookie": parsed["name"], "issue": issue, "type": "cookie_attr", "level": level})

        return out

    # Parse each Set-Cookie header individually
    for header in raw_headers:
        parsed = analyze_cookie_header(header)
        if not parsed:
            # If parsing failed, include raw header for manual review
            out["cookies_found"].append({"name": None, "value": None, "attrs": {}, "raw": header})
            out["findings"].append({"cookie": None, "issue": "failed_to_parse_set_cookie", "type": "parse_error"})
            continue

        out["cookies_found"].append(parsed)

        # Detect sensitive values
        for issue in sensitive_checks(parsed["value"]):
            out["findings"].append({"cookie": parsed["name"], "issue": issue, "type": "sensitive_value"})

        # Check attributes (missing Secure/HttpOnly/SameSite, long Max-Age, etc.)
        for issue in check_cookie_attrs(parsed):
            level = "info" if INSECURE_OK else "issue"
            out["findings"].append({"cookie": parsed["name"], "issue": issue, "type": "cookie_attr", "level": level})

    return out

# -------------------------
# CLI entrypoint
# -------------------------
if __name__ == "__main__":
    result = scan(TARGET)

    # Ensure output directory exists
    os.makedirs("reports/raw", exist_ok=True)

    # Save report
    out_path = "reports/raw/cookie_scan_report.json"
    with open(out_path, "w") as fh:
        json.dump(result, fh, indent=2)

    print(f"✅ Scan complete. Report saved at {out_path}")
