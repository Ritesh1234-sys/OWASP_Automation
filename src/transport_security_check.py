#!/usr/bin/env python3
"""
transport_security_check.py

Checks whether sensitive data might be exposed in transit for a target web page.

Outputs JSON to reports/raw/transport_security_report.json with the structure:
{
  "check_name": "transport_security",
  "status": "PASS|WARN|FAIL|ERROR",
  "summary": "...",
  "findings": [ { "type": "...", "detail": "..." }, ... ],
  "timestamp": "2025-10-27T12:34:56Z",
  "raw": { ... }  # optional raw data (headers, cert info)
}

How to use:
python3 src/transport_security_check.py --target https://example.com
"""

from __future__ import annotations
import argparse
import json
import os
import re
import socket
import ssl
import datetime
import math
from urllib.parse import urlparse, urljoin

import requests

# Output path (matches your framework)
OUTPUT_PATH = "reports/raw/transport_security_report.json"
CHECK_NAME = "transport_security"

# Regex patterns to detect possible secrets / sensitive tokens
RE_JWT = re.compile(r'[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9\-_]+')  # crude JWT pattern
RE_API_KEY = re.compile(r'(?i)(api[_-]?key|secret|access[_-]?token)[\s:=\"\']{0,10}([A-Za-z0-9\-\._]{16,})')
RE_EMAIL = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
# Credit card (very lenient): 13–19 digits optionally separated by spaces or dashes
RE_CC = re.compile(r'(?:(?:\d[ -]*?){13,19})')
# High-entropy token - heuristic; long string of base64/hex-like chars
RE_POTENTIALLY_SECRET = re.compile(r'([A-Za-z0-9\-_]{20,})')

# Common insecure resource tags to scan for mixed content
ATTR_HREF_SRC = re.compile(r'(?:src|href)=["\'](http:.*?)["\']', re.IGNORECASE)

# HSTS recommended minimum (seconds) — 1 year
HSTS_MIN_SECONDS = 31536000

# Helper: compute Shannon entropy for a string
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    # frequency counts
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = float(len(s))
    for _, count in freq.items():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# Helper: inspect TLS certificate & connection
def inspect_tls(hostname: str, port: int = 443, timeout: float = 5.0):
    result = {}
    try:
        ctx = ssl.create_default_context()
        # do not require client cert; we only inspect server cert
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()  # TLS protocol version, e.g., TLSv1.3
                cipher = ssock.cipher()  # tuple (name, protocol, bits)
                result["protocol"] = protocol
                result["cipher"] = cipher[0] if cipher else None
                # Convert cert fields to simpler dict
                result["cert"] = {
                    "subject": dict(x[0] for x in cert.get("subject", ())) if cert.get("subject") else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", ())) if cert.get("issuer") else {},
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "serialNumber": cert.get("serialNumber"),
                }
    except Exception as e:
        result["error"] = str(e)
    return result

# Main scanner function
def run_check(target_url: str, timeout: float = 10.0):
    findings = []
    status = "UNKNOWN"
    summary = ""
    raw = {"target": target_url, "headers": {}, "tls": {}}

    parsed = urlparse(target_url)
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"

    # 1) If page is plain HTTP -> high severity (FAIL)
    if scheme != "https":
        findings.append({"type": "transport_insecure", "detail": f"Target is not HTTPS: {target_url}"})
        status = "FAIL"
        summary = "Target is served over HTTP — data is sent in cleartext."
        # still attempt to fetch the page (some useful info)
    else:
        status = "PASS"  # optimistic; downgrade if issues found

    # 2) Fetch the page (follow redirects) and capture headers/body
    try:
        # set a reasonable User-Agent so servers respond normally
        headers = {"User-Agent": "OWASP-Automation/1.0 (+https://example.com)"}
        resp = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        raw["status_code"] = resp.status_code
        raw["headers"] = {k: v for k, v in resp.headers.items()}

        body = resp.text or ""
    except requests.exceptions.SSLError as e:
        findings.append({"type": "tls_error", "detail": f"SSL/TLS error when connecting: {e}"})
        status = "FAIL"
        body = ""
        raw["error"] = str(e)
    except Exception as e:
        findings.append({"type": "fetch_error", "detail": f"Failed to fetch page: {e}"})
        status = "ERROR"
        body = ""
        raw["error"] = str(e)

    # 3) If HTTPS, inspect TLS directly (protocol, cipher, cert dates)
    if scheme == "https" and hostname:
        tls_info = inspect_tls(hostname, port)
        raw["tls"] = tls_info
        if "error" in tls_info:
            findings.append({"type": "tls_inspect_error", "detail": tls_info["error"]})
            # don't escalate to FAIL automatically — might be a platform-specific issue
            if status != "FAIL":
                status = "WARN"
        else:
            # check protocol version
            proto = tls_info.get("protocol")
            if proto and ("TLSv1.2" not in proto and "TLSv1.3" not in proto):
                findings.append({"type": "weak_tls_version", "detail": f"Server using older TLS version: {proto}"})
                status = "WARN" if status != "FAIL" else status
            # check cipher strength presence
            cipher = tls_info.get("cipher")
            if cipher is None:
                findings.append({"type": "cipher_info_missing", "detail": "Cipher information unavailable"})
                status = "WARN"
            # check certificate expiry (notAfter)
            cert = tls_info.get("cert", {})
            not_after = cert.get("notAfter")
            if not_after:
                # cert notAfter format: e.g., 'Oct 27 22:28:21 2025 GMT'
                try:
                    dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (dt - datetime.datetime.utcnow()).days
                    raw["tls"]["cert_days_left"] = days_left
                    if days_left < 0:
                        findings.append({"type": "cert_expired", "detail": f"Certificate expired on {not_after}"})
                        status = "FAIL"
                    elif days_left < 30:
                        findings.append({"type": "cert_expiring_soon", "detail": f"Certificate expires in {days_left} days ({not_after})"})
                        if status != "FAIL":
                            status = "WARN"
                except Exception:
                    # ignore parse errors
                    pass

    # 4) Check security headers that protect transport
    headers = raw.get("headers", {})
    sts = headers.get("strict-transport-security") or headers.get("Strict-Transport-Security")
    if scheme == "https":
        if not sts:
            findings.append({"type": "missing_hsts", "detail": "Strict-Transport-Security header (HSTS) is not present"})
            if status != "FAIL":
                status = "WARN"
        else:
            # parse max-age
            try:
                m = re.search(r"max-age=(\d+)", sts)
                if m:
                    max_age = int(m.group(1))
                    if max_age < HSTS_MIN_SECONDS:
                        findings.append({"type": "hsts_too_short", "detail": f"HSTS max-age is {max_age}, recommended >= {HSTS_MIN_SECONDS}"})
                        if status != "FAIL":
                            status = "WARN"
                else:
                    findings.append({"type": "hsts_unparsable", "detail": f"HSTS header present but max-age missing or unparsable: {sts}"})
                    if status != "FAIL":
                        status = "WARN"
            except Exception:
                findings.append({"type": "hsts_parse_error", "detail": f"Could not parse HSTS header: {sts}"})
                if status != "FAIL":
                    status = "WARN"

    # 5) Detect mixed/content insecure resource loads (only for HTML bodies)
    mixed = []
    try:
        for match in ATTR_HREF_SRC.findall(body):
            # ATTR_HREF_SRC returns the captured http:... URL
            url = match
            mixed.append(url)
        if mixed:
            findings.append({"type": "mixed_content", "detail": f"Found {len(mixed)} insecure resource(s) loaded over http: (examples: {mixed[:3]})"})
            status = "FAIL"  # mixed content can cause sensitive data leakage
    except Exception:
        # ignore parsing issues
        pass

    # 6) Check forms for insecure action attributes
    try:
        form_actions = re.findall(r'<form[^>]+action=["\'](http:.*?)["\']', body, flags=re.IGNORECASE)
        if form_actions:
            findings.append({"type": "insecure_form_action", "detail": f"Found {len(form_actions)} form actions using http: (examples: {form_actions[:3]})"})
            status = "FAIL"
    except Exception:
        pass

    # 7) Search body for sensitive patterns: JWTs, API keys, emails, CC numbers, high entropy tokens
    found_secrets = []
    if body:
        # JWTs
        for m in RE_JWT.findall(body):
            # exclude very short base64-looking fragments < 20 chars
            if len(m) > 20:
                found_secrets.append(("jwt_like", m))

        # API key context detections (key near keywords)
        for m in RE_API_KEY.findall(body):
            # m is tuple; second group is the candidate key
            candidate = m[1] if len(m) > 1 else m[0]
            found_secrets.append(("api_key_like", candidate))

        # Emails (PII)
        for m in RE_EMAIL.findall(body):
            found_secrets.append(("email", m))

        # Credit card-like sequences
        for m in RE_CC.findall(body):
            # filter obviously date-like numbers (simple heuristic)
            digits_only = re.sub(r'\D', '', m)
            if 13 <= len(digits_only) <= 19:
                found_secrets.append(("credit_card_like", digits_only))

        # High-entropy tokens
        for m in RE_POTENTIALLY_SECRET.findall(body):
            if len(m) >= 20:
                ent = shannon_entropy(m)
                if ent >= 4.0:  # heuristic threshold for high entropy
                    found_secrets.append(("high_entropy_token", {"value_sample": m[:60], "entropy": round(ent, 2)}))

    # Deduplicate and report
    if found_secrets:
        for t, detail in found_secrets:
            findings.append({"type": t, "detail": str(detail)})
        # If secrets found in cleartext response body, mark as FAIL
        status = "FAIL"

    # 8) Check Set-Cookie headers for Secure flag (helpful transport protection)
    set_cookie_raw = headers.get("set-cookie") or headers.get("Set-Cookie")
    if set_cookie_raw:
        # simple split; some servers return multiple Set-Cookie headers concatenated with commas
        cookies = [c.strip() for c in re.split(r',(?=[^ ;]+=)', set_cookie_raw) if c.strip()]
        for c in cookies:
            if "secure" not in c.lower():
                findings.append({"type": "cookie_missing_secure", "detail": f"Cookie missing Secure flag: {c.split(';',1)[0]}"})
                if status != "FAIL":
                    status = "WARN"

    # 9) Produce summary message (if not already set)
    if not summary:
        if status == "PASS":
            summary = "No obvious transport security issues detected."
        elif status == "WARN":
            summary = "Potential transport-related weaknesses found — review findings."
        elif status == "FAIL":
            summary = "Transport security issues found (high priority)."
        elif status == "ERROR":
            summary = "Error occurred while running the check."
        else:
            summary = "Transport check produced ambiguous results."

    # 10) Build final report dict
    report = {
        "check_name": CHECK_NAME,
        "status": status,
        "summary": summary,
        "findings": findings,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "raw": raw
    }

    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    return report

# CLI entrypoint
def main():
    parser = argparse.ArgumentParser(description="Transport security / in-transit sensitive data check")
    parser.add_argument("--target", required=True, help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP/TLS timeout in seconds")
    args = parser.parse_args()

    report = run_check(args.target, timeout=args.timeout)
    # Print concise outcome for CLI visibility
    print(f"[{report['check_name']}] status={report['status']}, findings={len(report.get('findings', []))}")
    # Optionally show details (comment/uncomment)
    # print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
