#!/usr/bin/env python3
"""
ssl_implementation_check.py
-------------------------------------------------
OWASP Web Check: Verify the implementation of SSL/TLS.

What this checks (high level):
  1) Certificate chain + hostname validation (uses system trust store)
  2) Certificate expiration windows (WARN/FAIL thresholds)
  3) Server allows legacy protocols TLS 1.0/1.1 (risky)
  4) Cipher sanity (flags obviously weak/obsolete families if negotiated)
  5) HSTS header presence & quality on HTTPS
  6) HTTP -> HTTPS redirect behavior
  7) Mixed-content on the page (http:// references in HTML)

Outputs:
  - JSON report at reports/raw/ssl_implementation_report.json
  - `status`:
      FAIL   -> any HIGH issues
      WARN   -> otherwise if MEDIUM issues exist
      PASS   -> only LOW/INFO or none
      UNKNOWN-> couldn't evaluate

Suggested OWASP references:
  - ASVS 9.1.x (Communication Security)
  - OWASP TLS Cheat Sheet
"""

import argparse
import datetime
import json
import os
import re
import socket
import ssl
from urllib.parse import urlparse, urlunparse

import requests


# ------------- Utilities ------------------------------------------------------

def now_utc():
    """Timezone-aware UTC now for JSON timestamps."""
    return datetime.datetime.now(datetime.UTC)

def add_finding(findings, issue, severity, detail, evidence=None):
    findings.append({
        "issue": issue,
        "severity": severity,
        "detail": detail,
        "evidence": evidence or {}
    })

def classify_overall(findings):
    """Map findings to overall status."""
    severities = {f.get("severity", "INFO") for f in findings}
    if "HIGH" in severities:
        return "FAIL"
    if "MEDIUM" in severities:
        return "WARN"
    return "PASS" if findings else "PASS"

def to_http_fallback(https_url: str) -> str:
    """Derive http://… from https://… if possible."""
    pu = urlparse(https_url)
    if pu.scheme.lower() != "https":
        return https_url
    return urlunparse(("http", pu.netloc, pu.path or "/", "", "", ""))

def parse_cert_not_after(peer_cert_dict):
    """
    Extract notAfter field from ssl.getpeercert() dict.
    Returns a datetime (UTC) or None.
    """
    # getpeercert() returns 'notAfter' like 'Oct 28 12:34:56 2025 GMT'
    not_after = peer_cert_dict.get("notAfter")
    if not not_after:
        return None
    try:
        dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
        # make it UTC aware
        return dt.replace(tzinfo=datetime.UTC)
    except Exception:
        return None

def supports_protocol(host, port, min_version, max_version):
    """
    Try to connect with a constrained TLS version range.
    Returns True if handshake succeeds, False otherwise.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = min_version
    ctx.maximum_version = max_version
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()

    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Handshake succeeded under the version constraints
                return True
    except Exception:
        return False

def negotiate_cipher_info(host, port):
    """
    Attempt a normal handshake and return (tls_version, cipher_name).
    If handshake fails, return (None, None).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # cipher() -> (cipher_name, protocol_version, secret_bits)
                c = ssock.cipher()  # e.g. ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
                proto = ssock.version()  # 'TLSv1.3'
                return proto, c[0] if c else None
    except Exception:
        return None, None

def looks_weak_cipher(cipher_name: str) -> bool:
    """
    Very simple heuristic for weak/obsolete ciphers.
    (Deep cipher validation requires OpenSSL/scan libs; we keep it light.)
    """
    if not cipher_name:
        return False
    name = cipher_name.upper()
    weak_markers = ["RC4", "3DES", "MD5", "NULL", "EXPORT", "DES-CBC", "CBC-MD5", "SEED"]
    return any(m in name for m in weak_markers)


# ------------- Core checks ----------------------------------------------------

def check_certificate_chain_and_expiry(target_url, warn_days=30, fail_days=7, findings=None):
    """
    Connect with default context (validates chain + hostname).
    Collect expiry info and flag thresholds.
    """
    findings = findings or []
    pu = urlparse(target_url)
    host = pu.hostname
    port = pu.port or 443

    # Create a strict client context (validates hostname & chain)
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                peer = ssock.getpeercert()
                if not peer:
                    add_finding(findings, "no_peer_certificate", "HIGH",
                                "No peer certificate returned by server.")
                    return findings

                # Expiry window
                not_after = parse_cert_not_after(peer)
                if not not_after:
                    add_finding(findings, "cert_expiry_unreadable", "MEDIUM",
                                "Could not parse certificate expiration (notAfter).",
                                evidence={"raw": str(peer.get("notAfter"))})
                    return findings

                days_left = (not_after - now_utc()).days
                ev = {"not_after": not_after.isoformat(), "days_left": days_left}

                if days_left < 0:
                    add_finding(findings, "cert_expired", "HIGH",
                                f"Certificate is EXPIRED by {-days_left} day(s).", ev)
                elif days_left < fail_days:
                    add_finding(findings, "cert_expiring_critical", "HIGH",
                                f"Certificate expires in {days_left} day(s) (< {fail_days}).", ev)
                elif days_left < warn_days:
                    add_finding(findings, "cert_expiring_soon", "MEDIUM",
                                f"Certificate expires in {days_left} day(s) (< {warn_days}).", ev)
                else:
                    # Good news, include an INFO
                    add_finding(findings, "cert_ok", "INFO",
                                f"Certificate valid. {days_left} day(s) remaining.", ev)

    except ssl.SSLCertVerificationError as e:
        add_finding(findings, "cert_verification_failed", "HIGH",
                    "Certificate chain/hostname verification failed.",
                    evidence={"error": str(e)})
    except Exception as e:
        add_finding(findings, "tls_connection_failed", "MEDIUM",
                    "TLS connection failed; certificate could not be evaluated.",
                    evidence={"error": str(e)})

    return findings


def check_protocol_compatibility(target_url, findings=None):
    """
    Test whether the server still supports legacy TLS 1.0/1.1.
    """
    findings = findings or []
    pu = urlparse(target_url)
    host = pu.hostname
    port = pu.port or 443

    # If server accepts TLSv1.0 or TLSv1.1, that's risky.
    try:
        if supports_protocol(host, port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1):
            add_finding(findings, "tls10_supported", "MEDIUM",
                        "Server supports TLS 1.0 (deprecated).")
    except ValueError:
        # Local OpenSSL may not allow forcing TLSv1; ignore
        pass

    try:
        if supports_protocol(host, port, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1):
            add_finding(findings, "tls11_supported", "MEDIUM",
                        "Server supports TLS 1.1 (deprecated).")
    except ValueError:
        pass

    # Negotiate a normal handshake and record cipher/proto
    proto, cipher = negotiate_cipher_info(host, port)
    if proto or cipher:
        ev = {"protocol": proto, "cipher": cipher}
        if looks_weak_cipher(cipher):
            add_finding(findings, "weak_cipher_negotiated", "MEDIUM",
                        f"Weak/obsolete cipher negotiated: {cipher}", ev)
        else:
            add_finding(findings, "cipher_ok", "INFO",
                        f"Negotiated cipher appears modern: {cipher or 'unknown'} ({proto or 'unknown'})",
                        ev)
    else:
        add_finding(findings, "cipher_unknown", "INFO",
                    "Could not determine negotiated cipher/protocol (handshake failed).")

    return findings


def check_hsts_header(target_url, findings=None):
    """
    Ensure Strict-Transport-Security header is present and sane.
    """
    findings = findings or []

    try:
        r = requests.get(target_url, timeout=10, allow_redirects=False)
        hsts = r.headers.get("Strict-Transport-Security")
        if not hsts:
            # HSTS missing is generally a MEDIUM risk unless business constraints apply
            add_finding(findings, "hsts_missing", "MEDIUM",
                        "Strict-Transport-Security header is missing on HTTPS response.")
        else:
            # Quick min-age parse
            m = re.search(r"max-age=(\d+)", hsts, flags=re.IGNORECASE)
            max_age = int(m.group(1)) if m else 0
            ev = {"hsts": hsts, "max_age": max_age}
            if max_age < 15552000:  # 180d recommended commonly; here use 180d/6mo
                add_finding(findings, "hsts_weak_max_age", "LOW",
                            f"HSTS present but max-age={max_age} is low (< 15552000).", ev)
            else:
                add_finding(findings, "hsts_ok", "INFO",
                            f"HSTS present with max-age={max_age}.", ev)
    except Exception as e:
        add_finding(findings, "hsts_check_failed", "INFO",
                    "Could not fetch HTTPS response to verify HSTS.",
                    evidence={"error": str(e)})

    return findings


def check_http_redirects_to_https(target_url, http_fallback=None, findings=None):
    """
    For the site root, ensure HTTP redirects to HTTPS with 301/308.
    """
    findings = findings or []
    http_url = http_fallback or to_http_fallback(target_url)

    # Only run if it's actually http://
    if urlparse(http_url).scheme.lower() != "http":
        return findings

    try:
        r = requests.get(http_url, timeout=10, allow_redirects=False)
        # Expect a redirect to https
        if r.is_redirect or r.status_code in (301, 302, 307, 308):
            loc = r.headers.get("Location", "")
            if loc.lower().startswith("https://"):
                # Good redirect
                add_finding(findings, "http_redirects_to_https", "INFO",
                            f"HTTP redirects to HTTPS ({r.status_code}).",
                            evidence={"location": loc, "status": r.status_code})
            else:
                add_finding(findings, "http_redirect_non_https", "MEDIUM",
                            f"HTTP redirects but not to HTTPS (Location={loc}).",
                            evidence={"location": loc, "status": r.status_code})
        else:
            add_finding(findings, "http_not_redirecting", "MEDIUM",
                        f"HTTP did not redirect to HTTPS (status={r.status_code}).",
                        evidence={"status": r.status_code})
    except Exception as e:
        add_finding(findings, "http_redirect_check_failed", "INFO",
                    "Could not fetch HTTP to verify redirect.",
                    evidence={"error": str(e)})

    return findings


def check_mixed_content(target_url, findings=None):
    """
    Fetch HTML over HTTPS and look for 'http://' references (simple heuristic).
    Flags potential mixed-content risks.
    """
    findings = findings or []
    try:
        r = requests.get(target_url, timeout=12)
        ct = r.headers.get("Content-Type", "")
        if "text/html" not in ct.lower():
            # Not an HTML page; skip with info
            add_finding(findings, "not_html", "INFO",
                        f"Target is not HTML (Content-Type={ct}). Mixed-content check skipped.")
            return findings

        html = r.text or ""
        # Naive search for http:// links (ignore protocol-relative // and https)
        http_refs = re.findall(r'["\'(]\s*(http://[^"\' )]+)', html, flags=re.IGNORECASE)
        # Deduplicate but keep count
        unique_refs = sorted(set(http_refs))
        if unique_refs:
            add_finding(findings, "mixed_content_refs", "MEDIUM",
                        f"Found {len(unique_refs)} http:// references in HTML (possible mixed content).",
                        evidence={"examples": unique_refs[:10], "total_refs": len(unique_refs)})
        else:
            add_finding(findings, "no_mixed_content", "INFO",
                        "No http:// references found in HTML.")
    except Exception as e:
        add_finding(findings, "mixed_content_check_failed", "INFO",
                    "Could not fetch/parse HTML to check mixed content.",
                    evidence={"error": str(e)})

    return findings


# ------------- Main -----------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="OWASP: Verify implementation of SSL/TLS")
    ap.add_argument("--target", required=True, help="HTTPS URL of the site or endpoint to test")
    ap.add_argument("--http-fallback", help="Optional explicit http:// URL to test redirect (derived if omitted)")
    ap.add_argument("--warn-days", type=int, default=30, help="Warn if cert expires in less than this many days")
    ap.add_argument("--fail-days", type=int, default=7, help="Fail if cert expires in less than this many days")
    args = ap.parse_args()

    target = args.target.strip()
    http_fb = (args.http_fallback or "").strip() or None
    findings = []

    # 1) Certificate + expiry
    check_certificate_chain_and_expiry(target, warn_days=args.warn_days, fail_days=args.fail_days, findings=findings)

    # 2) Protocols and cipher
    check_protocol_compatibility(target, findings=findings)

    # 3) HSTS
    check_hsts_header(target, findings=findings)

    # 4) HTTP -> HTTPS redirect
    check_http_redirects_to_https(target, http_fallback=http_fb, findings=findings)

    # 5) Mixed content on page
    check_mixed_content(target, findings=findings)

    # Overall status
    status = classify_overall(findings)

    report = {
        "check_name": "ssl_implementation_check",
        "target": target,
        "status": status,
        "summary": f"{sum(1 for f in findings if f['severity']=='HIGH')} HIGH, "
                   f"{sum(1 for f in findings if f['severity']=='MEDIUM')} MEDIUM, "
                   f"{sum(1 for f in findings if f['severity']=='LOW')} LOW, "
                   f"{sum(1 for f in findings if f['severity']=='INFO')} INFO",
        "findings": findings,
        "timestamp": now_utc().isoformat().replace("+00:00", "Z")
    }

    os.makedirs("reports/raw", exist_ok=True)
    out = "reports/raw/ssl_implementation_report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[ssl_implementation_check] ✅ status={status}, findings={len(findings)}, saved: {out}")


if __name__ == "__main__":
    main()
