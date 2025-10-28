#!/usr/bin/env python3
"""
cors_policy_check.py
-------------------------------------------------
OWASP Web Check: Verify implementation of CORS policy.

Goal:
  Detect unsafe CORS configurations such as:
    - Access-Control-Allow-Origin: * (especially with credentials)
    - Reflection of arbitrary Origin
    - Overly-permissive allowed headers (e.g., Authorization or *)
    - Overly-permissive methods (e.g., PUT, DELETE everywhere)
    - Missing Vary: Origin when returning specific origins
    - Allow-Credentials true with wildcard or reflective origins

Outputs:
  - JSON report at reports/raw/cors_policy_report.json
    with normalized fields for your dashboard.

How it works (browser-like):
  1) Send a preflight OPTIONS request with headers:
       Origin, Access-Control-Request-Method, Access-Control-Request-Headers
  2) Send an actual GET/POST with Origin header.
  3) Evaluate CORS response headers per origin/method pair.

Severity model:
  HIGH:
    - ACAO == "*" AND ACA-Credentials == "true"
    - Reflecting arbitrary Origin (non-trusted) + credentials
  MEDIUM:
    - ACAO == "*" on sensitive paths (/api, /auth) or general
    - Missing Vary: Origin when ACAO returns a specific origin
    - Allowing Authorization or "*" in ACA-Headers broadly
  LOW:
    - Allowing many methods broadly (PUT, DELETE) without reason
  INFO:
    - No ACAO (CORS disabled) – not a vuln itself, but noted
  PASS:
    - No findings

CLI:
  python3 src/cors_policy_check.py \
    --target https://example.com/api \
    --origins https://example.com,https://evil.example,null \
    --methods GET,POST \
    --request-headers Authorization,Content-Type
"""

import os
import json
import argparse
import datetime
from urllib.parse import urlparse
import requests

# -------------------------
# Utility helpers
# -------------------------

def norm(s):
    """Normalize header strings safely."""
    if s is None:
        return ""
    return str(s).strip()

def header(d, key):
    """Case-insensitive header getter."""
    for k, v in d.items():
        if k.lower() == key.lower():
            return v
    return None

def is_sensitive_path(url):
    """Heuristic: treat certain paths as sensitive APIs."""
    p = urlparse(url).path.lower()
    return any(x in p for x in ("/api", "/auth", "/admin", "/token", "/session"))

def classify_severity(findings):
    """
    Decide overall status from individual findings:
      - Any HIGH -> FAIL
      - Else any MEDIUM -> WARN
      - Else any LOW/INFO -> PASS (with informational notes)
      - Else -> PASS
    """
    severities = {f.get("severity", "INFO") for f in findings}
    if "HIGH" in severities:
        return "FAIL"
    if "MEDIUM" in severities:
        return "WARN"
    return "PASS"

def add_finding(findings, issue, severity, origin, method, detail, evidence):
    findings.append({
        "issue": issue,
        "severity": severity,
        "origin": origin,
        "method": method,
        "detail": detail,
        "evidence": evidence
    })

# -------------------------
# CORS logic
# -------------------------

def evaluate_cors_for_origin(target, origin, methods, req_headers):
    """
    For one origin, run preflight + actual requests over each method and analyze.
    Returns a list of finding dicts.
    """
    findings = []
    sess = requests.Session()
    common_timeout = 15

    # Normalize request headers list
    req_headers_list = [h.strip() for h in (req_headers or "").split(",") if h.strip()]
    req_headers_join = ",".join(req_headers_list) if req_headers_list else ""

    for method in methods:
        # 1) Preflight OPTIONS
        preflight_headers = {
            "Origin": origin if origin != "null" else "null",
            "Access-Control-Request-Method": method,
        }
        if req_headers_join:
            preflight_headers["Access-Control-Request-Headers"] = req_headers_join

        try:
            pre = sess.options(target, headers=preflight_headers, timeout=common_timeout, allow_redirects=False)
            pre_hdrs = pre.headers or {}

        except Exception as e:
            add_finding(
                findings,
                "preflight_error",
                "INFO",
                origin,
                method,
                f"Preflight request failed: {e}",
                {"exception": str(e)}
            )
            pre = None
            pre_hdrs = {}

        # 2) Actual request (GET or POST; for POST send a tiny body)
        actual_headers = {"Origin": origin if origin != "null" else "null"}
        data = None
        try:
            if method.upper() == "GET":
                act = sess.get(target, headers=actual_headers, timeout=common_timeout, allow_redirects=False)
            else:
                data = {"ping": "pong"}
                act = sess.request(method.upper(), target, headers=actual_headers, data=data,
                                   timeout=common_timeout, allow_redirects=False)
            act_hdrs = act.headers or {}
            act_status = act.status_code
        except Exception as e:
            add_finding(
                findings,
                "actual_error",
                "INFO",
                origin,
                method,
                f"Actual request failed: {e}",
                {"exception": str(e)}
            )
            act = None
            act_hdrs = {}
            act_status = None

        # Extract CORS headers
        acao = norm(header(pre_hdrs or {}, "Access-Control-Allow-Origin") or header(act_hdrs, "Access-Control-Allow-Origin"))
        acac = norm(header(pre_hdrs or {}, "Access-Control-Allow-Credentials") or header(act_hdrs, "Access-Control-Allow-Credentials"))
        acah = norm(header(pre_hdrs or {}, "Access-Control-Allow-Headers") or header(act_hdrs, "Access-Control-Allow-Headers"))
        acam = norm(header(pre_hdrs or {}, "Access-Control-Allow-Methods") or header(act_hdrs, "Access-Control-Allow-Methods"))
        vary = norm(header(pre_hdrs or {}, "Vary") or header(act_hdrs, "Vary"))

        # Evidence snapshot for report
        evidence = {
            "preflight_status": getattr(pre, "status_code", None),
            "actual_status": act_status,
            "acao": acao,
            "acac": acac,
            "acah": acah,
            "acam": acam,
            "vary": vary
        }

        # -------------------------
        # Findings rules
        # -------------------------

        # No CORS at all -> informative (not a vuln by itself)
        if acao == "":
            add_finding(
                findings,
                "no_cors_headers",
                "INFO",
                origin,
                method,
                "No Access-Control-Allow-Origin returned. Cross-origin JS cannot read responses.",
                evidence
            )
            # Continue to next method
            continue

        # Wildcard origin
        if acao == "*":
            sev = "MEDIUM"
            if is_sensitive_path(target):
                sev = "MEDIUM"  # keep MEDIUM; many orgs treat as HIGH on sensitive endpoints
            add_finding(
                findings,
                "wildcard_origin",
                sev,
                origin,
                method,
                "Access-Control-Allow-Origin is '*', allowing any origin to make cross-origin reads.",
                evidence
            )

            # Wildcard + credentials is forbidden and dangerous
            if acac.lower() == "true":
                add_finding(
                    findings,
                    "wildcard_with_credentials",
                    "HIGH",
                    origin,
                    method,
                    "ACA-Origin '*' with ACA-Credentials 'true' is invalid and effectively unsafe if mis-implemented.",
                    evidence
                )

        # Reflected or overly-permissive specific origin
        # If the response echoes the supplied Origin (not your trusted origin), that suggests reflection.
        elif acao.lower() == (origin if origin != "null" else "null").lower():
            # If it's a known good origin (e.g., same as target host), treat as OK if Vary is correct.
            target_host = urlparse(target).netloc
            origin_host = urlparse(origin).netloc if origin not in ("null", "") else ""
            same_site = (origin_host == target_host) and (origin_host != "")

            # Reflection of potentially untrusted origin
            if not same_site:
                sev = "MEDIUM"
                if acac.lower() == "true":
                    sev = "HIGH"
                add_finding(
                    findings,
                    "reflected_origin",
                    sev,
                    origin,
                    method,
                    f"Server reflects Origin '{origin}'. If origin is untrusted and credentials are allowed, this is dangerous.",
                    evidence
                )

            # If returning a specific allowed origin, Vary: Origin should be present (to prevent cache poisoning).
            if vary and "origin" not in vary.lower():
                add_finding(
                    findings,
                    "missing_vary_origin",
                    "MEDIUM",
                    origin,
                    method,
                    "Server returns specific ACAO but missing 'Vary: Origin' – can cause cache mixing across origins.",
                    evidence
                )

        # Allowed headers too broad (e.g., '*') or sensitive ones like Authorization
        if acah:
            lower_acah = acah.lower()
            if "*" in lower_acah:
                add_finding(
                    findings,
                    "overly_permissive_headers",
                    "MEDIUM",
                    origin,
                    method,
                    "Access-Control-Allow-Headers includes '*', allowing any custom headers.",
                    evidence
                )
            if "authorization" in lower_acah:
                add_finding(
                    findings,
                    "authorization_header_allowed",
                    "MEDIUM",
                    origin,
                    method,
                    "Access-Control-Allow-Headers allows 'Authorization' header; ensure this is intended and locked to trusted origins only.",
                    evidence
                )

        # Allowed methods too broad
        if acam:
            methods_set = {m.strip().upper() for m in acam.split(",")}
            # If they’re allowing destructive methods widely, flag it
            if any(m in methods_set for m in ("PUT", "DELETE", "PATCH")) and acao in ("*", origin):
                add_finding(
                    findings,
                    "overly_permissive_methods",
                    "LOW",
                    origin,
                    method,
                    f"Access-Control-Allow-Methods allows potentially destructive methods ({acam}). Verify need and restrict to trusted origins.",
                    evidence
                )

        # Credentials with non-specific origin (handled above for wildcard, but also risky with reflection)
        if acac.lower() == "true" and acao in ("*", (origin if origin != "null" else "null")) and not is_sensitive_path(target):
            # If they're reflecting arbitrary origin with credentials, already flagged as HIGH
            pass  # Already covered by rules above

    return findings

def main():
    parser = argparse.ArgumentParser(description="OWASP: Verify implementation of CORS policy")
    parser.add_argument("--target", required=True, help="Target URL (API endpoint or page) to test CORS against")
    parser.add_argument("--origins", default="https://example.com,https://evil.example,null",
                        help="Comma-separated list of Origin values to simulate")
    parser.add_argument("--methods", default="GET,POST",
                        help="Comma-separated list of HTTP methods to test (e.g., GET,POST)")
    parser.add_argument("--request-headers", default="Authorization,Content-Type",
                        help="Comma-separated list for Access-Control-Request-Headers (preflight)")
    args = parser.parse_args()

    target = args.target.strip()
    origins = [o.strip() for o in args.origins.split(",") if o.strip()]
    methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    req_headers = args.request_headers.strip()

    print(f"🔍 CORS check on {target}")
    print(f"   Origins: {origins}")
    print(f"   Methods: {methods}")
    print(f"   Request-Headers: {req_headers or '(none)'}")

    all_findings = []
    for origin in origins:
        findings = evaluate_cors_for_origin(target, origin, methods, req_headers)
        all_findings.extend(findings)

    status = classify_severity(all_findings)
    if not all_findings:
        # No findings generated at all (e.g., network failures only) – mark as UNKNOWN
        status = "UNKNOWN"

    # Human summary
    highs = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    meds  = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
    lows  = sum(1 for f in all_findings if f.get("severity") == "LOW")
    infos = sum(1 for f in all_findings if f.get("severity") == "INFO")

    if status == "FAIL":
        summary = f"{highs} HIGH, {meds} MEDIUM findings — risky CORS configuration."
    elif status == "WARN":
        summary = f"No HIGH findings, but {meds} MEDIUM / {lows} LOW issues present."
    elif status == "PASS":
        summary = "CORS configuration looks safe for tested scenarios."
    else:
        summary = "Could not conclusively evaluate CORS (network/target behavior unclear)."

    report = {
        "check_name": "cors_policy_check",
        "target": target,
        "status": status,
        "summary": summary,
        "findings": all_findings,
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
    }

    os.makedirs("reports/raw", exist_ok=True)
    out = "reports/raw/cors_policy_report.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"[cors_policy_check] ✅ status={status}, findings={len(all_findings)}, saved: {out}")


if __name__ == "__main__":
    main()
