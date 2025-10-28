#!/usr/bin/env python3
"""
request_efficiency_check.py
-------------------------------------------------
OWASP Web Check: Verify the web application makes API requests only when required.

WHAT THIS CHECK DOES
- Replays one or more API endpoints several times (default: 3)
- Detects redundant calls (identical responses repeatedly)
- Flags empty/useless responses
- Measures latency (P50/P95) and payload sizes
- Produces a structured JSON report your HTML dashboard can consume

WHY IT MATTERS (OWASP context)
- Redundant calls expand attack surface, waste resources, and can amplify DoS
- Repeated responses without change suggest missing caching or unnecessary polling
- Empty responses may indicate poorly designed API usage or error hiding

USAGE (two modes)

A) Simple (backwards compatible with your checks.yml):
   python3 src/request_efficiency_check.py --target https://example.com

   -> The script will look for `data/api_endpoints.json` and test each endpoint there.
      (If that file is absent, it falls back to a few sensible defaults under the same base URL.)

B) Explicit config file:
   python3 src/request_efficiency_check.py --config data/api_endpoints.json

   Example `data/api_endpoints.json`:
   {
     "base_url": "https://example.com",
     "repeat": 3,
     "think_time_ms": 100,
     "endpoints": [
       {"path": "/api/profile", "method": "GET"},
       {"path": "/api/notifications", "method": "GET"},
       {"path": "/api/cart", "method": "GET"}
     ]
   }

TUNING THRESHOLDS (optional CLI flags)
  --dup-warn 1         # >= this many duplicate responses → WARN
  --dup-fail 2         # >= this many duplicate responses → FAIL
  --empty-warn 1       # >= this many empty responses   → WARN
  --p95-warn 800       # p95 latency (ms) above this    → WARN
  --p95-fail 1500      # p95 latency (ms) above this    → FAIL

OUTPUT
  reports/raw/request_efficiency_report.json
  {
    "check_name": "request_efficiency",
    "status": "PASS|WARN|FAIL|ERROR",
    "summary": "...",
    "metrics": {...},
    "findings": [
      {
        "endpoint": "GET https://example.com/api/profile",
        "repeats": 3,
        "duplicates": 2,
        "empty_responses": 0,
        "p50_ms": 110,
        "p95_ms": 130,
        "avg_size_bytes": 1829,
        "severity": "HIGH|MEDIUM|INFO|ERROR",
        "detail": "2 duplicate responses, 0 empty responses. p95=130ms."
      }
    ],
    "timestamp": "..."
  }
"""

from __future__ import annotations

import os
import re
import json
import time
import math
import argparse
import statistics
from hashlib import sha256
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import requests


# -----------------------------
# Helpers: safe JSON & hashing
# -----------------------------
def _safe_json_parse(text: str):
    """Try to parse JSON; return None if not valid JSON."""
    try:
        return json.loads(text)
    except Exception:
        return None


def _content_is_empty(text: str, obj: Any) -> bool:
    """
    Consider responses 'empty' if:
      - blank/whitespace-only string
      - JSON {} or [] (after successful parse)
    """
    if obj is not None:
        if isinstance(obj, dict) and not obj:
            return True
        if isinstance(obj, list) and len(obj) == 0:
            return True
    return (text or "").strip() == ""


def _classify_severity(duplicates: int,
                       empty_count: int,
                       p95_ms: float,
                       dup_warn: int,
                       dup_fail: int,
                       empty_warn: int,
                       p95_warn: float,
                       p95_fail: float) -> Tuple[str, List[str]]:
    """
    Decide severity for one endpoint based on rule-of-thumb thresholds.
    Returns (severity, reasons[])
    """
    reasons = []
    severity = "INFO"

    # Duplicates
    if duplicates >= dup_fail:
        severity = "HIGH"
        reasons.append(f"{duplicates} duplicate responses (>= dup_fail {dup_fail})")
    elif duplicates >= dup_warn:
        severity = max(severity, "MEDIUM", key=lambda s: ["INFO", "MEDIUM", "HIGH"].index(s))
        reasons.append(f"{duplicates} duplicate responses (>= dup_warn {dup_warn})")

    # Empty
    if empty_count >= empty_warn:
        # empty responses are significant but usually medium unless extreme
        new_sev = "MEDIUM" if empty_count == 1 else "HIGH"
        if ["INFO", "MEDIUM", "HIGH"].index(new_sev) > ["INFO", "MEDIUM", "HIGH"].index(severity):
            severity = new_sev
        reasons.append(f"{empty_count} empty responses (>= empty_warn {empty_warn})")

    # Latency
    if p95_ms is not None:
        if p95_ms >= p95_fail:
            severity = "HIGH"
            reasons.append(f"p95 latency {int(p95_ms)}ms >= p95_fail {int(p95_fail)}ms")
        elif p95_ms >= p95_warn:
            if severity == "INFO":
                severity = "MEDIUM"
            reasons.append(f"p95 latency {int(p95_ms)}ms >= p95_warn {int(p95_warn)}ms")

    return severity, reasons


def _status_rollup(endpoint_severities: List[str]) -> str:
    """
    Compute overall check status from endpoint severities.
    Order: FAIL(HIGH present) > WARN(MEDIUM present) > PASS
    NOTE:
      - If any endpoint has severity=ERROR, we return FAIL.
      - If at least one HIGH → FAIL
      - Else if at least one MEDIUM → WARN
      - Else PASS
    """
    if any(s == "ERROR" for s in endpoint_severities):
        return "FAIL"
    if any(s == "HIGH" for s in endpoint_severities):
        return "FAIL"
    if any(s == "MEDIUM" for s in endpoint_severities):
        return "WARN"
    return "PASS"


# -----------------------------
# Core runner for one endpoint
# -----------------------------
def _exercise_endpoint(base_url: str,
                       ep: Dict[str, Any],
                       repeat: int,
                       think_time_ms: int,
                       session: requests.Session) -> Dict[str, Any]:
    """
    Call a single endpoint multiple times, collect metrics and decide severity.
    ep fields:
      - path (required) e.g. "/api/profile"
      - method (default "GET")
      - headers (optional dict)
      - body (optional dict or string)
      - timeout_ms (optional int)
    """
    method = (ep.get("method") or "GET").upper()
    path = ep["path"]
    headers = ep.get("headers", {})
    body = ep.get("body")
    timeout_ms = ep.get("timeout_ms", 10000)  # default 10s
    timeout_sec = timeout_ms / 1000.0

    url = path if path.startswith("http") else f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    hashes: List[str] = []
    latencies_ms: List[float] = []
    sizes: List[int] = []
    http_codes: List[int] = []
    empty_flags: List[bool] = []
    errors: List[str] = []

    for i in range(repeat):
        try:
            t0 = time.perf_counter()
            if method == "GET":
                resp = session.get(url, headers=headers, timeout=timeout_sec)
            elif method == "POST":
                # If body is dict, requests will JSON-encode if json=body, else raw string via data
                if isinstance(body, dict):
                    resp = session.post(url, headers=headers, json=body, timeout=timeout_sec)
                else:
                    resp = session.post(url, headers=headers, data=body, timeout=timeout_sec)
            else:
                # Fallback to GET for unknown
                resp = session.request(method, url, headers=headers, data=body, timeout=timeout_sec)

            dt_ms = (time.perf_counter() - t0) * 1000.0

            text = resp.text or ""
            obj = _safe_json_parse(text)
            content_hash = sha256(text.encode("utf-8", errors="ignore")).hexdigest()
            is_empty = _content_is_empty(text, obj)

            hashes.append(content_hash)
            latencies_ms.append(dt_ms)
            sizes.append(len(resp.content or b""))
            http_codes.append(resp.status_code)
            empty_flags.append(is_empty)

        except Exception as e:
            # Record error and mark this repetition as ERROR
            errors.append(str(e))
            latencies_ms.append(math.nan)
            sizes.append(0)
            http_codes.append(-1)
            empty_flags.append(True)

        # small pause to mimic think time
        if think_time_ms > 0 and i < (repeat - 1):
            time.sleep(think_time_ms / 1000.0)

    # Metrics
    duplicates = len(hashes) - len(set(hashes))
    empty_responses = sum(1 for f in empty_flags if f)
    # compute p50/p95 safely ignoring NaNs
    valid_latencies = [x for x in latencies_ms if not math.isnan(x)]
    p50 = statistics.median(valid_latencies) if valid_latencies else None
    p95 = None
    if valid_latencies:
        sorted_lat = sorted(valid_latencies)
        # 95th percentile (nearest-rank method)
        idx = max(0, min(len(sorted_lat) - 1, math.ceil(0.95 * len(sorted_lat)) - 1))
        p95 = sorted_lat[idx]
    avg_size = int(sum(sizes) / max(1, len(sizes)))

    endpoint_label = f"{method} {url}"

    return {
        "endpoint": endpoint_label,
        "repeats": repeat,
        "http_codes": http_codes,
        "duplicates": duplicates,
        "empty_responses": empty_responses,
        "p50_ms": None if p50 is None else round(p50, 1),
        "p95_ms": None if p95 is None else round(p95, 1),
        "avg_size_bytes": avg_size,
        "errors": errors
    }


# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="OWASP: Request Efficiency Check")
    # Back-compat with your current checks.yml:
    parser.add_argument("--target", help="Base URL (used with data/api_endpoints.json if present)")
    # Preferred config option:
    parser.add_argument("--config", help="Path to JSON config (e.g. data/api_endpoints.json)")

    # Threshold tuning (defaults are sane)
    parser.add_argument("--repeat", type=int, default=None, help="Override repeat count for all endpoints")
    parser.add_argument("--think-time", type=int, default=None, help="Override think time (ms) between calls")

    parser.add_argument("--dup-warn", type=int, default=1, help="Duplicates >= dup-warn ⇒ WARN")
    parser.add_argument("--dup-fail", type=int, default=2, help="Duplicates >= dup-fail ⇒ FAIL")
    parser.add_argument("--empty-warn", type=int, default=1, help="Empty responses >= this ⇒ WARN")
    parser.add_argument("--p95-warn", type=int, default=800, help="p95 latency (ms) ≥ this ⇒ WARN")
    parser.add_argument("--p95-fail", type=int, default=1500, help="p95 latency (ms) ≥ this ⇒ FAIL")

    args = parser.parse_args()

    # Resolve configuration
    cfg_path = args.config
    base_url = args.target

    config: Dict[str, Any] = {}

    # If an explicit config file is provided, use it
    if cfg_path and os.path.isfile(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as fh:
            config = json.load(fh)
        if not base_url:
            base_url = config.get("base_url")
    else:
        # If not provided, we try the default file when a target is passed
        default_cfg = "data/api_endpoints.json"
        if os.path.isfile(default_cfg):
            with open(default_cfg, "r", encoding="utf-8") as fh:
                config = json.load(fh)
            if not base_url:
                base_url = config.get("base_url")
        else:
            # Last resort: minimal fallback config if neither file exists
            config = {
                "repeat": 3,
                "think_time_ms": 100,
                "endpoints": [
                    {"path": "/api/profile", "method": "GET"},
                    {"path": "/api/notifications", "method": "GET"},
                    {"path": "/api/cart", "method": "GET"}
                ]
            }

    if not base_url:
        print("❌ No base URL provided. Use --target or a config file with 'base_url'.")
        # Write a minimal ERROR report so the dashboard won’t break
        os.makedirs("reports/raw", exist_ok=True)
        with open("reports/raw/request_efficiency_report.json", "w", encoding="utf-8") as out:
            json.dump({
                "check_name": "request_efficiency",
                "status": "ERROR",
                "summary": "Missing base URL (use --target or config file).",
                "findings": [],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }, out, indent=2)
        return

    repeat = args.repeat if args.repeat is not None else int(config.get("repeat", 3))
    think_time_ms = args.think_time if args.think_time is not None else int(config.get("think_time_ms", 100))
    endpoints = config.get("endpoints", [])

    # Basic validation
    if not isinstance(endpoints, list) or len(endpoints) == 0:
        print("⚠️ No endpoints configured; writing WARN report.")
        os.makedirs("reports/raw", exist_ok=True)
        with open("reports/raw/request_efficiency_report.json", "w", encoding="utf-8") as out:
            json.dump({
                "check_name": "request_efficiency",
                "status": "WARN",
                "summary": "No endpoints provided to test.",
                "findings": [],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }, out, indent=2)
        return

    session = requests.Session()
    session.headers.update({"User-Agent": "OWASP_Automation/1.0"})

    findings: List[Dict[str, Any]] = []
    for ep in endpoints:
        if "path" not in ep:
            continue
        result = _exercise_endpoint(base_url, ep, repeat, think_time_ms, session)

        # Classify severity for this endpoint
        severity, reasons = _classify_severity(
            duplicates=result["duplicates"],
            empty_count=result["empty_responses"],
            p95_ms=(result["p95_ms"] or 0.0),
            dup_warn=args.dup_warn,
            dup_fail=args.dup_fail,
            empty_warn=args.empty_warn,
            p95_warn=args.p95_warn,
            p95_fail=args.p95_fail
        )

        # If there were request exceptions, escalate to ERROR for this endpoint
        if result.get("errors"):
            severity = "ERROR"
            reasons.append(f"{len(result['errors'])} request error(s)")

        result["severity"] = severity
        result["detail"] = (
            f"{result['duplicates']} duplicate responses, "
            f"{result['empty_responses']} empty responses. "
            f"p50={result['p50_ms']}ms, p95={result['p95_ms']}ms, "
            f"avg_size={result['avg_size_bytes']} bytes."
            + (f" Errors: {len(result['errors'])}" if result.get("errors") else "")
        )
        if reasons:
            result["reasons"] = reasons
        findings.append(result)

    # Roll up overall status
    endpoint_severities = [f["severity"] for f in findings]
    overall = _status_rollup(endpoint_severities)

    # Aggregate metrics across endpoints
    total_calls = sum(f["repeats"] for f in findings)
    total_dups = sum(f["duplicates"] for f in findings)
    total_empty = sum(f["empty_responses"] for f in findings)
    # compute a rough overall p95 (take max p95 across endpoints)
    global_p95s = [f["p95_ms"] for f in findings if f["p95_ms"] is not None]
    overall_p95 = max(global_p95s) if global_p95s else None

    summary = (
        f"Endpoints tested: {len(findings)} | Total calls: {total_calls} | "
        f"Duplicates: {total_dups} | Empty responses: {total_empty} | "
        f"Max p95 latency: {int(overall_p95)}ms" if overall_p95 is not None else
        f"Endpoints tested: {len(findings)} | Total calls: {total_calls} | "
        f"Duplicates: {total_dups} | Empty responses: {total_empty}"
    )

    report = {
        "check_name": "request_efficiency",
        "status": overall,
        "summary": summary,
        "metrics": {
            "endpoints": len(findings),
            "total_calls": total_calls,
            "total_duplicates": total_dups,
            "total_empty_responses": total_empty,
            "max_p95_latency_ms": None if overall_p95 is None else int(overall_p95)
        },
        "findings": findings,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    os.makedirs("reports/raw", exist_ok=True)
    out_path = "reports/raw/request_efficiency_report.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"[request_efficiency_check] ✅ status={overall}, findings={len(findings)}, saved: {out_path}")
