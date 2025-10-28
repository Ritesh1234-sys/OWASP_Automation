#!/usr/bin/env python3
"""
request_timeout_check.py

OWASP check: Verify server-side request timeouts are implemented.

Features added in this version:
- TLS (HTTPS) support for the slow-post and idle-connection raw-socket checks using ssl.wrap_socket.
- Per-subtest "severity" mapping (HIGH / MEDIUM / LOW / INFO) based on result.
- Produces consistent JSON report compatible with the dashboard generator.
- Conservative defaults (safe for staging environments).

Usage examples:
  python3 src/request_timeout_check.py \
    --target http://127.0.0.1:5001/login \
    --expected-timeout 30 \
    --slow-bytes 10240 \
    --slow-interval 2 \
    --concurrency 3 \
    --simple-endpoint /

Important safety note:
- Only run heavy tests against systems you control or have permission to test.
- The raw slow-post for HTTPS performs a TLS handshake (no certificate validation bypass).
"""

from __future__ import annotations
import argparse
import socket
import ssl
import time
import json
import os
import threading
import requests
from typing import Tuple, List, Dict
from datetime import datetime, timezone
from urllib.parse import urlparse

# -----------------------
# Defaults (conservative)
# -----------------------
DEFAULT_EXPECTED_TIMEOUT = 30         # seconds — expected server-side timeout
DEFAULT_SLOW_BYTES = 10 * 1024       # 10 KB total body
DEFAULT_SLOW_INTERVAL = 2.0          # seconds between chunks
DEFAULT_CHUNK_SIZE = 1024            # bytes per chunk
DEFAULT_CONCURRENCY = 5              # small number for light concurrency test
DEFAULT_SIMPLE_ENDPOINT = "/"        # used for concurrency test
REPORT_PATH_DEFAULT = "reports/raw/request_timeout_report.json"


# -----------------------
# Severity mapping helper
# -----------------------
def severity_for_result(result: str) -> str:
    """Map logical result to severity used in reports."""
    mapping = {
        "PASS": "Info",
        "SKIPPED": "Info",
        "WARN": "Medium",
        "FAIL": "High",
        "ERROR": "High"
    }
    return mapping.get(result, "Info")


# -----------------------
# Utilities: parse target
# -----------------------
def parse_target(url: str) -> Tuple[str, int, str, str]:
    """
    Return (host, port, path, scheme). Minimal parsing for http(s)://host[:port]/path
    """
    p = urlparse(url)
    scheme = p.scheme or "http"
    host = p.hostname
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path = path + "?" + p.query
    return host, port, path, scheme


# -----------------------
# Low-level slow POST (supports TLS)
# -----------------------
def slow_post_raw(host: str, port: int, path: str, expected_timeout: int,
                  total_bytes: int, chunk_size: int, interval: float,
                  use_tls: bool = False, server_hostname: str | None = None) -> Dict:
    """
    Perform a slow POST by sending headers and slowly streaming the body.
    Works over plain TCP or TLS depending on use_tls.

    Returns a dict with:
      - test: name
      - result: PASS/WARN/FAIL/ERROR/SKIPPED
      - severity: mapped severity
      - details: human text
      - timings: times (connect, duration)
      - raw_response_start: optional server bytes received
    """
    res = {
        "test": "slow_post",
        "result": None,
        "severity": None,
        "details": "",
        "timings": {},
        "raw_response_start": None
    }
    start = time.time()

    # create socket and optionally wrap with SSL
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        res["result"] = "ERROR"
        res["severity"] = severity_for_result(res["result"])
        res["details"] = f"Failed to connect: {e}"
        return res

    # perform TLS handshake if requested
    if use_tls:
        try:
            ctx = ssl.create_default_context()
            # do not set check_hostname False here — we use default validation
            wrapped = ctx.wrap_socket(sock, server_hostname=server_hostname or host)
            sock = wrapped
        except Exception as e:
            sock.close()
            res["result"] = "ERROR"
            res["severity"] = severity_for_result(res["result"])
            res["details"] = f"TLS handshake failed: {e}"
            return res

    res["timings"]["connect_time"] = time.time() - start

    # send headers with a large Content-Length
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: OWASP_Automation/RequestTimeoutChecker/1.0",
        "Content-Type: application/octet-stream",
        f"Content-Length: {total_bytes}",
        "Connection: close",
        "", ""
    ]
    try:
        sock.sendall("\r\n".join(headers).encode("utf-8"))
    except Exception as e:
        sock.close()
        res["result"] = "ERROR"
        res["severity"] = severity_for_result(res["result"])
        res["details"] = f"Failed sending headers: {e}"
        return res

    bytes_sent = 0
    first_response_time = None
    raw_resp = b""

    # set a short recv timeout so recv doesn't block forever
    sock.settimeout(1.0)

    try:
        while bytes_sent < total_bytes:
            # check for early server response
            try:
                chunk = sock.recv(4096)
                if chunk:
                    if not first_response_time:
                        first_response_time = time.time()
                    raw_resp += chunk
                    # server has replied early — break sending
                    break
            except socket.timeout:
                pass

            # send a chunk
            to_send = min(chunk_size, total_bytes - bytes_sent)
            try:
                sock.sendall(b"A" * to_send)
            except Exception as e:
                # likely server closed connection — treat as PASS
                res["result"] = "PASS"
                res["severity"] = severity_for_result(res["result"])
                res["details"] = f"Socket send failed (server closed connection) during streaming: {e}"
                break

            bytes_sent += to_send
            # wait between chunks
            time.sleep(interval)

            # exceeded expected timeout significantly? (grace 5s)
            if time.time() - start > expected_timeout + 5:
                # server did not close in time
                res["result"] = "WARN"
                res["severity"] = severity_for_result(res["result"])
                res["details"] = (f"Server did not close or respond within expected_timeout ({expected_timeout}s) "
                                  f"during slow send. Sent {bytes_sent}/{total_bytes} bytes.")
                break

        # after sending loop, try to read response bytes if any
        try:
            sock.settimeout(3.0)
            more = sock.recv(8192)
            if more:
                raw_resp += more
                if not first_response_time:
                    first_response_time = time.time()
        except Exception:
            pass

    finally:
        try:
            sock.close()
        except Exception:
            pass

    # classify based on raw_resp
    if raw_resp:
        # decode first line safely
        try:
            text = raw_resp.decode("utf-8", errors="ignore")
            res["raw_response_start"] = text.splitlines()[:10]
            # first non-empty line often contains HTTP status
            first_line = ""
            for ln in text.splitlines():
                ln = ln.strip()
                if ln:
                    first_line = ln
                    break
            if "408" in first_line or "Request Timeout" in text:
                res["result"] = "PASS"
                res["details"] = "Server returned 408/Request Timeout while slow-sending (good)."
            elif first_line.startswith("HTTP/") and len(first_line) >= 12 and first_line[9:12].isdigit():
                # numeric status parse
                code = int(first_line.split()[1]) if len(first_line.split()) > 1 and first_line.split()[1].isdigit() else None
                if code and 100 <= code < 300:
                    # server accepted request -> WARN/FAIL
                    res["result"] = res["result"] or "WARN"
                    res["details"] = res["details"] or "Server accepted slow body and returned successful status (may lack timeout)."
                elif code and 400 <= code < 500:
                    res["result"] = res["result"] or "PASS"
                    res["details"] = res["details"] or "Server rejected slow request with 4xx (good)."
                elif code and code >= 500:
                    res["result"] = res["result"] or "WARN"
                    res["details"] = res["details"] or "Server returned 5xx while slow-sending (server error)."
                else:
                    res["result"] = res["result"] or "WARN"
                    res["details"] = res["details"] or "Server returned unexpected status while slow-sending."
            else:
                # unknown response content; default to WARN if not set
                res["result"] = res["result"] or "WARN"
                res["details"] = res["details"] or "Server returned data but we couldn't classify it."
        except Exception as e:
            if not res["result"]:
                res["result"] = "WARN"
                res["details"] = f"Received response but classification failed: {e}"
    else:
        # no bytes received; if result not set, assume server closed socket -> PASS
        if not res["result"]:
            res["result"] = "PASS"
            res["details"] = "No response bytes and connection closed — server likely closed connection (expected)."

    res["timings"]["duration"] = time.time() - start
    res["severity"] = severity_for_result(res["result"])
    return res


# -----------------------
# Idle-connection test (supports TLS)
# -----------------------
def idle_connection_test(host: str, port: int, path: str, expected_timeout: int, use_tls: bool = False,
                         server_hostname: str | None = None) -> Dict:
    """
    Send headers and remain idle. Validate server closes or replies with 408 within expected_timeout.
    """
    r = {
        "test": "idle_connection",
        "result": None,
        "severity": None,
        "details": "",
        "timings": {}
    }
    start = time.time()

    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        r["result"] = "ERROR"
        r["severity"] = severity_for_result(r["result"])
        r["details"] = f"Connect failed: {e}"
        return r

    if use_tls:
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=server_hostname or host)
        except Exception as e:
            sock.close()
            r["result"] = "ERROR"
            r["severity"] = severity_for_result(r["result"])
            r["details"] = f"TLS handshake failed: {e}"
            return r

    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: OWASP_Automation/RequestTimeoutChecker/1.0",
        "Content-Length: 1000",
        "Connection: keep-alive",
        "", ""
    ]

    try:
        sock.sendall("\r\n".join(headers).encode("utf-8"))
    except Exception as e:
        sock.close()
        r["result"] = "ERROR"
        r["severity"] = severity_for_result(r["result"])
        r["details"] = f"Failed to send headers: {e}"
        return r

    r["timings"]["sent_headers_at"] = time.time() - start

    # Wait until expected_timeout + small grace (5s) for server to close/respond
    deadline = start + expected_timeout + 5
    sock.settimeout(1.0)
    closed_by_server = False
    try:
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
                if not data:
                    closed_by_server = True
                    break
                else:
                    # server sent some bytes — check for 408
                    if b"408" in data or b"Request Timeout" in data:
                        r["result"] = "PASS"
                        r["details"] = "Server returned 408/Request Timeout for idle connection."
                        closed_by_server = True
                        break
                    else:
                        r["result"] = "PASS"
                        r["details"] = "Server responded while idle (treated as enforcing timeout)."
                        closed_by_server = True
                        break
            except socket.timeout:
                # continue waiting
                pass
        if not closed_by_server:
            r["result"] = "WARN"
            r["details"] = f"Connection remained open beyond expected_timeout ({expected_timeout}s)."
    except Exception as e:
        r["result"] = "PASS"
        r["details"] = f"Socket error (server likely closed connection): {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    r["timings"]["duration"] = time.time() - start
    r["severity"] = severity_for_result(r["result"])
    return r


# -----------------------
# Light concurrency test using requests + threads
# -----------------------
def concurrency_test(simple_url: str, concurrency: int, timeout: int = 10) -> Dict:
    """
    Issue 'concurrency' parallel GET requests and measure failures/avg latency.
    Conservative default to avoid DoS.
    """
    results = {"test": "concurrency_light", "result": None, "severity": None, "details": "", "metrics": {}}
    latencies: List[float] = []
    failures = 0
    lock = threading.Lock()

    def worker():
        nonlocal failures
        try:
            t0 = time.time()
            resp = requests.get(simple_url, timeout=timeout, headers={"User-Agent": "OWASP_Automation/1.0"})
            lat = time.time() - t0
            with lock:
                latencies.append(lat)
                if resp.status_code >= 500:
                    failures += 1
        except Exception:
            with lock:
                failures += 1

    threads = []
    for _ in range(concurrency):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=timeout + 5)

    avg = sum(latencies) / len(latencies) if latencies else None
    results["metrics"] = {"requests": concurrency, "failures": failures, "avg_latency": avg}
    if failures == 0:
        results["result"] = "PASS"
        results["details"] = f"All {concurrency} requests succeeded. avg_latency={avg:.2f}s" if avg else "All requests succeeded."
    elif failures < concurrency:
        results["result"] = "WARN"
        results["details"] = f"{failures}/{concurrency} requests failed."
    else:
        results["result"] = "FAIL"
        results["details"] = "All concurrent requests failed."
    results["severity"] = severity_for_result(results["result"])
    return results


# -----------------------
# Combine results
# -----------------------
def combine_results(results: List[Dict]) -> Tuple[str, str]:
    """
    Overall status precedence: FAIL > WARN > PASS
    """
    has_fail = any(r.get("result") == "FAIL" for r in results)
    has_warn = any(r.get("result") == "WARN" for r in results)
    if has_fail:
        return "FAIL", "One or more sub-tests failed."
    if has_warn:
        return "WARN", "One or more sub-tests warned."
    return "PASS", "All sub-tests passed."


# -----------------------
# Entrypoint
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Verify server enforces request timeouts.")
    parser.add_argument("--target", required=True, help="Target URL for testing (e.g., http://127.0.0.1:5001/login)")
    parser.add_argument("--expected-timeout", type=int, default=DEFAULT_EXPECTED_TIMEOUT,
                        help=f"Expected server-side timeout in seconds (default {DEFAULT_EXPECTED_TIMEOUT})")
    parser.add_argument("--slow-bytes", type=int, default=DEFAULT_SLOW_BYTES,
                        help="Total bytes to send during slow-post test (default 10KB)")
    parser.add_argument("--slow-interval", type=float, default=DEFAULT_SLOW_INTERVAL,
                        help="Seconds between sending chunks in slow-post (default 2s)")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                        help="Bytes per chunk sent during slow POST")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help="Small concurrency level for light load test")
    parser.add_argument("--simple-endpoint", default=DEFAULT_SIMPLE_ENDPOINT,
                        help="Simple endpoint to hit for concurrency test (default '/')")
    parser.add_argument("--report-path", default=REPORT_PATH_DEFAULT, help="Where to save JSON report")
    args = parser.parse_args()

    host, port, path, scheme = parse_target(args.target)
    use_tls = (scheme == "https")
    server_hostname = host  # used for TLS SNI
    timestamp = datetime.now(timezone.utc).isoformat()

    results = []

    # 1) slow POST raw (supports TLS)
    try:
        r1 = slow_post_raw(host, port, path, args.expected_timeout,
                           total_bytes=args.slow_bytes,
                           chunk_size=args.chunk_size,
                           interval=args.slow_interval,
                           use_tls=use_tls,
                           server_hostname=server_hostname)
    except Exception as e:
        r1 = {"test": "slow_post", "result": "ERROR", "severity": "High", "details": f"Exception: {e}", "timings": {}}
    results.append(r1)

    # 2) idle connection test
    try:
        r2 = idle_connection_test(host, port, path, args.expected_timeout, use_tls=use_tls, server_hostname=server_hostname)
    except Exception as e:
        r2 = {"test": "idle_connection", "result": "ERROR", "severity": "High", "details": f"Exception: {e}", "timings": {}}
    results.append(r2)

    # 3) concurrency light test using requests (works for HTTPS too)
    simple_url = args.target.rstrip("/") + args.simple_endpoint
    try:
        r3 = concurrency_test(simple_url, args.concurrency, timeout=max(5, args.expected_timeout // 2))
    except Exception as e:
        r3 = {"test": "concurrency_light", "result": "ERROR", "severity": "High", "details": f"Exception: {e}", "metrics": {}}
    results.append(r3)

    overall_status, overall_summary = combine_results(results)

    # Build report
    report = {
        "check_name": "request_timeout_check",
        "target": args.target,
        "status": overall_status,
        "summary": overall_summary,
        "details": {
            "expected_timeout_seconds": args.expected_timeout,
            "slow_bytes": args.slow_bytes,
            "slow_interval": args.slow_interval,
            "chunk_size": args.chunk_size,
            "concurrency": args.concurrency,
            "simple_endpoint": args.simple_endpoint
        },
        "findings": results,
        "timestamp": timestamp
    }

    os.makedirs(os.path.dirname(args.report_path), exist_ok=True)
    with open(args.report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"[request_timeout_check] ✅ status={overall_status}, report saved: {args.report_path}")


if __name__ == "__main__":
    main()
