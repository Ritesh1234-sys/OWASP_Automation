#!/usr/bin/env python3
"""
api_concurrency_check.py
-------------------------------------------------
OWASP Web Check: Verify if multiple concurrent requests
can be safely handled by open APIs.

Purpose:
  - Ensure that public or unauthenticated APIs can sustain
    multiple simultaneous requests without timeouts or 5xx errors.
  - Detect any concurrency-related failures or degraded performance.

Covers OWASP ASVS:
  - 14.4.3: Verify the application can handle concurrent requests safely.
  - 16.4.1: Verify resource exhaustion protections and safe request limits.

Usage Example:
    python3 src/api_concurrency_check.py \
        --target https://example.com/api/public-data \
        --concurrency 10 \
        --requests 30 \
        --timeout 5
"""

import os
import sys
import time
import json
import argparse
import requests
import threading
from queue import Queue
from datetime import datetime


# ======================================================
# Worker Thread Function
# ======================================================
def worker(queue: Queue, target: str, timeout: int, results: list):
    """
    Worker function to send requests concurrently.
    Each worker pulls a job from the queue and performs a GET.
    Results (status code, latency) are appended to the shared results list.
    """
    while True:
        try:
            job_id = queue.get(block=False)
        except Exception:
            break  # Queue empty

        start = time.time()
        try:
            resp = requests.get(target, timeout=timeout)
            latency = round(time.time() - start, 3)
            results.append({
                "job_id": job_id,
                "status_code": resp.status_code,
                "latency": latency,
                "result": "PASS" if 200 <= resp.status_code < 300 else "FAIL"
            })
        except requests.Timeout:
            latency = round(time.time() - start, 3)
            results.append({
                "job_id": job_id,
                "status_code": None,
                "latency": latency,
                "result": "FAIL",
                "detail": "Timeout"
            })
        except Exception as e:
            latency = round(time.time() - start, 3)
            results.append({
                "job_id": job_id,
                "status_code": None,
                "latency": latency,
                "result": "FAIL",
                "detail": str(e)
            })
        finally:
            queue.task_done()


# ======================================================
# Core Concurrency Test Logic
# ======================================================
def run_concurrency_test(target: str, concurrency: int, total_requests: int, timeout: int):
    """
    Run concurrent requests using threading.
    Measures response codes, average latency, and error ratio.
    """
    queue = Queue()
    results = []

    # Populate the job queue
    for i in range(total_requests):
        queue.put(i + 1)

    threads = []
    for _ in range(concurrency):
        t = threading.Thread(target=worker, args=(queue, target, timeout, results))
        t.daemon = True
        threads.append(t)
        t.start()

    # Wait until all jobs are done
    queue.join()

    # Compute summary metrics
    total = len(results)
    pass_count = sum(1 for r in results if r["result"] == "PASS")
    fail_count = total - pass_count
    avg_latency = round(sum(r["latency"] for r in results) / total, 3) if total else 0.0
    max_latency = round(max(r["latency"] for r in results), 3) if total else 0.0

    status = "PASS"
    summary = f"All {total} concurrent requests succeeded."
    if fail_count > 0:
        status = "WARN" if fail_count < total * 0.3 else "FAIL"
        summary = f"{fail_count}/{total} requests failed under concurrency load."
    elif avg_latency > timeout:
        status = "WARN"
        summary = f"High average latency ({avg_latency}s) under load."

    findings = [
        {
            "test": "Concurrent Request Load",
            "concurrency": concurrency,
            "total_requests": total,
            "avg_latency": avg_latency,
            "max_latency": max_latency,
            "failures": fail_count,
            "status": status,
            "severity": "HIGH" if status == "FAIL" else "MEDIUM" if status == "WARN" else "LOW",
            "recommendation": (
                "Investigate performance degradation under concurrent requests."
                if status != "PASS"
                else "API handled concurrent requests efficiently."
            )
        }
    ]

    return status, summary, findings


# ======================================================
# Main Entrypoint
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="OWASP API Concurrency Checker")
    parser.add_argument("--target", required=True, help="Target API endpoint (unauthenticated preferred)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of parallel threads")
    parser.add_argument("--requests", type=int, default=30, help="Total number of requests to send")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout per request (in seconds)")
    args = parser.parse_args()

    print(f"🚀 Testing {args.target} with {args.concurrency} threads and {args.requests} total requests")

    status, summary, findings = run_concurrency_test(
        target=args.target,
        concurrency=args.concurrency,
        total_requests=args.requests,
        timeout=args.timeout
    )

    report = {
        "check_name": "api_concurrency_check",
        "target": args.target,
        "status": status,
        "summary": summary,
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs("reports/raw", exist_ok=True)
    output_path = "reports/raw/api_concurrency_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[api_concurrency_check] ✅ status={status}, report saved at {output_path}")


if __name__ == "__main__":
    main()
