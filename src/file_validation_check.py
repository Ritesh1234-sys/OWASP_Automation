#!/usr/bin/env python3
"""
file_validation_check.py
-------------------------------------------------
OWASP Web Check: Verify implementation of file validation.

Purpose:
  - Ensure the web application correctly validates uploaded files
  - Prevent upload of malicious or oversized files
  - Detect misconfigurations where dangerous file types are accepted

Covers OWASP ASVS:
  - V5.1.3: Validate file type, content, and size
  - V5.1.4: Reject executables and scripts
  - V5.1.6: Enforce MIME type validation
  - V5.1.8: Handle validation failures securely

Usage Example:
    python3 src/file_validation_check.py \
        --target http://127.0.0.1:5002/upload \
        --allowed-ext jpg,png,pdf \
        --max-size 5242880

Output:
    Generates JSON report at reports/raw/file_validation_report.json
"""

import os
import sys
import json
import argparse
import mimetypes
import tempfile
import requests
from datetime import datetime


# ======================================================
# Helper Function 1: Dummy File Generator
# ======================================================

def generate_dummy_file(extension: str, size_bytes: int = 1024) -> str:
    """
    Create a temporary dummy file of a specific extension and size.
    - extension: File extension (e.g., "jpg", "exe")
    - size_bytes: File size in bytes (default: 1 KB)

    Returns the path to the temporary file.
    The file will be deleted later after each upload test.
    """
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=f".{extension}")
    with os.fdopen(tmp_fd, "wb") as f:
        f.write(os.urandom(size_bytes))  # Fill file with random bytes
    return tmp_path


# ======================================================
# Core Validation Logic
# ======================================================

def check_upload(target_url: str, allowed_exts: list, max_size: int):
    """
    Run a series of upload validation tests against the given endpoint.

    Tests include:
      ✅ Allowed extensions (should succeed)
      🚫 Disallowed extensions (should fail)
      ⚠️ Oversized file (should fail)

    Each test performs an actual HTTP POST request to the target endpoint
    with different file types and sizes.
    """
    results = []  # Store detailed per-test results
    session = requests.Session()
    headers = {"User-Agent": "OWASP_Automation/1.0"}

    # --------------------------------------------------
    # ✅ Test 1: Allowed extensions
    # --------------------------------------------------
    for ext in allowed_exts:
        file_path = generate_dummy_file(ext)
        try:
            with open(file_path, "rb") as f:
                resp = session.post(
                    target_url,
                    files={"file": (
                        os.path.basename(file_path),
                        f,
                        mimetypes.guess_type(file_path)[0] or "application/octet-stream"
                    )},
                    headers=headers,
                    timeout=15
                )
            results.append({
                "test": f"Allowed extension ({ext})",
                "expected": "Accepted (HTTP 200–299)",
                "actual": resp.status_code,
                "result": "PASS" if 200 <= resp.status_code < 300 else "FAIL"
            })
        except Exception as e:
            results.append({
                "test": f"Allowed extension ({ext})",
                "expected": "Accepted (HTTP 200–299)",
                "actual": str(e),
                "result": "FAIL"
            })
        finally:
            os.remove(file_path)

    # --------------------------------------------------
    # 🚫 Test 2: Disallowed extensions
    # --------------------------------------------------
    malicious_exts = ["exe", "php", "js", "sh", "jsp"]
    for ext in malicious_exts:
        file_path = generate_dummy_file(ext)
        try:
            with open(file_path, "rb") as f:
                resp = session.post(
                    target_url,
                    files={"file": (
                        os.path.basename(file_path),
                        f,
                        "application/octet-stream"
                    )},
                    headers=headers,
                    timeout=15
                )
            results.append({
                "test": f"Disallowed extension ({ext})",
                "expected": "Rejected (HTTP 4xx)",
                "actual": resp.status_code,
                "result": "PASS" if 400 <= resp.status_code < 500 else "FAIL"
            })
        except Exception as e:
            results.append({
                "test": f"Disallowed extension ({ext})",
                "expected": "Rejected (HTTP 4xx)",
                "actual": str(e),
                "result": "FAIL"
            })
        finally:
            os.remove(file_path)

    # --------------------------------------------------
    # ⚠️ Test 3: Oversized file
    # --------------------------------------------------
    oversized_path = generate_dummy_file("jpg", size_bytes=max_size + 1024)
    try:
        with open(oversized_path, "rb") as f:
            resp = session.post(
                target_url,
                files={"file": (
                    os.path.basename(oversized_path),
                    f,
                    "image/jpeg"
                )},
                headers=headers,
                timeout=30
            )
        results.append({
            "test": f"Oversized file (> {max_size} bytes)",
            "expected": "Rejected (HTTP 4xx)",
            "actual": resp.status_code,
            "result": "PASS" if 400 <= resp.status_code < 500 else "FAIL"
        })
    except Exception as e:
        results.append({
            "test": f"Oversized file (> {max_size} bytes)",
            "expected": "Rejected (HTTP 4xx)",
            "actual": str(e),
            "result": "FAIL"
        })
    finally:
        os.remove(oversized_path)

    return results


# ======================================================
# Summarization Helper
# ======================================================

def summarize_results(results):
    """
    Compute an overall check status based on test results.

    Logic:
      - All PASS → status = PASS
      - Partial FAIL → status = WARN
      - All FAIL → status = FAIL
    """
    fail_count = sum(1 for r in results if r["result"] == "FAIL")
    pass_count = sum(1 for r in results if r["result"] == "PASS")

    if fail_count == 0:
        status = "PASS"
        summary = f"All {len(results)} file validation checks passed."
    elif fail_count < len(results):
        status = "WARN"
        summary = f"{fail_count} of {len(results)} file validation checks failed."
    else:
        status = "FAIL"
        summary = "All file validation checks failed."

    return status, summary


# ======================================================
# Main Execution
# ======================================================

def main():
    # ------------------------------
    # CLI Argument Parsing
    # ------------------------------
    parser = argparse.ArgumentParser(description="OWASP File Validation Checker")
    parser.add_argument("--target", required=True, help="Upload endpoint URL")
    parser.add_argument("--allowed-ext", required=True, help="Comma-separated list of allowed extensions (e.g., jpg,png,pdf)")
    parser.add_argument("--max-size", type=int, required=True, help="Maximum allowed file size in bytes")
    args = parser.parse_args()

    # ✅ Fix: use underscore attribute (not hyphen)
    allowed_exts = args.allowed_ext.split(",")

    # ------------------------------
    # Run Checks
    # ------------------------------
    print(f"🔍 Running file validation checks on {args.target}")
    results = check_upload(args.target, allowed_exts, args.max_size)

    # ------------------------------
    # Summarize and Save Report
    # ------------------------------
    status, summary = summarize_results(results)
    report = {
        "check_name": "file_validation_check",
        "target": args.target,
        "status": status,
        "summary": summary,
        "findings": results,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    os.makedirs("reports/raw", exist_ok=True)
    report_path = "reports/raw/file_validation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[file_validation_check] ✅ status={status}, report saved at {report_path}")


# ======================================================
# Entrypoint
# ======================================================
if __name__ == "__main__":
    main()
