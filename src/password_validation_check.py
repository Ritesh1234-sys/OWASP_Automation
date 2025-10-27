#!/usr/bin/env python3
"""
File: password_validation_check.py
Author: Security Automation Team
Purpose:
    Automatically verify if client-side password validation is implemented
    on a given registration or password-reset page.

How it works:
    1. Launches a headless Chromium browser (Playwright)
    2. Loads the provided URL and renders JavaScript
    3. Parses the resulting HTML with BeautifulSoup
    4. Looks for:
        - Password input fields
        - HTML5 validation attributes (minlength, pattern, etc.)
        - JavaScript functions or regexes used for password validation
    5. Generates a JSON report with results

Usage:
    python3 src/password_validation_check.py --target https://example.com/register
"""

import os
import json
import asyncio
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup

# Path where reports are saved
REPORT_PATH = "reports/raw/password_validation_report.json"

# ------------------------------------------------------------
# STEP 1 — Analyze HTML for password validation indicators
# ------------------------------------------------------------
def analyze_html(html):
    findings = []
    soup = BeautifulSoup(html, "lxml")

    # 1. Look for password input fields
    password_fields = soup.find_all("input", {"type": "password"})
    if not password_fields:
        findings.append("❌ No password input fields detected on this page.")
        return {"has_validation": False, "findings": findings}

    # 2. Check for HTML5 validation attributes (e.g., minlength, pattern)
    for field in password_fields:
        rules = {}
        for attr in ["minlength", "maxlength", "pattern"]:
            if field.get(attr):
                rules[attr] = field[attr]
        if rules:
            findings.append(f"✅ HTML validation rules found: {rules}")
        else:
            findings.append("⚠️ Password field missing HTML validation attributes.")

    # 3. Look for JavaScript password validation logic
    scripts = soup.find_all("script")
    keywords = ["password", "validate", "regex", "strength", "check"]
    js_hits = []
    for script in scripts:
        content = script.get_text()
        if any(k in content.lower() for k in keywords):
            js_hits.append(content[:150])  # just sample first 150 chars
    if js_hits:
        findings.append(f"✅ JavaScript validation logic detected ({len(js_hits)} scripts).")
    else:
        findings.append("⚠️ No inline or external JavaScript validation found.")

    has_validation = any("✅" in f for f in findings)
    return {"has_validation": has_validation, "findings": findings}

# ------------------------------------------------------------
# STEP 2 — Load the web page and capture rendered HTML
# ------------------------------------------------------------
async def fetch_page_html(url):
    """
    Uses Playwright to open the page in a headless Chromium browser
    and capture the HTML after JavaScript execution.
    """
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(url)
        await asyncio.sleep(3)  # wait for JS-rendered forms to load
        html = await page.content()
        await browser.close()
        return html

# ------------------------------------------------------------
# STEP 3 — Combine results and write to JSON
# ------------------------------------------------------------
async def run_check(target_url):
    print(f"🔍 Scanning {target_url} for client-side password validation...")
    try:
        html = await fetch_page_html(target_url)
        result = analyze_html(html)
        result["url"] = target_url
        result["status"] = "PASS" if result["has_validation"] else "FAIL"

        os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
        with open(REPORT_PATH, "w") as f:
            json.dump(result, f, indent=4)

        print(f"✅ Report saved at {REPORT_PATH}")
    except Exception as e:
        print(f"❌ Error while scanning: {e}")

# ------------------------------------------------------------
# STEP 4 — CLI entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Check for client-side password validation.")
    parser.add_argument("--target", required=True, help="Target URL (e.g., /register or /signup page)")
    args = parser.parse_args()
    asyncio.run(run_check(args.target))
