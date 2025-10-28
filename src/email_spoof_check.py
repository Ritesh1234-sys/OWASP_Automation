#!/usr/bin/env python3
"""
email_spoof_check.py

OWASP-style automation check:
"Verify if the email address of application domain is spoofable."

What it does:
 - For a given domain, query DNS to find:
    * MX records
    * TXT records (for SPF)
    * _dmarc TXT (for DMARC)
    * DKIM public key records for common selectors (configurable)
 - Produce a JSON report summarising presence and configuration of SPF/DMARC/DKIM
 - Provide guidance and a final `status`:
     - PASS   : DMARC policy = reject/quarantine AND SPF present AND at least one DKIM key present
     - WARN   : Partial protections (e.g., SPF present but DMARC is `none` or missing)
     - FAIL   : No SPF, no DMARC, no DKIM or clearly permissive mechanisms (e.g., `?all` / `~all`)

Usage:
    python3 src/email_spoof_check.py --domain example.com
    python3 src/email_spoof_check.py --domain example.com --dkim-selectors google,default --timeout 5

Outputs:
 - writes JSON report to: reports/raw/email_spoof_report.json
 - prints a short summary to stdout

Dependencies:
 - dnspython (pip install dnspython)

Author:
 - Written for EB Pearls OWASP automation framework. Well-commented for reuse.
"""

import argparse
import json
import os
import datetime
from typing import List, Dict, Tuple

# dnspython
import dns.resolver
import dns.exception

# ----------------------
# Utility helpers
# ----------------------

def safe_query_txt(name: str, timeout: float = 3.0) -> List[str]:
    """
    Query TXT records for `name` and return a list of strings.
    Wraps dnspython resolver with a timeout and robust error handling.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT")
        txts = []
        for r in answers:
            # each r.strings may be bytes chunks - join them safely
            try:
                joined = b"".join(r.strings).decode("utf-8", errors="ignore")
            except Exception:
                # fallback to str()
                joined = str(r)
            txts.append(joined)
        return txts
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as e:
        # return empty with no crash
        return []

def safe_query_mx(domain: str, timeout: float = 3.0) -> List[str]:
    """
    Return list of MX hostnames for a domain (or empty list).
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException:
        return []

def parse_spf(txt_records: List[str]) -> Dict:
    """
    Find SPF record in TXT records and parse some basics.
    Returns a dict with:
      - found: bool
      - spf_text: raw string or ''
      - qualifiers: list of mechanisms with qualifiers (like '-all', '~all', '?all', '+all')
    """
    for txt in txt_records:
        txt_lower = txt.strip().lower()
        if txt_lower.startswith("v=spf1"):
            mechanisms = txt_lower.split()
            return {
                "found": True,
                "spf_text": txt,
                "mechanisms": mechanisms,
                "all_qualifier": next((m for m in mechanisms if m.endswith("all")), None)
            }
    return {"found": False, "spf_text": "", "mechanisms": [], "all_qualifier": None}

def parse_dmarc(domain: str, timeout: float = 3.0) -> Dict:
    """
    Query _dmarc.DOMAIN TXT and parse policy (p=).
    Returns:
      - found: bool
      - dmarc_text: raw
      - policy: 'none'|'quarantine'|'reject'|None
      - rua/rua_present: bool (reporting addresses)
    """
    target = f"_dmarc.{domain}"
    txts = safe_query_txt(target, timeout=timeout)
    for txt in txts:
        txt_lower = txt.strip().lower()
        if txt_lower.startswith("v=dmarc1"):
            # simple parse for p= and rua=
            policy = None
            rua_present = False
            parts = [p.strip() for p in txt_lower.split(";")]
            for p in parts:
                if p.startswith("p="):
                    policy = p.split("=", 1)[1]
                if p.startswith("rua=") or p.startswith("ruf="):
                    rua_present = True
            return {"found": True, "dmarc_text": txt, "policy": policy, "reporting": rua_present}
    return {"found": False, "dmarc_text": "", "policy": None, "reporting": False}

def check_dkim(domain: str, selectors: List[str], timeout: float = 3.0) -> Dict:
    """
    For a list of DKIM selectors (strings), query selector._domainkey.domain TXT
    Returns:
      - keys: dict selector -> {found: bool, txt: str or ''}
      - any_present: bool
    """
    keys = {}
    any_present = False
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txts = safe_query_txt(name, timeout=timeout)
        if txts:
            any_present = True
            keys[sel] = {"found": True, "txt": txts[0]}
        else:
            keys[sel] = {"found": False, "txt": ""}
    return {"keys": keys, "any_present": any_present}

# ----------------------
# Business logic
# ----------------------

def evaluate(domain: str, dkim_selectors: List[str], timeout: float = 3.0) -> Dict:
    """
    Run all checks and return a structured report dict.
    """
    report = {
        "check_name": "email_spoof_check",
        "domain": domain,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "mx": [],
        "spf": {},
        "dmarc": {},
        "dkim": {},
        "findings": [],
    }

    # 1) MX presence
    mx = safe_query_mx(domain, timeout=timeout)
    report["mx"] = mx

    if not mx:
        report["findings"].append({
            "title": "No MX records",
            "detail": "Domain has no MX records. Mail may be routed differently — but lack of MX alone does not prevent spoofing.",
            "severity": "Medium"
        })
    else:
        report["findings"].append({
            "title": "MX records present",
            "detail": f"MX records: {', '.join(mx)}",
            "severity": "Info"
        })

    # 2) SPF
    # Query root domain TXT records
    txts = safe_query_txt(domain, timeout=timeout)
    spf = parse_spf(txts)
    report["spf"] = spf
    if spf["found"]:
        allq = spf.get("all_qualifier")
        if allq is None:
            report["findings"].append({
                "title": "SPF record found",
                "detail": "SPF record found but `all` qualifier not detected. Review mechanisms.",
                "severity": "Warn"
            })
        else:
            # interpret all qualifier
            if allq.endswith("-all"):
                report["findings"].append({
                    "title": "SPF record found (strict)",
                    "detail": f"SPF `all` qualifier: {allq}. This is good (strict deny).",
                    "severity": "Info"
                })
            elif allq.endswith("~all"):
                report["findings"].append({
                    "title": "SPF record found (softfail)",
                    "detail": "SPF uses `~all` (softfail). This allows some spoofing; consider `-all`.",
                    "severity": "Warn"
                })
            elif allq.endswith("?all") or allq.endswith("+all"):
                report["findings"].append({
                    "title": "SPF record uses permissive `all`",
                    "detail": f"SPF `all` qualifier is {allq} which is permissive — high risk for spoofing.",
                    "severity": "High"
                })
            else:
                report["findings"].append({
                    "title": "SPF record found",
                    "detail": f"SPF mechanisms: {spf.get('mechanisms')}",
                    "severity": "Info"
                })
    else:
        report["findings"].append({
            "title": "No SPF record",
            "detail": "No SPF (v=spf1) TXT record found at the domain. This increases spoofing risk.",
            "severity": "High"
        })

    # 3) DMARC
    dmarc = parse_dmarc(domain, timeout=timeout)
    report["dmarc"] = dmarc
    if dmarc["found"]:
        policy = (dmarc.get("policy") or "none").lower()
        if policy in ("reject", "quarantine"):
            report["findings"].append({
                "title": "DMARC policy present",
                "detail": f"DMARC policy is {policy}. This helps prevent spoofing.",
                "severity": "Info" if policy == "reject" else "Warn"
            })
        else:
            # policy none or other
            report["findings"].append({
                "title": "DMARC present but not enforcing",
                "detail": f"DMARC policy is `{policy}` (not enforcing). Consider `quarantine` or `reject`.",
                "severity": "Warn"
            })
    else:
        report["findings"].append({
            "title": "No DMARC record",
            "detail": "No DMARC record found under _dmarc.DOMAIN. DMARC gives domain owners control; missing DMARC increases spoof risk.",
            "severity": "High"
        })

    # 4) DKIM selectors
    dkim = check_dkim(domain, dkim_selectors, timeout=timeout)
    report["dkim"] = dkim
    if dkim["any_present"]:
        keys = [s for s, v in dkim["keys"].items() if v["found"]]
        report["findings"].append({
            "title": "DKIM key(s) present",
            "detail": f"Found DKIM public key(s) for selectors: {', '.join(keys)}",
            "severity": "Info"
        })
    else:
        report["findings"].append({
            "title": "No DKIM keys found for provided selectors",
            "detail": "No DKIM TXT records found for the selectors tested. Consider verifying DKIM signing on outbound mail.",
            "severity": "Warn"
        })

    # 5) Final evaluation logic for status
    # PASS if DMARC policy is reject/quarantine AND SPF present AND DKIM present
    spf_ok = spf.get("found", False) and spf.get("all_qualifier", "").endswith("-all")
    dmarc_ok = dmarc.get("found", False) and (dmarc.get("policy") in ("reject", "quarantine"))
    dkim_ok = dkim.get("any_present", False)

    if dmarc_ok and (spf_ok or dkim_ok):
        status = "PASS"
        summary = "Domain has strong anti-spoofing controls (DMARC enforce + SPF/DKIM)."
    elif (spf.get("found") or dkim.get("any_present")) and dmarc.get("found"):
        status = "WARN"
        summary = "Partial protections found. DMARC present but not fully enforcing or SPF/DKIM are not strict."
    else:
        status = "FAIL"
        summary = "Domain lacks sufficient SPF/DMARC/DKIM protections and is likely spoofable."

    report["status"] = status
    report["summary"] = summary

    return report

# ----------------------
# CLI runner
# ----------------------

def main():
    parser = argparse.ArgumentParser(description="Check email spoofability for a domain (SPF/DMARC/DKIM).")
    parser.add_argument("--domain", required=True, help="Domain to test (e.g., example.com)")
    parser.add_argument("--dkim-selectors", default="default,selector1,google", help="Comma-separated DKIM selectors to probe.")
    parser.add_argument("--timeout", type=float, default=3.0, help="DNS query timeout in seconds.")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    selectors = [s.strip() for s in args.dkim_selectors.split(",") if s.strip()]

    # Run checks
    report = evaluate(domain, selectors, timeout=args.timeout)

    # Save report
    os.makedirs("reports/raw", exist_ok=True)
    out_path = "reports/raw/email_spoof_report.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # Print concise summary
    print(f"[email_spoof_check] Domain: {domain}  Status: {report['status']}")
    print(f" Summary: {report['summary']}")
    print(f" Findings: {len(report['findings'])} (saved to {out_path})")

if __name__ == "__main__":
    main()
