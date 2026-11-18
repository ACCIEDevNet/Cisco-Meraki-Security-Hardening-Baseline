#!/usr/bin/env python3
"""Read-only audit of Meraki organization-level hardening controls.

Checks controls ADM-05, ADM-06, ADM-07, ADM-08, ADM-09, ADM-10, ADM-11,
ORG-02 and ORG-05 from the baseline using the Dashboard API.

Requires Python 3.11+ and the MERAKI_API_KEY environment variable.
Only GET requests are made. Nothing is changed.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE = "https://api.meraki.com/api/v1"
IDLE_MAX_MINUTES = 10
INACTIVE_DAYS = 90
MAX_FULL_ORG_ADMINS = 5


def api_get(path, key, retries=4):
    req = urllib.request.Request(
        BASE + path,
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                time.sleep(int(e.headers.get("Retry-After", "2")))
                continue
            if e.code in (400, 403, 404):
                return {"_error": f"HTTP {e.code}"}
            raise
    return {"_error": "retries exhausted"}


def result(cid, status, detail):
    return {"id": cid, "status": status, "detail": detail}


def check_login_security(ls):
    out = []
    if "_error" in ls:
        return [result("ADM-xx", "WARN", f"Could not read login security ({ls['_error']})")]
    out.append(result(
        "ADM-05",
        "PASS" if ls.get("enforceTwoFactorAuth") else "FAIL",
        "Two-factor authentication enforced" if ls.get("enforceTwoFactorAuth")
        else "Two-factor authentication is not enforced for local accounts"))
    idle = ls.get("idleTimeoutMinutes")
    ok = ls.get("enforceIdleTimeout") and idle and idle <= IDLE_MAX_MINUTES
    out.append(result(
        "ADM-09", "PASS" if ok else "FAIL",
        f"Idle timeout {idle} min" if ls.get("enforceIdleTimeout")
        else f"Idle timeout not enforced (target <= {IDLE_MAX_MINUTES} min)"))
    out.append(result(
        "ADM-08", "PASS" if ls.get("enforceStrongPasswords") else "FAIL",
        "Strong passwords enforced" if ls.get("enforceStrongPasswords")
        else "Strong passwords not enforced"))
    out.append(result(
        "ADM-08", "PASS" if ls.get("enforceAccountLockout") else "WARN",
        f"Account lockout after {ls.get('accountLockoutAttempts')} attempts"
        if ls.get("enforceAccountLockout") else "Account lockout not enforced"))
    out.append(result(
        "ADM-10", "PASS" if ls.get("enforceLoginIpRanges") else "WARN",
        "Login IP ranges enforced" if ls.get("enforceLoginIpRanges")
        else "Login IP ranges not enforced (consider for local accounts)"))
    api_ip = (ls.get("apiAuthentication") or {}).get("ipRestrictionsForKeys") or {}
    out.append(result(
        "ORG-02", "PASS" if api_ip.get("enabled") else "WARN",
        "API keys restricted to listed IP ranges" if api_ip.get("enabled")
        else "API keys are not restricted by IP range"))
    return out


def days_since(ts):
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def check_admins(admins):
    if isinstance(admins, dict) and "_error" in admins:
        return [result("ADM-xx", "WARN", f"Could not read administrators ({admins['_error']})")]
    out = []
    full_org = [a for a in admins if a.get("orgAccess") == "full"]
    local = [a for a in admins if (a.get("authenticationMethod") or "").lower() != "saml"]
    local_full = [a for a in local if a.get("orgAccess") == "full"]
    out.append(result(
        "ADM-06", "PASS" if len(local_full) == 2 else "WARN",
        f"{len(local_full)} local (non-SAML) org-level Full admins (baseline: exactly 2 break-glass)"))
    out.append(result(
        "ADM-07", "PASS" if len(full_org) <= MAX_FULL_ORG_ADMINS else "WARN",
        f"{len(full_org)} organization Full admins (review if more than {MAX_FULL_ORG_ADMINS})"))
    no_2fa = [a.get("email") for a in local if not a.get("twoFactorAuthEnabled")]
    out.append(result(
        "ADM-05", "PASS" if not no_2fa else "FAIL",
        "All local admins have 2FA" if not no_2fa
        else f"Local admins without 2FA: {', '.join(no_2fa)}"))
    stale = [a.get("email") for a in admins
             if (days_since(a.get("lastActive")) or 0) > INACTIVE_DAYS]
    out.append(result(
        "ADM-11", "PASS" if not stale else "WARN",
        f"No admins inactive over {INACTIVE_DAYS} days" if not stale
        else f"Inactive over {INACTIVE_DAYS} days: {', '.join(stale)}"))
    return out


def check_snmp(snmp):
    if "_error" in snmp:
        return [result("ORG-05", "WARN", f"Could not read SNMP settings ({snmp['_error']})")]
    if snmp.get("v2cEnabled"):
        return [result("ORG-05", "FAIL", "SNMPv2c is enabled (use SNMPv3 with auth and privacy)")]
    if snmp.get("v3Enabled"):
        weak = snmp.get("v3AuthMode") != "SHA" or snmp.get("v3PrivMode") != "AES128"
        return [result("ORG-05", "WARN" if weak else "PASS",
                       f"SNMPv3 enabled, auth {snmp.get('v3AuthMode')}, priv {snmp.get('v3PrivMode')}")]
    return [result("ORG-05", "PASS", "SNMP disabled at organization level")]


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--org-id")
    p.add_argument("--list-orgs", action="store_true")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args()

    key = os.environ.get("MERAKI_API_KEY")
    if not key:
        sys.exit("Set MERAKI_API_KEY (use a read-only service account key).")

    if args.list_orgs:
        for o in api_get("/organizations", key):
            print(f"{o['id']}\t{o['name']}")
        return
    if not args.org_id:
        sys.exit("Provide --org-id or use --list-orgs.")

    org = args.org_id
    results = []
    results += check_login_security(api_get(f"/organizations/{org}/loginSecurity", key))
    results += check_admins(api_get(f"/organizations/{org}/admins", key))
    results += check_snmp(api_get(f"/organizations/{org}/snmp", key))
    results.append(result("ADM-04", "WARN",
                          "Support Access is not readable via API: confirm it is Blocked manually"))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"[{r['status']:<4}] {r['id']:<7} {r['detail']}")
    sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
