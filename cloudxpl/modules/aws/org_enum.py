"""AWS Organizations enumeration  -  accounts, OUs, SCPs."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.org_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526"],
}


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def run(args: Any) -> int:

    print(f"[*] AWS Organizations Enumeration")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    org = session.client("organizations")
    results = {"organization": {}, "accounts": [], "roots": []}
    try:
        org_info = org.describe_organization()["Organization"]
        results["organization"] = {"id": org_info["Id"], "master_account": org_info["MasterAccountId"], "master_email": org_info.get("MasterAccountEmail", "")}
        print(f"[+] Org: {org_info['Id']} (master: {org_info['MasterAccountId']})")
    except Exception as exc:
        print(f"[-] Not an org member or insufficient permissions: {exc}"); return 1
    try:
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acct in page["Accounts"]:
                results["accounts"].append({"id": acct["Id"], "name": acct["Name"], "email": acct.get("Email", ""), "status": acct["Status"]})
                print(f"  [+] {acct['Id']}: {acct['Name']} ({acct['Status']})")
    except Exception: pass
    _save(args, "aws_org_enum", results)
    print(f"[+] {len(results['accounts'])} accounts found")
    return 0
