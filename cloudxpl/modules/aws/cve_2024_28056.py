"""CVE-2024-28056 Amplify IAM role assumption PoC."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.cve_2024_28056.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1190"],
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

    print("[*] CVE-2024-28056: AWS Amplify IAM Role Assumption")
    print("[*] Vulnerability: Amplify creates IAM roles with overly permissive trust policies")
    print("[*] Impact: Attacker can assume Amplify-provisioned roles from any AWS account")
    results = {"cve": "CVE-2024-28056", "cvss": 9.8, "status": "checking"}
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    iam = session.client("iam")
    try:
        paginator = iam.get_paginator("list_roles")
        amplify_roles = []
        for page in paginator.paginate():
            for role in page["Roles"]:
                if "amplify" in role["RoleName"].lower() or "amplify" in str(role.get("AssumeRolePolicyDocument", {})).lower():
                    trust = role.get("AssumeRolePolicyDocument", {})
                    amplify_roles.append({"name": role["RoleName"], "arn": role["Arn"], "trust": trust})
                    print(f"  [+] Amplify role: {role['RoleName']}")
        results["amplify_roles"] = amplify_roles
        results["status"] = "vulnerable" if amplify_roles else "not_affected"
    except Exception as exc:
        results["status"] = f"error: {exc}"
    _save(args, "aws_cve_2024_28056", results)
    return 0
