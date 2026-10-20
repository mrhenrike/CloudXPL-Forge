"""AWS STS credential enumeration  -  caller identity, assume-role chains, session tokens."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.sts_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078","T1528"],
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

    print(f"[*] AWS STS Credential Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client("sts")
    iam = session.client("iam")
    caller = sts.get_caller_identity()
    print(f"[+] Account: {caller['Account']}")
    print(f"[+] ARN: {caller['Arn']}")
    print(f"[+] UserId: {caller['UserId']}")
    results = {"identity": caller, "assumable_roles": []}
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                trust = role.get("AssumeRolePolicyDocument", {})
                stmts = trust.get("Statement", [])
                for stmt in stmts:
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if isinstance(principal, str) and principal == "*":
                            results["assumable_roles"].append({"role": role["RoleName"], "arn": role["Arn"], "trust": "wildcard"})
                            print(f"  [!] {role['RoleName']}: wildcard trust policy")
                        elif isinstance(principal, dict):
                            aws_principals = principal.get("AWS", [])
                            if isinstance(aws_principals, str): aws_principals = [aws_principals]
                            if caller["Arn"] in aws_principals or caller["Account"] in str(aws_principals):
                                results["assumable_roles"].append({"role": role["RoleName"], "arn": role["Arn"], "trust": "direct"})
                                print(f"  [+] {role['RoleName']}: assumable (direct trust)")
    except Exception as exc:
        print(f"[-] Role enumeration failed: {exc}", file=sys.stderr)
    _save(args, "aws_sts_enum", results)
    print(f"[+] {len(results['assumable_roles'])} assumable roles found")
    return 0
