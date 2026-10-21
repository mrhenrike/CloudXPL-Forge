"""AWS SSO/Identity Center enumeration  -  instances, permission sets."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.sso_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078"],
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

    print(f"[*] AWS SSO Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sso_admin = session.client("sso-admin")
    results = {"instances": [], "permission_sets": []}
    try:
        instances = sso_admin.list_instances()["Instances"]
        for inst in instances:
            arn = inst["InstanceArn"]
            info = {"arn": arn, "identity_store": inst.get("IdentityStoreId", "")}
            results["instances"].append(info)
            print(f"  [+] SSO Instance: {arn}")
            try:
                ps_paginator = sso_admin.get_paginator("list_permission_sets")
                for page in ps_paginator.paginate(InstanceArn=arn):
                    for ps_arn in page["PermissionSets"]:
                        try:
                            ps = sso_admin.describe_permission_set(InstanceArn=arn, PermissionSetArn=ps_arn)["PermissionSet"]
                            results["permission_sets"].append({"name": ps.get("Name", ""), "arn": ps_arn, "duration": ps.get("SessionDuration", "")})
                        except Exception: pass
            except Exception: pass
    except Exception as exc:
        print(f"[-] SSO enum failed: {exc}"); return 1
    _save(args, "aws_sso_enum", results)
    print(f"[+] {len(results['instances'])} instances, {len(results['permission_sets'])} permission sets")
    return 0
