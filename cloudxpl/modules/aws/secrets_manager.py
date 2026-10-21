"""AWS Secrets Manager enumeration and extraction."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.secrets_manager.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552"],
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

    print(f"[*] AWS Secrets Manager Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sm = session.client("secretsmanager")
    results = {"secrets": [], "accessible": []}
    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page["SecretList"]:
                info = {"name": secret["Name"], "arn": secret["ARN"], "last_changed": str(secret.get("LastChangedDate", "")), "rotation": secret.get("RotationEnabled", False)}
                try:
                    value = sm.get_secret_value(SecretId=secret["ARN"])
                    info["accessible"] = True
                    info["version_id"] = value.get("VersionId", "")
                    results["accessible"].append(info["name"])
                    print(f"  [!] {secret['Name']}: ACCESSIBLE (can read secret value)")
                except Exception:
                    info["accessible"] = False
                    print(f"  [-] {secret['Name']}: access denied")
                results["secrets"].append(info)
    except Exception as exc:
        print(f"[-] Secrets enum failed: {exc}"); return 1
    _save(args, "aws_secrets_manager", results)
    print(f"[+] {len(results['secrets'])} secrets found, {len(results['accessible'])} accessible")
    return 0
