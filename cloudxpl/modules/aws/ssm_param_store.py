"""AWS SSM Parameter Store enumeration — strings, SecureString, credential extraction."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.ssm_param_store.v1",
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

    print(f"[*] AWS SSM Parameter Store Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ssm = session.client("ssm")
    results = {"parameters": [], "secure_strings": [], "decryptable": []}
    try:
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page["Parameters"]:
                info = {"name": param["Name"], "type": param["Type"], "last_modified": str(param.get("LastModifiedDate", ""))}
                if param["Type"] == "SecureString":
                    results["secure_strings"].append(param["Name"])
                    try:
                        val = ssm.get_parameter(Name=param["Name"], WithDecryption=True)
                        info["decryptable"] = True
                        results["decryptable"].append(param["Name"])
                        print(f"  [!] {param['Name']}: SecureString DECRYPTABLE")
                    except Exception:
                        info["decryptable"] = False
                else:
                    try:
                        val = ssm.get_parameter(Name=param["Name"])
                        v = val["Parameter"]["Value"]
                        if any(k in param["Name"].upper() for k in ["KEY", "SECRET", "TOKEN", "PASS", "CRED"]):
                            print(f"  [!] {param['Name']}: sensitive parameter name")
                    except Exception: pass
                results["parameters"].append(info)
    except Exception as exc:
        print(f"[-] Parameter enumeration failed: {exc}"); return 1
    _save(args, "aws_ssm_param_store", results)
    print(f"[+] {len(results['parameters'])} params, {len(results['secure_strings'])} SecureString, {len(results['decryptable'])} decryptable")
    return 0
