"""AWS Lambda enumeration  -  list functions, runtimes, env vars, layers."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.lambda_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["aws_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526"],
}


def run(args: Any) -> int:
    print(f"[*] AWS Lambda Enumeration (region: {args.region})")

    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr)
        return 1

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    lam = session.client("lambda")

    try:
        paginator = lam.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page["Functions"])
    except Exception as exc:
        print(f"[-] list_functions failed: {exc}", file=sys.stderr)
        return 1

    print(f"[+] {len(functions)} Lambda functions")
    results = []

    for fn in functions:
        entry = {
            "name": fn["FunctionName"],
            "runtime": fn.get("Runtime", "container"),
            "role": fn["Role"],
            "handler": fn.get("Handler"),
            "code_size": fn["CodeSize"],
            "timeout": fn.get("Timeout"),
            "memory": fn.get("MemorySize"),
            "last_modified": fn.get("LastModified"),
            "layers": [l["Arn"] for l in fn.get("Layers", [])],
        }

        env_vars = fn.get("Environment", {}).get("Variables", {})
        if env_vars:
            sensitive_keys = [k for k in env_vars if any(
                s in k.upper() for s in ["SECRET", "KEY", "TOKEN", "PASSWORD", "CREDENTIAL", "API_KEY"]
            )]
            entry["env_var_count"] = len(env_vars)
            entry["sensitive_env_keys"] = sensitive_keys
            if sensitive_keys:
                print(f"  [!] {fn['FunctionName']}: sensitive env vars: {', '.join(sensitive_keys)}")

        vpc = fn.get("VpcConfig", {})
        if vpc.get("SubnetIds"):
            entry["vpc"] = True
            entry["subnets"] = vpc["SubnetIds"]
        else:
            entry["vpc"] = False

        results.append(entry)

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"aws_lambda_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    print(f"[+] Output: {out_path}")
    return 0
