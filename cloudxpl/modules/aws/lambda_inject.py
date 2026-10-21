"""AWS Lambda event injection  -  trigger abuse, environment extraction, layer analysis."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.lambda_inject.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ['aws_api_calls'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1648"],
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

    print(f"[*] AWS Lambda Injection Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    lam = session.client("lambda")
    results = {"functions": [], "injectable": []}
    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                fname = fn["FunctionName"]
                info = {"name": fname, "runtime": fn.get("Runtime", "unknown"), "role": fn["Role"], "handler": fn.get("Handler", "")}
                env_vars = fn.get("Environment", {}).get("Variables", {})
                if env_vars:
                    info["env_var_count"] = len(env_vars)
                    sensitive_keys = [k for k in env_vars if any(s in k.upper() for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "API"])]
                    if sensitive_keys:
                        info["sensitive_env_keys"] = sensitive_keys
                        print(f"  [!] {fname}: sensitive env vars: {sensitive_keys}")
                layers = fn.get("Layers", [])
                if layers:
                    info["layers"] = [l["Arn"] for l in layers]
                try:
                    policy = lam.get_policy(FunctionName=fname)
                    import json as _json
                    pol = _json.loads(policy["Policy"])
                    for stmt in pol.get("Statement", []):
                        if stmt.get("Principal") in ("*", {"AWS": "*"}):
                            info["public_invoke"] = True
                            results["injectable"].append({"function": fname, "type": "public_invoke"})
                            print(f"  [!] {fname}: publicly invokable!")
                except Exception: pass
                try:
                    mappings = lam.list_event_source_mappings(FunctionName=fname)["EventSourceMappings"]
                    if mappings:
                        info["event_sources"] = [{"source": m["EventSourceArn"], "state": m["State"]} for m in mappings]
                except Exception: pass
                results["functions"].append(info)
    except Exception as exc:
        print(f"[-] Lambda enum failed: {exc}"); return 1
    _save(args, "aws_lambda_inject", results)
    print(f"[+] {len(results['functions'])} functions, {len(results['injectable'])} injectable")
    return 0
