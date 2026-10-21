"""AWS Lambda persistence  -  layer poisoning analysis, trigger backdoor assessment."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.lambda_persist.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ['aws_api_calls'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1525","T1098"],
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

    print(f"[*] AWS Lambda Persistence Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    lam = session.client("lambda")
    results = {"layers": [], "persistence_vectors": []}
    try:
        paginator = lam.get_paginator("list_layers")
        for page in paginator.paginate():
            for layer in page["Layers"]:
                info = {"name": layer["LayerName"], "arn": layer["LayerArn"], "latest_version": layer["LatestMatchingVersion"]["Version"]}
                results["layers"].append(info)
                print(f"  [*] Layer: {layer['LayerName']} (v{info['latest_version']})")
    except Exception as exc:
        print(f"[-] Layer enum failed: {exc}")
    try:
        for page in lam.get_paginator("list_functions").paginate():
            for fn in page["Functions"]:
                fname = fn["FunctionName"]
                role = fn["Role"]
                if fn.get("Layers"):
                    results["persistence_vectors"].append({"function": fname, "type": "layer_attached", "layers": [l["Arn"] for l in fn["Layers"]], "role": role})
                url_config = None
                try:
                    url_config = lam.get_function_url_config(FunctionName=fname)
                    if url_config.get("AuthType") == "NONE":
                        results["persistence_vectors"].append({"function": fname, "type": "public_url", "url": url_config["FunctionUrl"]})
                        print(f"  [!] {fname}: public function URL (no auth)")
                except Exception: pass
    except Exception: pass
    _save(args, "aws_lambda_persist", results)
    print(f"[+] {len(results['layers'])} layers, {len(results['persistence_vectors'])} persistence vectors")
    return 0
