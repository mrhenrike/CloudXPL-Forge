"""AWS CloudTrail tampering assessment — trail deletion, S3 bucket manipulation."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.cloudtrail_tamper.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1562.008"],
}


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def run(args: Any) -> int:

    print(f"[*] AWS CloudTrail Tamper Assessment (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ct = session.client("cloudtrail")
    iam = session.client("iam")
    sts = session.client("sts")
    caller = sts.get_caller_identity()
    results = {"caller": caller["Arn"], "tamper_capabilities": []}
    try:
        trails = ct.describe_trails()["trailList"]
        for trail in trails:
            caps = {"trail": trail["Name"], "actions": []}
            try:
                ct.get_trail_status(Name=trail["TrailARN"])
                caps["actions"].append("describe")
            except Exception: pass
            results["tamper_capabilities"].append(caps)
            print(f"  [*] Trail: {trail['Name']} — {trail.get('S3BucketName', 'N/A')}")
    except Exception as exc:
        print(f"[-] Trail enumeration failed: {exc}"); return 1
    _save(args, "aws_cloudtrail_tamper", results)
    return 0
