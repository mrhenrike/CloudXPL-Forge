"""AWS S3 data exfiltration — object listing, download, cross-account copy simulation."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.s3_exfil.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ['aws_api_calls', 'data_access'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1537","T1530"],
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

    print(f"[*] AWS S3 Exfiltration Assessment (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    target = getattr(args, "target", None)
    if not target:
        print("[!] --target bucket name required"); return 1
    results = {"bucket": target, "objects": [], "total_size": 0}
    try:
        paginator = s3.get_paginator("list_objects_v2")
        count = 0
        for page in paginator.paginate(Bucket=target, MaxKeys=1000):
            for obj in page.get("Contents", []):
                results["objects"].append({"key": obj["Key"], "size": obj["Size"], "modified": obj["LastModified"].isoformat()})
                results["total_size"] += obj["Size"]
                count += 1
                if count <= 20:
                    print(f"  {obj['Key']} ({obj['Size']} bytes)")
        print(f"[+] {count} objects found, total size: {results['total_size'] / (1024*1024):.1f} MB")
    except Exception as exc:
        print(f"[-] List objects failed: {exc}"); return 1
    _save(args, "aws_s3_exfil", results)
    return 0
