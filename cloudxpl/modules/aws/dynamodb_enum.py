"""AWS DynamoDB enumeration and data access analysis."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.dynamodb_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1530"],
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

    print(f"[*] AWS DynamoDB Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ddb = session.client("dynamodb")
    results = {"tables": []}
    try:
        tables = ddb.list_tables()["TableNames"]
        for tname in tables:
            desc = ddb.describe_table(TableName=tname)["Table"]
            info = {"name": tname, "status": desc["TableStatus"], "item_count": desc.get("ItemCount", 0), "encrypted": bool(desc.get("SSEDescription")), "size_bytes": desc.get("TableSizeBytes", 0)}
            results["tables"].append(info)
            print(f"  [+] {tname}: {info['item_count']} items, {info['size_bytes']/1024:.0f} KB")
    except Exception as exc:
        print(f"[-] DynamoDB enum failed: {exc}"); return 1
    _save(args, "aws_dynamodb_enum", results)
    print(f"[+] {len(results['tables'])} tables found")
    return 0
