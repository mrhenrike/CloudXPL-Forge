"""AWS RDS enumeration — instances, clusters, public snapshots."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.rds_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526"],
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

    print(f"[*] AWS RDS Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    rds = session.client("rds")
    results = {"instances": [], "public": [], "snapshots": []}
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                info = {"id": db["DBInstanceIdentifier"], "engine": db["Engine"], "status": db["DBInstanceStatus"], "public": db.get("PubliclyAccessible", False), "encrypted": db.get("StorageEncrypted", False)}
                if info["public"]:
                    results["public"].append(db["DBInstanceIdentifier"])
                    print(f"  [!] {db['DBInstanceIdentifier']}: PUBLICLY accessible ({db['Engine']})")
                else:
                    print(f"  [+] {db['DBInstanceIdentifier']}: {db['Engine']} ({db['DBInstanceStatus']})")
                results["instances"].append(info)
    except Exception as exc:
        print(f"[-] RDS enum failed: {exc}"); return 1
    try:
        snaps = rds.describe_db_snapshots(SnapshotType="public")
        for snap in snaps.get("DBSnapshots", []):
            results["snapshots"].append({"id": snap["DBSnapshotIdentifier"], "engine": snap["Engine"]})
            print(f"  [!] Public snapshot: {snap['DBSnapshotIdentifier']}")
    except Exception: pass
    _save(args, "aws_rds_enum", results)
    print(f"[+] {len(results['instances'])} instances, {len(results['public'])} public")
    return 0
