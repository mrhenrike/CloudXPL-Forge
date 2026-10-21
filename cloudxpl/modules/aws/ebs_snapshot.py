"""AWS EBS snapshot enumeration — public snapshots, cross-account sharing."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.ebs_snapshot.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1530"],
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

    print(f"[*] AWS EBS Snapshot Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ec2 = session.client("ec2")
    sts = session.client("sts")
    account = sts.get_caller_identity()["Account"]
    results = {"snapshots": [], "public": [], "shared": []}
    try:
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[account]):
            for snap in page["Snapshots"]:
                info = {"id": snap["SnapshotId"], "volume_size": snap["VolumeSize"], "encrypted": snap.get("Encrypted", False), "state": snap["State"]}
                try:
                    attrs = ec2.describe_snapshot_attribute(SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission")
                    perms = attrs.get("CreateVolumePermissions", [])
                    for p in perms:
                        if p.get("Group") == "all":
                            info["public"] = True
                            results["public"].append(snap["SnapshotId"])
                            print(f"  [!] {snap['SnapshotId']}: PUBLIC")
                        elif p.get("UserId"):
                            info["shared_with"] = p["UserId"]
                            results["shared"].append({"snapshot": snap["SnapshotId"], "shared_with": p["UserId"]})
                except Exception: pass
                results["snapshots"].append(info)
    except Exception as exc:
        print(f"[-] Snapshot enum failed: {exc}"); return 1
    _save(args, "aws_ebs_snapshot", results)
    print(f"[+] {len(results['snapshots'])} snapshots, {len(results['public'])} public, {len(results['shared'])} shared")
    return 0
