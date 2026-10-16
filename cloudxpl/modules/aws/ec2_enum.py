"""AWS EC2 instance enumeration — instances, security groups, metadata."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.ec2_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["aws_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1580"],
}


def run(args: Any) -> int:
    print(f"[*] AWS EC2 Enumeration (region: {args.region})")

    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr)
        return 1

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ec2 = session.client("ec2")

    try:
        reservations = ec2.describe_instances()["Reservations"]
    except Exception as exc:
        print(f"[-] describe_instances failed: {exc}", file=sys.stderr)
        return 1

    results = []
    for res in reservations:
        for inst in res["Instances"]:
            entry = {
                "instance_id": inst["InstanceId"],
                "state": inst["State"]["Name"],
                "type": inst["InstanceType"],
                "private_ip": inst.get("PrivateIpAddress"),
                "public_ip": inst.get("PublicIpAddress"),
                "vpc_id": inst.get("VpcId"),
                "subnet_id": inst.get("SubnetId"),
                "iam_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                "imds_v2": inst.get("MetadataOptions", {}).get("HttpTokens", "optional"),
                "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
            }
            if entry["imds_v2"] == "optional":
                print(f"  [!] {entry['instance_id']}: IMDSv1 enabled (no token required)")
            if entry["public_ip"]:
                print(f"  [*] {entry['instance_id']}: public IP {entry['public_ip']}")
            results.append(entry)

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"aws_ec2_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    print(f"[+] {len(results)} instances → {out_path}")
    return 0
