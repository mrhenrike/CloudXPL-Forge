"""AWS Route53 subdomain takeover — dangling CNAME, alias records, NS delegation."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.route53_takeover.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1584.001"],
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

    print(f"[*] AWS Route53 Subdomain Takeover Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    r53 = session.client("route53")
    results = {"zones": [], "dangling": []}
    try:
        zones = r53.list_hosted_zones()["HostedZones"]
        for zone in zones:
            zid = zone["Id"].split("/")[-1]
            info = {"id": zid, "name": zone["Name"], "private": zone["Config"].get("PrivateZone", False), "records": []}
            paginator = r53.get_paginator("list_resource_record_sets")
            for page in paginator.paginate(HostedZoneId=zid):
                for rr in page["ResourceRecordSets"]:
                    if rr["Type"] == "CNAME":
                        target = rr.get("ResourceRecords", [{}])[0].get("Value", "") if rr.get("ResourceRecords") else ""
                        info["records"].append({"name": rr["Name"], "type": "CNAME", "target": target})
                        takeover_sigs = [".s3.amazonaws.com", ".cloudfront.net", ".elasticbeanstalk.com", ".herokuapp.com", ".azurewebsites.net", ".trafficmanager.net"]
                        if any(sig in target for sig in takeover_sigs):
                            results["dangling"].append({"record": rr["Name"], "target": target, "zone": zone["Name"]})
                            print(f"  [!] Potential takeover: {rr['Name']} -> {target}")
            results["zones"].append(info)
    except Exception as exc:
        print(f"[-] Route53 enum failed: {exc}"); return 1
    _save(args, "aws_route53_takeover", results)
    print(f"[+] {len(results['zones'])} zones, {len(results['dangling'])} potential takeovers")
    return 0
