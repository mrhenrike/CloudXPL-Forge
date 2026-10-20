"""AWS CloudTrail evasion analysis — identifies trails, logging gaps, tampering vectors."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.cloudtrail_disable.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1562.008"],
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

    print(f"[*] AWS CloudTrail Evasion Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ct = session.client("cloudtrail")
    results = {"trails": [], "evasion_vectors": []}
    try:
        trails = ct.describe_trails()["trailList"]
        for trail in trails:
            info = {"name": trail["Name"], "s3_bucket": trail.get("S3BucketName"), "is_multi_region": trail.get("IsMultiRegionTrail", False), "log_validation": trail.get("LogFileValidationEnabled", False), "is_organization": trail.get("IsOrganizationTrail", False)}
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                info["is_logging"] = status.get("IsLogging", False)
                if not info["is_logging"]:
                    results["evasion_vectors"].append({"trail": trail["Name"], "type": "logging_disabled"})
                    print(f"  [!] {trail['Name']}: LOGGING DISABLED")
            except Exception: pass
            if not info["log_validation"]:
                results["evasion_vectors"].append({"trail": trail["Name"], "type": "no_log_validation"})
                print(f"  [!] {trail['Name']}: log file validation disabled")
            try:
                selectors = ct.get_event_selectors(TrailName=trail["TrailARN"])
                info["event_selectors"] = len(selectors.get("EventSelectors", []))
            except Exception: pass
            results["trails"].append(info)
    except Exception as exc:
        print(f"[-] CloudTrail enum failed: {exc}"); return 1
    _save(args, "aws_cloudtrail_disable", results)
    print(f"[+] {len(results['trails'])} trails, {len(results['evasion_vectors'])} evasion vectors")
    return 0
