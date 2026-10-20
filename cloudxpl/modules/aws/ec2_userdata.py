"""AWS EC2 User Data extraction  -  cloud-init scripts, embedded credentials."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.ec2_userdata.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552.005"],
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

    print(f"[*] AWS EC2 User Data Extraction (region: {args.region})")
    try:
        import boto3; import base64
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ec2 = session.client("ec2")
    results = {"instances": [], "credentials_found": []}
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
                    try:
                        ud = ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")
                        data = ud.get("UserData", {}).get("Value")
                        if data:
                            decoded = base64.b64decode(data).decode("utf-8", errors="replace")
                            info = {"instance_id": iid, "state": inst["State"]["Name"], "userdata_size": len(decoded)}
                            sensitive = []
                            for line in decoded.split("\n"):
                                ll = line.upper()
                                if any(k in ll for k in ["PASSWORD", "SECRET", "API_KEY", "TOKEN", "AWS_ACCESS", "AWS_SECRET"]):
                                    sensitive.append(line.strip()[:80])
                            if sensitive:
                                info["sensitive_lines"] = len(sensitive)
                                results["credentials_found"].append({"instance": iid, "count": len(sensitive)})
                                print(f"  [!] {iid}: {len(sensitive)} sensitive lines in userdata")
                            results["instances"].append(info)
                    except Exception: pass
    except Exception as exc:
        print(f"[-] EC2 enum failed: {exc}"); return 1
    _save(args, "aws_ec2_userdata", results)
    print(f"[+] {len(results['instances'])} instances with userdata, {len(results['credentials_found'])} with credentials")
    return 0
