"""AWS Systems Manager exploitation  -  RunCommand, session manager, parameter store."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.ec2_ssm.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ['aws_api_calls'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1059","T1021"],
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

    print(f"[*] AWS SSM Exploitation Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ssm = session.client("ssm")
    results = {"managed_instances": [], "documents": [], "command_history": []}
    try:
        paginator = ssm.get_paginator("describe_instance_information")
        for page in paginator.paginate():
            for inst in page["InstanceInformationList"]:
                info = {"instance_id": inst["InstanceId"], "platform": inst.get("PlatformType", "unknown"), "agent_version": inst.get("AgentVersion"), "ip": inst.get("IPAddress")}
                results["managed_instances"].append(info)
                print(f"  [+] {inst['InstanceId']}: {inst.get('PlatformType')} ({inst.get('IPAddress')})")
    except Exception as exc:
        print(f"[-] Instance enum failed: {exc}")
    try:
        docs = ssm.list_documents(Filters=[{"Key": "Owner", "Values": ["Self"]}])
        for doc in docs.get("DocumentIdentifiers", []):
            results["documents"].append({"name": doc["Name"], "type": doc.get("DocumentType"), "format": doc.get("DocumentFormat")})
    except Exception: pass
    try:
        cmds = ssm.list_commands(MaxResults=50)
        for cmd in cmds.get("Commands", []):
            results["command_history"].append({"id": cmd["CommandId"], "document": cmd["DocumentName"], "status": cmd["Status"], "targets": cmd.get("Targets", [])})
    except Exception: pass
    _save(args, "aws_ec2_ssm", results)
    print(f"[+] {len(results['managed_instances'])} managed instances, {len(results['documents'])} custom documents")
    return 0
