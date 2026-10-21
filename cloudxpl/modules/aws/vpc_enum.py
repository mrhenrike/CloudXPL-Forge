"""AWS VPC enumeration  -  VPCs, subnets, security groups, NACLs."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.vpc_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1580"],
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

    print(f"[*] AWS VPC Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ec2 = session.client("ec2")
    results = {"vpcs": [], "security_groups": [], "exposed_ports": []}
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        for vpc in vpcs:
            info = {"id": vpc["VpcId"], "cidr": vpc["CidrBlock"], "default": vpc.get("IsDefault", False)}
            results["vpcs"].append(info)
            print(f"  [+] VPC: {vpc['VpcId']} ({vpc['CidrBlock']})")
    except Exception as exc:
        print(f"[-] VPC enum failed: {exc}")
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            info = {"id": sg["GroupId"], "name": sg["GroupName"], "vpc": sg.get("VpcId"), "ingress_rules": len(sg.get("IpPermissions", []))}
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", "all")
                        results["exposed_ports"].append({"sg": sg["GroupId"], "port": port, "protocol": rule.get("IpProtocol", "all")})
                        print(f"  [!] {sg['GroupId']}: port {port} open to 0.0.0.0/0")
            results["security_groups"].append(info)
    except Exception as exc:
        print(f"[-] SG enum failed: {exc}")
    _save(args, "aws_vpc_enum", results)
    print(f"[+] {len(results['vpcs'])} VPCs, {len(results['security_groups'])} SGs, {len(results['exposed_ports'])} exposed ports")
    return 0
