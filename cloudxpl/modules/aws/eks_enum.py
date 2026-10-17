"""AWS EKS cluster enumeration — clusters, node groups, RBAC, IRSA."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.eks_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526"],
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

    print(f"[*] AWS EKS Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    eks = session.client("eks")
    results = {"clusters": []}
    try:
        clusters = eks.list_clusters()["clusters"]
        for cname in clusters:
            cluster = eks.describe_cluster(name=cname)["cluster"]
            info = {"name": cname, "version": cluster.get("version"), "endpoint": cluster.get("endpoint", "")[:50] + "...", "status": cluster["status"], "public_access": cluster.get("resourcesVpcConfig", {}).get("endpointPublicAccess", False), "logging": {}}
            logging_config = cluster.get("logging", {}).get("clusterLogging", [])
            for lc in logging_config:
                for lt in lc.get("types", []):
                    info["logging"][lt] = lc.get("enabled", False)
            if info["public_access"]:
                cidrs = cluster.get("resourcesVpcConfig", {}).get("publicAccessCidrs", [])
                if "0.0.0.0/0" in cidrs:
                    print(f"  [!] {cname}: public endpoint open to 0.0.0.0/0")
                else:
                    print(f"  [+] {cname}: public endpoint restricted")
            try:
                nodegroups = eks.list_nodegroups(clusterName=cname)["nodegroups"]
                info["nodegroups"] = len(nodegroups)
            except Exception: pass
            results["clusters"].append(info)
    except Exception as exc:
        print(f"[-] EKS enum failed: {exc}"); return 1
    _save(args, "aws_eks_enum", results)
    print(f"[+] {len(results['clusters'])} EKS clusters found")
    return 0
