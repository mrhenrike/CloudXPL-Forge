"""AWS ECR enumeration  -  repositories, images, scan findings."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.ecr_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1525"],
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

    print(f"[*] AWS ECR Enumeration (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ecr = session.client("ecr")
    results = {"repositories": [], "public_repos": []}
    try:
        paginator = ecr.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page["repositories"]:
                info = {"name": repo["repositoryName"], "uri": repo["repositoryUri"], "scan_on_push": repo.get("imageScanningConfiguration", {}).get("scanOnPush", False)}
                try:
                    policy = ecr.get_repository_policy(repositoryName=repo["repositoryName"])
                    import json as _json
                    pol = _json.loads(policy["policyText"])
                    for stmt in pol.get("Statement", []):
                        if stmt.get("Principal") == "*":
                            info["public"] = True
                            results["public_repos"].append(repo["repositoryName"])
                            print(f"  [!] {repo['repositoryName']}: PUBLIC access policy")
                except Exception: pass
                results["repositories"].append(info)
                print(f"  [+] {repo['repositoryName']} (scan: {info['scan_on_push']})")
    except Exception as exc:
        print(f"[-] ECR enum failed: {exc}"); return 1
    _save(args, "aws_ecr_enum", results)
    print(f"[+] {len(results['repositories'])} repos, {len(results['public_repos'])} public")
    return 0
