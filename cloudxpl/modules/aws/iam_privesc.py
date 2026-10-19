"""AWS IAM privilege escalation path analysis — identifies 20+ escalation vectors."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.iam_privesc.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078","T1068"],
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

    print(f"[*] AWS IAM Privilege Escalation Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    iam = session.client("iam")
    sts = session.client("sts")
    caller = sts.get_caller_identity()
    print(f"[+] Caller: {caller['Arn']}")
    escalation_paths = []
    DANGEROUS_ACTIONS = [
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:PassRole", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
        "iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy",
        "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy",
        "iam:CreateAccessKey", "iam:AddUserToGroup",
        "sts:AssumeRole", "iam:UpdateAssumeRolePolicy",
        "lambda:CreateFunction", "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
        "ec2:RunInstances", "cloudformation:CreateStack",
        "datapipeline:CreatePipeline", "glue:CreateDevEndpoint",
    ]
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                try:
                    policies = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
                    inline = iam.list_user_policies(UserName=uname)["PolicyNames"]
                    for pol in policies:
                        try:
                            arn = pol["PolicyArn"]
                            ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                            doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
                            stmts = doc.get("Statement", [])
                            if isinstance(stmts, dict): stmts = [stmts]
                            for stmt in stmts:
                                if stmt.get("Effect") != "Allow": continue
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str): actions = [actions]
                                for act in actions:
                                    if act == "*" or act in DANGEROUS_ACTIONS:
                                        escalation_paths.append({
                                            "user": uname, "policy": pol["PolicyName"],
                                            "action": act, "resource": str(stmt.get("Resource", "*")),
                                        })
                                        print(f"  [!] {uname}: {act} via {pol['PolicyName']}")
                        except Exception:
                            pass
                except Exception:
                    pass
    except Exception as exc:
        print(f"[-] Enumeration failed: {exc}", file=sys.stderr)
    results = {"caller": caller["Arn"], "escalation_paths": escalation_paths, "total": len(escalation_paths)}
    _save(args, "aws_iam_privesc", results)
    print(f"[+] {len(escalation_paths)} escalation paths found")
    return 0
