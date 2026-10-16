"""AWS IAM enumeration — users, roles, policies, access keys."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.iam_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["aws_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004"],
}


def run(args: Any) -> int:
    print(f"[*] AWS IAM Enumeration (region: {args.region})")

    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed: pip install cloudxpl-forge[aws]", file=sys.stderr)
        return 1

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    iam = session.client("iam")
    sts = session.client("sts")

    results: dict[str, Any] = {}

    try:
        identity = sts.get_caller_identity()
        results["caller_identity"] = {
            "account": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }
        print(f"[+] Identity: {identity['Arn']}")
    except Exception as exc:
        print(f"[-] get_caller_identity failed: {exc}", file=sys.stderr)
        return 1

    try:
        users = iam.list_users()["Users"]
        results["users"] = [
            {"UserName": u["UserName"], "Arn": u["Arn"],
             "CreateDate": u["CreateDate"].isoformat(),
             "PasswordLastUsed": u.get("PasswordLastUsed", "").isoformat() if u.get("PasswordLastUsed") else None}
            for u in users
        ]
        print(f"[+] {len(users)} IAM users")
    except Exception as exc:
        results["users_error"] = str(exc)

    try:
        roles = iam.list_roles()["Roles"]
        results["roles"] = [
            {"RoleName": r["RoleName"], "Arn": r["Arn"],
             "AssumeRolePolicyDocument": r.get("AssumeRolePolicyDocument")}
            for r in roles
        ]
        print(f"[+] {len(roles)} IAM roles")
    except Exception as exc:
        results["roles_error"] = str(exc)

    try:
        policies = iam.list_policies(Scope="Local")["Policies"]
        results["custom_policies"] = [
            {"PolicyName": p["PolicyName"], "Arn": p["Arn"],
             "AttachmentCount": p["AttachmentCount"]}
            for p in policies
        ]
        print(f"[+] {len(policies)} custom policies")
    except Exception as exc:
        results["policies_error"] = str(exc)

    for user in results.get("users", []):
        try:
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            user["access_keys"] = [
                {"AccessKeyId": k["AccessKeyId"], "Status": k["Status"],
                 "CreateDate": k["CreateDate"].isoformat()}
                for k in keys
            ]
        except Exception:
            pass

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"aws_iam_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    print(f"[+] Output: {out_path}")
    return 0
