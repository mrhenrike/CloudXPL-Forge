"""Route CLI commands to cloud provider modules."""

from __future__ import annotations

import importlib
import sys
from typing import Any


MODULE_MAP = {
    "aws": {
        "iam-enum": "cloudxpl.modules.aws.iam_enum",
        "s3-enum": "cloudxpl.modules.aws.s3_enum",
        "lambda-enum": "cloudxpl.modules.aws.lambda_enum",
        "ssrf-imds": "cloudxpl.modules.aws.ssrf_imds",
        "ec2-enum": "cloudxpl.modules.aws.ec2_enum",
    },
    "azure": {
        "enum-subs": "cloudxpl.modules.azure.subscription_enum",
        "enum-storage": "cloudxpl.modules.azure.storage_enum",
        "managed-identity": "cloudxpl.modules.azure.managed_identity",
        "arm-injection": "cloudxpl.modules.azure.arm_injection",
    },
    "gcp": {
        "bucket-enum": "cloudxpl.modules.gcp.bucket_enum",
        "sa-enum": "cloudxpl.modules.gcp.service_account_enum",
        "metadata-ssrf": "cloudxpl.modules.gcp.metadata_ssrf",
        "project-enum": "cloudxpl.modules.gcp.project_enum",
    },
}


def dispatch(args: Any) -> int:
    module_path = MODULE_MAP.get(args.command, {}).get(args.module)
    if not module_path:
        print(f"[!] Unknown: {args.command}/{args.module}", file=sys.stderr)
        return 1

    try:
        mod = importlib.import_module(module_path)
    except ImportError as exc:
        print(f"[!] Failed to load {module_path}: {exc}", file=sys.stderr)
        print(f"[*] Install provider deps: pip install cloudxpl-forge[{args.command}]", file=sys.stderr)
        return 1

    return mod.run(args)
