"""CloudXPL-Forge CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from cloudxpl import __version__, __product__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cxf",
        description=f"{__product__} v{__version__} — Cloud security assessment framework",
    )
    p.add_argument("--version", action="version", version=f"{__product__} {__version__}")

    sub = p.add_subparsers(dest="command")

    aws_p = sub.add_parser("aws", help="AWS modules")
    aws_p.add_argument("module", choices=[
        "iam-enum", "s3-enum", "lambda-enum", "ssrf-imds", "ec2-enum",
    ])
    aws_p.add_argument("--profile", default=None, help="AWS CLI profile")
    aws_p.add_argument("--region", default="us-east-1")
    aws_p.add_argument("--target", "-t", help="Target URL for SSRF")
    aws_p.add_argument("--output", "-o", default=".")

    azure_p = sub.add_parser("azure", help="Azure modules")
    azure_p.add_argument("module", choices=[
        "enum-subs", "enum-storage", "managed-identity", "arm-injection",
    ])
    azure_p.add_argument("--tenant-id", help="Azure tenant ID")
    azure_p.add_argument("--subscription-id", help="Azure subscription ID")
    azure_p.add_argument("--output", "-o", default=".")

    gcp_p = sub.add_parser("gcp", help="GCP modules")
    gcp_p.add_argument("module", choices=[
        "bucket-enum", "sa-enum", "metadata-ssrf", "project-enum",
    ])
    gcp_p.add_argument("--project", help="GCP project ID")
    gcp_p.add_argument("--target", "-t", help="Target URL for SSRF")
    gcp_p.add_argument("--output", "-o", default=".")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    from cloudxpl.core.dispatcher import dispatch
    return dispatch(args)


if __name__ == "__main__":
    sys.exit(main())
