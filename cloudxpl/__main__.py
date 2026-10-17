"""CloudXPL-Forge CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from cloudxpl import __version__, __product__
from cloudxpl.core.dispatcher import MODULE_MAP


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--target", "-t", help="Target URL/host")
    p.add_argument("--output", "-o", default=".", help="Output directory")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--verbose", "-v", action="store_true")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cxf",
        description=f"{__product__} v{__version__} — Cloud security assessment framework",
    )
    p.add_argument("--version", action="version", version=f"{__product__} {__version__}")

    sub = p.add_subparsers(dest="command")

    # --- AWS ---
    aws_p = sub.add_parser("aws", help="AWS modules (IAM, S3, EC2, Lambda, EKS, RDS, ...)")
    aws_p.add_argument("module", choices=sorted(MODULE_MAP["aws"]))
    aws_p.add_argument("--profile", default=None, help="AWS CLI profile")
    aws_p.add_argument("--region", default="us-east-1")
    aws_p.add_argument("--role-arn", help="ARN to assume")
    _add_common(aws_p)

    # --- Azure ---
    azure_p = sub.add_parser("azure", help="Azure modules (Entra, Blob, AKS, KeyVault, ...)")
    azure_p.add_argument("module", choices=sorted(MODULE_MAP["azure"]))
    azure_p.add_argument("--tenant-id", help="Azure tenant ID")
    azure_p.add_argument("--subscription-id", help="Azure subscription ID")
    azure_p.add_argument("--client-id", help="App/SP client ID")
    _add_common(azure_p)

    # --- GCP ---
    gcp_p = sub.add_parser("gcp", help="GCP modules (IAM, Buckets, GKE, Cloud SQL, ...)")
    gcp_p.add_argument("module", choices=sorted(MODULE_MAP["gcp"]))
    gcp_p.add_argument("--project", help="GCP project ID")
    gcp_p.add_argument("--sa-key", help="Service account key file")
    _add_common(gcp_p)

    # --- Kubernetes ---
    k8s_p = sub.add_parser("k8s", help="Kubernetes/container modules (RBAC, pods, escape, ...)")
    k8s_p.add_argument("module", choices=sorted(MODULE_MAP["k8s"]))
    k8s_p.add_argument("--kubeconfig", help="Kubeconfig path")
    k8s_p.add_argument("--context", help="Kubernetes context")
    k8s_p.add_argument("--namespace", "-n", default="default")
    _add_common(k8s_p)

    # --- Serverless ---
    sls_p = sub.add_parser("serverless", help="Serverless attack modules (Lambda, Functions, ...)")
    sls_p.add_argument("module", choices=sorted(MODULE_MAP["serverless"]))
    sls_p.add_argument("--provider", choices=["aws", "azure", "gcp"], default="aws")
    sls_p.add_argument("--function-name", help="Target function")
    _add_common(sls_p)

    # --- Storage ---
    sto_p = sub.add_parser("storage", help="Cloud storage attack modules (S3, GCS, Blob, ...)")
    sto_p.add_argument("module", choices=sorted(MODULE_MAP["storage"]))
    sto_p.add_argument("--provider", choices=["aws", "azure", "gcp", "all"], default="all")
    sto_p.add_argument("--bucket", "-b", help="Bucket/container name")
    sto_p.add_argument("--wordlist", "-w", help="Wordlist for brute-force")
    _add_common(sto_p)

    # --- Multi-cloud ---
    multi_p = sub.add_parser("multi", help="Multi-cloud and cross-provider modules")
    multi_p.add_argument("module", choices=sorted(MODULE_MAP["multi"]))
    multi_p.add_argument("--providers", nargs="+", choices=["aws", "azure", "gcp"], default=["aws", "azure", "gcp"])
    _add_common(multi_p)

    # --- Credential ---
    cred_p = sub.add_parser("cred", help="Credential discovery and abuse modules")
    cred_p.add_argument("module", choices=sorted(MODULE_MAP["cred"]))
    cred_p.add_argument("--scan-path", help="Path to scan for credentials")
    _add_common(cred_p)

    # --- Network ---
    net_p = sub.add_parser("net", help="Cloud network attack modules (VPC, SG, DNS, ...)")
    net_p.add_argument("module", choices=sorted(MODULE_MAP["net"]))
    net_p.add_argument("--provider", choices=["aws", "azure", "gcp"], default="aws")
    net_p.add_argument("--cidr", help="Target CIDR range")
    _add_common(net_p)

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
