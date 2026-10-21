"""CloudXPL-Forge CLI entrypoint."""


import argparse
import sys

from cloudxpl import __product__, __version__
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
    gcp_p = sub.add_parser("gcp", help="GCP modules (IAM, Buckets, GKE, Cloud SQL, Cloud Armor, WIF, ...)")
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
    multi_p.add_argument("--providers", nargs="+", choices=["aws", "azure", "gcp", "oci", "alibaba", "tencent", "ibm"],
                         default=["aws", "azure", "gcp"])
    _add_common(multi_p)

    # --- Credential ---
    cred_p = sub.add_parser("cred", help="Credential discovery and abuse modules (RSA SecurID, MFA relay, ...)")
    cred_p.add_argument("module", choices=sorted(MODULE_MAP["cred"]))
    cred_p.add_argument("--scan-path", help="Path to scan for credentials")
    _add_common(cred_p)

    # --- Network ---
    net_p = sub.add_parser("net", help="Cloud network attack modules (VPC, SG, DNS, ...)")
    net_p.add_argument("module", choices=sorted(MODULE_MAP["net"]))
    net_p.add_argument("--provider", choices=["aws", "azure", "gcp"], default="aws")
    net_p.add_argument("--cidr", help="Target CIDR range")
    _add_common(net_p)

    # --- OCI (Oracle Cloud) ---
    oci_p = sub.add_parser("oci", help="Oracle Cloud modules (OCI IAM, buckets, compute, CVEs, ...)")
    oci_p.add_argument("module", choices=sorted(MODULE_MAP["oci"]))
    oci_p.add_argument("--tenancy-ocid", help="OCI tenancy OCID")
    oci_p.add_argument("--region", default="us-ashburn-1", help="OCI region")
    oci_p.add_argument("--config-file", default="~/.oci/config", help="OCI config file path")
    _add_common(oci_p)

    # --- Virtualization / Hypervisors ---
    virt_p = sub.add_parser("virt", help="Hypervisor modules (VMware, Hyper-V, KVM, QEMU, Citrix, Nutanix, ...)")
    virt_p.add_argument("module", choices=sorted(MODULE_MAP["virt"]))
    virt_p.add_argument("--vcenter-host", help="vCenter/ESXi host")
    virt_p.add_argument("--hyperv-host", help="Hyper-V host")
    virt_p.add_argument("--libvirt-uri", default="qemu:///system", help="Libvirt connection URI")
    _add_common(virt_p)

    # --- Alibaba Cloud ---
    ali_p = sub.add_parser("alibaba", help="Alibaba Cloud modules (ECS, OSS, RAM, RDS, ...)")
    ali_p.add_argument("module", choices=sorted(MODULE_MAP["alibaba"]))
    ali_p.add_argument("--access-key-id", help="Alibaba Cloud AccessKey ID")
    ali_p.add_argument("--region", default="cn-hangzhou", help="Alibaba Cloud region")
    _add_common(ali_p)

    # --- Tencent Cloud ---
    tc_p = sub.add_parser("tencent", help="Tencent Cloud modules (COS, CVM, CAM, ...)")
    tc_p.add_argument("module", choices=sorted(MODULE_MAP["tencent"]))
    tc_p.add_argument("--secret-id", help="Tencent Cloud SecretId")
    tc_p.add_argument("--region", default="ap-guangzhou", help="Tencent Cloud region")
    _add_common(tc_p)

    # --- IBM Cloud ---
    ibm_p = sub.add_parser("ibm", help="IBM Cloud modules (COS, IAM, VPC, QRadar, CloudPak, ...)")
    ibm_p.add_argument("module", choices=sorted(MODULE_MAP["ibm"]))
    ibm_p.add_argument("--api-key", help="IBM Cloud API key")
    ibm_p.add_argument("--region", default="us-south", help="IBM Cloud region")
    _add_common(ibm_p)

    # --- DigitalOcean ---
    do_p = sub.add_parser("digitalocean", help="DigitalOcean modules (Droplets, Spaces, DOKS, ...)")
    do_p.add_argument("module", choices=sorted(MODULE_MAP["digitalocean"]))
    do_p.add_argument("--api-token", help="DigitalOcean API token")
    do_p.add_argument("--region", default="nyc1", help="DigitalOcean region")
    _add_common(do_p)

    # --- OVHcloud ---
    ovh_p = sub.add_parser("ovh", help="OVHcloud modules (OpenStack, vRack, Swift, IPMI, ...)")
    ovh_p.add_argument("module", choices=sorted(MODULE_MAP["ovh"]))
    ovh_p.add_argument("--app-key", help="OVH application key")
    ovh_p.add_argument("--region", default="GRA", help="OVHcloud region")
    _add_common(ovh_p)

    # --- Hetzner ---
    hetz_p = sub.add_parser("hetzner", help="Hetzner Cloud modules (servers, firewalls, floating IPs, ...)")
    hetz_p.add_argument("module", choices=sorted(MODULE_MAP["hetzner"]))
    hetz_p.add_argument("--api-token", help="Hetzner API token")
    hetz_p.add_argument("--region", default="nbg1", help="Hetzner datacenter/region")
    _add_common(hetz_p)

    # --- VDI (Virtual Desktop Infrastructure) ---
    vdi_p = sub.add_parser("vdi", help="VDI escape modules (Horizon, Citrix VDA, AVD, WorkSpaces, kiosk, ...)")
    vdi_p.add_argument("module", choices=sorted(MODULE_MAP["vdi"]))
    vdi_p.add_argument("--vdi-host", help="VDI broker/connection server host")
    vdi_p.add_argument("--session-id", help="Target VDI session ID")
    _add_common(vdi_p)

    # --- PaaS (Platform-as-a-Service) ---
    paas_p = sub.add_parser("paas", help="PaaS escape modules (App Service, ACI, Cloud Run, Fargate, Lambda, ...)")
    paas_p.add_argument("module", choices=sorted(MODULE_MAP["paas"]))
    paas_p.add_argument("--provider", choices=["aws", "azure", "gcp", "heroku", "railway"], default="aws")
    paas_p.add_argument("--function-name", help="Target function/service name")
    _add_common(paas_p)

    # --- CI/CD ---
    cicd_p = sub.add_parser("cicd", help="CI/CD runner escape modules (GitHub Actions, GitLab CI, Jenkins, Terraform, ...)")
    cicd_p.add_argument("module", choices=sorted(MODULE_MAP["cicd"]))
    cicd_p.add_argument("--runner-url", help="CI/CD runner or server URL")
    cicd_p.add_argument("--token", help="CI/CD API token or runner token")
    _add_common(cicd_p)

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
