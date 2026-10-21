# Third-Party Components  -  CloudXPL-Forge

| Component | License | Usage |
|-----------|---------|-------|
| boto3 | Apache 2.0 | AWS SDK  -  IAM, S3, EC2, Lambda API calls |
| azure-identity | MIT | Azure credential management |
| azure-mgmt-resource | MIT | Azure Resource Manager API |
| azure-mgmt-storage | MIT | Azure Storage management API |
| google-cloud-storage | Apache 2.0 | GCP Cloud Storage API |
| google-auth | Apache 2.0 | GCP authentication |
| requests | Apache 2.0 | HTTP client for SSRF/metadata/API calls |
| rich | MIT | Terminal formatting and output |
| dnspython | ISC | DNS resolution utilities |
| impacket | Apache 2.0 | Network protocol library (optional) |
| pytest | MIT | Testing framework (dev) |

| Stratus Red Team | Apache-2.0 | Cloud adversary emulation (AWS, Azure, GCP, K8s) via CLI bridge |
| CVE-2026-31431 PoC | LGPL-2.1-or-later OR MIT | K8s container escape via page-cache corruption |
| ebpfkit | Apache-2.0 | eBPF rootkit for container escape and process hiding |
| TripleCross | GPL-3.0 | eBPF rootkit for backdoor, privesc, and packet hijack |
| bad-bpf | BSD-3-Clause | eBPF offensive tools (pidhide, exechijack, sudoadd, bpfdos) |
| pamspy | Apache-2.0 | eBPF credential harvester via PAM hooking |
| AADInternals | MIT | Azure AD / Entra ID exploitation via PowerShell bridge |
| ligolo-ng | GPL-3.0 | Network tunneling and pivoting via Go bridge |

All dependencies are optional per provider group (`[aws]`, `[azure]`, `[gcp]`).
Core functionality (ARM template analysis, dispatcher) requires only `requests` and `rich`.
External tool bridges (Stratus, ebpfkit, TripleCross, bad-bpf, pamspy, AADInternals, ligolo-ng) require their respective binaries installed separately.
