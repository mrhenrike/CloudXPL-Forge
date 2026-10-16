# Third-Party Components — CloudXPL-Forge

| Component | License | Usage |
|-----------|---------|-------|
| boto3 | Apache 2.0 | AWS SDK — IAM, S3, EC2, Lambda API calls |
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

All dependencies are optional per provider group (`[aws]`, `[azure]`, `[gcp]`).
Core functionality (ARM template analysis, dispatcher) requires only `requests` and `rich`.
