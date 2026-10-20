# CloudXPL-Forge Expansion Roadmap

**Meta:** Expandir de 13 para ~200 módulos com cobertura máxima de técnicas cloud offensive.
**Baseline:** 13 módulos (5 AWS, 4 Azure, 4 GCP) em 3 categorias.
**Target:** ~200 módulos em 12+ categorias cobrindo AWS, Azure, GCP, Kubernetes, Serverless, Multi-cloud.

## Categorias e Módulos Planejados

### 1. AWS (aws)  -  45 módulos

#### Enumeração (existentes + novos)
| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | iam-enum | P1 | **EXISTENTE**  -  Enumera IAM users, roles, policies |
| 2 | s3-enum | P1 | **EXISTENTE**  -  Lista e audita buckets S3 |
| 3 | lambda-enum | P1 | **EXISTENTE**  -  Enumera Lambda functions |
| 4 | ssrf-imds | P1 | **EXISTENTE**  -  SSRF para metadata IMDS v1/v2 |
| 5 | ec2-enum | P1 | **EXISTENTE**  -  Enumera instâncias EC2 |
| 6 | iam-privesc | P1 | Identifica caminhos de escalação IAM (20+ vetores Pacu/PMapper) |
| 7 | sts-enum | P1 | Enumera credenciais STS, assume-role chains |
| 8 | s3-exploit | P1 | Exploração de buckets: ACL bypass, policy abuse, object takeover |
| 9 | s3-exfil | P1 | Exfiltração via S3: ransomware S3, cópia cross-account |
| 10 | lambda-inject | P1 | Injeção de evento Lambda, layer poisoning |
| 11 | lambda-persist | P2 | Persistência via Lambda layers e triggers |
| 12 | ec2-userdata | P1 | Extração/injection de userdata EC2 (cloud-init abuse) |
| 13 | ec2-ssm | P1 | AWS Systems Manager exploitation, RunCommand RCE |
| 14 | ec2-imds-pivot | P1 | Pivot via IMDSv1/v2 token theft para lateral movement |
| 15 | rds-enum | P2 | Enumera RDS instances, snapshots públicos |
| 16 | rds-exploit | P2 | Snapshot sharing abuse, master password reset |
| 17 | secrets-manager | P1 | Enumera e extrai segredos do Secrets Manager |
| 18 | ssm-param-store | P1 | Enumera e extrai SSM Parameter Store (strings e SecureString) |
| 19 | cloudtrail-disable | P2 | Desabilita/evade CloudTrail logging |
| 20 | cloudtrail-tamper | P2 | Manipulação de trail: delete trail, stop logging, remove S3 |
| 21 | guardduty-bypass | P2 | Técnicas de evasão de GuardDuty findings |
| 22 | vpc-enum | P2 | Enumera VPCs, security groups, NACLs |
| 23 | route53-takeover | P2 | Subdomain takeover via Route53 dangling records |
| 24 | ebs-snapshot | P2 | Snapshot público, cross-account sharing, extração |
| 25 | ecr-enum | P2 | Enumera ECR registries, imagens, vulnerabilidades |
| 26 | ecs-exploit | P2 | ECS task definition injection, container escape |
| 27 | eks-enum | P2 | Enumera clusters EKS, RBAC, service accounts |
| 28 | eks-exploit | P2 | IRSA abuse, pod identity exploitation |
| 29 | sqs-exploit | P3 | SQS queue hijack, message injection |
| 30 | sns-exploit | P3 | SNS topic hijack, subscription abuse |
| 31 | dynamodb-enum | P3 | Enumera tabelas DynamoDB, exfiltração de dados |
| 32 | codebuild-exploit | P2 | CodeBuild env var extraction, buildspec injection |
| 33 | codepipeline-exploit | P3 | Pipeline poisoning, artifact manipulation |
| 34 | cognito-exploit | P2 | Cognito user pool abuse, identity pool misconfiguration |
| 35 | cloudformation-exploit | P3 | Stack injection, exported values leak |
| 36 | org-enum | P3 | AWS Organizations enumeration, cross-account pivot |
| 37 | sso-enum | P3 | AWS SSO/Identity Center enumeration |
| 38 | glue-exploit | P3 | Glue job exploitation, ETL data theft |
| 39 | stepfunctions-exploit | P3 | Step Functions state machine manipulation |
| 40 | eventbridge-exploit | P3 | EventBridge rule injection |
| 41 | cve-2024-28056 | P1 | Amplify IAM role assumption (CVE-2024-28056) |
| 42 | cve-2026-5707 | P1 | AWS RES session hijack (CVE-2026-5707) |
| 43 | cve-2026-5708 | P1 | AWS RES stored XSS (CVE-2026-5708) |
| 44 | cve-2026-5709 | P1 | AWS RES access control bypass (CVE-2026-5709) |
| 45 | pacu-bridge | P2 | Bridge para Pacu framework (execução e import de resultados) |

### 2. Azure (azure)  -  42 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | enum-subs | P1 | **EXISTENTE**  -  Enumera subscriptions |
| 2 | enum-storage | P1 | **EXISTENTE**  -  Enumera storage accounts |
| 3 | managed-identity | P1 | **EXISTENTE**  -  Managed Identity token theft |
| 4 | arm-injection | P1 | **EXISTENTE**  -  ARM template injection |
| 5 | entra-enum | P1 | Entra ID (Azure AD) user/group/app enumeration |
| 6 | entra-tokens | P1 | OAuth token theft, refresh token abuse, PRT extraction |
| 7 | entra-consent | P1 | Illicit consent grant attack |
| 8 | entra-privesc | P1 | Entra ID role escalation paths |
| 9 | blob-exploit | P1 | Blob storage exploitation: SAS token abuse, ACL bypass |
| 10 | blob-exfil | P2 | Exfiltração via Blob: snapshot, cross-tenant copy |
| 11 | keyvault-exploit | P1 | Key Vault secrets extraction, key theft |
| 12 | function-exploit | P2 | Azure Functions exploitation: injection, env vars |
| 13 | function-persist | P3 | Persistência via Function triggers |
| 14 | aks-enum | P2 | AKS cluster enumeration, RBAC, managed identity |
| 15 | aks-exploit | P2 | AKS pod escape, AAD pod identity abuse |
| 16 | vm-enum | P2 | VM enumeration, extensions, custom script |
| 17 | vm-exploit | P2 | VM custom script extension RCE, run command abuse |
| 18 | vm-imds | P1 | Azure IMDS token theft (169.254.169.254) |
| 19 | cosmosdb-exploit | P3 | Cosmos DB key extraction, data exfiltration |
| 20 | devops-exploit | P2 | Azure DevOps pipeline poisoning, variable group theft |
| 21 | automation-exploit | P2 | Automation Account runbook abuse, credential extraction |
| 22 | logic-apps-exploit | P3 | Logic Apps workflow manipulation |
| 23 | sql-enum | P2 | Azure SQL/Managed Instance enumeration |
| 24 | sql-exploit | P3 | Azure SQL firewall bypass, admin password reset |
| 25 | rbac-enum | P1 | Azure RBAC role assignment enumeration |
| 26 | rbac-exploit | P2 | Custom role abuse, User Access Admin escalation |
| 27 | resource-group-enum | P2 | Resource group enumeration and scope analysis |
| 28 | nsg-enum | P2 | NSG rules enumeration, exposed ports |
| 29 | app-service-exploit | P2 | App Service env vars, SCM/Kudu abuse |
| 30 | service-principal | P1 | Service Principal enumeration and secret extraction |
| 31 | conditional-access | P2 | Conditional Access policy bypass analysis |
| 32 | pim-abuse | P2 | Privileged Identity Management escalation |
| 33 | graph-api-abuse | P2 | Microsoft Graph API over-scoped permissions |
| 34 | stormspotter-bridge | P3 | Stormspotter graph analysis bridge |
| 35 | azurehound-bridge | P2 | AzureHound data collection bridge |
| 36 | cve-2025-29813 | P1 | Azure DevOps CVSS 10.0  -  pipeline secret exposure |
| 37 | cve-2025-29972 | P1 | Azure Storage SSRF CVSS 9.9 |
| 38 | cve-2025-29827 | P1 | Azure Automation CVSS 9.9  -  managed identity abuse |
| 39 | cve-2025-53767 | P1 | Azure DevOps Services CVSS 10.0 |
| 40 | cve-2024-50603 | P1 | Aviatrix Controller RCE (CVE-2024-50603) |
| 41 | defender-bypass | P2 | Microsoft Defender for Cloud evasion |
| 42 | sentinel-bypass | P3 | Microsoft Sentinel logging evasion |

### 3. GCP (gcp)  -  38 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | bucket-enum | P1 | **EXISTENTE**  -  GCS bucket enumeration |
| 2 | sa-enum | P1 | **EXISTENTE**  -  Service account enumeration |
| 3 | metadata-ssrf | P1 | **EXISTENTE**  -  GCP metadata SSRF |
| 4 | project-enum | P1 | **EXISTENTE**  -  Project enumeration |
| 5 | iam-privesc | P1 | GCP IAM privilege escalation paths |
| 6 | bucket-exploit | P1 | GCS ACL abuse, bucket takeover, uniform bucket-level access bypass |
| 7 | bucket-exfil | P2 | GCS data exfiltration, cross-project copy |
| 8 | sa-key-theft | P1 | Service account key extraction e impersonation |
| 9 | sa-impersonate | P1 | Service account impersonation chain |
| 10 | cloudfunctions-exploit | P2 | Cloud Functions exploitation e injection |
| 11 | cloudfunctions-persist | P3 | Persistência via Cloud Functions triggers |
| 12 | gke-enum | P2 | GKE cluster enumeration, RBAC, Workload Identity |
| 13 | gke-exploit | P2 | GKE pod escape, metadata access, node pool abuse |
| 14 | compute-enum | P2 | Compute Engine instance enumeration |
| 15 | compute-exploit | P2 | Compute startup script injection, SSH key injection |
| 16 | compute-imds | P1 | GCP IMDS token theft (metadata.google.internal) |
| 17 | cloudsql-enum | P2 | Cloud SQL instance enumeration |
| 18 | cloudsql-exploit | P3 | Cloud SQL user password reset, backup extraction |
| 19 | pubsub-exploit | P3 | Pub/Sub message injection e subscription hijack |
| 20 | cloudbuild-exploit | P2 | Cloud Build step injection, secret extraction |
| 21 | secretmanager-exploit | P1 | Secret Manager enumeration e extraction |
| 22 | kms-exploit | P2 | KMS key abuse, crypto operations |
| 23 | bigquery-exploit | P2 | BigQuery dataset enumeration, data exfiltration |
| 24 | cloudrun-exploit | P2 | Cloud Run injection, env var extraction |
| 25 | composer-exploit | P3 | Cloud Composer/Airflow DAG injection |
| 26 | dataflow-exploit | P3 | Dataflow job manipulation |
| 27 | logging-bypass | P2 | Cloud Logging evasion techniques |
| 28 | org-policy-enum | P3 | Organization Policy enumeration |
| 29 | vpc-firewall-enum | P2 | VPC firewall rules enumeration |
| 30 | dns-takeover | P2 | Cloud DNS dangling record takeover |
| 31 | workload-identity | P1 | Workload Identity Federation exploitation |
| 32 | artifact-registry | P3 | Artifact Registry image manipulation |
| 33 | terraform-state | P2 | GCS Terraform state extraction (secretos em state files) |
| 34 | cve-2026-2031 | P1 | GCP Iam Trust CVSS 10.0  -  cross-tenant escalation |
| 35 | cve-2026-2264 | P1 | GCP Compute CVSS 9.2  -  metadata service escape |
| 36 | cve-2026-81867 | P1 | GCP Org Policy bypass CVSS 9.4 |
| 37 | cve-2025-51591 | P2 | Pandoc SSRF affecting GCP IMDS |
| 38 | gcpbucketbrute-bridge | P3 | GCPBucketBrute tool bridge |

### 4. Kubernetes (k8s)  -  28 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | cluster-enum | P1 | Cluster discovery e API server enumeration |
| 2 | rbac-enum | P1 | RBAC roles, bindings, service accounts analysis |
| 3 | pod-enum | P1 | Pod enumeration across namespaces |
| 4 | secret-dump | P1 | Kubernetes Secrets extraction |
| 5 | configmap-dump | P2 | ConfigMap extraction com credenciais |
| 6 | sa-token-theft | P1 | Service account token theft |
| 7 | container-escape | P1 | Container escape techniques (nsenter, mount, cgroups) |
| 8 | privileged-pod | P1 | Privileged pod exploitation |
| 9 | hostpath-mount | P1 | HostPath volume abuse para node access |
| 10 | kubelet-exploit | P2 | Kubelet API exploitation (10250/10255) |
| 11 | etcd-exploit | P2 | etcd direct access e secret extraction |
| 12 | api-server-anon | P1 | Anonymous API server access exploitation |
| 13 | rbac-escalation | P1 | RBAC privilege escalation paths |
| 14 | pod-escape-cve | P1 | CVE-based container escapes (runc CVEs) |
| 15 | network-policy-bypass | P2 | Network policy bypass techniques |
| 16 | admission-bypass | P2 | Admission controller/PSA bypass |
| 17 | sidecar-inject | P2 | Sidecar container injection |
| 18 | node-proxy | P2 | Node proxy para lateral movement |
| 19 | helm-exploit | P3 | Helm release secret extraction |
| 20 | crd-abuse | P3 | Custom Resource Definition abuse |
| 21 | service-mesh-exploit | P3 | Istio/Linkerd exploitation |
| 22 | registry-exploit | P2 | Private registry credential theft |
| 23 | cve-2024-21626 | P1 | runc fd leak container escape |
| 24 | cve-2025-31133 | P1 | runc symlink container escape |
| 25 | cve-2025-52565 | P1 | runc console race container escape |
| 26 | cve-2025-52881 | P1 | runc proc write container escape |
| 27 | peirates-bridge | P3 | Peirates K8s pentesting bridge |
| 28 | kube-hunter-bridge | P3 | Kube-hunter scanner bridge |

### 5. Serverless (serverless)  -  14 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | event-injection | P1 | Serverless event injection (S3/SNS/SQS triggers) |
| 2 | env-extraction | P1 | Environment variable extraction de functions |
| 3 | layer-poisoning | P1 | Lambda layer poisoning/trojanization |
| 4 | cold-start-abuse | P2 | Cold start timing attacks |
| 5 | runtime-rce | P1 | Runtime execution abuse via malicious dependencies |
| 6 | trigger-hijack | P2 | Event trigger hijacking |
| 7 | api-gateway-bypass | P2 | API Gateway authorization bypass |
| 8 | step-function-abuse | P2 | Step/Workflow function state manipulation |
| 9 | tmp-persistence | P2 | /tmp directory persistence between invocations |
| 10 | concurrency-abuse | P3 | Reserved concurrency DoS |
| 11 | iam-role-chain | P1 | Lambda execution role escalation chain |
| 12 | vpc-pivot | P2 | VPC-connected function network pivot |
| 13 | log-injection | P3 | CloudWatch/Stackdriver log injection |
| 14 | reverse-shell | P1 | Serverless reverse shell via HTTP poll |

### 6. Storage/Buckets (storage)  -  15 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | bucket-finder | P1 | Multi-cloud bucket enumeration (S3/GCS/Blob) |
| 2 | bucket-bruteforce | P1 | Bucket name bruteforce por wordlist |
| 3 | acl-check | P1 | ACL permission check (read/write/list) |
| 4 | public-objects | P1 | Public object enumeration e download |
| 5 | upload-exploit | P1 | Upload para bucket writable (webshell, payload) |
| 6 | download-mass | P1 | Mass download de objetos expostos |
| 7 | policy-abuse | P2 | Bucket policy exploitation |
| 8 | versioning-exploit | P2 | Object versioning abuse, recover deleted |
| 9 | presigned-abuse | P2 | Presigned URL manipulation e extension |
| 10 | cors-exploit | P2 | CORS misconfiguration exploitation |
| 11 | static-site-takeover | P2 | Static website hosting takeover |
| 12 | s3scanner-bridge | P3 | S3Scanner tool bridge |
| 13 | bucketloot-bridge | P3 | BucketLoot tool bridge |
| 14 | grayhat-search | P2 | Busca de buckets via GrayHatWarfare patterns |
| 15 | ransomware-sim | P3 | Storage ransomware simulation (encrypt objects) |

### 7. Multi-Cloud (multi)  -  12 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | terraform-state-exploit | P1 | Terraform state file extraction e analysis |
| 2 | terraform-plan-inject | P2 | Terraform plan manipulation, provider abuse |
| 3 | iac-secret-scan | P1 | IaC secret scanning (TF, CF, Pulumi, ARM) |
| 4 | cross-cloud-pivot | P2 | Cross-cloud credential pivoting |
| 5 | ci-cd-exploit | P1 | CI/CD pipeline poisoning (GitHub Actions, GitLab CI) |
| 6 | git-secret-scan | P1 | Git repository credential scanning |
| 7 | docker-escape | P1 | Docker container escape (non-K8s environments) |
| 8 | docker-socket | P1 | Docker socket exploitation |
| 9 | cloudfox-bridge | P2 | CloudFox enumeration bridge |
| 10 | scoutsuite-bridge | P2 | ScoutSuite audit bridge |
| 11 | prowler-bridge | P2 | Prowler compliance/security bridge |
| 12 | steampipe-bridge | P3 | Steampipe query bridge |

### 8. Credential (cred)  -  10 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | metadata-harvest | P1 | Multi-cloud IMDS credential harvesting |
| 2 | env-var-scan | P1 | Environment variable credential scanning |
| 3 | config-file-scan | P1 | Cloud CLI config file extraction (~/.aws, ~/.azure, ~/.config/gcloud) |
| 4 | key-rotation-check | P2 | Access key rotation audit |
| 5 | token-lifetime-abuse | P2 | Long-lived token exploitation |
| 6 | oauth-token-theft | P1 | OAuth/OIDC token theft e replay |
| 7 | federation-abuse | P2 | Identity federation exploitation (SAML, OIDC) |
| 8 | temp-cred-extend | P2 | Temporary credential extension techniques |
| 9 | credential-report | P2 | IAM credential report analysis |
| 10 | leaked-key-exploit | P1 | Exploração de chaves vazadas (GitHub, paste sites) |

### 9. Network (net)  -  8 módulos

| # | Módulo | Prioridade | Descrição |
|---|--------|-----------|-----------|
| 1 | vpc-enum | P2 | VPC/VNet/Network enumeration |
| 2 | sg-analysis | P2 | Security Group/NSG/Firewall Rule analysis |
| 3 | exposed-services | P1 | Exposed service discovery (IP ranges, DNS) |
| 4 | dns-takeover | P1 | Subdomain takeover multi-cloud |
| 5 | vpn-exploit | P3 | VPN gateway exploitation |
| 6 | peering-abuse | P3 | VPC/VNet peering exploitation |
| 7 | load-balancer-enum | P2 | LB enumeration e misconfiguration |
| 8 | privatelink-abuse | P3 | PrivateLink/Endpoint exploitation |

## Resumo de Cobertura

| Categoria | Módulos | P1 | P2 | P3 |
|-----------|---------|----|----|-----|
| AWS | 45 | 20 | 15 | 10 |
| Azure | 42 | 15 | 16 | 11 |
| GCP | 38 | 14 | 13 | 11 |
| Kubernetes | 28 | 14 | 8 | 6 |
| Serverless | 14 | 6 | 5 | 3 |
| Storage | 15 | 6 | 5 | 4 |
| Multi-Cloud | 12 | 6 | 4 | 2 |
| Credential | 10 | 5 | 4 | 1 |
| Network | 8 | 2 | 3 | 3 |
| **TOTAL** | **212** | **88** | **73** | **51** |

## Fases de Implementação

### Fase 1  -  P1 (88 módulos)
Módulos prioritários de cada categoria. Cobre enumeração essencial, exploração primária, CVEs críticas e credential access.

### Fase 2  -  P2 (73 módulos)
Módulos de exploração avançada, evasão, persistência e bridge tools.

### Fase 3  -  P3 (51 módulos)
Módulos especializados, bridges opcionais e técnicas avançadas.

## CVEs Cobertas

| CVE | Provider | CVSS | Descrição |
|-----|----------|------|-----------|
| CVE-2024-28056 | AWS | 9.8 | Amplify IAM role assumption |
| CVE-2026-5707 | AWS | Alto | AWS RES session hijack |
| CVE-2026-5708 | AWS | Alto | AWS RES stored XSS |
| CVE-2026-5709 | AWS | Alto | AWS RES access control bypass |
| CVE-2025-29813 | Azure | 10.0 | Azure DevOps pipeline secret exposure |
| CVE-2025-29972 | Azure | 9.9 | Azure Storage SSRF |
| CVE-2025-29827 | Azure | 9.9 | Azure Automation managed identity abuse |
| CVE-2025-53767 | Azure | 10.0 | Azure DevOps Services |
| CVE-2024-50603 | Azure/Aviatrix | 10.0 | Aviatrix Controller RCE |
| CVE-2026-2031 | GCP | 10.0 | GCP IAM Trust cross-tenant escalation |
| CVE-2026-2264 | GCP | 9.2 | GCP Compute metadata service escape |
| CVE-2026-81867 | GCP | 9.4 | GCP Org Policy bypass |
| CVE-2025-51591 | Multi | Alto | Pandoc SSRF affecting IMDS |
| CVE-2024-21626 | K8s | 8.6 | runc fd leak container escape |
| CVE-2025-31133 | K8s | Alto | runc symlink container escape |
| CVE-2025-52565 | K8s | Alto | runc console race container escape |
| CVE-2025-52881 | K8s | Alto | runc proc write container escape |

## MITRE ATT&CK Cloud Matrix Coverage Target

| Tática | Técnicas-alvo |
|--------|---------------|
| Initial Access | T1078 (Valid Accounts), T1190 (Exploit Public-Facing App) |
| Execution | T1059 (Command Interpreter), T1648 (Serverless Execution) |
| Persistence | T1098 (Account Manipulation), T1525 (Implant Container Image) |
| Privilege Escalation | T1068 (Exploitation), T1078 (Valid Accounts) |
| Defense Evasion | T1562 (Impair Defenses), T1550 (Use Alternate Auth) |
| Credential Access | T1552 (Unsecured Credentials), T1528 (Steal App Access Token) |
| Discovery | T1580 (Cloud Infrastructure), T1526 (Cloud Service Discovery) |
| Lateral Movement | T1021 (Remote Services), T1550 (Alternate Auth) |
| Collection | T1530 (Data from Cloud Storage) |
| Exfiltration | T1537 (Transfer to Cloud Account) |
| Impact | T1485 (Data Destruction), T1486 (Data Encrypted) |
