"""Exploit stub for CVE-2026-31431: K8s container escape without privilege.

Source: https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC
License: verify
SRC-ID: SRC-674
CVSS: Critical
Category: Container escape, Kubernetes, unprivileged

CVE-2026-31431 allows unprivileged container escape in Kubernetes.
Validated against ACK, EKS, and GKE managed clusters. Exploits
the Copy-Fail mechanism in kubectl cp / container runtime.
"""

from dataclasses import dataclass


@dataclass
class CVE202631431Config:
    target_pod: str = ""
    namespace: str = "default"
    container: str | None = None
    kubeconfig: str | None = None
