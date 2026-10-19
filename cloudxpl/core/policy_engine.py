"""Cloud IAM policy analysis engine for CloudXPL-Forge.

Evaluates IAM policies (AWS, Azure, GCP) for overly permissive
configurations, privilege escalation paths and misconfigurations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyFinding:
    provider: str
    resource: str
    issue: str
    severity: str = "MEDIUM"
    remediation: str = ""
    mitre: list[str] = field(default_factory=list)


class PolicyEngine:
    """Analyze cloud IAM policies for security issues."""

    def __init__(self) -> None:
        self._findings: list[PolicyFinding] = []

    @property
    def findings(self) -> list[PolicyFinding]:
        return list(self._findings)

    def clear(self) -> None:
        self._findings.clear()

    # --- AWS ---

    def analyze_aws_policy(self, policy: dict[str, Any], resource_name: str = "") -> list[PolicyFinding]:
        """Analyze an AWS IAM policy document for issues."""
        findings: list[PolicyFinding] = []

        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            condition = stmt.get("Condition", {})

            if "*" in actions and "*" in resources:
                findings.append(PolicyFinding(
                    provider="AWS",
                    resource=resource_name,
                    issue="Full wildcard: Action=* Resource=*",
                    severity="CRITICAL",
                    remediation="Apply least-privilege, scope to specific services/resources",
                    mitre=["T1078.004"],
                ))

            privesc_actions = {
                "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                "iam:AttachUserPolicy", "iam:AttachGroupPolicy",
                "iam:AttachRolePolicy", "iam:PutUserPolicy",
                "iam:PutGroupPolicy", "iam:PutRolePolicy",
                "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
                "iam:CreateAccessKey", "sts:AssumeRole",
                "iam:PassRole", "lambda:CreateFunction",
                "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
                "ec2:RunInstances", "iam:AddUserToGroup",
                "iam:UpdateAssumeRolePolicy",
            }
            matched = set(actions) & privesc_actions
            if matched:
                findings.append(PolicyFinding(
                    provider="AWS",
                    resource=resource_name,
                    issue=f"Privilege escalation path via: {', '.join(sorted(matched))}",
                    severity="HIGH",
                    remediation="Restrict these actions to admin roles with MFA condition",
                    mitre=["T1078.004", "T1098"],
                ))

            if not condition:
                data_actions = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}
                if set(actions) & data_actions and "*" in resources:
                    findings.append(PolicyFinding(
                        provider="AWS",
                        resource=resource_name,
                        issue="S3 data actions on * resource without conditions",
                        severity="HIGH",
                        remediation="Scope resources to specific buckets, add conditions",
                    ))

        self._findings.extend(findings)
        return findings

    # --- Azure ---

    def analyze_azure_role(self, role_def: dict[str, Any]) -> list[PolicyFinding]:
        """Analyze an Azure role definition for issues."""
        findings: list[PolicyFinding] = []
        name = role_def.get("roleName", role_def.get("name", ""))

        for perm in role_def.get("permissions", []):
            actions = perm.get("actions", [])
            not_actions = perm.get("notActions", [])

            if "*" in actions:
                if not not_actions:
                    findings.append(PolicyFinding(
                        provider="Azure",
                        resource=name,
                        issue="Custom role with Action=* and no NotActions",
                        severity="CRITICAL",
                        remediation="Scope to specific resource providers",
                        mitre=["T1078.004"],
                    ))
                else:
                    findings.append(PolicyFinding(
                        provider="Azure",
                        resource=name,
                        issue=f"Broad role with * minus {len(not_actions)} NotActions",
                        severity="HIGH",
                        remediation="Review NotActions list for bypass paths",
                    ))

            data_actions = perm.get("dataActions", [])
            if "*" in data_actions:
                findings.append(PolicyFinding(
                    provider="Azure",
                    resource=name,
                    issue="Wildcard dataActions grants all data-plane access",
                    severity="HIGH",
                    remediation="Restrict dataActions to specific operations",
                ))

        self._findings.extend(findings)
        return findings

    # --- GCP ---

    def analyze_gcp_bindings(
        self, bindings: list[dict[str, Any]], project: str = ""
    ) -> list[PolicyFinding]:
        """Analyze GCP IAM bindings for issues."""
        findings: list[PolicyFinding] = []

        dangerous_roles = {
            "roles/owner",
            "roles/editor",
            "roles/iam.securityAdmin",
            "roles/iam.serviceAccountAdmin",
            "roles/iam.serviceAccountKeyAdmin",
            "roles/cloudfunctions.admin",
        }

        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])
            condition = binding.get("condition")

            if role in dangerous_roles:
                for member in members:
                    if member.startswith("allUsers") or member.startswith("allAuthenticatedUsers"):
                        findings.append(PolicyFinding(
                            provider="GCP",
                            resource=f"{project}/{role}",
                            issue=f"Public access: {member} has {role}",
                            severity="CRITICAL",
                            remediation="Remove public member bindings",
                            mitre=["T1078.004"],
                        ))
                    elif not condition and role in {"roles/owner", "roles/editor"}:
                        findings.append(PolicyFinding(
                            provider="GCP",
                            resource=f"{project}/{role}",
                            issue=f"{member} has {role} without conditions",
                            severity="HIGH",
                            remediation="Add IAM conditions, prefer custom roles",
                        ))

            if role == "roles/iam.serviceAccountTokenCreator":
                for member in members:
                    findings.append(PolicyFinding(
                        provider="GCP",
                        resource=f"{project}/{role}",
                        issue=f"{member} can impersonate any SA via token creation",
                        severity="HIGH",
                        remediation="Restrict to specific service accounts",
                        mitre=["T1134"],
                    ))

        self._findings.extend(findings)
        return findings
