"""Tests for cloudxpl.core.policy_engine."""

from __future__ import annotations

from cloudxpl.core.policy_engine import PolicyEngine


class TestPolicyEngineAWS:
    def test_full_wildcard(self) -> None:
        engine = PolicyEngine()
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }],
        }
        findings = engine.analyze_aws_policy(policy, "admin-policy")
        assert any(f.severity == "CRITICAL" for f in findings)
        assert any("wildcard" in f.issue.lower() for f in findings)

    def test_privesc_actions(self) -> None:
        engine = PolicyEngine()
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreatePolicyVersion", "iam:AttachRolePolicy"],
                "Resource": "arn:aws:iam::123:role/target",
            }],
        }
        findings = engine.analyze_aws_policy(policy)
        assert any("Privilege escalation" in f.issue for f in findings)

    def test_s3_wildcard_no_condition(self) -> None:
        engine = PolicyEngine()
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }],
        }
        findings = engine.analyze_aws_policy(policy)
        assert any("S3 data" in f.issue for f in findings)

    def test_deny_ignored(self) -> None:
        engine = PolicyEngine()
        policy = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }],
        }
        findings = engine.analyze_aws_policy(policy)
        assert len(findings) == 0

    def test_safe_policy(self) -> None:
        engine = PolicyEngine()
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/team": "data"}},
            }],
        }
        findings = engine.analyze_aws_policy(policy)
        assert len(findings) == 0


class TestPolicyEngineAzure:
    def test_wildcard_no_notactions(self) -> None:
        engine = PolicyEngine()
        role = {
            "roleName": "SuperAdmin",
            "permissions": [{"actions": ["*"], "notActions": []}],
        }
        findings = engine.analyze_azure_role(role)
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_wildcard_with_notactions(self) -> None:
        engine = PolicyEngine()
        role = {
            "roleName": "AlmostAdmin",
            "permissions": [{"actions": ["*"], "notActions": ["Microsoft.Authorization/*"]}],
        }
        findings = engine.analyze_azure_role(role)
        assert any("NotActions" in f.issue for f in findings)

    def test_wildcard_data_actions(self) -> None:
        engine = PolicyEngine()
        role = {
            "name": "DataAll",
            "permissions": [{"actions": [], "dataActions": ["*"]}],
        }
        findings = engine.analyze_azure_role(role)
        assert any("dataActions" in f.issue for f in findings)

    def test_safe_role(self) -> None:
        engine = PolicyEngine()
        role = {
            "roleName": "Reader",
            "permissions": [{"actions": ["Microsoft.Compute/*/read"]}],
        }
        findings = engine.analyze_azure_role(role)
        assert len(findings) == 0


class TestPolicyEngineGCP:
    def test_public_owner(self) -> None:
        engine = PolicyEngine()
        bindings = [{
            "role": "roles/owner",
            "members": ["allUsers"],
        }]
        findings = engine.analyze_gcp_bindings(bindings, "my-project")
        assert any(f.severity == "CRITICAL" for f in findings)
        assert any("allUsers" in f.issue for f in findings)

    def test_owner_no_condition(self) -> None:
        engine = PolicyEngine()
        bindings = [{
            "role": "roles/owner",
            "members": ["user:admin@corp.com"],
        }]
        findings = engine.analyze_gcp_bindings(bindings, "proj")
        assert any("without conditions" in f.issue for f in findings)

    def test_token_creator(self) -> None:
        engine = PolicyEngine()
        bindings = [{
            "role": "roles/iam.serviceAccountTokenCreator",
            "members": ["user:dev@corp.com"],
        }]
        findings = engine.analyze_gcp_bindings(bindings)
        assert any("impersonate" in f.issue for f in findings)

    def test_safe_binding(self) -> None:
        engine = PolicyEngine()
        bindings = [{
            "role": "roles/viewer",
            "members": ["user:dev@corp.com"],
        }]
        findings = engine.analyze_gcp_bindings(bindings)
        assert len(findings) == 0


class TestPolicyEngineClear:
    def test_clear(self) -> None:
        engine = PolicyEngine()
        engine.analyze_aws_policy({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        assert len(engine.findings) > 0
        engine.clear()
        assert len(engine.findings) == 0
