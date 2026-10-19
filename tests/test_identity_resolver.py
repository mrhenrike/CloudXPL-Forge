"""Tests for cloudxpl.core.identity_resolver."""

from __future__ import annotations

from cloudxpl.core.identity_resolver import (
    CloudIdentity,
    CloudProvider,
    FederationLink,
    IdentityResolver,
)


class TestCloudIdentity:
    def test_not_privileged(self) -> None:
        i = CloudIdentity(
            provider=CloudProvider.AWS,
            principal_id="dev-user",
            permissions=["s3:GetObject"],
        )
        assert i.is_privileged is False

    def test_privileged_aws(self) -> None:
        i = CloudIdentity(
            provider=CloudProvider.AWS,
            principal_id="admin",
            permissions=["AdministratorAccess"],
        )
        assert i.is_privileged is True

    def test_privileged_gcp(self) -> None:
        i = CloudIdentity(
            provider=CloudProvider.GCP,
            principal_id="sa@proj.iam",
            permissions=["roles/owner"],
        )
        assert i.is_privileged is True


class TestIdentityResolver:
    def _resolver(self) -> IdentityResolver:
        return IdentityResolver()

    def test_add_and_resolve(self) -> None:
        r = self._resolver()
        identity = CloudIdentity(
            provider=CloudProvider.AWS,
            principal_id="admin-role",
        )
        r.add_identity(identity)
        assert r.resolve(CloudProvider.AWS, "admin-role") is identity
        assert r.resolve(CloudProvider.AWS, "missing") is None

    def test_find_federation_chain(self) -> None:
        r = self._resolver()
        r.add_federation(FederationLink(
            source_provider=CloudProvider.GCP,
            source_identity="sa@proj.iam",
            target_provider=CloudProvider.AWS,
            target_identity="cross-cloud-role",
            trust_type="OIDC",
        ))
        r.add_federation(FederationLink(
            source_provider=CloudProvider.AWS,
            source_identity="cross-cloud-role",
            target_provider=CloudProvider.AZURE,
            target_identity="app-sp",
            trust_type="OIDC",
        ))
        chain = r.find_federation_chain("sa@proj.iam")
        assert len(chain) == 2
        assert chain[0].target_identity == "cross-cloud-role"
        assert chain[1].target_identity == "app-sp"

    def test_find_cross_cloud_pivots(self) -> None:
        r = self._resolver()
        r.add_identity(CloudIdentity(
            provider=CloudProvider.AWS,
            principal_id="attacker-role",
            permissions=["sts:AssumeRole"],
        ))
        r.add_identity(CloudIdentity(
            provider=CloudProvider.GCP,
            principal_id="target-sa",
            permissions=["roles/owner"],
        ))
        r.add_federation(FederationLink(
            source_provider=CloudProvider.AWS,
            source_identity="attacker-role",
            target_provider=CloudProvider.GCP,
            target_identity="target-sa",
            trust_type="WIF",
        ))
        pivots = r.find_cross_cloud_pivots()
        assert len(pivots) == 1
        assert pivots[0]["source"]["provider"] == "AWS"
        assert pivots[0]["target"]["privileged"] is True

    def test_find_privileged_identities(self) -> None:
        r = self._resolver()
        r.add_identity(CloudIdentity(
            provider=CloudProvider.AWS,
            principal_id="admin",
            permissions=["AdministratorAccess"],
        ))
        r.add_identity(CloudIdentity(
            provider=CloudProvider.AWS,
            principal_id="reader",
            permissions=["ReadOnlyAccess"],
        ))
        priv = r.find_privileged_identities()
        assert len(priv) == 1
        assert priv[0].principal_id == "admin"

    def test_ingest_aws_iam(self) -> None:
        r = self._resolver()
        data = {
            "UserDetailList": [
                {"UserName": "alice", "Arn": "arn:aws:iam::123:user/alice"},
            ],
            "RoleDetailList": [
                {
                    "RoleName": "federated-role",
                    "Arn": "arn:aws:iam::123:role/federated-role",
                    "AssumeRolePolicyDocument": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": "accounts.google.com/projects/123",
                            },
                            "Action": "sts:AssumeRoleWithWebIdentity",
                        }],
                    },
                },
            ],
        }
        count = r.ingest_aws_iam(data)
        assert count == 2
        assert r.resolve(CloudProvider.AWS, "alice") is not None
        assert len(r.federation_links) == 1
        assert r.federation_links[0].trust_type == "SAML"

    def test_ingest_gcp_iam(self) -> None:
        r = self._resolver()
        bindings = [
            {"role": "roles/viewer", "members": ["user:dev@corp.com"]},
            {"role": "roles/owner", "members": ["serviceAccount:admin@proj.iam"]},
        ]
        count = r.ingest_gcp_iam(bindings, project="my-project")
        assert count == 2
        admin = r.resolve(CloudProvider.GCP, "admin@proj.iam")
        assert admin is not None
        assert admin.permissions == ["roles/owner"]

    def test_detect_provider(self) -> None:
        assert IdentityResolver._detect_provider("arn:aws:iam") == CloudProvider.AWS
        assert IdentityResolver._detect_provider("https://login.microsoftonline.com/xxx") == CloudProvider.AZURE
        assert IdentityResolver._detect_provider("accounts.google.com/123") == CloudProvider.GCP
        assert IdentityResolver._detect_provider("system:serviceaccount:ns:sa") == CloudProvider.K8S
