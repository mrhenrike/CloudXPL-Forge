"""Cross-cloud identity resolver for CloudXPL-Forge.

Unifies identity resolution across AWS (IAM), Azure (Entra ID),
GCP (IAM/WIF) and K8s (ServiceAccounts). Maps principals to their
effective permissions, federation links and trust chains.
"""


from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class CloudProvider(Enum):
    AWS = auto()
    AZURE = auto()
    GCP = auto()
    K8S = auto()


@dataclass
class CloudIdentity:
    provider: CloudProvider
    principal_id: str
    principal_type: str = ""  # user, role, service-account, managed-identity, etc.
    display_name: str = ""
    arn_or_id: str = ""
    permissions: list[str] = field(default_factory=list)
    federation_links: list["FederationLink"] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_privileged(self) -> bool:
        priv_indicators = {
            "AdministratorAccess", "Owner", "roles/owner",
            "GlobalAdministrator", "cluster-admin",
            "iam:*", "sts:AssumeRole",
        }
        return bool(set(self.permissions) & priv_indicators)


@dataclass
class FederationLink:
    source_provider: CloudProvider
    source_identity: str
    target_provider: CloudProvider
    target_identity: str
    trust_type: str = ""  # OIDC, SAML, WIF, cross-account, etc.
    conditions: dict[str, str] = field(default_factory=dict)


class IdentityResolver:
    """Resolve and correlate cloud identities across providers."""

    def __init__(self) -> None:
        self._identities: dict[str, CloudIdentity] = {}
        self._federation_map: list[FederationLink] = []

    @property
    def identities(self) -> dict[str, CloudIdentity]:
        return dict(self._identities)

    @property
    def federation_links(self) -> list[FederationLink]:
        return list(self._federation_map)

    def add_identity(self, identity: CloudIdentity) -> None:
        key = f"{identity.provider.name}:{identity.principal_id}"
        self._identities[key] = identity

    def add_federation(self, link: FederationLink) -> None:
        self._federation_map.append(link)

    def resolve(self, provider: CloudProvider, principal_id: str) -> CloudIdentity | None:
        key = f"{provider.name}:{principal_id}"
        return self._identities.get(key)

    def find_federation_chain(self, start_id: str) -> list[FederationLink]:
        """Trace federation/trust chain from a starting identity."""
        chain: list[FederationLink] = []
        visited: set[str] = set()
        current = start_id

        while current and current not in visited:
            visited.add(current)
            for link in self._federation_map:
                if link.source_identity == current:
                    chain.append(link)
                    current = link.target_identity
                    break
            else:
                break

        return chain

    def find_cross_cloud_pivots(self) -> list[dict[str, Any]]:
        """Identify identities that can pivot between cloud providers."""
        pivots: list[dict[str, Any]] = []

        for link in self._federation_map:
            if link.source_provider != link.target_provider:
                source = self.resolve(link.source_provider, link.source_identity)
                target = self.resolve(link.target_provider, link.target_identity)
                if source and target:
                    pivots.append({
                        "source": {
                            "provider": link.source_provider.name,
                            "identity": link.source_identity,
                            "privileged": source.is_privileged,
                        },
                        "target": {
                            "provider": link.target_provider.name,
                            "identity": link.target_identity,
                            "privileged": target.is_privileged,
                        },
                        "trust_type": link.trust_type,
                        "conditions": link.conditions,
                    })

        return pivots

    def find_privileged_identities(self) -> list[CloudIdentity]:
        return [i for i in self._identities.values() if i.is_privileged]

    # --- Provider-specific ingestion ---

    def ingest_aws_iam(self, iam_data: dict[str, Any]) -> int:
        """Ingest AWS IAM users/roles from get-account-authorization-details."""
        count = 0
        for user in iam_data.get("UserDetailList", []):
            self.add_identity(CloudIdentity(
                provider=CloudProvider.AWS,
                principal_id=user.get("UserName", ""),
                principal_type="user",
                arn_or_id=user.get("Arn", ""),
                display_name=user.get("UserName", ""),
            ))
            count += 1

        for role in iam_data.get("RoleDetailList", []):
            identity = CloudIdentity(
                provider=CloudProvider.AWS,
                principal_id=role.get("RoleName", ""),
                principal_type="role",
                arn_or_id=role.get("Arn", ""),
                display_name=role.get("RoleName", ""),
            )
            self.add_identity(identity)
            count += 1

            for stmt in role.get("AssumeRolePolicyDocument", {}).get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal", {})
                    federated = principal.get("Federated", "")
                    if federated:
                        self.add_federation(FederationLink(
                            source_provider=self._detect_provider(federated),
                            source_identity=federated,
                            target_provider=CloudProvider.AWS,
                            target_identity=role.get("RoleName", ""),
                            trust_type="OIDC" if "oidc" in federated.lower() else "SAML",
                        ))

        return count

    def ingest_gcp_iam(self, bindings: list[dict[str, Any]], project: str = "") -> int:
        """Ingest GCP IAM policy bindings."""
        count = 0
        for binding in bindings:
            role = binding.get("role", "")
            for member in binding.get("members", []):
                member_type, _, member_id = member.partition(":")
                self.add_identity(CloudIdentity(
                    provider=CloudProvider.GCP,
                    principal_id=member_id or member,
                    principal_type=member_type,
                    permissions=[role],
                    metadata={"project": project},
                ))
                count += 1
        return count

    @staticmethod
    def _detect_provider(identifier: str) -> CloudProvider:
        if "amazonaws.com" in identifier or identifier.startswith("arn:aws:"):
            return CloudProvider.AWS
        if "login.microsoftonline.com" in identifier or "graph.microsoft.com" in identifier:
            return CloudProvider.AZURE
        if "accounts.google.com" in identifier or "googleapis.com" in identifier:
            return CloudProvider.GCP
        return CloudProvider.K8S
