"""Extended tests for cloudxpl.core.credential module."""

import pytest

from cloudxpl.core.credential import CloudCredential


class TestCredentialEdgeCases:
    def test_empty_identity(self) -> None:
        cred = CloudCredential(provider="aws", identity="")
        assert cred.identity == ""

    def test_short_secret_masking(self) -> None:
        cred = CloudCredential(provider="aws", identity="test")
        cred.secret_key = "AB"
        masked = cred.masked_secret
        assert "****" in masked or len(masked) <= 10

    def test_long_secret_masking(self) -> None:
        cred = CloudCredential(provider="aws", identity="test")
        cred.secret_key = "A" * 100
        masked = cred.masked_secret
        assert "****" in masked
        assert len(masked) < 100

    def test_to_dict_all_fields(self) -> None:
        cred = CloudCredential(
            provider="gcp",
            identity="sa@project.iam",
            region="us-central1",
            subscription_id=None,
            profile="default",
            token="eyJ.abc.xyz",
            credential_type="service_account",
            extra={"scope": "read"},
        )
        d = cred.to_dict()
        assert d["provider"] == "gcp"
        assert d["identity"] == "sa@project.iam"
        assert d["region"] == "us-central1"
        assert d["credential_type"] == "service_account"
        assert "secret_key" not in d

    def test_multiple_providers(self) -> None:
        providers = ["aws", "azure", "gcp", "oci", "alibaba", "tencent", "ibm"]
        for prov in providers:
            cred = CloudCredential(provider=prov, identity=f"test-{prov}")
            assert cred.provider == prov

    def test_credential_type_custom(self) -> None:
        cred = CloudCredential(
            provider="azure",
            identity="sp@tenant",
            credential_type="service_principal",
        )
        assert cred.credential_type == "service_principal"

    def test_extra_none_default(self) -> None:
        cred = CloudCredential(provider="aws", identity="test")
        assert cred.extra is None or cred.extra == {}

    def test_to_dict_is_serializable(self) -> None:
        import json
        cred = CloudCredential(
            provider="aws", identity="test",
            region="us-east-1", extra={"tags": ["admin"]},
        )
        d = cred.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)
