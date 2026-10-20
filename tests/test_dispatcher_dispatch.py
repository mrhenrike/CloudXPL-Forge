"""Tests for cloudxpl.core.dispatcher.dispatch function."""

import types
from unittest.mock import patch, MagicMock

import pytest

from cloudxpl.core.dispatcher import dispatch, MODULE_MAP


class _FakeArgs:
    def __init__(self, command: str, module: str, **kwargs):
        self.command = command
        self.module = module
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestDispatchRouting:
    def test_unknown_provider(self, capsys) -> None:
        args = _FakeArgs("nonexistent", "foo")
        ret = dispatch(args)
        assert ret == 1
        assert "Unknown" in capsys.readouterr().err

    def test_unknown_module(self, capsys) -> None:
        args = _FakeArgs("aws", "nonexistent-module-xyz")
        ret = dispatch(args)
        assert ret == 1

    def test_successful_dispatch(self) -> None:
        fake_mod = types.ModuleType("fake_mod")
        fake_mod.run = MagicMock(return_value=0)
        with patch("importlib.import_module", return_value=fake_mod) as mock_import:
            args = _FakeArgs("aws", "s3-enum", region="us-east-1", profile=None)
            ret = dispatch(args)
        assert ret == 0
        fake_mod.run.assert_called_once_with(args)
        mock_import.assert_called_once_with("cloudxpl.modules.aws.s3_enum")

    def test_import_error_returns_one(self, capsys) -> None:
        with patch("importlib.import_module", side_effect=ImportError("no boto3")):
            args = _FakeArgs("aws", "s3-enum")
            ret = dispatch(args)
        assert ret == 1
        err = capsys.readouterr().err
        assert "boto3" in err or "Failed" in err

    def test_dispatch_azure(self) -> None:
        fake_mod = types.ModuleType("fake_mod")
        fake_mod.run = MagicMock(return_value=0)
        with patch("importlib.import_module", return_value=fake_mod):
            args = _FakeArgs("azure", "entra-enum")
            ret = dispatch(args)
        assert ret == 0

    def test_dispatch_gcp(self) -> None:
        fake_mod = types.ModuleType("fake_mod")
        fake_mod.run = MagicMock(return_value=0)
        with patch("importlib.import_module", return_value=fake_mod):
            args = _FakeArgs("gcp", "bucket-enum")
            ret = dispatch(args)
        assert ret == 0

    def test_dispatch_k8s(self) -> None:
        fake_mod = types.ModuleType("fake_mod")
        fake_mod.run = MagicMock(return_value=0)
        with patch("importlib.import_module", return_value=fake_mod):
            args = _FakeArgs("k8s", "cluster-enum")
            ret = dispatch(args)
        assert ret == 0

    def test_run_nonzero_propagates(self) -> None:
        fake_mod = types.ModuleType("fake_mod")
        fake_mod.run = MagicMock(return_value=2)
        with patch("importlib.import_module", return_value=fake_mod):
            args = _FakeArgs("aws", "iam-enum")
            ret = dispatch(args)
        assert ret == 2


class TestModuleMapCoverage:
    def test_all_providers_present(self) -> None:
        expected = {
            "aws", "azure", "gcp", "k8s", "oci", "alibaba",
            "tencent", "ibm", "digitalocean", "hetzner", "ovh",
            "virt", "serverless", "storage", "multi", "cred",
            "net", "cicd", "vdi", "paas",
        }
        assert expected.issubset(set(MODULE_MAP.keys()))

    def test_aws_module_count(self) -> None:
        assert len(MODULE_MAP["aws"]) >= 30

    def test_azure_module_count(self) -> None:
        assert len(MODULE_MAP["azure"]) >= 30

    def test_gcp_module_count(self) -> None:
        assert len(MODULE_MAP["gcp"]) >= 25

    def test_k8s_module_count(self) -> None:
        assert len(MODULE_MAP["k8s"]) >= 20

    def test_virt_module_count(self) -> None:
        assert len(MODULE_MAP["virt"]) >= 50

    def test_module_paths_start_with_cloudxpl(self) -> None:
        for provider, modules in MODULE_MAP.items():
            for key, path in modules.items():
                assert path.startswith("cloudxpl.modules."), (
                    f"{provider}/{key}: path '{path}' does not start with cloudxpl.modules."
                )
