"""Tests for cloudxpl CLI entrypoint (__main__)."""

import subprocess
import sys
from unittest.mock import patch, MagicMock

import pytest

from cloudxpl.__main__ import _build_parser, main


class TestBuildParser:
    def test_parser_prog(self) -> None:
        p = _build_parser()
        assert p.prog == "cxf"

    def test_parser_has_version(self) -> None:
        p = _build_parser()
        with pytest.raises(SystemExit) as exc:
            p.parse_args(["--version"])
        assert exc.value.code == 0

    def test_aws_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["aws", "s3-enum", "--region", "eu-west-1"])
        assert args.command == "aws"
        assert args.module == "s3-enum"
        assert args.region == "eu-west-1"

    def test_azure_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["azure", "entra-enum", "--tenant-id", "abc"])
        assert args.command == "azure"
        assert args.module == "entra-enum"
        assert args.tenant_id == "abc"

    def test_gcp_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["gcp", "bucket-enum", "--project", "my-proj"])
        assert args.command == "gcp"
        assert args.module == "bucket-enum"
        assert args.project == "my-proj"

    def test_k8s_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["k8s", "cluster-enum", "--namespace", "kube-system"])
        assert args.command == "k8s"
        assert args.module == "cluster-enum"
        assert args.namespace == "kube-system"

    def test_serverless_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["serverless", "env-extraction", "--provider", "gcp"])
        assert args.command == "serverless"
        assert args.provider == "gcp"

    def test_storage_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["storage", "bucket-bruteforce", "--bucket", "test-bkt"])
        assert args.command == "storage"
        assert args.bucket == "test-bkt"

    def test_multi_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["multi", "cross-cloud-pivot"])
        assert args.command == "multi"

    def test_oci_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["oci", "bucket-enum", "--tenancy-ocid", "ocid1.tenancy"])
        assert args.command == "oci"
        assert args.tenancy_ocid == "ocid1.tenancy"

    def test_virt_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["virt", "esxi-enum"])
        assert args.command == "virt"

    def test_cicd_subcommand(self) -> None:
        p = _build_parser()
        args = p.parse_args(["cicd", "gha-runner-escape"])
        assert args.command == "cicd"

    def test_default_region_aws(self) -> None:
        p = _build_parser()
        args = p.parse_args(["aws", "iam-enum"])
        assert args.region == "us-east-1"

    def test_common_args_json(self) -> None:
        p = _build_parser()
        args = p.parse_args(["aws", "s3-enum", "--json"])
        assert args.json is True

    def test_common_args_verbose(self) -> None:
        p = _build_parser()
        args = p.parse_args(["aws", "s3-enum", "-v"])
        assert args.verbose is True


class TestMain:
    def test_no_command_returns_zero(self) -> None:
        assert main([]) == 0

    def test_dispatch_called(self) -> None:
        mock_dispatch = MagicMock(return_value=0)
        with patch("cloudxpl.core.dispatcher.dispatch", mock_dispatch):
            ret = main(["aws", "s3-enum"])
        assert ret == 0
        mock_dispatch.assert_called_once()
        call_args = mock_dispatch.call_args[0][0]
        assert call_args.command == "aws"
        assert call_args.module == "s3-enum"


class TestCLIProcess:
    def test_help_exit_code(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "cloudxpl", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "cxf" in result.stdout.lower() or "cloudxpl" in result.stdout.lower()

    def test_no_args_shows_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "cloudxpl"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
