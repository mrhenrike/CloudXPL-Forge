"""Tests for cloudxpl.core.dispatcher module."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cloudxpl.core.dispatcher import MODULE_MAP


def test_module_map_is_dict():
    assert isinstance(MODULE_MAP, dict)


def test_module_map_has_providers():
    expected = {"aws", "azure", "gcp", "k8s", "oci", "alibaba", "tencent", "ibm"}
    assert expected.issubset(set(MODULE_MAP.keys()))


def test_module_paths_are_dotted():
    for provider, modules in MODULE_MAP.items():
        for key, path in modules.items():
            assert "." in path, "{}/{} module path must be dotted".format(provider, key)


def test_total_module_count():
    total = sum(len(v) for v in MODULE_MAP.values())
    assert total >= 400


def test_aws_has_s3_enum():
    assert "s3-enum" in MODULE_MAP["aws"]


def test_azure_has_entra_enum():
    assert "entra-enum" in MODULE_MAP["azure"]


def test_gcp_has_bucket_enum():
    assert "bucket-enum" in MODULE_MAP["gcp"]


def test_k8s_has_container_escape():
    assert "container-escape" in MODULE_MAP["k8s"]


def test_virt_category_exists():
    assert "virt" in MODULE_MAP
    assert len(MODULE_MAP["virt"]) >= 50


def test_serverless_category_exists():
    assert "serverless" in MODULE_MAP
    assert len(MODULE_MAP["serverless"]) >= 10


def test_cicd_category_exists():
    assert "cicd" in MODULE_MAP
    assert len(MODULE_MAP["cicd"]) >= 5
