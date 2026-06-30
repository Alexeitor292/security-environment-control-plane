"""AC4 — scenario schema validation, including the web-breach-101 sample."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml
from secp_scenario_schema import canonicalize, content_hash, validate_definition
from secp_scenario_schema.validator import SchemaValidationError

REPO_ROOT = Path(__file__).resolve().parents[3]
SCENARIO = REPO_ROOT / "docs" / "scenarios" / "web-breach-101.yaml"


@pytest.fixture
def web_breach() -> dict:
    return yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))


def test_web_breach_101_is_valid(web_breach):
    definition = validate_definition(web_breach)
    assert definition.metadata.name == "web-breach-101"
    assert definition.spec.teams.count == 2
    assert definition.spec.teams.isolationPolicy.value == "strict"


def test_web_breach_101_required_content(web_breach):
    d = validate_definition(web_breach)
    images = {r.image for r in d.spec.roles}
    kinds = {r.kind.value for r in d.spec.roles}
    assert any("kali" in i for i in images)  # Kali attacker
    assert any("ubuntu" in i for i in images)  # Ubuntu web server
    assert "attacker" in kinds and "target" in kinds
    assert d.spec.telemetry.providers == ["wazuh"]  # Wazuh telemetry
    assert d.spec.validation.provider == "ctfd"  # CTFd validation
    assert len(d.spec.validation.objectives) >= 1  # objectives
    assert any(p.ref == "weak-ssh" for p in d.spec.vulnerabilityPacks)
    assert "simulator" in d.spec.requiredPlugins


def test_missing_required_field_rejected(web_breach):
    broken = copy.deepcopy(web_breach)
    del broken["spec"]["teams"]
    with pytest.raises(SchemaValidationError):
        validate_definition(broken)


def test_unsupported_api_version_rejected(web_breach):
    broken = copy.deepcopy(web_breach)
    broken["apiVersion"] = "controlplane.security/v2"
    with pytest.raises(SchemaValidationError):
        validate_definition(broken)


def test_role_referencing_unknown_network_rejected(web_breach):
    broken = copy.deepcopy(web_breach)
    broken["spec"]["roles"][0]["network"] = "does-not-exist"
    with pytest.raises(SchemaValidationError):
        validate_definition(broken)


def test_additional_properties_rejected(web_breach):
    broken = copy.deepcopy(web_breach)
    broken["spec"]["unexpectedField"] = True
    with pytest.raises(SchemaValidationError):
        validate_definition(broken)


def test_content_hash_is_stable_and_order_independent(web_breach):
    reordered = {k: web_breach[k] for k in reversed(list(web_breach.keys()))}
    assert content_hash(web_breach) == content_hash(reordered)
    assert canonicalize(web_breach) == canonicalize(reordered)
