"""Descriptor schema + forbidden-secret scanner (SECP-PR5C, defects #1C, #5, #9)."""

from __future__ import annotations

import pytest
from _support import valid_descriptor_raw
from secp_commissioning.descriptor import (
    CONTRACT_VERSION,
    DescriptorError,
    descriptor_digest,
    parse_descriptor,
    scan_forbidden,
)


def test_valid_descriptor_parses_and_digests_deterministically():
    d1 = parse_descriptor(valid_descriptor_raw())
    d2 = parse_descriptor(valid_descriptor_raw())
    assert d1.contract_version == CONTRACT_VERSION
    assert descriptor_digest(d1) == descriptor_digest(d2)


def test_descriptor_carries_no_install_path_field():
    # The absolute-path fields are gone; supplying one is an unknown field and is refused.
    for bad in ("entrypoint_install_path", "managed_directories"):
        with pytest.raises(DescriptorError):
            parse_descriptor({**valid_descriptor_raw(), bad: "/opt/x"})


def test_unknown_field_is_rejected():
    with pytest.raises(DescriptorError):
        parse_descriptor({**valid_descriptor_raw(), "surprise": 1})


@pytest.mark.parametrize("field", ["vault_token", "api_key", "provider_credential", "openbao_path"])
def test_secret_like_field_name_refused(field):
    raw = valid_descriptor_raw()
    raw["ordinary_worker"] = {**raw["ordinary_worker"], field: "x"}
    with pytest.raises(DescriptorError) as exc:
        parse_descriptor(raw)
    assert exc.value.reason_code.startswith("forbidden_secret_field")


def test_secret_shaped_key_never_leaks_into_reason_code():
    for key in ("AKIAIOSFODNN7EXAMPLE", "-----BEGIN RSA PRIVATE KEY-----", "vault:secret/data/x"):
        raw = valid_descriptor_raw()
        raw["ordinary_worker"] = {**raw["ordinary_worker"], key: "x"}
        with pytest.raises(DescriptorError) as exc:
            parse_descriptor(raw)
        assert key not in exc.value.reason_code


def test_unknown_field_name_never_leaks_into_reason_code():
    secret_key = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    with pytest.raises(DescriptorError) as exc:
        parse_descriptor({**valid_descriptor_raw(), secret_key: "x"})
    assert secret_key not in exc.value.reason_code
    assert exc.value.reason_code.startswith("descriptor_unknown_field")


def test_pem_value_refused():
    raw = valid_descriptor_raw()
    raw["deployment"] = {**raw["deployment"], "site_label": "-----BEGIN RSA PRIVATE KEY-----"}
    with pytest.raises(DescriptorError):
        parse_descriptor(raw)


def test_operator_enabled_true_refused():
    with pytest.raises(DescriptorError):
        parse_descriptor(valid_descriptor_raw(operator_preparation={"enabled": True}))


def test_operator_queue_equal_to_ordinary_refused():
    with pytest.raises(DescriptorError):
        parse_descriptor(
            valid_descriptor_raw(operator_preparation={"task_queue": "secp-orchestration"})
        )


def test_root_runtime_uid_refused():
    raw = valid_descriptor_raw()
    raw["ordinary_worker"] = {
        **raw["ordinary_worker"],
        "runtime": {"uid": 0, "gid": 0, "read_only_root_fs": True},
    }
    with pytest.raises(DescriptorError):
        parse_descriptor(raw)


def test_scan_reason_never_contains_the_value():
    raw = valid_descriptor_raw()
    raw["ordinary_worker"] = {**raw["ordinary_worker"], "client_secret": "s3cr3t-not-in-code"}
    with pytest.raises(DescriptorError) as exc:
        scan_forbidden(raw)
    assert "s3cr3t" not in exc.value.reason_code
