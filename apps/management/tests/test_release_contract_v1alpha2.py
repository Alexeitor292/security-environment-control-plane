"""Versioned release contract v1alpha1/v1alpha2 (SECP-PR5H-B2, commit 2b-1).

Proves the closed compatibility window: legacy v1alpha1 bundles still parse + verify byte-for-byte
(the v1alpha2 installation-profile fields are version-gated out of the v1alpha1 canonical/signing
form), while newly-issued v1alpha2 bundles carry + sign the closed installation profile (platform,
host-runtime executable pins, controller TLS policy). Unknown/future versions and malformed profiles
refuse; a v1alpha1 bundle is refused for clean-host B2 with a bounded reason.
"""

from __future__ import annotations

import copy
import json

import pytest
from _mgmt_support import default_artifacts, ephemeral_trust_root, manifest_dict
from secp_management import (
    BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2 as V2,
)
from secp_management import ManagementError
from secp_management.release_bundle import (
    manifest_signing_message,
    parse_manifest_bytes,
    require_b2_installation_profile,
)
from secp_management.signing import sign_ed25519


def _valid_profile() -> dict:
    return {
        "platform_profile": {
            "os": "linux",
            "arch": "x86_64",
            "installation_profile_version": "secp.controller-install/v1",
        },
        "runtime_profile": {
            "pins": [
                {
                    "capability": "container_runtime",
                    "path": "/usr/bin/docker",
                    "sha256": "sha256:" + "1" * 64,
                    "invocation": [],
                    "allowed_subcommands": ["load", "image"],
                },
                {
                    "capability": "compose",
                    "path": "/usr/bin/docker",
                    "sha256": "sha256:" + "1" * 64,
                    "invocation": ["compose"],
                    "allowed_subcommands": ["up", "down"],
                },
                {
                    "capability": "service_manager",
                    "path": "/usr/bin/systemctl",
                    "sha256": "sha256:" + "2" * 64,
                    "invocation": [],
                    "allowed_subcommands": ["daemon-reload"],
                },
            ]
        },
        "controller_tls_policy": {
            "allowed_modes": ["generated_local_ca", "imported_enterprise_tls"],
            "key_algorithm": "ecdsa-p256",
            "signature_algorithm": "ecdsa-with-sha256",
            "max_validity_days": 825,
            "require_san": True,
            "server_auth_eku_required": True,
            "ca_pathlen_zero": True,
            "min_tls_version": "1.2",
            "allow_ip_origin": False,
            "allow_generated_local_ca": True,
        },
    }


def _v2_manifest(**over) -> dict:
    d = manifest_dict("controller", default_artifacts("controller"))
    d["bootstrap_contract_version"] = V2
    d.update(_valid_profile())
    d.update(over)
    return d


def _sign_and_verify(manifest_dict_: dict) -> bool:
    trust, key_id, priv, _pub = ephemeral_trust_root()
    d = dict(manifest_dict_)
    d["signing_anchor_id"] = key_id
    manifest = parse_manifest_bytes(json.dumps(d).encode())
    sig = sign_ed25519(priv, manifest_signing_message(manifest))
    return trust.verify(
        key_id=key_id, message=manifest_signing_message(manifest), signature_hex=sig
    )


# --- back-compat: v1alpha1 still parses + verifies -----------------------------------------------


def test_v1alpha1_bundle_still_parses_and_verifies():
    assert _sign_and_verify(manifest_dict("controller", default_artifacts("controller")))


def test_v1alpha1_with_a_profile_field_is_refused():
    d = manifest_dict("controller", default_artifacts("controller"))
    d["platform_profile"] = _valid_profile()["platform_profile"]
    with pytest.raises(ManagementError) as e:
        parse_manifest_bytes(json.dumps(d).encode())
    assert e.value.reason_code == "release_v1alpha1_profile_unexpected"


# --- v1alpha2: full profile signs + verifies -----------------------------------------------------


def test_v1alpha2_bundle_with_the_full_profile_verifies():
    assert _sign_and_verify(_v2_manifest())


def test_v1alpha2_canonical_includes_the_installation_profile():
    trust, key_id, _priv, _pub = ephemeral_trust_root()
    d = _v2_manifest(signing_anchor_id=key_id)
    m = parse_manifest_bytes(json.dumps(d).encode())
    canon = m.canonical()
    for field in ("platform_profile", "runtime_profile", "controller_tls_policy"):
        assert field in canon  # v1alpha2 SIGNS the profile


def test_v1alpha2_missing_a_profile_field_is_refused():
    d = _v2_manifest()
    del d["controller_tls_policy"]
    with pytest.raises(ManagementError) as e:
        parse_manifest_bytes(json.dumps(d).encode())
    assert e.value.reason_code == "release_v1alpha2_profile_incomplete"


# --- profile validation refusals -----------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (
            lambda d: d["platform_profile"].__setitem__("arch", "riscv"),
            "release_platform_unsupported",
        ),
        (
            lambda d: d["platform_profile"].__setitem__("os", "windows"),
            "release_platform_unsupported",
        ),
        (
            lambda d: d["runtime_profile"]["pins"].__delitem__(2),
            "release_runtime_capabilities_incomplete",
        ),
        (
            lambda d: d["runtime_profile"]["pins"][0].__setitem__("path", "relative/docker"),
            "release_runtime_path_invalid",
        ),
        (
            lambda d: d["controller_tls_policy"].__setitem__("allowed_modes", ["bogus"]),
            "release_tls_mode_invalid",
        ),
        (
            lambda d: d["controller_tls_policy"].__setitem__("server_auth_eku_required", False),
            "release_tls_policy_too_weak",
        ),
        (
            lambda d: d["controller_tls_policy"].__setitem__("key_algorithm", "rot13"),
            "release_tls_key_algorithm_invalid",
        ),
    ],
)
def test_malformed_v1alpha2_profile_is_refused(mutate, reason):
    d = _v2_manifest()
    mutate(d)
    with pytest.raises(ManagementError) as e:
        parse_manifest_bytes(json.dumps(d).encode())
    assert e.value.reason_code == reason


# --- unknown/future version + B2 gate ------------------------------------------------------------


def test_unknown_contract_version_is_refused():
    d = manifest_dict("controller", default_artifacts("controller"))
    d["bootstrap_contract_version"] = "secp.management-bootstrap/v9alpha9"
    with pytest.raises(ManagementError) as e:
        parse_manifest_bytes(json.dumps(d).encode())
    assert e.value.reason_code == "release_contract_version_invalid"


def test_require_b2_profile_refuses_v1alpha1_accepts_v1alpha2():
    m1 = parse_manifest_bytes(
        json.dumps(manifest_dict("controller", default_artifacts("controller"))).encode()
    )
    with pytest.raises(ManagementError) as e:
        require_b2_installation_profile(m1)
    assert e.value.reason_code == "release_b2_installation_profile_required"
    m2 = parse_manifest_bytes(json.dumps(_v2_manifest()).encode())
    require_b2_installation_profile(m2)  # v1alpha2 accepted (no raise)


# --- 2b-1c: closed runtime-profile + TLS-policy semantics -----------------------------------------


@pytest.mark.parametrize(
    "mutate,reason",
    [
        # a shell/interpreter can never be a host-runtime binary
        (
            lambda d: d["runtime_profile"]["pins"][0].__setitem__("path", "/usr/bin/bash"),
            "release_runtime_interpreter_forbidden",
        ),
        # extra subcommand beyond the exact adapter set
        (
            lambda d: d["runtime_profile"]["pins"][0].__setitem__(
                "allowed_subcommands", ["load", "image", "run"]
            ),
            "release_runtime_subcommand_set_mismatch",
        ),
        # missing subcommand the adapter requires
        (
            lambda d: d["runtime_profile"]["pins"][0].__setitem__("allowed_subcommands", ["load"]),
            "release_runtime_subcommand_set_mismatch",
        ),
        # wrong compose model (an arbitrary invocation prefix)
        (
            lambda d: d["runtime_profile"]["pins"][1].__setitem__("invocation", ["exec"]),
            "release_runtime_invocation_incompatible",
        ),
        # capability/invocation mismatch: a container_runtime pin using the compose prefix
        (
            lambda d: d["runtime_profile"]["pins"][0].__setitem__("invocation", ["compose"]),
            "release_runtime_invocation_incompatible",
        ),
        # signed profile must use the CANONICAL arch — an alias is ambiguous
        (
            lambda d: d["platform_profile"].__setitem__("arch", "amd64"),
            "release_platform_arch_alias",
        ),
        # key/signature algorithm incompatibility
        (
            lambda d: d["controller_tls_policy"].__setitem__("signature_algorithm", "ed25519"),
            "release_tls_signature_incompatible",
        ),
        # generated_local_ca in modes but the flag is false (contradiction)
        (
            lambda d: d["controller_tls_policy"].__setitem__("allow_generated_local_ca", False),
            "release_tls_generated_ca_inconsistent",
        ),
        # validity beyond the closed ceiling
        (
            lambda d: d["controller_tls_policy"].__setitem__("max_validity_days", 900),
            "release_tls_validity_out_of_bounds",
        ),
        # a controller server policy must require a SAN
        (
            lambda d: d["controller_tls_policy"].__setitem__("require_san", False),
            "release_tls_policy_too_weak",
        ),
    ],
)
def test_hardened_v1alpha2_profile_refuses_semantic_escapes(mutate, reason):
    d = _v2_manifest()
    mutate(d)
    with pytest.raises(ManagementError) as e:
        parse_manifest_bytes(json.dumps(d).encode())
    assert e.value.reason_code == reason


def test_normalize_arch_is_a_parity_boundary():
    from secp_management.release_bundle import _SUPPORTED_PLATFORMS, normalize_arch

    assert normalize_arch("x86_64") == "x86_64"
    assert normalize_arch("amd64") == "x86_64"
    assert normalize_arch("aarch64") == "arm64"
    assert normalize_arch("arm64") == "arm64"
    with pytest.raises(ManagementError) as e:
        normalize_arch("riscv64")
    assert e.value.reason_code == "release_platform_arch_unknown"
    # every normalization OUTPUT is a canonical arch the signed profile accepts (no drift)
    outputs = {normalize_arch(a) for a in ("x86_64", "amd64", "aarch64", "arm64")}
    assert outputs == _SUPPORTED_PLATFORMS["linux"]


def test_v1alpha1_signature_is_byte_stable_across_the_b2_field_addition():
    # a v1alpha1 manifest's signing message must not contain any v1alpha2 field name.
    m = parse_manifest_bytes(
        json.dumps(manifest_dict("controller", default_artifacts("controller"))).encode()
    )
    msg = manifest_signing_message(m).decode()
    for field in ("platform_profile", "runtime_profile", "controller_tls_policy"):
        assert field not in msg
    assert copy.copy(m) is not None  # frozen model is usable
