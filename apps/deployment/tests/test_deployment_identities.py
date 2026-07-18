"""Independent trusted deployment identity pins (SECP-PR5D, blocker #4)."""

from __future__ import annotations

import pytest
from _deploy_support import valid_expected, valid_profile
from secp_operator_deployment.identities import (
    IdentityError,
    assert_expected_package_identity,
    require_profile_agreement,
)


def test_valid_profile_agrees_with_expected():
    require_profile_agreement(valid_profile(), valid_expected())  # no raise


@pytest.mark.parametrize(
    "override,reason",
    [
        (dict(release_source_sha="c" * 40), "release_source_sha_mismatch"),
        (dict(operator_image_digest="sha256:" + "9" * 64), "operator_image_mismatch"),
        (dict(operator_service_name="other.service"), "operator_service_mismatch"),
        (dict(ordinary_container_name="other-container"), "ordinary_container_mismatch"),
        (
            dict(container_runtime_executable="/usr/bin/podman"),
            "container_runtime_executable_mismatch",
        ),
        (
            dict(container_runtime_executable_digest="sha256:" + "0" * 64),
            "container_runtime_digest_mismatch",
        ),
        (
            dict(service_inspector_executable_digest="sha256:" + "0" * 64),
            "service_inspector_digest_mismatch",
        ),
        (dict(ordinary_runtime_uid=999), "ordinary_runtime_uid_mismatch"),
        # blocker #6: each of the three provider identities is an independent agreement point.
        (
            dict(plan_provider_identity="secp_worker.plan_gen.composition_provider.Other"),
            "plan_provider_identity_mismatch",
        ),
        (
            dict(readiness_provider_identity="secp_worker.readiness.composition_provider.Other"),
            "readiness_provider_identity_mismatch",
        ),
        (
            dict(eligibility_provider_identity="secp_worker.onboarding.eligibility_provider.Other"),
            "eligibility_provider_identity_mismatch",
        ),
    ],
)
def test_profile_disagreement_refused(override, reason):
    with pytest.raises(IdentityError) as exc:
        require_profile_agreement(valid_profile(**override), valid_expected())
    assert exc.value.reason_code == reason


@pytest.mark.parametrize(
    "override,reason",
    [
        (
            dict(plan_provider_identity="evil.module.Foo"),
            "expected_plan_provider_invalid",
        ),
        (
            dict(readiness_provider_identity="evil.module.Foo"),
            "expected_readiness_provider_invalid",
        ),
        (
            dict(eligibility_provider_identity="evil.module.Foo"),
            "expected_eligibility_provider_invalid",
        ),
    ],
)
def test_expected_cannot_lie_about_provider_identities(override, reason):
    # blocker #6: even the independent trusted-pins object cannot lie about the reviewed provider
    # identities — they are cross-checked against the code-owned constants.
    with pytest.raises(IdentityError) as exc:
        assert_expected_package_identity(valid_expected(**override))
    assert exc.value.reason_code == reason


def test_profile_is_never_the_sole_authority_health_argv():
    # A profile whose health argv differs from the trusted pin is refused (identity, not just
    # schema).
    with pytest.raises(IdentityError) as exc:
        require_profile_agreement(
            valid_profile(ordinary_health_command=["/usr/bin/python3", "-m", "x"]),
            valid_expected(),
        )
    assert exc.value.reason_code == "ordinary_health_mismatch"


def test_expected_cannot_lie_about_package_manifest_digest():
    with pytest.raises(IdentityError) as exc:
        assert_expected_package_identity(
            valid_expected(package_implementation_digest="sha256:" + "0" * 64)
        )
    assert exc.value.reason_code == "expected_manifest_digest_invalid"


def test_expected_cannot_lie_about_composition_pins():
    with pytest.raises(IdentityError) as exc:
        assert_expected_package_identity(
            valid_expected(controlled_live_process_digest="sha256:" + "0" * 64)
        )
    assert exc.value.reason_code == "expected_process_digest_invalid"


def test_valid_expected_passes_package_cross_check():
    assert_expected_package_identity(valid_expected())  # no raise
