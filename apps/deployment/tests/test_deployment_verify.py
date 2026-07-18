"""Pure, exact-typed, sectioned verify + the sealed_prepared success (SECP-PR5D Round 4,
#2/#4/#5/#6).

Prepared-deployment success (``sealed_prepared``, exit 0) requires trusted install +
profile/expected agreement + a prepared host + safe seals, but NOT runtime provisioning or
composition readiness (which are reported separately). Verify is PURE and refuses a foreign input
by EXACT type without touching an arbitrary attribute; a supplied composition aggregate is
SEMANTICALLY validated.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from _deploy_support import (
    built_controlled_live_compositions,
    host_evidence,
    prepared_host_runner,
    runtime_attestation,
    seeded_production_fs,
    valid_expected,
    valid_profile,
)
from secp_operator_deployment import PACKAGE_IMPLEMENTATION_ID
from secp_operator_deployment.cli import VerifyDeps, run
from secp_operator_deployment.verify import STATUS_EXIT_CODES, build_verification


def _prepared(**over):
    d = dict(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=True,
        host_observation=host_evidence(),
    )
    d.update(over)
    return build_verification(**d)


# --------------------------------------------------------------------------- prepared success


def test_sealed_prepared_success():
    report = _prepared()
    assert report["status"] == "sealed_prepared" and report["exit_code"] == 0
    assert report["deployment_readiness"]["prepared"] is True
    # prepared success does NOT require runtime provisioning or composition readiness
    assert report["deployment_readiness"]["runtime_provisioned"] is False
    assert report["deployment_readiness"]["compositions_verified"] is False


def test_prepared_success_without_attestation_or_composition():
    report = build_verification(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=True,
        host_observation=host_evidence(),
        attestation=None,
        compositions=None,
    )
    assert report["status"] == "sealed_prepared"


def test_seals_reported_and_correct():
    seals = _prepared()["code_seals"]
    assert seals["operator_activation_sealed"] is True
    assert seals["plan_only_process_sealed"] is False
    assert seals["b1a_subprocess_sealed_activation"] is True
    assert seals["b1a_subprocess_sealed_executor"] is True
    assert seals["apply_destroy_available"] is False
    assert seals["seals_correct"] is True


def test_effects_are_scoped_and_pure():
    report = _prepared()
    assert report["effects_of_this_verification"] == {
        "worker_constructed": False,
        "workflow_submitted": False,
        "run_plan_generation_called": False,
        "secret_resolver_constructed": False,
        "external_contact_performed": False,
    }


# --------------------------------------------------------------------------- fail-closed statuses


def test_untrusted_install_blocks_prepared():
    report = _prepared(
        installed_trust_ok=False, installed_trust_reason="manifest_ancestor_not_root_owned"
    )
    assert report["status"] == "install_untrusted" and report["exit_code"] == 15
    assert report["package_trust"]["installed_trust_ok"] is False
    assert report["package_trust"]["reason_code"] == "manifest_ancestor_not_root_owned"


def test_missing_profile_is_sealed_but_unprovisioned():
    report = _prepared(profile=None)
    assert report["status"] == "sealed_but_unprovisioned" and report["exit_code"] == 10
    assert report["profile"]["present"] is False


def test_present_but_invalid_profile_is_profile_invalid():
    report = _prepared(profile=None, profile_load_reason="profile_invalid:contract_version")
    assert report["status"] == "profile_invalid" and report["exit_code"] == 11
    assert report["profile"]["present"] is True and report["profile"]["schema_valid"] is False


def test_missing_expected_is_sealed_but_unprovisioned():
    report = _prepared(expected=None)
    assert report["status"] == "sealed_but_unprovisioned"
    assert report["identity_agreement"]["expected_provided"] is False


def test_identity_mismatch():
    report = _prepared(profile=valid_profile(operator_image_digest="sha256:" + "9" * 64))
    assert report["status"] == "identity_mismatch" and report["exit_code"] == 12
    assert report["identity_agreement"]["agrees"] is False


def test_host_uninspected_is_unavailable():
    report = _prepared(host_observation=host_evidence(inspected=False))
    assert report["status"] == "host_unavailable" and report["exit_code"] == 13


def test_host_incoherent_is_unavailable():
    report = _prepared(host_observation=host_evidence(coherent=False))
    assert report["status"] == "host_unavailable"


def test_operator_running_is_host_not_ready():
    report = _prepared(host_observation=host_evidence(enabled=True, running=True))
    assert report["status"] == "host_not_ready" and report["exit_code"] == 14


def test_ordinary_down_is_host_not_ready():
    report = _prepared(host_observation=host_evidence(ordinary=False))
    assert report["status"] == "host_not_ready"


def test_host_not_attempted_is_sealed_but_unprovisioned():
    report = _prepared(host_observation=None)
    assert report["status"] == "sealed_but_unprovisioned"


# --------------------------------------------------------------------------- exact-type refusal
# (#5)


class _Hostile:
    def __getattr__(self, name):
        raise AssertionError(f"verify must not access attribute {name!r} on a foreign object")


def test_foreign_profile_refused_without_attribute_access():
    report = _prepared(profile=_Hostile())
    assert report["profile"]["reason_code"] == "profile_type_invalid"
    assert report["status"] == "profile_invalid"


def test_foreign_expected_refused_without_attribute_access():
    report = _prepared(expected=_Hostile())
    assert report["identity_agreement"]["expected_provided"] is False
    assert report["status"] == "sealed_but_unprovisioned"


def test_foreign_host_observation_refused_without_attribute_access():
    report = _prepared(host_observation=_Hostile())
    assert report["host_observation"]["reason_code"] == "host_observation_type_invalid"
    assert report["status"] == "host_unavailable"


def test_foreign_attestation_refused_without_attribute_access():
    report = _prepared(attestation=_Hostile())
    assert report["runtime_provisioning"]["attested"] is False
    assert report["runtime_provisioning"]["provisioned"] is False


def test_foreign_composition_refused_without_attribute_access():
    report = _prepared(compositions=_Hostile())
    assert report["compositions"]["verified"] is False
    assert report["compositions"]["reason_code"] == "compositions_object_invalid"
    # a foreign aggregate never blocks prepared success (composition readiness is separate)
    assert report["status"] == "sealed_prepared"


# --------------------------------------------------------------------------- runtime attestation
# (#3)


def test_unprovisioned_attestation_reported_not_ready():
    report = _prepared(attestation=runtime_attestation())
    assert report["runtime_provisioning"]["attested"] is True
    assert report["runtime_provisioning"]["provisioned"] is False
    assert report["runtime_provisioning"]["reason_code"] == "attestation_not_provisioned"


# --------------------------------------------------------------------------- semantic composition
# (#4)


def _agg():
    return built_controlled_live_compositions()


def test_valid_composition_verifies_and_reports_provenance():
    report = _prepared(compositions=_agg())
    assert report["compositions"]["supplied"] is True
    assert report["compositions"]["verified"] is True
    assert (
        report["composition_provenance"]["package_implementation_id"] == PACKAGE_IMPLEMENTATION_ID
    )


def test_composition_untrusted_install_binding_refuses():
    # A valid aggregate but an untrusted install must not verify (provenance is bound to install
    # trust).
    report = build_verification(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=False,
        host_observation=host_evidence(),
        compositions=_agg(),
    )
    assert report["compositions"]["verified"] is False
    assert report["compositions"]["reason_code"] == "provenance_untrusted_install"


def _mutate_pe(agg, **kw):
    return dataclasses.replace(agg, plan_execution=dataclasses.replace(agg.plan_execution, **kw))


def test_bad_provenance_digest_refuses():
    agg = _agg()
    bad = dataclasses.replace(
        agg,
        provenance=dataclasses.replace(
            agg.provenance, package_implementation_digest="sha256:" + "0" * 64
        ),
    )
    assert _prepared(compositions=bad)["compositions"]["verified"] is False


def test_disabled_plan_gate_refuses():
    from secp_worker.plan_gen.composition import PlanExecutionGate

    agg = _mutate_pe(_agg(), gate=PlanExecutionGate(enabled=False))
    assert _prepared(compositions=agg)["compositions"]["verified"] is False


def test_wrong_classification_refuses():
    agg = _mutate_pe(_agg(), classification="ordinary")
    assert _prepared(compositions=agg)["compositions"]["verified"] is False


def test_wrong_executor_factory_refuses():
    agg = _mutate_pe(_agg(), executor_factory=lambda *a, **k: None)
    assert _prepared(compositions=agg)["compositions"]["verified"] is False


def test_wrong_renderer_digest_refuses():
    agg = _mutate_pe(_agg(), renderer_module_digest="sha256:" + "0" * 64)
    assert _prepared(compositions=agg)["compositions"]["verified"] is False


def test_wrong_process_digest_refuses():
    agg = _mutate_pe(_agg(), process_implementation_digest="sha256:" + "0" * 64)
    assert _prepared(compositions=agg)["compositions"]["verified"] is False


def test_wrong_provider_source_refuses():
    agg = _mutate_pe(_agg(), provider_source="evil/provider")
    assert _prepared(compositions=agg)["compositions"]["verified"] is False


def test_disabled_readiness_gate_refuses():
    from secp_worker.readiness.composition import ReadinessGate

    agg = _agg()
    bad = dataclasses.replace(
        agg, readiness=dataclasses.replace(agg.readiness, gate=ReadinessGate(enabled=False))
    )
    assert _prepared(compositions=bad)["compositions"]["verified"] is False


def test_disabled_eligibility_gate_refuses():
    from secp_worker.onboarding.eligibility_preflight import EligibilityPreflightGate

    agg = _agg()
    bad = dataclasses.replace(
        agg,
        eligibility=dataclasses.replace(
            agg.eligibility, gate=EligibilityPreflightGate(enabled=False)
        ),
    )
    assert _prepared(compositions=bad)["compositions"]["verified"] is False


# --------------------------------------------------------------------------- determinism + secrets


def test_report_is_deterministic():
    a = _prepared(compositions=_agg())
    b = _prepared(compositions=_agg())
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_report_is_secret_free():
    text = json.dumps(_prepared(compositions=_agg()))
    for leak in (
        "secp-orchestration",
        "secp-controlled-live-v1",
        "/usr/bin/docker",
        "secp-ordinary-worker",
    ):
        assert leak not in text


# --------------------------------------------------------------------------- operational CLI (#2)


def test_cli_production_default_fails_closed_in_shipped_state(monkeypatch):
    # deps=None → the CLI resolves the production context (empty fs here) → fail closed, no
    # injection.
    import secp_operator_deployment.production_context as pc
    from secp_commissioning.runtime import InMemoryFilesystem

    monkeypatch.setattr(pc, "_production_fs", InMemoryFilesystem)
    code, payload = run(["verify", "--json"], deps=None)
    assert code == STATUS_EXIT_CODES[payload["status"]]
    assert payload["status"] in ("sealed_but_unprovisioned", "install_untrusted")


def test_cli_reaches_prepared_via_real_production_context(monkeypatch):
    # The REAL context loader (seeded fs + trusted install + prepared host runner), consumed by the
    # CLI with NO Python VerifyDeps injection, reaches sealed_prepared.
    import secp_operator_deployment.manifest as manifest
    import secp_operator_deployment.production_context as pc
    from secp_operator_deployment import package_implementation_digest

    monkeypatch.setattr(pc, "_production_fs", seeded_production_fs)
    monkeypatch.setattr(pc, "_command_runner", prepared_host_runner)
    monkeypatch.setattr(
        manifest,
        "verify_installed_package_trust",
        lambda _dir, *, expected_aggregate=None: package_implementation_digest(),
    )
    code, payload = run(["verify", "--json"], deps=None)
    assert code == 0 and payload["status"] == "sealed_prepared"
    assert payload["package_trust"]["installed_trust_ok"] is True
    assert payload["host_observation"]["operator_prepared_and_disabled"] is True


def test_cli_exit_codes_match_status():
    deps = VerifyDeps(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=True,
        host_observation=host_evidence(),
    )
    code, payload = run(["verify", "--json"], deps)
    assert code == 0 and payload["status"] == "sealed_prepared"


def test_cli_has_no_activate_or_profile_flag():
    import io
    from contextlib import redirect_stderr

    from secp_operator_deployment.cli import build_parser

    parser = build_parser()
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
        parser.parse_args(["activate"])
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
        parser.parse_args(["verify", "--profile", "/tmp/x.json"])
