"""Consolidated SECP-PR5D Round 4 regressions (section 9): the operational + fail-closed contract.

Cross-cutting checks that the operational binding path, the trusted-install gate, exact-type
refusal, and every preserved seal hold together — and that nothing constructs a Worker / submits a
workflow / runs OpenTofu / mutates the ordinary worker / contacts infrastructure.
"""

from __future__ import annotations

import pathlib

import pytest
from _deploy_support import host_evidence, valid_expected, valid_profile
from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment.cli import VerifyDeps, run


def test_cli_refuses_untrusted_package_install():
    deps = VerifyDeps(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=False,
        installed_trust_reason="manifest_ancestor_not_root_owned",
        host_observation=host_evidence(),
    )
    code, payload = run(["verify", "--json"], deps)
    assert code == 15 and payload["status"] == "install_untrusted"


def test_cli_foreign_context_yields_fail_closed():
    class _Evil:
        def __getattr__(self, name):
            raise AssertionError("the CLI must not read data from a foreign context")

    code, payload = run(["verify", "--json"], VerifyDeps(context=_Evil()))
    assert payload["profile"]["reason_code"] == "verify_context_type_invalid"
    assert payload["status"] in ("profile_invalid", "sealed_but_unprovisioned")


def test_foreign_filesystem_to_loaders_fails_closed():
    from secp_operator_deployment.identities import IdentityError, read_expected_identities
    from secp_operator_deployment.profile import ProfileError, read_deployment_profile

    class _EvilFS:
        def lstat(self, path):  # noqa: ANN001, ANN201
            raise RuntimeError("boom")

    with pytest.raises(ProfileError):
        read_deployment_profile(fs=_EvilFS())
    with pytest.raises(IdentityError):
        read_expected_identities(fs=_EvilFS())


def test_all_four_seals_remain_exact():
    from secp_operator_deployment.runner import _OPERATOR_ACTIVATION_SEALED
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert _OPERATOR_ACTIVATION_SEALED is True
    assert pb._PLAN_ONLY_PROCESS_SEALED is False
    assert act._B1A_SUBPROCESS_SEALED is True
    assert pe._B1A_SUBPROCESS_SEALED is True


def test_queues_are_distinct_and_exact():
    p = valid_profile()
    assert p.ordinary_task_queue == "secp-orchestration"
    assert p.operator_task_queue == "secp-controlled-live-v1"
    assert p.ordinary_task_queue != p.operator_task_queue


def test_runner_refuses_and_constructs_no_worker():
    # (test_deployment_runner_seal.py proves the runner imports no temporalio at module load and
    # constructs no Worker; here we assert the refusal behaviour end to end.)
    from secp_operator_deployment.runner import run_operator_worker

    with pytest.raises(DeploymentPackageError) as exc:
        run_operator_worker(object())
    assert exc.value.reason_code in ("operator_registration_invalid", "operator_activation_sealed")


def test_no_apply_destroy_or_run_plan_generation_in_package():
    import secp_operator_deployment

    pkg_dir = pathlib.Path(secp_operator_deployment.__file__).parent
    for py in pkg_dir.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        # the package never calls apply/destroy or run_plan_generation, and never runs OpenTofu
        assert "run_plan_generation(" not in text, py.name
        assert ".apply(" not in text and ".destroy(" not in text, py.name


def test_adapters_expose_no_mutation_verb():
    text = pathlib.Path(
        __import__("secp_operator_deployment.host_adapters", fromlist=["x"]).__file__
    ).read_text(encoding="utf-8")
    for verb in ("start", "stop", "restart", "enable", "disable", "reload", "mask", "kill", "rm"):
        assert f'"{verb}",' not in text, verb


def test_verify_effects_are_structurally_true():
    deps = VerifyDeps(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=True,
        host_observation=host_evidence(),
    )
    _code, payload = run(["verify", "--json"], deps)
    assert payload["status"] == "sealed_prepared"
    assert payload["effects_of_this_verification"] == {
        "worker_constructed": False,
        "workflow_submitted": False,
        "run_plan_generation_called": False,
        "secret_resolver_constructed": False,
        "external_contact_performed": False,
    }
