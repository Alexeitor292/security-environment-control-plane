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
    """A cheap TEXTUAL smoke check, and only that (WS-E).

    It matches a double-quoted verb followed immediately by a comma, so it catches the accidental
    regression — someone typing ``("enable", self.operator_service)`` — and nothing subtler. A
    constructed verb (``verb = "en" + "able"``) passes it, and so does ``("enable")`` with no
    trailing comma.

    The real guarantee is structural and lives in ``test_operator_adapter_mutation_surface.py``:
    every ``runner.run`` argv must begin with a string LITERAL drawn from a read-only allowlist, no
    mutation verb may appear as any string constant, and the concrete adapters' public surface is
    pinned to an exact set. This check is kept because it is nearly free, not because it is
    sufficient.
    """
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
    # WS-E: the effects section separates MEASURED-this-invocation from structural. The old flat
    # `external_contact_performed: False` was false on a provisioned POSIX host, where resolving
    # the context runs systemctl/docker commands; contact is now counted as those commands run.
    # These deps are injected, so no context is resolved and zero is the honest count.
    assert payload["effects_of_this_verification"] == {
        "measured_this_invocation": {
            "host_commands_executed": 0,
            "local_host_contact_performed": False,
        },
        "structural_invariants": {
            "worker_constructed": False,
            "workflow_submitted": False,
            "run_plan_generation_called": False,
            "secret_resolver_constructed": False,
        },
    }
