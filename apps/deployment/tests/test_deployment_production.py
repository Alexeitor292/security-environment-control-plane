"""Production binding path + independent expected-identities loader (SECP-PR5D Round 4, blocker #1).

The fixed PR5C entrypoint calls ``build_controlled_live_compositions()`` with NO arguments; that
hook must resolve fixed root-controlled bindings and fail closed when they are absent, while a
complete test-modelled binding (over an in-memory filesystem, via the private test seams) satisfies
it.
"""

from __future__ import annotations

import json

import pytest
from _deploy_support import (
    StubControlledLiveRuntime,
    expected_identities_raw,
    seeded_production_fs,
    valid_profile,
)
from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment.identities import (
    IdentityError,
    parse_expected_identities_bytes,
    read_expected_identities,
)

# --------------------------------------------------------------------------- expected-identities
# loader


def test_expected_identities_roundtrips_and_agrees_with_profile():
    from secp_operator_deployment.identities import require_profile_agreement

    expected = parse_expected_identities_bytes(json.dumps(expected_identities_raw()).encode())
    require_profile_agreement(valid_profile(), expected)  # no raise → agrees


@pytest.mark.parametrize(
    "field",
    ["operator_image_digest", "operator_service_name", "plan_provider_identity"],
)
def test_expected_identities_missing_field_refused(field):
    raw = expected_identities_raw()
    raw.pop(field)
    with pytest.raises(IdentityError):
        parse_expected_identities_bytes(json.dumps(raw).encode())


def test_expected_identities_unknown_field_refused():
    with pytest.raises(IdentityError):
        parse_expected_identities_bytes(
            json.dumps({**expected_identities_raw(), "surprise": 1}).encode()
        )


def test_expected_identities_duplicate_key_refused():
    body = json.dumps(expected_identities_raw())
    dup = (body[:-1] + ',"operator_image_digest":"sha256:' + "0" * 64 + '"}').encode()
    with pytest.raises(IdentityError) as exc:
        parse_expected_identities_bytes(dup)
    assert exc.value.reason_code == "expected_identities_duplicate_key"


def test_expected_identities_forbidden_secret_refused():
    with pytest.raises(IdentityError):
        parse_expected_identities_bytes(
            json.dumps({**expected_identities_raw(), "openbao_token": "x"}).encode()
        )


def test_expected_identities_hardened_read_from_fixed_path():
    expected = read_expected_identities(fs=seeded_production_fs())
    assert expected.operator_task_queue == "secp-controlled-live-v1"


def test_expected_identities_absent_fails_closed():
    from secp_commissioning.runtime import InMemoryFilesystem

    with pytest.raises(IdentityError) as exc:
        read_expected_identities(fs=InMemoryFilesystem())
    assert exc.value.reason_code == "expected_identities_not_installed"


def test_expected_identities_untrusted_owner_fails_closed():
    from secp_commissioning.runtime import InMemoryFilesystem
    from secp_operator_deployment.identities import FIXED_EXPECTED_IDENTITIES_PATH

    fs = InMemoryFilesystem()
    fs.seed_dir("/etc/secp/operator-deployment", uid=0, gid=0, mode=0o755)
    fs.seed_file(
        FIXED_EXPECTED_IDENTITIES_PATH,
        json.dumps(expected_identities_raw()).encode(),
        uid=1000,
        gid=0,
        mode=0o640,
    )
    with pytest.raises(IdentityError) as exc:
        read_expected_identities(fs=fs)
    assert exc.value.reason_code == "expected_identities_unreadable"


# --------------------------------------------------------------------------- production no-arg
# hook


def _use_production(monkeypatch, *, fs, runtime=None):
    import secp_operator_deployment.production_context as pc

    monkeypatch.setattr(pc, "_production_fs", lambda: fs)
    if runtime is not None:
        monkeypatch.setattr(pc, "_load_installed_runtime", lambda: runtime)


def test_no_arg_build_fails_closed_when_bindings_absent(monkeypatch):
    from secp_commissioning.runtime import InMemoryFilesystem
    from secp_operator_deployment.compositions import build_controlled_live_compositions

    _use_production(monkeypatch, fs=InMemoryFilesystem())
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions()  # NO arguments — the exact PR5C entrypoint call
    assert exc.value.reason_code == "profile_not_installed"


def test_no_arg_build_fails_if_only_profile_exists(monkeypatch):
    from secp_operator_deployment.compositions import build_controlled_live_compositions

    _use_production(monkeypatch, fs=seeded_production_fs(seed_expected=False))
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions()
    assert exc.value.reason_code == "expected_identities_not_installed"


def test_profile_cannot_supply_its_own_expected_identities(monkeypatch):
    # Only the profile is present; the independent expected pins come from a SEPARATE file, so the
    # build cannot proceed from the profile alone.
    from secp_operator_deployment.compositions import build_controlled_live_compositions

    _use_production(monkeypatch, fs=seeded_production_fs(seed_expected=False))
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions()
    assert exc.value.reason_code == "expected_identities_not_installed"


def test_no_arg_build_shipped_runtime_is_sealed(monkeypatch):
    # Both fixed files present, but the shipped installed runtime is sealed (no reviewed provider),
    # so the no-argument build still fails closed.
    from secp_operator_deployment.compositions import build_controlled_live_compositions

    _use_production(
        monkeypatch, fs=seeded_production_fs()
    )  # default _load_installed_runtime = sealed
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions()
    assert exc.value.reason_code == "controlled_live_runtime_not_provisioned"


def test_complete_binding_satisfies_no_arg_hook(monkeypatch):
    from secp_operator_deployment.compositions import (
        ControlledLiveCompositions,
        build_controlled_live_compositions,
    )

    _use_production(monkeypatch, fs=seeded_production_fs(), runtime=StubControlledLiveRuntime())
    agg = build_controlled_live_compositions()  # NO arguments
    assert type(agg) is ControlledLiveCompositions


def test_pr5c_entrypoint_consumes_the_no_arg_result(monkeypatch):
    from secp_operator_deployment.compositions import build_controlled_live_compositions
    from secp_worker.operator_bootstrap import build_operator_activity_set

    _use_production(monkeypatch, fs=seeded_production_fs(), runtime=StubControlledLiveRuntime())
    agg = build_controlled_live_compositions()
    activity_set = build_operator_activity_set(
        plan_execution_composition=agg.plan_execution,
        readiness_composition=agg.readiness,
        eligibility_composition=agg.eligibility,
    )
    assert len(activity_set.registerable_activities()) == 5


def test_no_arg_build_selects_no_task_queue(monkeypatch):
    from secp_operator_deployment.compositions import build_controlled_live_compositions

    _use_production(monkeypatch, fs=seeded_production_fs(), runtime=StubControlledLiveRuntime())
    agg = build_controlled_live_compositions()
    assert not hasattr(agg, "task_queue")
    assert not hasattr(agg.plan_execution, "task_queue")


def test_runner_still_refuses_at_activation_seal():
    # The no-arg composition path never constructs a Worker; the runner still hard-refuses.
    from secp_operator_deployment.runner import run_operator_worker

    with pytest.raises(DeploymentPackageError) as exc:
        run_operator_worker(object())
    assert exc.value.reason_code in ("operator_registration_invalid", "operator_activation_sealed")
