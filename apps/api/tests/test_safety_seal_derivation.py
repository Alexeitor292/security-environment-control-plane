"""Safety seals are re-derived by exercise — and the derivation is proved IN THE RED DIRECTION.

The four seals published as ``safety_seals`` in the activation evidence payload were module-level
booleans. Each was a claim ABOUT code elsewhere, and nothing checked that the code still behaved
the way the boolean said. Delete the guard inside ``SubprocessProcessExecutor.__init__`` and every
seal still reported ``true``: the evidence payload would have asserted the executor was sealed
while it constructed freely.

One of them was simply false. ``real_provisioning_disabled`` reported ``true`` while #105-#110
shipped desired-state compilation, plan generation, apply authorization, observed verification,
destroy authorization and the residue proof.

This module is the reason to believe the replacement. A seal that has never been seen to fail is a
seal nobody knows works, and these gate a hold point — so every derivation is made to fail on
purpose here.
"""

from __future__ import annotations

# Imported at module scope ONLY so `Base.metadata` is complete before the `engine` fixture runs
# `create_all`. `safety_seal_probe` imports these lazily on purpose — importing the probe must do
# nothing — so without this the provisioning table is absent from the test schema and the apply
# history reads `undetermined` for a harness reason rather than a real one.
from secp_api.models import ProvisioningOperation  # noqa: F401
from secp_api.range_models import RangeDeploymentOperation  # noqa: F401
from secp_worker.safety_seal_probe import (
    PROVISIONING_CAPABILITY,
    SealState,
    all_sealed,
    derive_seals,
    observe_apply_history,
    seal_payload,
)

# --- the seals hold today, and say how they know ----------------------------------


def test_every_seal_is_derived_by_exercise_and_holds():
    observations = derive_seals()
    assert len(observations) == 3
    for item in observations:
        assert item.state is SealState.sealed, (item.name, item.detail)
        # The detail says what was EXERCISED, not what a constant said.
        assert item.detail
    assert all_sealed(observations) is True


def test_the_payload_publishes_states_not_booleans():
    """Three states need three values.

    A boolean carries two, and the third is the load-bearing one.
    """
    payload = seal_payload(derive_seals())
    assert set(payload.values()) == {"sealed"}
    assert all(isinstance(value, str) for value in payload.values())


def test_an_empty_observation_set_is_not_vacuously_sealed():
    """``all()`` over nothing is True. That is exactly the shape a broken derivation produces."""
    assert all_sealed(()) is False


# --- the red direction: each seal made to fail on purpose -------------------------


def test_the_executor_seal_fails_when_the_executor_can_be_constructed(monkeypatch):
    """Unseal the real subprocess executor and the seal must report ``unsealed``.

    This is the case the old constant could not see: flip the guard inside ``__init__`` and the
    boolean ``_B1A_SUBPROCESS_SEALED`` still reads True, so the payload still claimed sealed. Here
    the surface is constructed for real, so the claim tracks the behaviour.
    """
    from secp_worker.provisioning import process_executor

    monkeypatch.setattr(process_executor, "_B1A_SUBPROCESS_SEALED", False)
    observations = {item.name: item for item in derive_seals()}
    seal = observations["generic_executor_subprocess_sealed"]
    assert seal.state is SealState.unsealed
    assert all_sealed(tuple(observations.values())) is False


def test_the_activation_seal_fails_when_a_grant_yields_a_real_executor(monkeypatch):
    """The activation path is exercised with a VALID grant — the most permissive input there is."""
    from secp_worker.provisioning import activation
    from secp_worker.provisioning.process_executor import ProcessExecutor

    class _Real(ProcessExecutor):
        def run(self, *args, **kwargs):  # pragma: no cover - never invoked
            raise AssertionError("the seal probe must not run anything")

    monkeypatch.setattr(activation, "build_process_executor", lambda *a, **k: _Real())
    observations = {item.name: item for item in derive_seals()}
    assert observations["generic_activation_subprocess_sealed"].state is SealState.unsealed


def test_the_plan_only_gate_fails_when_it_stops_refusing(monkeypatch):
    from secp_worker.plan_gen import process_boundary

    monkeypatch.setattr(process_boundary, "issue_plan_only_executor", lambda **kwargs: object())
    observations = {item.name: item for item in derive_seals()}
    assert observations["plan_only_process_gated"].state is SealState.unsealed


def test_a_derivation_that_cannot_run_is_undetermined_never_sealed(monkeypatch):
    """The most important red case: a BROKEN derivation must not read as a passing seal."""
    from secp_worker.provisioning import process_executor

    def _explode(*args, **kwargs):
        raise RuntimeError("the surface could not be exercised")

    monkeypatch.setattr(process_executor, "SubprocessProcessExecutor", _explode)
    observations = {item.name: item for item in derive_seals()}
    seal = observations["generic_executor_subprocess_sealed"]
    assert seal.state is SealState.undetermined
    assert seal.holds is False
    assert all_sealed(tuple(observations.values())) is False
    # The detail names the failure TYPE and never its message — a probe payload carries no raw
    # error text.
    assert "RuntimeError" in seal.detail
    assert "could not be exercised" not in seal.detail


# --- apply history: a fact about the record, not a claim about capability ---------


def test_no_apply_recorded_reads_as_absent(session):
    seal = observe_apply_history(session)
    assert seal.state is SealState.sealed
    assert "nothing has been observed executing" in seal.detail


def test_an_executed_range_operation_makes_the_apply_history_seal_fail(session, principal):
    """The seal tracks HISTORY, so making history must move it.

    An operation that left ``pending`` means a worker picked it up. That is the observable the
    hold point needs — "no apply has occurred" — and it is checkable rather than asserted.
    """
    from secp_api.range_enums import RangeOperationKind, RangeOperationStatus
    from secp_api.services import ranges
    from test_proxmox_http_surface import make_range

    instance = make_range(session, principal)
    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.deploy
    )
    session.flush()
    assert observe_apply_history(session).state is SealState.sealed, (
        "a PENDING operation has applied nothing; counting it would make an unconsumed queue look "
        "like an executed one"
    )

    operation.status = RangeOperationStatus.succeeded
    session.flush()
    seal = observe_apply_history(session)
    assert seal.state is SealState.unsealed
    assert "an apply has occurred" in seal.detail


def test_an_unreadable_record_is_undetermined_not_absent(monkeypatch):
    """ "We could not look" must never render as "it did not happen"."""

    class _Broken:
        def execute(self, *args, **kwargs):
            raise RuntimeError("no database")

    seal = observe_apply_history(_Broken())
    assert seal.state is SealState.undetermined
    assert seal.holds is False
    assert "is unknown" in seal.detail


# --- the capability is reported honestly and is NOT a seal ------------------------


def test_the_provisioning_capability_is_reported_as_present_and_gated():
    """The replaced flag said the capability was absent. It has not been absent since #105."""
    assert PROVISIONING_CAPABILITY["state"] == "present_and_gated"
    detail = PROVISIONING_CAPABILITY["detail"]
    for shipped in ("apply authorization", "destroy authorization", "residue proof"):
        assert shipped in detail
    # And it is not in the seal set: a capability being present is not a safety failure.
    assert "provisioning" not in {item.name for item in derive_seals()}


def test_no_seal_name_claims_provisioning_is_disabled():
    """The specific false claim, and anything shaped like it, must not come back."""
    names = {item.name for item in derive_seals()} | {"apply_execution_absent"}
    for banned in ("real_provisioning_disabled", "provisioning_disabled", "provisioning_absent"):
        assert banned not in names


def test_the_seal_probe_runs_nothing_and_reaches_nothing():
    """Checked on the parsed imports, not on the source text."""
    import ast

    import secp_worker.safety_seal_probe as module

    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    roots = {name.split(".")[0] for name in imported}
    assert not (roots & {"subprocess", "socket", "os", "shutil", "httpx", "requests"}), roots
