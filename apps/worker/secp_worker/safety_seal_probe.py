"""Safety seals, DERIVED BY EXERCISE rather than read from constants. Worker-local.

WHAT WAS WRONG
---------------
``activation_probe._default_seals`` read four module-level booleans and published them as
``safety_seals`` in the activation evidence payload::

    "generic_activation_subprocess_sealed": activation._B1A_SUBPROCESS_SEALED,
    "generic_executor_subprocess_sealed":   process_executor._B1A_SUBPROCESS_SEALED,
    "plan_only_process_sealed":             process_boundary._PLAN_ONLY_PROCESS_SEALED,
    "real_provisioning_disabled":           not providers.PROVISIONING_ENABLED,

Two things are wrong with that, and the second is worse than the first.

**A constant is a restatement, not evidence.** Each of those booleans is a claim ABOUT code
elsewhere. Nothing checks that the code still behaves the way the boolean says. Delete the guard
inside ``SubprocessProcessExecutor.__init__`` and every seal still reports ``true`` — the evidence
payload would assert the executor is sealed while it constructs freely. The seal detects one thing
only: somebody editing the constant itself, which is the change least likely to happen by accident.

**``real_provisioning_disabled`` was simply false.** It reported ``true`` while #105-#110 shipped
desired-state compilation, plan generation, apply authorization, observed verification, destroy
authorization and the residue proof. It had been false for six merges. And it is not a boolean
question: it conflates *"the capability is absent"* with *"the capability exists and is gated"*, and
only the second has been true for some time. One word, two meanings.

WHAT THIS DOES INSTEAD
-----------------------
Every seal here is derived by EXERCISING the surface it describes with the most permissive input
available, and observing the refusal:

* the generic subprocess executor is *constructed* — with ``armed=True``, directly — and the seal
  holds only if that raises;
* the activation path is asked to build an executor while holding a VALID activation grant, and the
  seal holds only if what comes back is the fake;
* the plan-only executor is asked for without a capability, and the gate holds only if it refuses.

A derivation that cannot be performed reports :attr:`SealState.undetermined`, never ``sealed``.
Unknown is not permission, and a seal that cannot be re-derived is unknown.

Exercising these is safe by construction: every call is expected to REFUSE, and the fake executor
that a permissive activation call returns runs nothing. Nothing here spawns a process, opens a
socket, or reaches a provider — which is the same property the probe as a whole is required to have.

WHAT REPLACED THE FALSE SEAL
-----------------------------
``real_provisioning_disabled`` is gone and is not renamed to something equally declarative. It is
replaced by the two facts underneath it that can actually be observed, kept separate because they
answer different questions:

``apply_execution_absent``    a fact about HISTORY. Has an apply ever been recorded for this
                              deployment? That is what a hold point needs — "no apply has occurred"
                              — and it is observable from the durable record rather than asserted.
``provisioning_capability``   a fact about CODE. The capability exists and is gated; saying it is
                              absent stopped being true at #105. Reported for context, and
                              deliberately NOT a seal, because a capability being present is not a
                              safety failure — executing it without authorization would be.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SealState(str, Enum):
    """Whether a seal was re-derived, and what happened when it was.

    Three values, and ``undetermined`` is the one that makes the other two mean something: a seal
    that could not be exercised is not sealed. Reporting it as sealed is how a broken derivation
    becomes a safety claim.
    """

    #: Exercised, and the surface refused. The seal holds.
    sealed = "sealed"
    #: Exercised, and the surface did NOT refuse. The seal does not hold.
    unsealed = "unsealed"
    #: The derivation could not be performed at all. NOT sealed and not unsealed.
    undetermined = "undetermined"


@dataclass(frozen=True)
class SealObservation:
    """One seal, its state, and how that state was reached."""

    name: str
    state: SealState
    #: What was exercised and what happened. Never an exception's text — a probe payload carries no
    #: raw error strings — but enough to tell a reviewer which surface was tried.
    detail: str

    @property
    def holds(self) -> bool:
        return self.state is SealState.sealed


def _observe(name: str, detail_sealed: str, probe) -> SealObservation:
    """Run one derivation. Any unexpected failure is ``undetermined``, never ``sealed``.

    ``probe`` returns True when the surface REFUSED (the seal holds). It may raise; a raise is a
    derivation that did not complete, which is exactly the case that must not be reported as a
    passing seal.
    """
    try:
        refused = bool(probe())
    except Exception as exc:  # noqa: BLE001 - the type is reported, never the message
        return SealObservation(
            name=name,
            state=SealState.undetermined,
            detail=(
                f"the derivation could not be completed ({type(exc).__name__}); the seal is "
                "unknown rather than held"
            ),
        )
    if refused:
        return SealObservation(name=name, state=SealState.sealed, detail=detail_sealed)
    return SealObservation(
        name=name,
        state=SealState.unsealed,
        detail="the surface was exercised and did not refuse",
    )


def _generic_executor_sealed() -> bool:
    """Construct the real subprocess executor. The seal holds only if construction RAISES.

    ``armed=True`` and constructed directly, which is the most permissive call available: the seal
    is documented as non-bypassable "even with armed=True, even directly", so that is what is
    tested. Constructing nothing is the point — a successful construction is the failure.
    """
    from secp_worker.provisioning.process_executor import (
        ProcessExecutionError,
        SubprocessProcessExecutor,
    )

    try:
        SubprocessProcessExecutor(armed=True)
    except ProcessExecutionError:
        return True
    return False


def _activation_path_sealed() -> bool:
    """Ask the activation path for an executor while holding a VALID grant.

    A grant is minted through the real ``grant_real_lab_activation`` with ``gate_passed=True`` —
    the strongest input a caller can present. The seal holds only if what comes back is the FAKE
    executor. Minting a grant performs no I/O and the fake executor runs nothing.
    """
    from secp_api.config import get_settings

    from secp_worker.provisioning.activation import (
        build_process_executor,
        grant_real_lab_activation,
    )
    from secp_worker.provisioning.process_executor import FakeProcessExecutor

    grant = grant_real_lab_activation(manifest_id="seal-probe", gate_passed=True)
    executor = build_process_executor(get_settings(), grant=grant)
    return isinstance(executor, FakeProcessExecutor)


def _plan_only_gate_holds() -> bool:
    """The plan-only executor must refuse to be issued without a controlled-live capability.

    This one is deliberately NOT a "sealed constant" question. ``_PLAN_ONLY_PROCESS_SEALED`` is
    ``False`` by design — the reviewed PR5B activation flipped it so the plan-only executor can be
    constructed on the production path — so reading the constant says nothing useful. What matters
    is that the GATE in front of it still refuses an unauthorized issue, and that is what is
    exercised.
    """
    from secp_worker.plan_gen.process_boundary import issue_plan_only_executor

    try:
        # No context at all: the weakest possible caller. ``PlanOnlyProcessExecutor.__init__``
        # independently re-verifies an exact context carrying a mandatory ``controlled_live``
        # capability, so a bare issue must refuse.
        issue_plan_only_executor(context=None)
    except Exception:
        return True
    return False


#: The seal names, defined ONCE, here, next to the code that produces them.
#:
#: The probe's validator and the deployment package's payload parser each used to carry their own
#: hardcoded copy of this set — two restatements of one fact in two packages, free to drift apart.
#: They had not drifted only because nobody had changed them yet. Importing this module is inert
#: (every worker import below is function-local), so a consumer can share the vocabulary without
#: pulling in anything that executes.
#:
#: A SECOND, DELIBERATE READER OF THIS REGION EXISTS AND IT IS NOT THIS ONE.
#: ``secp_operator_deployment/verify.py:336-355`` (``_read_seals``) asks a DIFFERENT question about
#: the same surfaces: it reads the module constants (``_OPERATOR_ACTIVATION_SEALED``,
#: ``_PLAN_ONLY_PROCESS_SEALED``, and two ``_B1A_SUBPROCESS_SEALED``) and folds them into one
#: ``seals_correct`` boolean for ``verify``'s prerequisite-F rung. This module instead EXERCISES
#: each surface — it constructs an armed executor and requires a refusal — and reports a per-seal
#: state. A constant can say "sealed" while the code path it is supposed to close still runs, and
#: that disagreement is only visible because the two do not share an implementation. Keep both.
#:
#: They also do not share a vocabulary, and the overlap is a trap rather than a convenience:
#: ``verify.py:350`` names the plan-only fact ``plan_only_process_sealed`` and requires it to be
#: **False**, while this module names it ``plan_only_process_gated`` and requires it to be
#: **sealed**. Same region, near-identical spelling, opposite polarity, different question. Neither
#: is a rename of the other and neither may be mapped onto the other.
REQUIRED_SEAL_NAMES: frozenset[str] = frozenset(
    {
        "generic_activation_subprocess_sealed",
        "generic_executor_subprocess_sealed",
        "plan_only_process_gated",
        # The fact the hold point actually needs: "no apply has occurred". It is in the REQUIRED
        # set rather than reported alongside it, because a posture that does not include it would
        # be a posture about code alone — and the question being asked is about this deployment.
        "apply_execution_absent",
    }
)


def derive_seals() -> tuple[SealObservation, ...]:
    """Re-derive every safety seal by exercising the surface it describes."""
    return (
        _observe(
            "generic_executor_subprocess_sealed",
            "SubprocessProcessExecutor(armed=True) was constructed directly and refused",
            _generic_executor_sealed,
        ),
        _observe(
            "generic_activation_subprocess_sealed",
            "build_process_executor returned the fake executor while holding a valid grant",
            _activation_path_sealed,
        ),
        _observe(
            "plan_only_process_gated",
            "issue_plan_only_executor refused without a controlled-live capability",
            _plan_only_gate_holds,
        ),
    )


def observe_apply_history(session) -> SealObservation:
    """Has an apply ever been OBSERVED executing in this deployment?

    This is what replaced ``real_provisioning_disabled``, and it is a different kind of statement.
    That flag claimed a capability was absent — a claim about code, which stopped being true at
    #105. This is a claim about HISTORY, which a hold point can actually use: *no apply has
    occurred* is checkable against the durable record, and it stays checkable as the capability
    grows.

    "Executing" means an operation left ``pending``: a worker picked it up. An operation that was
    enqueued and never claimed has not applied anything, and counting it would make an
    unconsumed queue look like an executed one.

    Both planes are counted. The range lifecycle and the provisioning plane can each reach a
    provider, and a seal that watched only one would be a seal over half the system.
    """
    try:
        from secp_api.models import ProvisioningOperation
        from secp_api.range_models import RangeDeploymentOperation
        from sqlalchemy import func, select

        ranges_executed = session.execute(
            select(func.count())
            .select_from(RangeDeploymentOperation)
            .where(RangeDeploymentOperation.status != "pending")
        ).scalar_one()
        provisioning_executed = session.execute(
            select(func.count())
            .select_from(ProvisioningOperation)
            .where(ProvisioningOperation.status != "queued")
        ).scalar_one()
    except Exception as exc:  # noqa: BLE001 - the type is reported, never the message
        return SealObservation(
            name="apply_execution_absent",
            state=SealState.undetermined,
            detail=(
                f"the durable record could not be read ({type(exc).__name__}); whether an apply "
                "has occurred is unknown, which is not the same as it not having occurred"
            ),
        )

    total = int(ranges_executed) + int(provisioning_executed)
    if total == 0:
        return SealObservation(
            name="apply_execution_absent",
            state=SealState.sealed,
            detail=(
                "no range deployment operation and no provisioning operation has ever left its "
                "queued state, so nothing has been observed executing against a provider"
            ),
        )
    return SealObservation(
        name="apply_execution_absent",
        state=SealState.unsealed,
        detail=(
            f"{ranges_executed} range operation(s) and {provisioning_executed} provisioning "
            "operation(s) have left their queued state; an apply has occurred in this deployment"
        ),
    )


#: What the provisioning capability actually is, reported for context and DELIBERATELY NOT A SEAL.
#:
#: A capability being present is not a safety failure — executing it without authorization would
#: be. Reporting "provisioning is absent" was the error; reporting "provisioning is present and
#: gated" is true, and the gates are the thing worth naming, so they are named.
PROVISIONING_CAPABILITY = {
    "state": "present_and_gated",
    "detail": (
        "desired-state compilation, plan generation, apply authorization, observed verification, "
        "reset authorization, destroy authorization and the residue proof all exist (#105-#110, "
        "SECP-P7-A). Each execution path is gated by an approval over its own hash domain; the "
        "gates are the safety property, not the absence of the capability."
    ),
}


def default_apply_history() -> SealObservation:
    """Open a short read-only session and observe the apply history.

    Its own session, opened and rolled back like every other reader in the probe: the probe holds
    no long-lived session and commits nothing. A session that cannot be opened is
    ``undetermined`` — :func:`observe_apply_history` already turns any failure into that, and
    "we could not look" must never render as "it did not happen".
    """
    try:
        from secp_api.db import get_sessionmaker
    except Exception as exc:  # noqa: BLE001 - the type is reported, never the message
        return SealObservation(
            name="apply_execution_absent",
            state=SealState.undetermined,
            detail=(
                f"the durable record could not be reached ({type(exc).__name__}); whether an "
                "apply has occurred is unknown"
            ),
        )
    factory = get_sessionmaker()
    with factory() as session:
        observation = observe_apply_history(session)
        session.rollback()
    return observation


def seal_payload(observations: tuple[SealObservation, ...]) -> dict[str, str]:
    """The seals as they appear in the evidence payload: name -> state, states not booleans.

    Strings rather than booleans because there are three states and a boolean carries two. The
    consumer folds them, and it treats anything that is not ``sealed`` as not sealed — so an
    ``undetermined`` seal fails the posture rather than passing it.
    """
    return {item.name: item.state.value for item in observations}


def all_sealed(observations: tuple[SealObservation, ...]) -> bool:
    """True only when every seal was exercised AND held. Empty is False, never vacuously true."""
    return bool(observations) and all(item.holds for item in observations)
