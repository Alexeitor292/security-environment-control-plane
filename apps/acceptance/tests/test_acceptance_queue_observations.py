"""The six queues-stage producers: what each one concludes, and what it refuses to conclude.

Every test here is written against the failure an adversarial reviewer would look for, not against
the happy path. Three shapes recur, and they are the ones worth understanding before editing:

**Discrimination.** A probe that cannot tell two situations apart is worthless no matter how green
it is. :func:`test_the_poller_probe_answers_per_queue_and_is_keyed_to_no_name` is the hermetic half
of the container tier's swap control: the same function, called with two different queue names,
must return the two different answers the seam gave for them.

**Vacuity.** Several of these checks succeed on "nothing found", which is the outcome a broken query
also produces. Each one therefore has a control, and each control has a test that the control can
FAIL — ``operator_queues_probed == 0``, a visibility query that returns nothing for the ordinary
queue either, an ordinary poller with no worker identity to bind to.

**Direction.** ``violated`` and ``unprovable`` are never interchangeable. Tests are paired so that
the same producer is shown returning each of them for the situation that genuinely warrants it: a
server that ANSWERED and reported something bad is a violation; a server that could not be reached
is an outage. A producer that returned the same value for both would pass a one-sided test.
"""

from __future__ import annotations

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.queues import (
    MAX_POLLERS,
    ROLE_OPERATOR_MANAGEMENT,
    ROLE_OPERATOR_PROFILE,
    ROLE_ORDINARY,
    VERDICT_HELD,
    VERDICT_UNPROVABLE,
    VERDICT_VIOLATED,
    PollerObservation,
    management_operator_queue_name,
    observe_pollers,
    ordinary_queue_name,
    resolve_operator_executions,
    resolve_operator_isolation,
    resolve_operator_queues,
    resolve_operator_unit_dormant,
    resolve_ordinary_execution,
    resolve_ordinary_poller,
    resolve_self_reported_queues,
)

WORKER_IDENTITY = "41@secp-ordinary-worker"

#: Every systemd state value the product's classifiers in ``host_adapters`` recognise. Used by the
#: guard that the harness holds no copy of that table, and pinned against the product itself so the
#: guard cannot shrink silently.
_SYSTEMD_STATE_VALUES: tuple[str, ...] = (
    "loaded",
    "not-found",
    "masked",
    "bad-setting",
    "error",
    "active",
    "inactive",
    "failed",
    "deactivating",
    "activating",
    "enabled",
    "enabled-runtime",
    "alias",
    "indirect",
    "disabled",
    "linked",
    "generated",
    "transient",
    "static",
)


def _executable_body(func: object) -> str:
    """A function's source with its DOCSTRING removed.

    Several guards below assert that a function does not restate a constant. Those functions
    explain in prose exactly which constant they are avoiding and why — so asserting over the raw
    source would make each one fail for documenting itself, and the cheapest way to satisfy it
    would be to delete the explanation. Stripping the docstring keeps the guard pointed at the
    code.
    """
    import inspect

    source = inspect.getsource(func)  # type: ignore[arg-type]
    doc = inspect.getdoc(func)
    if not doc:
        return source
    # Match on the first and last lines of the docstring rather than on the reflowed `getdoc`
    # text, which has been dedented and cannot be found verbatim in the source.
    lines = source.splitlines()
    opened = closed = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if opened is None:
            if stripped.startswith(('"""', "'''")):
                opened = index
                if len(stripped) > 3 and stripped.endswith(('"""', "'''")):
                    closed = index
                    break
        elif stripped.endswith(('"""', "'''")):
            closed = index
            break
    if opened is None or closed is None:
        return source
    return "\n".join(lines[:opened] + lines[closed + 1 :])


def test_the_docstring_stripper_actually_strips():
    """CONTROL for the helper above. A stripper that returned the source unchanged would make every
    guard that uses it pass vacuously — the guards assert that text is ABSENT."""
    from secp_acceptance import queues

    assert "activation_probe" in __import__("inspect").getsource(queues.ordinary_queue_name)
    assert "activation_probe" not in _executable_body(queues.ordinary_queue_name)
    # ...and it must not eat the body along with the docstring
    assert "worker_ordinary_task_queue" in _executable_body(queues.ordinary_queue_name)


def _answer(*pollers: str) -> dict:
    return {"answered": True, "pollers": list(pollers)}


def _unanswered(cause: str = "acceptance_observation_unavailable") -> dict:
    return {"answered": False, "cause": cause}


def _operator(role: str, *pollers: str) -> PollerObservation:
    return observe_pollers(f"queue-for-{role}", role, _answer(*pollers))


# --------------------------------------------------------------------------- the queue identities


def test_the_ordinary_queue_name_is_the_one_the_shipped_worker_is_constructed_on():
    """Bound to the ``Settings`` field default the worker entrypoint hands ``Worker(task_queue=)``,
    not to a second copy of the same string."""
    from secp_operator_deployment.identities import worker_ordinary_task_queue

    assert ordinary_queue_name() == worker_ordinary_task_queue()


def test_the_ordinary_queue_authority_is_not_the_activation_probes_copy():
    """There are two constants holding this string. The harness must follow the one the worker
    polls, so that a change to the worker moves this rather than having to be remembered.

    Their values agree today, which is exactly why the SOURCE of the binding is what is asserted —
    an equality test between the two constants would pass either way.

    The DOCSTRING is stripped before the assertion, because it names the rejected constant on
    purpose. Asserting over the prose would make the test fail for explaining itself, and the fix
    for that would be to delete the explanation.
    """
    from secp_acceptance import queues

    body = _executable_body(queues.ordinary_queue_name)
    assert "worker_ordinary_task_queue" in body
    assert "activation_probe" not in body


def test_the_management_operator_queue_name_is_imported_from_the_product():
    """It is a PRODUCT constant, not a test fixture: ``real_adapters._observe_queue_containment``
    tests the worker's self-report against exactly this name, so it must have zero pollers for that
    probe's ``contained`` verdict to mean anything."""
    from secp_management.topology import OPERATOR_TASK_QUEUE

    assert management_operator_queue_name() == OPERATOR_TASK_QUEUE


class _Profile:
    def __init__(self, value: object) -> None:
        self._value = value

    def operator_task_queue(self) -> str:
        if isinstance(self._value, Exception):
            raise self._value
        return self._value  # type: ignore[return-value]


def test_the_operator_queue_union_covers_both_owning_planes():
    queues, degradation = resolve_operator_queues(
        ordinary=ordinary_queue_name(), profile_reader=_Profile("secp-operator-acc")
    )
    assert set(queues) == {ROLE_OPERATOR_MANAGEMENT, ROLE_OPERATOR_PROFILE}
    assert queues[ROLE_OPERATOR_PROFILE] == "secp-operator-acc"
    assert degradation is None


def test_an_unreadable_profile_narrows_the_union_and_SAYS_so():
    """The degradation must be reported, not absorbed. A narrower proof wearing the same green as a
    complete one is the substitution this whole harness exists to refuse."""
    queues, degradation = resolve_operator_queues(
        ordinary=ordinary_queue_name(),
        profile_reader=_Profile(AcceptanceError("acceptance_observation_unavailable")),
    )
    assert set(queues) == {ROLE_OPERATOR_MANAGEMENT}
    assert degradation == "acceptance_observation_unavailable"


def test_an_absent_profile_reader_is_a_degradation_not_a_silent_narrowing():
    _, degradation = resolve_operator_queues(ordinary=ordinary_queue_name(), profile_reader=None)
    assert degradation is not None


@pytest.mark.parametrize("value", ["", None, 7])
def test_a_malformed_profile_queue_is_a_degradation(value: object):
    _, degradation = resolve_operator_queues(
        ordinary=ordinary_queue_name(), profile_reader=_Profile(value)
    )
    assert degradation == "acceptance_observation_malformed"


def test_an_operator_queue_equal_to_the_ordinary_queue_is_dropped_not_probed():
    """ "Zero pollers on the operator queue" is not a well-posed question when that queue IS the one
    the worker polls. Dropping it fails toward an EMPTY union, which is unprovable — whereas probing
    it would report zero pollers for a shared queue and read as isolation."""
    queues, _ = resolve_operator_queues(
        ordinary=ordinary_queue_name(), profile_reader=_Profile(ordinary_queue_name())
    )
    assert ROLE_OPERATOR_PROFILE not in queues


# --------------------------------------------------------------------------- the poller probe


def test_the_poller_probe_answers_per_queue_and_is_keyed_to_no_name():
    """THE discrimination property, hermetic half. One function, two queue names, two answers.

    The container tier runs the same comparison against a LIVE server with the two arguments
    swapped. Here the seam is explicit, so the assertion is that the function reports what the seam
    said FOR THAT QUEUE — a probe keyed to a name, or one that always answered empty, fails.
    """
    seam = {"queue-a": _answer(WORKER_IDENTITY), "queue-b": _answer()}
    a = observe_pollers("queue-a", ROLE_ORDINARY, seam["queue-a"])
    b = observe_pollers("queue-b", ROLE_OPERATOR_MANAGEMENT, seam["queue-b"])

    assert a.poller_count == 1 and b.poller_count == 0
    assert a.queue_digest != b.queue_digest
    # ...and the same call with the arguments SWAPPED follows the argument, not the call site
    swapped_a = observe_pollers("queue-b", ROLE_ORDINARY, seam["queue-b"])
    swapped_b = observe_pollers("queue-a", ROLE_OPERATOR_MANAGEMENT, seam["queue-a"])
    assert swapped_a.poller_count == 0 and swapped_b.poller_count == 1


def test_the_probe_never_puts_a_queue_name_in_its_projection():
    """This is the module most tempted to print a queue name into an evidence document."""
    projection = observe_pollers("secp-some-queue", ROLE_ORDINARY, _answer(WORKER_IDENTITY))
    rendered = repr(projection.projection())
    assert "secp-some-queue" not in rendered
    assert WORKER_IDENTITY not in rendered


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "not a mapping",
        {"answered": True},  # no pollers key
        {"answered": True, "pollers": "one-string"},
        {"answered": True, "pollers": [""]},
        {"answered": True, "pollers": [123]},
        {"answered": True, "pollers": ["x" * 500]},
        {"answered": True, "pollers": ["p"] * (MAX_POLLERS + 1)},
    ],
)
def test_a_malformed_answer_is_never_read_as_zero_pollers(raw: object):
    """The two outcomes it would be most damaging to confuse: safety, and silence."""
    observed = observe_pollers("q", ROLE_OPERATOR_MANAGEMENT, raw)
    assert observed.answered is False
    assert observed.cause == "acceptance_observation_malformed"


def test_an_unanswered_probe_keeps_its_own_bounded_cause():
    observed = observe_pollers(
        "q", ROLE_OPERATOR_MANAGEMENT, _unanswered("acceptance_host_command_timeout")
    )
    assert observed.answered is False
    assert observed.cause == "acceptance_host_command_timeout"


def test_a_cause_outside_the_vocabulary_is_replaced_not_carried():
    observed = observe_pollers("q", ROLE_ORDINARY, {"answered": False, "cause": "made_up"})
    assert observed.cause == "acceptance_observation_unavailable"


# --------------------------------------------------------------------------- the ordinary queue


def test_the_ordinary_queue_holds_when_the_worker_itself_is_the_poller():
    verdict = resolve_ordinary_poller(
        observe_pollers("ordinary", ROLE_ORDINARY, _answer(WORKER_IDENTITY, "other")),
        worker_identities=[WORKER_IDENTITY],
    )
    assert verdict.verdict == VERDICT_HELD
    assert verdict.observation["matched_worker_pollers"] == 1


def test_a_poller_that_is_not_the_worker_does_not_satisfy_the_ordinary_check():
    """Without the identity binding this check would pass for any poller at all, including one
    belonging to something the acceptance never installed."""
    verdict = resolve_ordinary_poller(
        observe_pollers("ordinary", ROLE_ORDINARY, _answer("999@somewhere-else")),
        worker_identities=[WORKER_IDENTITY],
    )
    assert verdict.verdict == VERDICT_VIOLATED


def test_no_poller_at_all_is_a_violation_not_an_outage():
    """The server ANSWERED. Zero pollers on the ordinary queue is an observation of a bad state, and
    recording it as ``unprovable`` would file a broken deployment as a transport problem."""
    verdict = resolve_ordinary_poller(
        observe_pollers("ordinary", ROLE_ORDINARY, _answer()), worker_identities=[WORKER_IDENTITY]
    )
    assert verdict.verdict == VERDICT_VIOLATED


def test_an_unreachable_server_is_an_outage_not_a_violation():
    """The paired direction test. Same producer, opposite classification."""
    verdict = resolve_ordinary_poller(
        observe_pollers("ordinary", ROLE_ORDINARY, _unanswered()),
        worker_identities=[WORKER_IDENTITY],
    )
    assert verdict.verdict == VERDICT_UNPROVABLE


def test_a_poller_count_with_nothing_to_bind_to_refuses_rather_than_passing():
    """VACUITY control. With no worker identity supplied, a count alone would pass for a poller that
    is not the worker — so the weaker fact must not be accepted under the stronger check's name."""
    verdict = resolve_ordinary_poller(
        observe_pollers("ordinary", ROLE_ORDINARY, _answer(WORKER_IDENTITY)), worker_identities=[]
    )
    assert verdict.verdict == VERDICT_UNPROVABLE
    assert verdict.cause == "acceptance_proof_would_be_vacuous"


# --------------------------------------------------------------------------- operator isolation


def test_isolation_holds_only_when_every_operator_queue_was_asked_and_answered_zero():
    verdict = resolve_operator_isolation(
        [_operator(ROLE_OPERATOR_MANAGEMENT), _operator(ROLE_OPERATOR_PROFILE)]
    )
    assert verdict.verdict == VERDICT_HELD
    assert verdict.observation["operator_queues_probed"] == 2


def test_a_poller_on_an_operator_queue_is_a_violation():
    """The mutation that answers "would this stay green if the worker really did poll?" — no."""
    verdict = resolve_operator_isolation(
        [
            _operator(ROLE_OPERATOR_MANAGEMENT, WORKER_IDENTITY),
            _operator(ROLE_OPERATOR_PROFILE),
        ]
    )
    assert verdict.verdict == VERDICT_VIOLATED
    assert verdict.observation["roles_with_pollers"] == (ROLE_OPERATOR_MANAGEMENT,)


def test_an_observed_violation_outranks_an_unanswered_probe_elsewhere():
    """A run that SAW a poller and could not reach another queue has observed a violation. Reporting
    that as merely "unprovable" would bury the finding under the outage."""
    verdict = resolve_operator_isolation(
        [
            _operator(ROLE_OPERATOR_MANAGEMENT, WORKER_IDENTITY),
            observe_pollers("p", ROLE_OPERATOR_PROFILE, _unanswered()),
        ]
    )
    assert verdict.verdict == VERDICT_VIOLATED


def test_one_unanswered_operator_queue_prevents_isolation_from_holding():
    verdict = resolve_operator_isolation(
        [
            _operator(ROLE_OPERATOR_MANAGEMENT),
            observe_pollers("p", ROLE_OPERATOR_PROFILE, _unanswered()),
        ]
    )
    assert verdict.verdict == VERDICT_UNPROVABLE
    assert verdict.observation["roles_unanswered"] == (ROLE_OPERATOR_PROFILE,)


def test_probing_no_operator_queue_at_all_is_unprovable_not_isolated():
    """THE vacuity hole for this check. "No operator queue had a poller" is trivially true of a run
    that probed nothing, and that must never read as isolation."""
    verdict = resolve_operator_isolation([])
    assert verdict.verdict == VERDICT_UNPROVABLE
    assert verdict.cause == "acceptance_proof_would_be_vacuous"


# --------------------------------------------------------------------------- ordinary execution


def _execution(**overrides: object) -> dict:
    base = {
        "answered": True,
        "task_queue": ordinary_queue_name(),
        "status": "COMPLETED",
        "task_completed_by": [WORKER_IDENTITY],
    }
    base.update(overrides)
    return base


def test_a_workflow_worked_by_the_ordinary_worker_holds():
    verdict = resolve_ordinary_execution(_execution(), expected_queue=ordinary_queue_name())
    assert verdict.verdict == VERDICT_HELD
    assert verdict.observation["ran_on_expected_queue"] is True


def test_a_sealed_refusal_still_proves_the_ordinary_worker_executed_it():
    """The claim is EXECUTION, not success. A workflow that reached a sealed refusal was still
    polled, dispatched and worked by the ordinary worker — and it is the contact-free outcome, so it
    is if anything the better proof."""
    verdict = resolve_ordinary_execution(
        _execution(status="FAILED"), expected_queue=ordinary_queue_name()
    )
    assert verdict.verdict == VERDICT_HELD


def test_a_workflow_that_ran_on_another_queue_is_a_violation():
    verdict = resolve_ordinary_execution(
        _execution(task_queue="somewhere-else"), expected_queue=ordinary_queue_name()
    )
    assert verdict.verdict == VERDICT_VIOLATED
    assert verdict.observation["ran_on_expected_queue"] is False


def test_a_workflow_no_worker_ever_worked_is_a_violation():
    """Submitted and sitting there is not execution. Without this the check would pass for a
    workflow that was merely accepted by the server."""
    verdict = resolve_ordinary_execution(
        _execution(task_completed_by=[]), expected_queue=ordinary_queue_name()
    )
    assert verdict.verdict == VERDICT_VIOLATED


def test_a_still_running_workflow_is_unprovable_not_violated():
    """Nothing has been observed about whether it finishes, so the honest verdict is an incomplete
    proof — not a finding against the product."""
    verdict = resolve_ordinary_execution(
        _execution(status="RUNNING"), expected_queue=ordinary_queue_name()
    )
    assert verdict.verdict == VERDICT_UNPROVABLE
    assert verdict.observation["status"] == "non_terminal"


@pytest.mark.parametrize(
    "raw", [None, "text", {"answered": True, "status": "COMPLETED"}, _execution(task_queue=5)]
)
def test_a_malformed_or_unreachable_history_is_unprovable(raw: object):
    verdict = resolve_ordinary_execution(raw, expected_queue=ordinary_queue_name())
    assert verdict.verdict == VERDICT_UNPROVABLE


# --------------------------------------------------------------------------- operator executions


def test_zero_operator_executions_holds_only_against_a_control_that_returned_rows():
    verdict = resolve_operator_executions(
        {"answered": True, "execution_count": 0},
        ordinary_control={"answered": True, "execution_count": 1},
    )
    assert verdict.verdict == VERDICT_HELD
    assert verdict.observation["control_can_return_rows"] is True


def test_zero_operator_executions_with_an_empty_control_proves_nothing():
    """THE vacuity control. A broken filter, a wrong namespace and real isolation all return zero
    rows; only a query that demonstrably CAN return rows tells them apart."""
    verdict = resolve_operator_executions(
        {"answered": True, "execution_count": 0},
        ordinary_control={"answered": True, "execution_count": 0},
    )
    assert verdict.verdict == VERDICT_UNPROVABLE
    assert verdict.cause == "acceptance_proof_would_be_vacuous"


def test_a_missing_control_proves_nothing_either():
    verdict = resolve_operator_executions({"answered": True, "execution_count": 0})
    assert verdict.verdict == VERDICT_UNPROVABLE


def test_any_execution_on_an_operator_queue_is_a_violation():
    verdict = resolve_operator_executions(
        {"answered": True, "execution_count": 1},
        ordinary_control={"answered": True, "execution_count": 1},
    )
    assert verdict.verdict == VERDICT_VIOLATED


def test_a_violation_does_not_need_the_control_to_be_believed():
    """A row that EXISTS is a positive observation. Requiring the control here would let a broken
    control suppress a real finding."""
    verdict = resolve_operator_executions(
        {"answered": True, "execution_count": 2}, ordinary_control={"answered": False}
    )
    assert verdict.verdict == VERDICT_VIOLATED


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {"answered": False, "cause": "acceptance_host_command_timeout"},
        {"answered": True, "execution_count": -1},
        {"answered": True, "execution_count": True},
        {"answered": True, "execution_count": "many"},
    ],
)
def test_an_unusable_visibility_answer_is_unprovable(raw: object):
    verdict = resolve_operator_executions(
        raw, ordinary_control={"answered": True, "execution_count": 1}
    )
    assert verdict.verdict == VERDICT_UNPROVABLE


# --------------------------------------------------------------------------- the operator unit

#: The canonical prepared posture: loaded, inactive, STATIC (the shipped unit is rendered with no
#: ``[Install]`` section, so systemd reports ``static`` and NOT ``disabled``), never started.
DORMANT = {
    "LoadState": "loaded",
    "ActiveState": "inactive",
    "UnitFileState": "static",
    "InvocationID": "",
    "StateChangeTimestampMonotonic": "5150123",
    "NRestarts": "0",
}


def test_the_canonical_prepared_operator_unit_is_dormant():
    """The posture a correct install actually produces. If this failed, the check would be demanding
    a state the product never reaches — which is how a harness manufactures a false breach."""
    verdict = resolve_operator_unit_dormant(DORMANT, DORMANT)
    assert verdict.verdict == VERDICT_HELD
    assert verdict.observation["invocation_id_empty"] is True


def test_a_disabled_unit_file_state_is_also_dormant():
    """``static`` and ``disabled`` both mean "will not auto-start". The classification is the
    product's, not this harness's, so both must be accepted."""
    verdict = resolve_operator_unit_dormant(
        {**DORMANT, "UnitFileState": "disabled"}, {**DORMANT, "UnitFileState": "disabled"}
    )
    assert verdict.verdict == VERDICT_HELD


def test_the_dormancy_check_uses_the_products_classifiers_not_its_own_table():
    """Restating the table would have been wrong, not merely duplicative: a harness checking for
    ``UnitFileState == "disabled"`` fails a correctly prepared host, because the shipped unit is
    ``static``."""
    from secp_acceptance import queues

    body = _executable_body(queues._product_unit_classifiers)
    assert "host_adapters" in body
    # Quoted literals, not substrings: ``_classify_active`` legitimately contains "active" in its
    # NAME. What must not appear is a systemd state VALUE written as a string here.
    for literal in _SYSTEMD_STATE_VALUES:
        assert f'"{literal}"' not in body and f"'{literal}'" not in body, (
            f"{literal!r} is written as a literal in the classifier binding. The product's "
            f"table is the authority; a copy here is how a harness ends up demanding a state "
            f"the product never reaches."
        )


def test_the_classifier_guard_is_looking_for_values_the_product_actually_uses():
    """NON-VACUITY for the guard above. It succeeds on "not found", so it is worth exactly the
    value list it was evaluated over — a typo'd list would make it pass against anything.

    Checked against the product's own classifiers, so a renamed or removed systemd state fails here
    rather than quietly shrinking what the guard covers.
    """
    import inspect

    from secp_operator_deployment import host_adapters

    source = inspect.getsource(host_adapters)
    for literal in _SYSTEMD_STATE_VALUES:
        assert f'"{literal}"' in source, (
            f"{literal!r} is in this file's list of systemd states but the product's classifiers "
            f"no longer mention it; the guard above is covering a value that does not exist."
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"UnitFileState": "enabled"},
        {"ActiveState": "active"},
        {"InvocationID": "0" * 32},
        {"NRestarts": "1"},
    ],
)
def test_any_sign_the_operator_unit_ran_or_will_run_is_a_violation(mutation: dict):
    """Four independent tells, each fatal on its own. An empty ``InvocationID`` is the positive
    statement that the unit has never run; a populated one says it has."""
    reading = {**DORMANT, **mutation}
    verdict = resolve_operator_unit_dormant(reading, reading)
    assert verdict.verdict == VERDICT_VIOLATED
    assert verdict.cause == "worker_operator_not_disabled_stopped"


def test_a_unit_that_moved_during_the_stage_cannot_be_certified():
    """The reason this takes TWO readings. A single snapshot is satisfied by a unit that was started
    and stopped again while the queue stage ran — exactly the window this check covers."""
    verdict = resolve_operator_unit_dormant(
        DORMANT, {**DORMANT, "StateChangeTimestampMonotonic": "9999999"}
    )
    assert verdict.verdict != VERDICT_HELD


def test_an_absent_operator_unit_is_unprovable_not_dormant():
    """Trivially dormant, but this check's claim is about the PACKAGED unit. If it is not installed
    the run has a different problem and this proof must not absorb it."""
    reading = {**DORMANT, "LoadState": "not-found"}
    verdict = resolve_operator_unit_dormant(reading, reading)
    assert verdict.verdict == VERDICT_UNPROVABLE


def test_an_unrecognised_systemd_state_is_never_guessed_at():
    """The product's classifiers return ``None`` for an unknown value precisely so it is not
    assumed either way, and neither is it here."""
    reading = {**DORMANT, "ActiveState": "reloading-but-different"}
    verdict = resolve_operator_unit_dormant(reading, reading)
    assert verdict.verdict == VERDICT_UNPROVABLE


@pytest.mark.parametrize("missing", sorted(DORMANT))
def test_an_incomplete_systemd_reading_is_unprovable(missing: str):
    reading = {k: v for k, v in DORMANT.items() if k != missing}
    verdict = resolve_operator_unit_dormant(reading, DORMANT)
    assert verdict.verdict == VERDICT_UNPROVABLE


# --------------------------------------------------------------------------- the self-report


def test_the_containment_verdict_passes_through_untranslated():
    """The management plane already answers in this vocabulary, so there is nothing to map — which
    is the point of binding the harness vocabulary to the product's constants."""
    from secp_management.adapters import (
        CONTAINMENT_BREACHED,
        CONTAINMENT_CONTAINED,
        CONTAINMENT_UNPROVABLE,
    )

    assert (
        resolve_self_reported_queues({"containment": CONTAINMENT_CONTAINED}).verdict == VERDICT_HELD
    )
    assert (
        resolve_self_reported_queues({"containment": CONTAINMENT_BREACHED}).verdict
        == VERDICT_VIOLATED
    )
    assert (
        resolve_self_reported_queues(
            {
                "containment": CONTAINMENT_UNPROVABLE,
                "containment_reason": "queue_probe_command_failed",
            }
        ).verdict
        == VERDICT_UNPROVABLE
    )


@pytest.mark.parametrize("cause", ["queue_probe_command_failed", "queue_probe_runtime_unavailable"])
def test_the_two_containment_causes_stay_distinguishable(cause: str):
    """They have different remediations: a probe that RAN and exited non-zero is not a runtime that
    could not be invoked at all."""
    verdict = resolve_self_reported_queues(
        {"containment": VERDICT_UNPROVABLE, "containment_reason": cause}
    )
    assert verdict.cause == cause


def test_the_three_containment_verdicts_produce_three_different_harness_verdicts():
    """ANTI-COLLAPSE, at the seam where the product's three values enter the harness."""
    verdicts = {
        resolve_self_reported_queues(
            {"containment": value, "containment_reason": "queue_probe_command_failed"}
        ).verdict
        for value in (VERDICT_HELD, VERDICT_VIOLATED, VERDICT_UNPROVABLE)
    }
    assert len(verdicts) == 3


@pytest.mark.parametrize("raw", [None, "text", {}, {"containment": "sort-of-fine"}])
def test_an_unreadable_containment_answer_is_unprovable(raw: object):
    assert resolve_self_reported_queues(raw).verdict == VERDICT_UNPROVABLE
