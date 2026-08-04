"""A residue sweep that could not look must never report a clean machine.

The hermetic contract of :mod:`secp_acceptance.residue`, pinned in ALL THREE directions. Two of them
are the reason the module exists; the third is the half a naive fix breaks.

WHY THIS FILE IS NOT A COPY OF ``test_acceptance_teardown_honesty.py``
---------------------------------------------------------------------
That file pins ``HostFleet.destroy`` — the REMOVER, which takes the names it created and deletes
them. This one pins the SWEEP — the auditor, which asks the machine what is still there and belongs
to this run. They fail differently: a broken remover leaves objects behind, while a broken sweep
leaves them behind AND says it did not. Both were built from the same finding, so both keep the same
control structure, and neither is allowed to be the other's copy.

THE MUTATION THAT MOTIVATES THE STRUCTURAL GUARD
------------------------------------------------
Rewriting ``sweep`` to ask ``docker inspect NAME`` instead of enumerating restores the original
defect: ``inspect`` fails identically for "the object is gone" and "the daemon is not there", so the
unreachable case silently reports clean again.

That rewrite was applied and measured rather than argued about. Against ``_Daemon`` as written it
fails 15 of 27 — but almost all of that is the fake REFUSING an unrecognised call, which is a
property of this file rather than of the module. Relax that one line to answer unknown calls the way
a live daemon answers a miss (a plausible future edit, and the state this file would be in if the
fake were ever made permissive) and 24 of 27 pass, with only three failures left:
:func:`test_the_sweep_never_asks_whether_a_named_object_exists`,
:func:`test_a_listing_that_times_out_is_not_an_empty_listing`, and the call-count assertion in
:func:`test_an_empty_listing_from_a_live_daemon_is_clean`.

So the structural guard is load-bearing in the way that matters: it asserts on the CALLS rather than
on the verdict, which is why it does not depend on the strictness of the fake to keep working.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.reasons import (
    HARNESS_REASONS,
    OUTCOME_OBSERVED,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
)
from secp_acceptance.residue import (
    KINDS,
    SWEEP_ARGV,
    VERDICT_CLEAN,
    VERDICT_RESIDUAL,
    VERDICT_UNOBSERVABLE,
    VERDICTS,
    ResidueReport,
    outcome_for,
    sweep,
)
from secp_acceptance.shell import Result

PREFIX = "secp-acc-abc123"


class _Daemon:
    """A configurable outer runtime, recording every call it was asked to make.

    ``alive`` controls the version probe; ``listings`` maps a kind to the names it reports; a kind
    absent from ``fails`` succeeds, a kind present in it fails the way a broken/incomplete
    enumeration does.
    """

    def __init__(
        self,
        *,
        alive: bool = True,
        listings: dict[str, list[str]] | None = None,
        fails: frozenset[str] = frozenset(),
    ) -> None:
        self.alive = alive
        self.listings = listings or {}
        self.fails = fails
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
        self.calls.append(args)
        if args[0] == "version":
            return Result(exit_code=0 if self.alive else 1, stdout="linux\n", stderr="")
        for kind, argv in SWEEP_ARGV:
            if args == argv:
                if kind in self.fails:
                    return Result(exit_code=1, stdout="", stderr="")
                return Result(exit_code=0, stdout="\n".join(self.listings.get(kind, [])), stderr="")
        raise AssertionError(f"the sweep made an unexpected call: {args}")


def _install(monkeypatch, daemon: _Daemon) -> _Daemon:
    monkeypatch.setattr("secp_acceptance.residue.docker", daemon)
    return daemon


# --------------------------------------------------------------------------- controls
#
# Every assertion below is worth exactly what these three are worth. Without them a sweep that
# returned one constant would satisfy most of this file.


def test_the_fake_daemon_can_produce_all_three_verdicts(monkeypatch):
    """CONTROL. The harness of this test file must be able to reach every outcome, or the
    individual assertions are each measuring an outcome nothing else could have produced."""
    seen = set()
    for daemon in (
        _Daemon(alive=False),
        _Daemon(listings={"container": [f"{PREFIX}-worker"]}),
        _Daemon(),
    ):
        _install(monkeypatch, daemon)
        seen.add(sweep(PREFIX).verdict)
    assert seen == VERDICTS


def test_the_prefix_filter_can_both_match_and_miss(monkeypatch):
    """CONTROL for every "is ignored" assertion below.

    A filter that never matched would make "objects that are not ours are ignored" vacuously true,
    and a filter that always matched would make the clean case unreachable. Same daemon, two
    prefixes, opposite answers — so the filter is doing the work.
    """
    _install(monkeypatch, _Daemon(listings={"container": [f"{PREFIX}-worker"]}))
    assert sweep(PREFIX).verdict == VERDICT_RESIDUAL
    assert sweep("secp-acc-different").verdict == VERDICT_CLEAN


def test_an_empty_prefix_refuses_rather_than_sweeping(monkeypatch):
    """An empty prefix matches every object on the machine, and a prefix nobody used makes the
    sweep vacuously clean forever. Neither is an answer."""
    _install(monkeypatch, _Daemon())
    with pytest.raises(AcceptanceError) as caught:
        sweep("")
    assert caught.value.reason_code == "acceptance_proof_would_be_vacuous"


# --------------------------------------------------------------------------- the three verdicts


def test_a_sweep_that_cannot_reach_the_runtime_is_unobservable(monkeypatch):
    """THE regression, in its own right. Not clean, and nameably so."""
    _install(monkeypatch, _Daemon(alive=False))

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_UNOBSERVABLE
    assert report.clean is False
    assert report.observed is False
    assert report.reason_code == "acceptance_container_runtime_unavailable"
    assert report.kinds_observed == ()


def test_the_unreachable_sweep_stops_at_the_probe(monkeypatch):
    """It must not grind through three listings against a daemon that is not there.

    Each would wait out its own timeout, which is how a fast honest failure became an eight-minute
    one last time. Bounded by counting: exactly one call, and it is the probe.
    """
    daemon = _install(monkeypatch, _Daemon(alive=False))

    sweep(PREFIX)

    assert len(daemon.calls) == 1
    assert daemon.calls[0][0] == "version"


def test_an_empty_listing_from_a_live_daemon_is_clean(monkeypatch):
    """The half a naive fix breaks. A sweep that always reported unobservable would be just as
    green and just as useless, so the honest clean answer has to stay reachable."""
    daemon = _install(monkeypatch, _Daemon())

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_CLEAN
    assert report.clean is True
    assert report.observed is True
    assert report.reason_code is None
    assert report.residual == ()
    # ...and it did the work rather than short-circuiting: the probe plus all three enumerations
    assert report.kinds_observed == KINDS
    assert len(daemon.calls) == 1 + len(SWEEP_ARGV)


def test_surviving_objects_of_every_kind_are_found_and_named(monkeypatch):
    """The leak the caller is actually reading this for. All three kinds, because a sweep that
    only looked at containers would miss the volumes a privileged host leaves behind."""
    _install(
        monkeypatch,
        _Daemon(
            listings={
                "container": [f"{PREFIX}-controller", f"{PREFIX}-worker"],
                "volume": [f"{PREFIX}-worker-docker"],
                "network": [f"{PREFIX}-net"],
            }
        ),
    )

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_RESIDUAL
    assert report.clean is False
    assert report.observed is True
    assert report.reason_code == "acceptance_fleet_teardown_incomplete"
    assert report.residual == (
        f"container:{PREFIX}-controller",
        f"container:{PREFIX}-worker",
        f"network:{PREFIX}-net",
        f"volume:{PREFIX}-worker-docker",
    )


def test_objects_belonging_to_someone_else_are_never_reported(monkeypatch):
    """The sweep runs on a developer's machine and on a shared CI runner. Reporting anything it did
    not create would make the verdict unusable, and the pressure would land on switching it off."""
    _install(
        monkeypatch,
        _Daemon(
            listings={
                "container": ["postgres", "my-dev-box", "secp-acc-OTHER-RUN-worker"],
                "volume": ["node_modules"],
                "network": ["bridge", "host", "none"],
            }
        ),
    )

    assert sweep(PREFIX).verdict == VERDICT_CLEAN


# --------------------------------------------------------------------------- partial sweeps


@pytest.mark.parametrize("broken", sorted(KINDS))
def test_a_kind_that_cannot_be_enumerated_makes_the_whole_sweep_unobservable(
    monkeypatch, broken: str
):
    """Two thirds of a sweep is not a pass.

    A run that leaked a volume but could only read containers has not been shown to be clean of
    anything that matters. Parametrised over every kind, so a sweep that fails closed for
    containers and open for networks is caught.
    """
    _install(monkeypatch, _Daemon(fails=frozenset({broken})))

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_UNOBSERVABLE
    assert report.clean is False
    assert report.reason_code == "acceptance_observation_unavailable"
    assert broken not in report.kinds_observed


def test_a_partial_sweep_still_names_what_it_managed_to_see(monkeypatch):
    """An incomplete answer may still name what it saw.

    The verdict stays ``unobservable`` — the residue was not enumerated completely, so "clean" was
    never established — but discarding the container it did find would hide a known leak behind
    "we do not know", which helps nobody.
    """
    _install(
        monkeypatch,
        _Daemon(listings={"container": [f"{PREFIX}-worker"]}, fails=frozenset({"volume"})),
    )

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_UNOBSERVABLE
    assert report.residual == (f"container:{PREFIX}-worker",)
    assert report.kinds_observed == ("container",)


def test_a_listing_that_times_out_is_not_an_empty_listing(monkeypatch):
    """A bounded timeout is a failure to observe, not an observation of nothing.

    ``shell.run`` raises rather than returning on a timeout, so without explicit handling this
    would escape as a harness crash — or, worse, be caught somewhere that treated it as empty.
    """

    class _TimesOutListing(_Daemon):
        def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
            if args[0] != "version":
                raise AcceptanceError("acceptance_host_command_timeout")
            return super().__call__(*args, timeout=timeout, check=check)

    _install(monkeypatch, _TimesOutListing())

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_UNOBSERVABLE
    assert report.clean is False


def test_a_probe_that_times_out_is_unobservable_with_its_own_reason(monkeypatch):
    """Same rule one level up, and the reason code stays attributable to the timeout."""

    class _TimesOutProbe:
        def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
            raise AcceptanceError("acceptance_host_command_timeout")

    monkeypatch.setattr("secp_acceptance.residue.docker", _TimesOutProbe())

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_UNOBSERVABLE
    assert report.reason_code == "acceptance_host_command_timeout"


def test_the_probe_alone_decides_between_looking_and_not(monkeypatch):
    """Attribution. With every other answer held identical, the probe's exit status alone flips the
    verdict — so neither result is an artefact of the listings happening to be empty."""
    verdicts = set()
    for alive in (True, False):
        _install(monkeypatch, _Daemon(alive=alive))
        verdicts.add((alive, sweep(PREFIX).verdict))
    assert verdicts == {(True, VERDICT_CLEAN), (False, VERDICT_UNOBSERVABLE)}


# --------------------------------------------------------------------------- the right machine


OUR_DAEMON = "SPWJ:AAAA:BBBB:CCCC"
SOME_OTHER_DAEMON = "ZZZZ:9999:8888:7777"


class _IdentifiedDaemon(_Daemon):
    """A daemon that also answers ``docker info --format {{.ID}}`` with a configurable identity."""

    def __init__(self, *, identity: str = OUR_DAEMON, info_ok: bool = True, **kw: object) -> None:
        super().__init__(**kw)  # type: ignore[arg-type]
        self.identity = identity
        self.info_ok = info_ok

    def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
        if args[0] == "info":
            self.calls.append(args)
            return Result(
                exit_code=0 if self.info_ok else 1,
                stdout=self.identity if self.info_ok else "",
                stderr="",
            )
        return super().__call__(*args, timeout=timeout, check=check)


def test_a_live_daemon_that_is_not_ours_is_unobservable_not_clean(monkeypatch):
    """The third false clean, and the one the negative control's own technique would produce.

    ``DOCKER_HOST`` pointing elsewhere gives a perfectly healthy daemon that our objects were never
    created on. It enumerates cleanly and answers "nothing here" — about the wrong computer.
    """
    _install(monkeypatch, _IdentifiedDaemon(identity=SOME_OTHER_DAEMON))

    report = sweep(PREFIX, expected_daemon=OUR_DAEMON)

    assert report.verdict == VERDICT_UNOBSERVABLE
    assert report.clean is False
    assert report.reason_code == "acceptance_residue_daemon_mismatch"
    assert report.daemon_bound is False


def test_the_expected_daemon_alone_decides(monkeypatch):
    """CONTROL, and the attribution. Same daemon, same empty listings, same everything — only the
    identity we demand of it changes, and that alone flips clean to unobservable."""
    _install(monkeypatch, _IdentifiedDaemon(identity=OUR_DAEMON))

    assert sweep(PREFIX, expected_daemon=OUR_DAEMON).verdict == VERDICT_CLEAN
    assert sweep(PREFIX, expected_daemon=SOME_OTHER_DAEMON).verdict == VERDICT_UNOBSERVABLE


def test_a_bound_sweep_of_the_right_machine_is_clean_and_says_it_was_bound(monkeypatch):
    """The strong sentence: we looked, at OUR machine, and it is clean."""
    _install(monkeypatch, _IdentifiedDaemon(identity=OUR_DAEMON))

    report = sweep(PREFIX, expected_daemon=OUR_DAEMON)

    assert report.verdict == VERDICT_CLEAN
    assert report.daemon_bound is True
    assert report.observation()["daemon_bound"] is True


def test_an_unbound_sweep_never_claims_it_was_bound(monkeypatch):
    """The weaker sentence, and it must READ as the weaker one.

    A caller with no fleet genuinely has no identity to bind to, so unbound stays permitted — but a
    clean verdict from it is a statement about some machine, and the report has to say so rather
    than let a reader assume the stronger claim.
    """
    _install(monkeypatch, _IdentifiedDaemon())

    report = sweep(PREFIX)

    assert report.verdict == VERDICT_CLEAN
    assert report.daemon_bound is False
    assert report.observation()["daemon_bound"] is False


def test_an_unreadable_daemon_identity_is_unobservable(monkeypatch):
    """Binding that cannot be checked is not binding that passed."""
    _install(monkeypatch, _IdentifiedDaemon(info_ok=False))

    report = sweep(PREFIX, expected_daemon=OUR_DAEMON)

    assert report.verdict == VERDICT_UNOBSERVABLE
    assert report.reason_code == "acceptance_observation_unavailable"
    assert report.daemon_bound is False


def test_a_mismatched_daemon_is_not_enumerated_at_all(monkeypatch):
    """Stop at the mismatch. Enumerating the wrong machine cannot produce a usable answer, and
    anything it found would be somebody else's objects."""
    daemon = _install(monkeypatch, _IdentifiedDaemon(identity=SOME_OTHER_DAEMON))

    sweep(PREFIX, expected_daemon=OUR_DAEMON)

    assert [call[0] for call in daemon.calls] == ["version", "info"]


def test_the_daemon_mismatch_reason_is_distinct_from_an_outage(monkeypatch):
    """Two different problems needing two different fixes must not share one code.

    A wrong ``DOCKER_HOST`` and a stopped daemon look identical to a reader who only has
    ``acceptance_container_runtime_unavailable`` to go on, and the reason code is the only part of
    this report that survives into readable evidence.
    """
    _install(monkeypatch, _IdentifiedDaemon(identity=SOME_OTHER_DAEMON))
    mismatch = sweep(PREFIX, expected_daemon=OUR_DAEMON).reason_code
    _install(monkeypatch, _IdentifiedDaemon(alive=False))
    outage = sweep(PREFIX, expected_daemon=OUR_DAEMON).reason_code

    assert mismatch != outage
    assert {mismatch, outage} <= HARNESS_REASONS


# --------------------------------------------------------------------------- structural guards


def test_the_sweep_never_asks_whether_a_named_object_exists(monkeypatch):
    """THE structural guard, and the only test here that survives the motivating rewrite.

    ``docker inspect NAME`` fails identically for "the object is gone" and "the daemon is not
    there", so a sweep built on it cannot tell absence from ignorance — that IS the original defect.
    Every behavioural assertion in this file still passes if ``sweep`` is rewritten to use it, on a
    daemon that answers. This asserts on the CALLS instead, which does not.
    """
    daemon = _install(monkeypatch, _Daemon())

    sweep(PREFIX)

    assert daemon.calls, "the sweep made no calls at all; this guard would pass vacuously"
    for call in daemon.calls:
        assert "inspect" not in call, (
            f"the sweep asked `docker {' '.join(call)}`. An existence probe cannot distinguish an "
            f"absent object from an unreachable daemon, which is precisely the false clean this "
            f"module exists to prevent. Enumerate and filter instead."
        )


def test_every_reason_code_the_sweep_can_emit_is_in_the_closed_harness_vocabulary(monkeypatch):
    """A reason code outside the vocabulary is refused by the evidence loader at SEAL time.

    That is the end of a twenty-minute container run, which is the worst possible moment to
    discover a typo in a string. Every code the sweep can produce is checked here instead, by
    driving each failure path rather than by rereading the module's literals.
    """
    emitted: set[str] = set()
    for daemon, expected in (
        (_Daemon(alive=False), ""),
        (_Daemon(fails=frozenset({"container"})), ""),
        (_Daemon(listings={"container": [f"{PREFIX}-worker"]}), ""),
        (_IdentifiedDaemon(identity=SOME_OTHER_DAEMON), OUR_DAEMON),
        (_IdentifiedDaemon(info_ok=False), OUR_DAEMON),
    ):
        _install(monkeypatch, daemon)
        code = sweep(PREFIX, expected_daemon=expected).reason_code
        assert code is not None
        emitted.add(code)

    # Five paths, four codes: the unreadable-identity path deliberately shares
    # `acceptance_observation_unavailable` with a failed enumeration, because both mean the same
    # thing to a reader — a bounded observation the sweep needed could not be made.
    assert len(emitted) == 4, "two failure paths collapsed onto one code; they are not attributable"
    assert emitted <= HARNESS_REASONS


def test_the_sweep_reads_the_same_object_kinds_the_workflow_greps():
    """Two readings of one fact are only worth having while they are readings of the SAME fact.

    The acceptance workflow's outer "Refuse to finish having leaked a privileged host" step is a
    shell backstop that runs even when the harness process died; this module is the inner reading
    that can be recorded as evidence. A kind added to one and not the other means the pair silently
    stops agreeing, and the weaker of the two becomes the real guarantee.

    Derived from the workflow FILE, never restated here — a copied list would agree with itself
    after someone changed the real one.
    """
    here = pathlib.Path(__file__).resolve()
    root = next(p for p in here.parents if (p / ".github").is_dir())
    workflow = (root / ".github" / "workflows" / "acceptance.yml").read_text(encoding="utf-8")

    line = next(
        (ln for ln in workflow.splitlines() if "for kind in" in ln and "--format" in ln), None
    )
    assert line is not None, (
        "the workflow's leaked-object sweep no longer has a recognisable `for kind in ...` line; "
        "this guard cannot read it, so re-derive the comparison rather than deleting it"
    )
    workflow_kinds = set(re.findall(r'"([^"]+--format[^"]*)"', line))
    assert workflow_kinds, "no enumerations parsed out of the workflow line; the guard is vacuous"

    assert workflow_kinds == {" ".join(argv) for _kind, argv in SWEEP_ARGV}


# --------------------------------------------------------------------------- outcome mapping


def test_only_a_clean_sweep_maps_to_a_positive_observation():
    assert outcome_for(ResidueReport(VERDICT_CLEAN, (), KINDS, None)) == (OUTCOME_OBSERVED, None)


@pytest.mark.parametrize(
    ("verdict", "reason"),
    [
        (VERDICT_RESIDUAL, "acceptance_fleet_teardown_incomplete"),
        (VERDICT_UNOBSERVABLE, "acceptance_container_runtime_unavailable"),
    ],
)
def test_residual_and_unobservable_both_map_to_unproven(verdict: str, reason: str):
    """THE one-way property. There is no path from "we could not look" to a pass, and a leak is a
    failed proof rather than a product refusal."""
    outcome, code = outcome_for(ResidueReport(verdict, (), KINDS, reason))
    assert outcome == OUTCOME_UNPROVEN
    assert code == reason


def test_no_verdict_can_ever_map_to_refused():
    """``refused`` means THE PRODUCT refused and the refusal was the point of the check. Nothing
    about a teardown sweep is a product refusal, so keeping it unreachable is what stops ``refused``
    and ``unproven`` blurring in the stages that consume this."""
    for verdict in sorted(VERDICTS):
        outcome, _code = outcome_for(
            ResidueReport(verdict, (), KINDS, "acceptance_evidence_invalid")
        )
        assert outcome != OUTCOME_REFUSED


def test_the_mapping_is_exhaustive_over_the_declared_verdicts():
    """A verdict added later must be handled here rather than falling through to a default.

    Derived from ``VERDICTS`` rather than from a list typed into this test, so a new member fails
    this immediately instead of quietly acquiring whatever the default happened to be.
    """
    for verdict in sorted(VERDICTS):
        outcome, _code = outcome_for(
            ResidueReport(verdict, (), KINDS, "acceptance_evidence_invalid")
        )
        assert outcome in (OUTCOME_OBSERVED, OUTCOME_UNPROVEN)


def test_an_unrecognised_verdict_raises_rather_than_defaulting():
    """A default here would be a silent third path to a pass."""
    with pytest.raises(AcceptanceError) as caught:
        outcome_for(ResidueReport("probably_fine", (), KINDS, None))
    assert caught.value.reason_code == "acceptance_observation_malformed"


def test_a_non_clean_report_missing_its_reason_still_cannot_become_a_pass():
    """Defence in depth. ``reason_code`` is ``None`` only on a clean verdict by construction, but a
    future caller building a report by hand must not be able to launder an unobservable one into a
    pass by omitting the reason."""
    outcome, code = outcome_for(ResidueReport(VERDICT_UNOBSERVABLE, (), (), None))
    assert outcome == OUTCOME_UNPROVEN
    assert code == "acceptance_observation_unavailable"


# --------------------------------------------------------------------------- evidence projection


def test_the_recorded_projection_is_bounded_and_carries_no_object_name(monkeypatch):
    """The evidence document takes digests and counts, never per-run ids. The surviving NAMES stay
    in the report for an operator to read and never reach the document."""
    leaked = f"{PREFIX}-worker"
    _install(monkeypatch, _Daemon(listings={"container": [leaked]}))

    projection = sweep(PREFIX).observation()

    assert projection["verdict"] == VERDICT_RESIDUAL
    assert projection["residual_count"] == 1
    assert str(projection["residual_identity"]).startswith("sha256:")
    rendered = repr(projection)
    assert leaked not in rendered
    assert PREFIX not in rendered


def test_the_projection_distinguishes_a_clean_sweep_from_an_unobservable_one(monkeypatch):
    """Both carry zero residue. A reader of the evidence must still be able to tell them apart —
    that is the entire point of recording the verdict rather than a count."""
    _install(monkeypatch, _Daemon())
    clean = sweep(PREFIX).observation()
    _install(monkeypatch, _Daemon(alive=False))
    blind = sweep(PREFIX).observation()

    assert clean["residual_count"] == blind["residual_count"] == 0
    assert clean != blind
    assert clean["verdict"] == VERDICT_CLEAN
    assert blind["verdict"] == VERDICT_UNOBSERVABLE
    assert clean["kinds_observed"] == list(KINDS)
    assert blind["kinds_observed"] == []
