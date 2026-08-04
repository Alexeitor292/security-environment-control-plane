"""Lifecycle observations of an installed worker: what the host actually says, three-valued.

The lifecycle and failure-injection stages ask a real host questions — how does it classify this
bundle, is the operator still dormant, are the managed documents byte-identical to what they were
before the failed upgrade. Every one of those questions has THREE answers, not two, and this module
exists so the third is never quietly rendered as one of the first two:

* the host answered, and the answer is the good one;
* the host answered, and the answer is the bad one;
* **we did not get an answer at all.**

:mod:`secp_acceptance.residue` established that shape for teardown. This is the same discipline
applied to the rest of the stage, for the same reason: a check that could not be settled must read
as unsettled, never as settled either way. The mistake is symmetric and both halves are live here —
reporting "clean" when we could not look (the original defect) and reporting "we do not know" about
something we just observed (the mirror of it, found in this harness's own partial-sweep path).

WHY A REFUSAL IS NOT AN ERROR
-----------------------------
``secpctl`` refuses with exit 2 and a bounded ``reason_code``, and for the failure-injection stage
that refusal IS the expected result. So :func:`secpctl` separates "refused with a bounded product
code" from "we could not read a report", which look identical if you only check the exit status.
Collapsing them would make every failure-injection check unfalsifiable: a command that failed to run
at all would satisfy an assertion that the product refused.

PATHS AND FORMULAS ARE READ FROM THE PRODUCT, NEVER RESTATED
------------------------------------------------------------
The five managed document paths come from ``engine._DOC_ORDER`` / ``engine._KIND_PATH`` resolved
through :class:`~secp_management.layout.ManagementLocations`, and the installation-id derivation
comes from ``engine._installation_id``. A copied path or a re-implemented digest formula would agree
with itself after someone changed the real one — the exact failure this program keeps finding (the
worker health interpreter that named a path the image did not have; the operator unit that reports
``static`` where a restated table said ``disabled``).

What that costs, stated plainly: comparing the product's installation id against the product's own
formula cannot detect the formula changing. It is not meant to. The independence that check needs
comes from its INPUTS being separately obtained — the aggregate digest from one report and the
installation id from another — not from re-deriving the arithmetic.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import observation_digest
from secp_acceptance.hosts import Host
from secp_acceptance.reasons import OUTCOME_OBSERVED, OUTCOME_UNPROVEN, OUTCOME_VIOLATED
from secp_acceptance.residue import VIOLATION_REASON

#: The management CLI, invoked on a host by name. Resolved through the host's PATH because the
#: package installs a console script; a hard-coded absolute path here would be this module's guess
#: about someone else's install layout, which is the class of pin that has already broken once.
SECPCTL = "secpctl"

#: ``secpctl`` exits 0 on success and 2 on a bounded refusal. ANY other status means the command did
#: not reach its own reporting path — a missing entrypoint, a killed process, a host that could not
#: be reached — and is never read as a refusal.
EXIT_OK = 0
EXIT_REFUSED = 2

REPORT_OK = "ok"
REPORT_REFUSED = "refused"
REPORT_UNREADABLE = "unreadable"

#: A document is PRESENT with a digest, ABSENT, or we could not tell. The first two are positive
#: observations printed by the probe; the third is everything else.
DOC_PRESENT = "present"
DOC_ABSENT = "absent"
DOC_UNREADABLE = "unreadable"

RESTORED = "restored"
CHANGED = "changed"
RESTORATION_UNPROVEN = "unproven"

_DEFAULT_TIMEOUT = 600


# --------------------------------------------------------------------------- the secpctl seam


@dataclass(frozen=True)
class Report:
    """One ``secpctl`` invocation, reduced to a bounded, three-valued result.

    ``payload`` is the parsed report and is EMPTY unless ``status`` is ok or refused. It is for the
    caller to project from — never to hand to ``observe()`` whole, because a real report carries
    host paths, container ids and origins.
    """

    status: str
    exit_code: int
    payload: dict[str, Any]
    reason_code: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == REPORT_OK

    @property
    def readable(self) -> bool:
        """Whether a bounded report was obtained at all — success OR refusal."""
        return self.status in (REPORT_OK, REPORT_REFUSED)

    def field(self, *path: str) -> tuple[bool, object]:
        """``(present, value)`` for a nested report field.

        Returns presence SEPARATELY rather than a value-or-default, because the two are different
        facts and the default would be indistinguishable from a real one. A report with no
        ``operator_disabled`` field must not be read as an operator that is not disabled; that is
        the same confusion as an unreachable daemon reading as a clean machine.
        """
        cursor: object = self.payload
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor:
                return False, None
            cursor = cursor[key]
        return True, cursor

    def flag(self, *path: str) -> bool | None:
        """A strictly BOOLEAN report field. ``None`` when absent or not a bool.

        Deliberately not truthiness: a field carrying the string ``"false"`` is a report shape this
        harness does not understand, and guessing at it is how a drifted contract reads as a pass.
        """
        present, value = self.field(*path)
        return value if present and isinstance(value, bool) else None

    def text(self, *path: str) -> str | None:
        present, value = self.field(*path)
        return value if present and isinstance(value, str) and value else None


def secpctl(host: Host, argv: tuple[str, ...], *, timeout: int = _DEFAULT_TIMEOUT) -> Report:
    """Run ``secpctl`` on ``host`` and return its bounded report.

    ``--json`` is appended HERE rather than by callers. Without it the CLI renders human text, which
    parses as no report at all — and a caller who forgot the flag would get ``unreadable`` for every
    invocation, which is a confusing way to discover a typo. Appended only when absent, so an
    explicit one does not become a duplicate argument.

    THE PAYLOAD IS EXTRACTED, NOT ASSUMED
    -------------------------------------
    Delegates to :func:`secp_acceptance.install.secpctl_payload` rather than parsing ``stdout``
    whole. This function DID parse it whole, and that was a defect with a very specific shape: a
    real host emits pip warnings, systemd notices and journal lines around the report, so
    ``json.loads(stdout)`` succeeds locally against a clean fixture and fails on every real
    invocation. It failed CLOSED — every check would have read ``unreadable`` rather than passing
    falsely — but a stage that reports "could not observe" for its whole run is not much better
    than one that lies, and it would have looked like an infrastructure problem rather than a
    parser bug.

    Shared rather than reimplemented: a second copy of the tolerance is a second thing to keep
    correct, and this is exactly the seam where the two would drift apart unnoticed.
    """
    args = tuple(argv)
    if "--json" not in args:
        args += ("--json",)
    result = host.exec((SECPCTL, *args), timeout=timeout)

    if result.exit_code not in (EXIT_OK, EXIT_REFUSED):
        # The command did not reach its own reporting path. This is NOT a refusal, and reading it as
        # one would let a missing entrypoint satisfy an assertion that the product refused.
        return Report(REPORT_UNREADABLE, result.exit_code, {})

    from secp_acceptance.install import secpctl_payload

    parsed = secpctl_payload(result)
    if not parsed:
        # No JSON object anywhere in the output. An absent report, not an empty one.
        return Report(REPORT_UNREADABLE, result.exit_code, {})

    if result.exit_code == EXIT_OK:
        return Report(REPORT_OK, result.exit_code, parsed)

    # Exit 2 promises a bounded reason code. A refusal WITHOUT one is a report shape this harness
    # cannot attribute, so it is unreadable rather than a refusal with an invented reason.
    reason = parsed.get("reason_code")
    if not isinstance(reason, str) or not reason:
        return Report(REPORT_UNREADABLE, result.exit_code, parsed)
    return Report(REPORT_REFUSED, result.exit_code, parsed, reason_code=reason)


# --------------------------------------------------------------------------- managed documents


def managed_document_paths(role: str) -> tuple[tuple[str, str], ...]:
    """``(kind, path)`` for the five root-controlled documents a transaction owns.

    READ from the engine's own ordering and layout rather than listed here. A copied list would keep
    passing after the product added a sixth document, and the rollback proofs below would silently
    stop covering it.
    """
    from secp_management.engine import _DOC_ORDER, _KIND_PATH
    from secp_management.layout import ManagementLocations

    locations = ManagementLocations()
    return tuple((kind, getattr(locations, _KIND_PATH[kind])(role)) for kind in _DOC_ORDER)


#: Probes one path and prints a POSITIVE token for each of the two real states. A discriminated
#: answer is the whole point: ``sha256sum`` alone fails identically for "the file is gone" and "the
#: probe could not run", which is precisely the ambiguity that produced a false clean teardown in
#: this harness once already. The path arrives as ``$1``, never interpolated into the script text.
_PROBE = 'if [ -e "$1" ]; then echo PRESENT; sha256sum "$1"; else echo ABSENT; fi'


@dataclass(frozen=True)
class DocumentState:
    """One managed document: present with a digest, absent, or unreadable."""

    kind: str
    state: str
    digest: str | None = None


@dataclass(frozen=True)
class DocumentSnapshot:
    """The five managed documents as they stood at one moment."""

    role: str
    documents: tuple[DocumentState, ...]

    def by_kind(self) -> dict[str, DocumentState]:
        return {doc.kind: doc for doc in self.documents}

    @property
    def complete(self) -> bool:
        """Whether every document was settled — present or absent, none unreadable."""
        return all(doc.state != DOC_UNREADABLE for doc in self.documents)

    @property
    def present_kinds(self) -> tuple[str, ...]:
        return tuple(doc.kind for doc in self.documents if doc.state == DOC_PRESENT)

    @property
    def unreadable_kinds(self) -> tuple[str, ...]:
        return tuple(doc.kind for doc in self.documents if doc.state == DOC_UNREADABLE)

    def observation(self) -> dict[str, object]:
        """The bounded projection an evidence check records — never a path, never a document body.

        The per-document digests ARE the point of the snapshot, but they are digests of real
        installed documents, so they are folded into one content address rather than listed.
        """
        return {
            "role": self.role,
            "complete": self.complete,
            "present": list(self.present_kinds),
            "unreadable": list(self.unreadable_kinds),
            "content_identity": observation_digest(
                {"docs": [[d.kind, d.state, d.digest] for d in self.documents]}
            ),
        }


def _probe_document(host: Host, path: str, *, timeout: int) -> tuple[str, str | None]:
    """Probe one path. Returns ``(state, digest)``; never guesses."""
    result = host.exec(("sh", "-c", _PROBE, "sh", path), timeout=timeout)
    if not result.ok:
        return DOC_UNREADABLE, None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return DOC_UNREADABLE, None
    if lines[0] == "ABSENT":
        return DOC_ABSENT, None
    if lines[0] != "PRESENT" or len(lines) < 2:
        return DOC_UNREADABLE, None
    digest = lines[1].split()[0] if lines[1].split() else ""
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        # A PRESENT with no usable digest is not a present document we can compare; saying so is
        # the difference between "unchanged" and "we never read it".
        return DOC_UNREADABLE, None
    return DOC_PRESENT, digest


def document_snapshot(host: Host, role: str, *, timeout: int = 120) -> DocumentSnapshot:
    """Capture the five managed documents. Every one is settled or explicitly unreadable."""
    states = [
        DocumentState(kind, *_probe_document(host, path, timeout=timeout))
        for kind, path in managed_document_paths(role)
    ]
    return DocumentSnapshot(role=role, documents=tuple(states))


# --------------------------------------------------------------------------- restoration proof


@dataclass(frozen=True)
class RestorationVerdict:
    """Did a failed upgrade put the managed documents back exactly as they were?

    This is the DISK half of the failed-upgrade rollback proof. The runtime half — that the baseline
    release is what is actually running — is a separate observation, and the check is recorded only
    when both agree. Either alone is satisfiable by a state the other would refuse: documents can be
    byte-perfect while the successor's containers are still up, and the baseline can be running
    while a document was left rewritten.
    """

    verdict: str
    reason_code: str | None
    differing: tuple[str, ...]

    def observation(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "differing": list(self.differing),
            "reason_code": self.reason_code,
        }


def restoration_verdict(before: DocumentSnapshot, after: DocumentSnapshot) -> RestorationVerdict:
    """Compare two snapshots of the same role.

    Refuses to compare snapshots of DIFFERENT roles rather than producing a confident answer about
    two unrelated installations.
    """
    if before.role != after.role:
        raise AcceptanceError("acceptance_observation_malformed")

    # An incomplete snapshot cannot support either conclusion: what we did not read might be the
    # document that changed. "We could not check" is the honest answer, and it is not a pass.
    if not (before.complete and after.complete):
        return RestorationVerdict(
            RESTORATION_UNPROVEN,
            "acceptance_observation_unavailable",
            tuple(sorted(set(before.unreadable_kinds) | set(after.unreadable_kinds))),
        )

    # STATE and DIGEST are both compared, and under the probe's own invariants that is redundant:
    # it only ever emits ``present`` WITH a valid digest or ``absent`` with ``None``, so any state
    # change moves the digest too. The redundancy is kept deliberately, because ``DocumentState`` is
    # public and a hand-built or future ``present``-with-no-digest would otherwise compare EQUAL to
    # an absent one — a silent "restored" over a document that vanished.
    #
    # Mutation testing found this: dropping the state comparison passed the whole suite, because
    # every case then covered happened to differ in digest as well. The test that kills it now
    # (`test_a_state_change_alone_is_enough_to_fail_the_comparison`) is the one that makes keeping
    # this line meaningful rather than decorative.
    old, new = before.by_kind(), after.by_kind()
    differing = tuple(
        sorted(
            kind
            for kind in old
            if old[kind].state != new[kind].state or old[kind].digest != new[kind].digest
        )
    )
    if differing:
        # We READ both sides and they disagree: the restoration provably did not happen. That is a
        # proven defect, not an absence of evidence.
        return RestorationVerdict(CHANGED, VIOLATION_REASON, differing)
    return RestorationVerdict(RESTORED, None, ())


def outcome_for_restoration(verdict: RestorationVerdict) -> tuple[str, str | None]:
    """The ONLY mapping from a restoration verdict to an acceptance outcome.

    * ``restored`` -> ``observed`` (we read both sides and they are identical)
    * ``changed``  -> ``violated`` (we read both sides; the documents were NOT put back)
    * ``unproven`` -> ``unproven`` (we could not read one of them)

    Same one-way shape as :func:`secp_acceptance.residue.outcome_for`, and for the same reason:
    ``changed`` is knowledge and ``unproven`` is ignorance, so folding them would make a proven
    failed restoration indistinguishable from a probe that did not run. ``refused`` is unreachable —
    nothing here is a product refusal — and an unrecognised verdict raises rather than defaulting.
    """
    if verdict.verdict == RESTORED:
        return OUTCOME_OBSERVED, None
    if verdict.verdict == CHANGED:
        return OUTCOME_VIOLATED, verdict.reason_code or VIOLATION_REASON
    if verdict.verdict == RESTORATION_UNPROVEN:
        return OUTCOME_UNPROVEN, verdict.reason_code or "acceptance_observation_unavailable"
    raise AcceptanceError("acceptance_observation_malformed")


# --------------------------------------------------------------------------- identity binding


def expected_installation_id(role: str, release_aggregate: str) -> str:
    """The installation id a given release aggregate must produce.

    Delegates to the engine's own derivation rather than re-implementing it — see this module's
    docstring for what that does and does not prove. The check this supports is a CROSS-report one:
    the aggregate comes from one observation and the installation id from another, and they must
    agree. An upgrade that changed the release without changing the identity, or the reverse, fails
    it.
    """
    from secp_management.engine import _installation_id

    if not role or not release_aggregate:
        raise AcceptanceError("acceptance_observation_malformed")
    return _installation_id(role, release_aggregate)


# --------------------------------------------------------------------------- upgrade lineage

#: The successor descends from what is actually installed. This is the trust window the managed
#: upgrade rests on, and the reason an attacker holding a validly-signed but UNRELATED release
#: cannot install it over a running worker.
LINEAR = "linear"
#: The successor does NOT descend from the installed release. Observed, not guessed — a downgrade,
#: a sideways move, or an unrelated bundle. This is the state the failure-injection twin drives.
NOT_LINEAR = "not_linear"
#: No baseline to descend FROM, or a reading we could not make. Never a mismatch.
LINEAGE_UNPROVEN = "unproven"


@dataclass(frozen=True)
class LineageVerdict:
    """Whether a candidate bundle is a linear successor of the INSTALLED release."""

    verdict: str
    reason_code: str | None
    observation: dict[str, object] = field(default_factory=dict)


def linear_successor_binding(
    *, baseline: Mapping[str, object], successor: Mapping[str, object]
) -> LineageVerdict:
    """Bind a candidate successor to the release that is actually installed on the host.

    ``baseline`` is :func:`secp_acceptance.install.observe_installed_release` — read OFF THE HOST
    and re-parsed through the product's own manifest parser, not what the harness believes it
    installed. That distinction is the whole point: an upgrade proof built on the harness's memory
    would still pass if the install had silently put something else there.

    ABSENT BASELINE IS ``unproven``, NEVER ``not_linear``
    ----------------------------------------------------
    ``present: False`` from that seam means one of several things — no record, an unreadable record,
    an unreachable host — and NONE of them is "the successor does not descend from the baseline".
    There is no baseline to descend from, so the question was never asked. Recording it as a
    mismatch would manufacture a lineage failure out of an infrastructure outage, which is a false
    accusation in the direction this program cares about least but still cares about.

    (That collapse is real and known: the seam returns ``present: False`` on any ``cat`` failure. It
    is on the owning stream's fix list. This function is written so the ambiguity cannot become a
    wrong verdict HERE regardless of when that lands.)
    """
    if not baseline.get("present"):
        return LineageVerdict(
            LINEAGE_UNPROVEN,
            "acceptance_observation_unavailable",
            {"baseline_present": False},
        )
    installed = baseline.get("source_sha")
    claimed_parent = successor.get("parent_sha")
    observation: dict[str, object] = {
        "baseline_present": True,
        "successor_declares_parent": bool(claimed_parent),
        # Digested, not carried: a source sha is a real commit identity of this repository.
        "lineage_identity": observation_digest({"installed": installed, "parent": claimed_parent}),
    }
    if not isinstance(installed, str) or not installed:
        # The record parsed but carries no source sha. That is a malformed baseline, not a
        # non-linear successor.
        return LineageVerdict(LINEAGE_UNPROVEN, "acceptance_observation_malformed", observation)
    # One comparison settles both shapes. A successor declaring NO parent (absent, empty, or a
    # non-string) cannot equal a non-empty installed sha, so it falls out here as NOT_LINEAR —
    # which is the right answer and the one the engine gives, for the same reason: a bundle that
    # descends from nothing descends from nothing in particular.
    #
    # There WAS a separate branch for the no-parent case. Mutation testing showed deleting it
    # changed no result and failed no test, because this comparison already covered it. An
    # unexercised branch that cannot alter an outcome is not defence in depth, it is a second place
    # to have to keep correct — unlike the state/digest pair in `restoration_verdict`, which a
    # hand-built DocumentState genuinely can drive apart. ``successor_declares_parent`` keeps the
    # distinction visible to a reader of the observation without branching on it.
    if claimed_parent != installed:
        return LineageVerdict(NOT_LINEAR, None, observation)
    return LineageVerdict(LINEAR, None, observation)


# --------------------------------------------------------------------------- classification


#: What ``secpctl bootstrap worker --bundle X`` (DRY RUN) called the operation. Read from the
#: engine so a renamed classification breaks the build rather than turning a check into a branch
#: that can never be taken.
def managed_upgrade_classification() -> str:
    from secp_management.evidence import CLASSIFY_MANAGED_UPGRADE

    return CLASSIFY_MANAGED_UPGRADE


CLASSIFIED_MANAGED = "managed_upgrade"
CLASSIFIED_OTHER = "other"
CLASSIFICATION_UNPROVEN = "unproven"


@dataclass(frozen=True)
class ClassificationVerdict:
    """How the product classified a candidate bundle, before any mutation."""

    verdict: str
    reason_code: str | None
    classification: str
    observation: dict[str, object] = field(default_factory=dict)


def classification_verdict(report: Report) -> ClassificationVerdict:
    """Read the classification out of a DRY-RUN bootstrap report.

    The dry run is where this is settled, and that matters: the engine classifies before any host
    op, so the upgrade is admitted (or refused) with the host untouched. A check that only looked
    after the write could not tell an admitted upgrade from one that was never classified at all.

    A REFUSAL is passed through with the product's own reason rather than flattened. The
    failure-injection twin drives the identical path with one field changed and expects
    ``worker_upgrade_not_linear_successor``; if a refusal read as "unclassified" here, that twin
    would assert on a branch it could never reach.
    """
    if not report.readable:
        return ClassificationVerdict(
            CLASSIFICATION_UNPROVEN,
            "acceptance_observation_unavailable",
            "",
            {"report_readable": False},
        )
    if report.status == REPORT_REFUSED:
        return ClassificationVerdict(
            CLASSIFICATION_UNPROVEN,
            report.reason_code,
            "",
            {"report_readable": True, "refused": True},
        )
    declared = report.text("classification") or ""
    mode = report.text("mode") or ""
    observation: dict[str, object] = {
        "report_readable": True,
        "refused": False,
        "classification": declared[:32],
        "declared_dry_run": mode == "dry_run",
    }
    if not declared:
        # An OK report with no classification field is a report shape this harness does not
        # understand. Guessing "not managed" would be inventing the product's answer.
        return ClassificationVerdict(
            CLASSIFICATION_UNPROVEN, "acceptance_observation_malformed", "", observation
        )
    if declared != managed_upgrade_classification():
        # We READ the classification and it was not the one this check requires. Observed-false.
        return ClassificationVerdict(CLASSIFIED_OTHER, None, declared, observation)
    return ClassificationVerdict(CLASSIFIED_MANAGED, None, declared, observation)


# --------------------------------------------------------------------------- upgraded identity


def upgraded_identity_verdict(
    *, before: Mapping[str, object], after: Mapping[str, object], evidence: Report
) -> tuple[bool, dict[str, object]]:
    """Did the upgrade actually change the installation to the successor release?

    Three separate facts, all required, each obtained from a DIFFERENT reading:

    * the release read back off the host CHANGED (``before`` vs ``after``, both
      :func:`observe_installed_release`);
    * ``secpctl evidence worker`` — a different command, which reports its identity only after the
      attestation, record binding and document integrity all verify — names the successor aggregate;
    * that aggregate DERIVES the installation id the same command reports.

    The third is the cross-report check, and it is why this takes both a snapshot pair and an
    evidence report rather than trusting either alone. A product that updated its release record but
    kept the old identity, or minted an identity unrelated to the release it claims, fails it.
    """
    observation: dict[str, object] = {
        "baseline_present": bool(before.get("present")),
        "successor_present": bool(after.get("present")),
        "evidence_readable": evidence.readable,
        "evidence_authenticated": evidence.flag("authenticated") is True,
    }
    if not (before.get("present") and after.get("present") and evidence.ok):
        return False, observation

    old_aggregate = before.get("aggregate_digest")
    new_aggregate = after.get("aggregate_digest")
    reported_aggregate = evidence.text("release_aggregate_digest")
    reported_identity = evidence.text("installation_id")
    observation["release_changed"] = bool(
        isinstance(old_aggregate, str)
        and isinstance(new_aggregate, str)
        and old_aggregate != new_aggregate
    )
    observation["evidence_names_successor"] = reported_aggregate == new_aggregate
    if not (reported_aggregate and reported_identity):
        observation["identity_derives_from_release"] = False
        return False, observation

    try:
        expected = expected_installation_id("worker", reported_aggregate)
    except AcceptanceError:
        observation["identity_derives_from_release"] = False
        return False, observation
    observation["identity_derives_from_release"] = reported_identity == expected
    observation["identity_changed"] = (
        reported_identity != expected_installation_id("worker", str(old_aggregate))
        if isinstance(old_aggregate, str) and old_aggregate
        else False
    )

    # ``release_changed`` stays in the OBSERVATION — a reader wants to see that the two host
    # readings moved — but it is deliberately NOT a term here, because the remaining three already
    # imply it: the identity derives from the reported aggregate, the reported aggregate IS the
    # successor, and the identity differs from the one the baseline aggregate derives. Those cannot
    # all hold unless the release changed.
    #
    # Mutation testing is why this is stated rather than assumed: dropping ``release_changed`` from
    # the conjunction failed no test, because it is perfectly correlated with ``identity_changed``.
    # A term that cannot change an answer does not strengthen a proof; keeping it in the conjunction
    # would only have made the redundancy harder to see next time.
    ok = bool(
        observation["evidence_names_successor"]
        and observation["identity_derives_from_release"]
        and observation["identity_changed"]
    )
    return ok, observation


__all__ = [
    "CHANGED",
    "CLASSIFICATION_UNPROVEN",
    "CLASSIFIED_MANAGED",
    "CLASSIFIED_OTHER",
    "LINEAGE_UNPROVEN",
    "LINEAR",
    "NOT_LINEAR",
    "ClassificationVerdict",
    "LineageVerdict",
    "classification_verdict",
    "linear_successor_binding",
    "managed_upgrade_classification",
    "upgraded_identity_verdict",
    "VIOLATION_REASON",
    "DOC_ABSENT",
    "DOC_PRESENT",
    "DOC_UNREADABLE",
    "EXIT_OK",
    "EXIT_REFUSED",
    "REPORT_OK",
    "REPORT_REFUSED",
    "REPORT_UNREADABLE",
    "RESTORATION_UNPROVEN",
    "RESTORED",
    "SECPCTL",
    "DocumentSnapshot",
    "DocumentState",
    "Report",
    "RestorationVerdict",
    "document_snapshot",
    "expected_installation_id",
    "managed_document_paths",
    "outcome_for_restoration",
    "restoration_verdict",
    "secpctl",
]
