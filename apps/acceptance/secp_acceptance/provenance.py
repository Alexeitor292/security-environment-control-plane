"""Completion-gate clause C1: no stage represented only by a literal.

THE FAILURE THIS EXISTS FOR
---------------------------
An acceptance evidence document cannot, on its own, tell a real observation from an invented one.
:func:`~secp_acceptance.evidence.observation_digest` faithfully hashes whatever it is handed, so a
stage that recorded ``{"check": check}`` for each of its checks produces a document that is
structurally perfect: every check present, every outcome ``observed``, coverage complete, verdict
``passed``. Every validation rule in the loader agrees with it, because there is nothing wrong with
it — the document is a correct record of what the harness claimed.

The hermetic contract tests do exactly this, legitimately, and they must keep working. So the
distinction cannot live in the document's own validation. It lives here, in the gate that decides
whether a run is an ACCEPTANCE RESULT rather than merely a well-formed document.

WHAT MAKES IT MECHANICAL
------------------------
Every host effect the harness produces goes through :func:`secp_acceptance.shell.run`, which
advances a process-wide counter. The recorder snapshots that counter when a stage opens and at each
check it records, so the sealed document carries, per stage, how many commands that stage actually
ran. A stage represented only by literals moved the counter zero times, and no amount of care in
constructing its observations can change that number.

THREE-VALUED, LIKE EVERYTHING ELSE HERE
---------------------------------------
:data:`PROVENANCE_OBSERVED` / :data:`PROVENANCE_REFUSED` / :data:`PROVENANCE_UNPROVEN`, with
``unproven`` never a pass. A document carrying NO provenance at all is ``unproven``, not
``refused``: it was produced by a harness that did not record any, which is a different fact from a
stage that demonstrably did nothing, and collapsing them would repeat the mistake this program has
now corrected four times.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_acceptance.evidence import AcceptanceEvidence
from secp_acceptance.reasons import (
    OUTCOME_OBSERVED,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
)

#: The clause's verdict vocabulary, reusing the contract's own three values so a reader does not
#: have to learn a second set of words for the same three epistemic states.
PROVENANCE_OBSERVED = OUTCOME_OBSERVED
PROVENANCE_REFUSED = OUTCOME_REFUSED
PROVENANCE_UNPROVEN = OUTCOME_UNPROVEN


@dataclass(frozen=True)
class ProvenanceVerdict:
    """Whether every attempted stage was derived from execution.

    ``passed`` is a property, not a fourth value, so that no caller can accidentally treat
    ``unproven`` as success by testing ``verdict != REFUSED``.
    """

    outcome: str
    reason_code: str | None
    literal_only_stages: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.outcome == PROVENANCE_OBSERVED


def stage_provenance(evidence: AcceptanceEvidence) -> ProvenanceVerdict:
    """Judge whether every attempted stage actually executed.

    ``refused`` — at least one attempted stage ran ZERO commands through the seam. It is named, and
    the run is not an acceptance result.

    ``unproven`` — the document carries no provenance at all, so the question cannot be answered.
    Never a pass: an unanswerable question about execution is exactly the state a false green
    inhabits.

    ``observed`` — every attempted stage moved the counter.
    """
    if not evidence.provenance:
        return ProvenanceVerdict(
            outcome=PROVENANCE_UNPROVEN,
            reason_code="acceptance_stage_provenance_absent",
            literal_only_stages=(),
        )
    literal_only = tuple(
        sorted(record.stage for record in evidence.provenance if record.seam_calls == 0)
    )
    if literal_only:
        return ProvenanceVerdict(
            outcome=PROVENANCE_REFUSED,
            reason_code="acceptance_stage_not_derived_from_execution",
            literal_only_stages=literal_only,
        )
    return ProvenanceVerdict(outcome=PROVENANCE_OBSERVED, reason_code=None, literal_only_stages=())


def assert_stages_derived_from_execution(evidence: AcceptanceEvidence) -> None:
    """Raise unless every attempted stage was derived from execution.

    The enforcing form, for the completion gate. Both non-``observed`` outcomes raise — an
    unanswerable question is not a pass.
    """
    from secp_acceptance import AcceptanceError

    verdict = stage_provenance(evidence)
    if not verdict.passed:
        assert verdict.reason_code is not None  # every non-observed verdict carries one
        raise AcceptanceError(verdict.reason_code)


__all__ = [
    "PROVENANCE_OBSERVED",
    "PROVENANCE_REFUSED",
    "PROVENANCE_UNPROVEN",
    "ProvenanceVerdict",
    "assert_stages_derived_from_execution",
    "stage_provenance",
]
