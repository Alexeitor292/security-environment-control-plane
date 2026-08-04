"""The acceptance recorder: accumulates checks and seals them into an evidence document.

The recorder is the ONLY way a check enters the evidence. It exists so that recording a check and
asserting it are the same act: :meth:`AcceptanceRecorder.observe` records a positive observation,
:meth:`expect_refusal` records a refusal the scenario required, and :meth:`unproven` records a
proof the harness could not make. There is no "record a pass without observing anything" verb.

Two properties are enforced here rather than left to caller discipline:

* a stage must be OPENED before any of its checks can be recorded, and opening it commits the run
  to covering every check that stage declares — so a stage cannot be entered, half-covered, and
  quietly reported as fine;
* :meth:`expect_refusal` requires the caller to name the reason code it expected AND the reason
  code it actually got. A refusal that arrived with a different code than the scenario predicted is
  recorded ``unproven`` with ``acceptance_unexpected_reason_code``, never as a pass. This is the
  difference between "the product refused" and "the product refused for the reason that makes this
  test meaningful".
"""

from __future__ import annotations

import datetime as _dt

from secp_acceptance import ACCEPTANCE_CONTRACT_VERSION, AcceptanceError
from secp_acceptance.evidence import (
    ACCEPTANCE_EVIDENCE_SCHEMA,
    AcceptanceEvidence,
    CheckRecord,
    FleetRecord,
    GapRecord,
    ReleaseRecord,
    evidence_from_dict,
    observation_digest,
    run_identity,
)
from secp_acceptance.reasons import (
    ALL_REASONS,
    CHECKS,
    CHECKS_BY_STAGE,
    OUTCOME_OBSERVED,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
    RUN_FAILED,
    RUN_PASSED,
    STAGES,
)


def utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


class AcceptanceRecorder:
    """Accumulates the checks of one acceptance run and seals them into evidence."""

    def __init__(self, *, started_at: str | None = None) -> None:
        self._started_at = started_at or utc_now()
        self._stages: list[str] = []
        self._checks: list[CheckRecord] = []
        self._gaps: list[GapRecord] = []
        self._seen: set[str] = set()

    # --- stages ---------------------------------------------------------------------------

    def open_stage(self, stage: str) -> None:
        """Enter a stage, committing the run to covering every check it declares."""
        if stage not in STAGES:
            raise AcceptanceError("acceptance_evidence_unknown_stage")
        if stage not in self._stages:
            self._stages.append(stage)

    @property
    def stages(self) -> tuple[str, ...]:
        return tuple(self._stages)

    # --- checks ---------------------------------------------------------------------------

    def _record(
        self, *, check: str, stage: str, outcome: str, reason_code: str | None, observation: object
    ) -> None:
        if stage not in self._stages:
            raise AcceptanceError("acceptance_evidence_unknown_stage")
        if check not in CHECKS_BY_STAGE.get(stage, ()):
            raise AcceptanceError("acceptance_evidence_unknown_check")
        if check in self._seen:
            raise AcceptanceError("acceptance_evidence_duplicate_check")
        if reason_code is not None and reason_code not in ALL_REASONS:
            raise AcceptanceError("acceptance_evidence_unknown_reason")
        self._seen.add(check)
        self._checks.append(
            CheckRecord(
                check=check,
                stage=stage,
                outcome=outcome,
                reason_code=reason_code,
                observation_digest=observation_digest(observation),
            )
        )

    def observe(self, check: str, stage: str, observation: object) -> None:
        """Record a POSITIVE observation. ``observation`` must be the bounded, secret-free
        projection the check actually asserted on — its content address is what is stored."""
        self._record(
            check=check,
            stage=stage,
            outcome=OUTCOME_OBSERVED,
            reason_code=None,
            observation=observation,
        )

    def expect_refusal(
        self, check: str, stage: str, *, expected: str, actual: str | None, observation: object
    ) -> bool:
        """Record a refusal the scenario REQUIRED, and return whether it was the expected one.

        ``actual is None`` means the product did not refuse at all, which is the worst outcome for
        a failure-injection check and is recorded as ``acceptance_expected_refusal_absent`` — never
        as a pass, and never silently dropped.
        """
        if expected not in ALL_REASONS:
            raise AcceptanceError("acceptance_evidence_unknown_reason")
        if actual is None:
            self._record(
                check=check,
                stage=stage,
                outcome=OUTCOME_UNPROVEN,
                reason_code="acceptance_expected_refusal_absent",
                observation=observation,
            )
            return False
        if actual != expected:
            self._record(
                check=check,
                stage=stage,
                outcome=OUTCOME_UNPROVEN,
                reason_code="acceptance_unexpected_reason_code",
                observation=observation,
            )
            return False
        self._record(
            check=check,
            stage=stage,
            outcome=OUTCOME_REFUSED,
            reason_code=actual,
            observation=observation,
        )
        return True

    def unproven(self, check: str, stage: str, *, reason_code: str, observation: object) -> None:
        """Record a proof the harness could NOT make. Never a pass."""
        self._record(
            check=check,
            stage=stage,
            outcome=OUTCOME_UNPROVEN,
            reason_code=reason_code,
            observation=observation,
        )

    # --- gaps -----------------------------------------------------------------------------

    def declare_gap(
        self, *, gap: str, stage: str, substitute: str, why: str, weakens: tuple[str, ...]
    ) -> None:
        """Name a fidelity substitution and the checks it weakens.

        Validated HERE, not only at seal time: a gap is declared by the stage that made the
        substitution, and that is the only place with enough context to fix a wrong ``weakens``
        list. Discovering it at the end of a twenty-minute run points at the sealer instead.
        """
        self.open_stage(stage)
        if not weakens:
            raise AcceptanceError("acceptance_evidence_invalid")
        for check in weakens:
            if check not in CHECKS:
                raise AcceptanceError("acceptance_evidence_unknown_check")
        self._gaps.append(
            GapRecord(gap=gap, stage=stage, substitute=substitute, why=why, weakens=weakens)
        )

    # --- sealing --------------------------------------------------------------------------

    def missing(self) -> tuple[str, ...]:
        expected: set[str] = set()
        for stage in self._stages:
            expected.update(CHECKS_BY_STAGE[stage])
        return tuple(sorted(expected - self._seen))

    def seal(self, *, fleet: FleetRecord, release: ReleaseRecord) -> AcceptanceEvidence:
        """Seal the run. The outcome is DERIVED, never supplied.

        A run passes only when every attempted stage is completely covered and no check is
        ``unproven``. There is deliberately no way for a caller to assert ``passed``: the whole
        point of the recorder is that the verdict is a function of what was recorded.
        """
        unproven = [r.check for r in self._checks if r.outcome == OUTCOME_UNPROVEN]
        outcome = RUN_PASSED if (not self.missing() and not unproven) else RUN_FAILED
        fleet_identity = observation_digest(fleet.canonical())
        release_identity = observation_digest(release.canonical())
        document = {
            "schema_version": ACCEPTANCE_EVIDENCE_SCHEMA,
            "harness_contract_version": ACCEPTANCE_CONTRACT_VERSION,
            "run_id": run_identity(
                harness_version=ACCEPTANCE_CONTRACT_VERSION,
                fleet_identity=fleet_identity,
                release_identity=release_identity,
            ),
            "outcome": outcome,
            "started_at": self._started_at,
            "completed_at": utc_now(),
            "stages_attempted": list(self._stages),
            "fleet": fleet.canonical(),
            "release": release.canonical(),
            "checks": [record.canonical() for record in self._checks],
            "gaps": [record.canonical() for record in self._gaps],
            "proxmox_contacted": False,
            "opentofu_executed": False,
            "ephemeral_material_only": True,
            "trust_roots_modified": False,
        }
        # Seal THROUGH the loader, so the document a run produces has already survived the exact
        # revalidation a reader will apply. A recorder that could emit a document the loader
        # refuses would make the loader's guarantees decorative.
        return evidence_from_dict(document)


__all__ = ["AcceptanceRecorder", "utc_now"]
