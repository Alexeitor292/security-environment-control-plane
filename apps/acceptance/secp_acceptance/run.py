"""The ONE acceptance run: a single recorder, a single fleet, a single sealed evidence document.

WHY THIS EXISTS
---------------
Four streams produce the nine evidence stages. If each builds its own
:class:`~secp_acceptance.recorder.AcceptanceRecorder`, there is no run — there are four partial
documents that cannot be reconciled, ``stages_attempted`` means "whatever this module happened to
open", and any cross-stage property (every stage covered; the fleet that installed the worker is the
fleet that enrolled it) becomes unstateable. The evidence document is this harness's product, and a
product assembled from four disagreeing drafts is not one.

So the run is a SESSION-scoped object. Stages do not construct it; they are handed it.

THE FOUR-LINE CONTRACT FOR A STAGE
----------------------------------
1. ``run.open_stage(STAGE_X)`` — commits the run to covering every check that stage declares.
2. Record EVERY check the stage declares, through ``run.observe`` / ``expect_refusal`` /
   ``unproven`` / ``violated``. A check you cannot settle is ``unproven``; it is never omitted.
3. Reach hosts ONLY through :mod:`secp_acceptance.shell`. That is already structurally enforced
   (``test_acceptance_process_seam.py`` proves no other module can spawn a process), and it is what
   makes execution provenance countable later.
4. NEVER hand raw command output to ``observe``. Pass the bounded, secret-free projection the check
   actually asserted on — only its content address is stored.

WHAT SEALING GUARANTEES, AND WHAT IT DOES NOT
---------------------------------------------
:meth:`AcceptanceRun.seal` derives the verdict; nothing can assert ``passed``. A run that never
reached a stage simply does not carry it, and the document says so in ``stages_attempted`` — it does
NOT silently read as complete. Completeness is :meth:`AcceptanceEvidence.coverage_complete`, and
whether the run is a valid ACCEPTANCE result at all is a separate judgement the completion gate
makes over this document plus the execution record.

SINGLE PROCESS, AND WHY THAT IS CHECKED
---------------------------------------
The recorder accumulates in memory, so the run is meaningful only within one process. The container
tier is one ``pytest`` invocation (see ``.github/workflows/acceptance.yml``), so this holds today —
but ``.ci/pytest-suite.json`` shards the ORDINARY corpus by FILE, and the acceptance stages are
about to span several files. If anyone ever parallelises the container tier, each worker would seal
its own partial document and every one of them would look like a run. :meth:`assert_single_process`
refuses that arrangement instead of producing four plausible lies.
"""

from __future__ import annotations

import os
import pathlib

from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import (
    AcceptanceEvidence,
    FleetRecord,
    ReleaseRecord,
    canonical_bytes,
    observation_digest,
)
from secp_acceptance.recorder import AcceptanceRecorder

#: Where the sealed document is written. Read by the completion gate and uploaded by the acceptance
#: workflow. Relative to the repository root, so it is the same path in CI and locally.
EVIDENCE_FILENAME = "acceptance-evidence.json"

#: Environment variable pytest-xdist sets in each worker process. Its PRESENCE is the signal; the
#: value ("gw0", "gw1", ...) does not matter.
_XDIST_WORKER = "PYTEST_XDIST_WORKER"


def assert_single_process() -> None:
    """Refuse a parallelised run, which would seal one partial document per worker.

    Keyed on the environment variable xdist actually sets rather than on whether the plugin is
    importable: the plugin being installed is harmless, and it is only distributing work that breaks
    the run.
    """
    if os.environ.get(_XDIST_WORKER):
        raise AcceptanceError("acceptance_run_not_single_process")


def _release_not_established() -> ReleaseRecord:
    """The release lineage of a run that never built one.

    Every field is a digest of the STATEMENT that no release was established, not a
    plausible-looking stand-in. A run reaching this has not covered the packages or worker_install
    stages, so it cannot seal ``passed`` anyway — but the document must still say plainly that there
    was no lineage, rather than carrying a shape a later reader could mistake for one.
    """
    absent = observation_digest({"release": "none_established"})
    return ReleaseRecord(
        role="worker",
        baseline_aggregate=absent,
        # The git NULL object id. A source sha must be a 40-hex commit identity, and there is no
        # honest commit to name here — this is git's own conventional spelling of "no object",
        # which is both truthful and inside the grammar.
        baseline_source_sha="0" * 40,
        signing_anchor_id=absent,
        # True is the honest value: no anchor was used at all, and this field exists to guarantee no
        # PRODUCTION anchor was. Recording False here would assert the opposite of what happened.
        test_only_anchor=True,
    )


class AcceptanceRun:
    """One acceptance run. Constructed once per session and handed to every stage.

    Delegates the recording verbs rather than exposing the recorder, so a stage cannot reach past
    the run and open a second one.
    """

    def __init__(self, *, recorder: AcceptanceRecorder | None = None) -> None:
        assert_single_process()
        self._recorder = recorder or AcceptanceRecorder()
        self._fleet_record: FleetRecord | None = None
        self._release_record: ReleaseRecord | None = None
        self._sealed: AcceptanceEvidence | None = None

    # --- what a stage calls ---------------------------------------------------------------

    def open_stage(self, stage: str) -> None:
        self._recorder.open_stage(stage)

    def observe(self, check: str, stage: str, observation: object) -> None:
        self._recorder.observe(check, stage, observation)

    def expect_refusal(
        self, check: str, stage: str, *, expected: str, actual: str | None, observation: object
    ) -> bool:
        return self._recorder.expect_refusal(
            check, stage, expected=expected, actual=actual, observation=observation
        )

    def unproven(self, check: str, stage: str, *, reason_code: str, observation: object) -> None:
        self._recorder.unproven(check, stage, reason_code=reason_code, observation=observation)

    def violated(self, check: str, stage: str, *, reason_code: str, observation: object) -> None:
        self._recorder.violated(check, stage, reason_code=reason_code, observation=observation)

    def declare_gap(
        self, *, gap: str, stage: str, substitute: str, why: str, weakens: tuple[str, ...]
    ) -> None:
        self._recorder.declare_gap(
            gap=gap, stage=stage, substitute=substitute, why=why, weakens=weakens
        )

    # --- what the fleet and release owners call -------------------------------------------

    def set_fleet(self, record: FleetRecord) -> None:
        """Record the fleet that was actually built. Owned by the SESSION-scoped fleet fixture.

        Idempotent for the same fleet, and REFUSES a different one. The document carries exactly one
        :class:`~secp_acceptance.evidence.FleetRecord`, so two fleets in a session would produce a
        document that describes one machine pair while carrying claims gathered against two — with
        nothing in the evidence to say which check belongs to which. That is not a discrepancy a
        reader could detect afterwards, so it is refused at the moment it happens.

        This is why the fleet fixture must be session-scoped rather than module-scoped: as stage
        modules multiply, module scope silently builds a second fleet for the second module.
        """
        if self._fleet_record is not None and self._fleet_record != record:
            raise AcceptanceError("acceptance_run_fleet_conflict")
        self._fleet_record = record

    def set_release(self, record: ReleaseRecord) -> None:
        """Record the signed release lineage the run installed across.

        Owned by the packages stage — the only one that builds a release.
        """
        self._release_record = record

    # --- introspection --------------------------------------------------------------------

    @property
    def stages(self) -> tuple[str, ...]:
        return self._recorder.stages

    def missing(self) -> tuple[str, ...]:
        return self._recorder.missing()

    @property
    def sealed(self) -> AcceptanceEvidence | None:
        return self._sealed

    # --- sealing --------------------------------------------------------------------------

    def seal(self) -> AcceptanceEvidence:
        """Seal the run into an evidence document. Idempotent within a session.

        Refuses when no fleet was recorded: every stage's claims are claims ABOUT a fleet, and a
        document whose fleet record was invented rather than observed would misdescribe the thing
        every other field depends on.
        """
        if self._sealed is not None:
            return self._sealed
        if self._fleet_record is None:
            raise AcceptanceError("acceptance_run_fleet_not_recorded")
        self._sealed = self._recorder.seal(
            fleet=self._fleet_record,
            release=self._release_record or _release_not_established(),
        )
        return self._sealed

    def write(self, root: pathlib.Path) -> pathlib.Path:
        """Seal (if needed) and write the canonical document. Returns the path written."""
        document = self.seal()
        path = pathlib.Path(root) / EVIDENCE_FILENAME
        path.write_bytes(canonical_bytes(document))
        return path


__all__ = [
    "EVIDENCE_FILENAME",
    "AcceptanceRun",
    "assert_single_process",
]
