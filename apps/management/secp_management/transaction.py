"""The explicit management-bootstrap transaction model (SECP-PR5E).

Phases are explicit and NEVER implicitly chained: ``inspect → plan → verify → write → reverify →
commit-evidence``. Every mutation defaults to DRY-RUN; a real write requires BOTH ``--write`` and
``--confirm``. On failure, only objects CREATED by this invocation are compensated — adopted /
pre-existing objects are never removed, and the ordinary worker is never restarted as compensation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Report modes (the engine returns one; the CLI never decides policy).
MODE_DRY_RUN = "dry_run"
MODE_WRITTEN = "written"
MODE_REFUSED = "refused"
MODE_ADOPTED = "adopted"

# Exit codes: 0 success (dry-run plan or a completed write/adoption), 2 refused/fail-closed.
EXIT_OK = 0
EXIT_REFUSED = 2
#: A refusal the caller could not have avoided and must not read as a finding: the operator-queue
#: containment probe did not complete, so NOTHING was observed about which queues the ordinary
#: worker serves. Still fail-closed and still non-zero — it never certifies — but distinct from
#: ``EXIT_REFUSED``, which for this dimension means "a containment breach was OBSERVED".
#:
#: The exit code is the only channel a shell reads without parsing the report, so conflating the
#: two here would leave automation paging someone for a containment incident when the real fault is
#: an unreachable probe. See ``queue_containment`` in ``secpctl status worker``.
#:
#: 11 is chosen because ``secpctl`` is ONE binary with ONE exit-code namespace: 0/1/2 are taken
#: here and by the signer broker, 3-9 by ``enrollment_cli``, and 10/20 by the discovery-activation
#: CLI. ADDITIVE ONLY — no existing code changes meaning.
EXIT_CONTAINMENT_UNPROVABLE = 11


@dataclass(frozen=True)
class WriteGate:
    """The dry-run vs write/confirm gate. A mutation proceeds only when BOTH flags are set."""

    write: bool
    confirm: bool

    @property
    def is_write(self) -> bool:
        return self.write and self.confirm

    def refusal_reason(self) -> str | None:
        """A closed reason when a write was partially requested (never a value)."""
        if self.write and not self.confirm:
            return "write_requires_confirm"
        if self.confirm and not self.write:
            return "confirm_requires_write"
        return None


@dataclass
class OwnershipLedger:
    """Objects CREATED by this transaction (rollback-owned) vs ADOPTED/pre-existing (never
    removed)."""

    created: list[str] = field(default_factory=list)
    adopted: list[str] = field(default_factory=list)

    def create(self, path_binding: str) -> None:
        if path_binding not in self.created:
            self.created.append(path_binding)

    def adopt(self, path_binding: str) -> None:
        if path_binding not in self.adopted:
            self.adopted.append(path_binding)
