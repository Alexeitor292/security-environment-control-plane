"""Worker-owned remote-state readiness orchestration (B1B-PR4 / ADR-021 §B, §D).

The single worker seam that turns an authoritative readiness binding into immutable, redacted,
expiry-bound remote-state readiness evidence and then **STOPS**. It is **sealed by default**: the
shipped composition disables the gate and injects no adapter, so no shipped runtime path can reach a
real state backend.

Ordering (fail closed; every privileged seam runs only AFTER its gate):

  seal → AUTHORITATIVE BINDING (manifest/plan/target/onboarding/toolchain + CURRENT eligible live
  eligibility evidence + worker identity) → operation fingerprint → terminal-replay short-circuit →
  started audit → adapter contract + no-state-body-surface check → **THE ONLY BACKEND CONTACT**
  (bounded control-metadata validation) → typed evaluation → immutable persistence → completed audit
  → STOP.

It runs no OpenTofu, executes no subprocess, renders no workspace, resolves no secret, mints no
activation grant, creates no plan, and **cannot read or write an OpenTofu state body** (the adapter
contract has no such method, and one that exposes it is refused before invocation).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    ReadinessOperationKind,
    ReadinessReason,
    RemoteStateReadinessOutcome,
)
from secp_api.readiness_binding import load_readiness_binding
from secp_api.readiness_contract import (
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    ReadinessBinding,
    as_utc,
    is_placeholder_dossier,
)
from secp_api.toolchain_profile import validate_toolchain_profile
from sqlalchemy.orm import Session

from secp_worker.readiness.capability import (
    AdapterCapabilityRefused,
    issue_readiness_adapter_capability,
    issue_test_only_capability,
)
from secp_worker.readiness.composition import ReadinessComposition, sealed_readiness_composition
from secp_worker.readiness.state_adapter import (
    RemoteStateAdapterReport,
    RemoteStateReadinessBinding,
    RemoteStateReadinessUnavailable,
    assert_no_state_body_surface,
)
from secp_worker.readiness.state_evaluation import evaluate_remote_state_readiness

_R = ReadinessReason


class RemoteStateReadinessRefused(Exception):
    """Internal control-flow signal carrying a closed, secret-free reason code."""

    def __init__(self, reason: ReadinessReason) -> None:
        super().__init__(f"remote-state readiness refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True)
class RemoteStateReadinessResult:
    """Closed, secret-free outcome of one attempt (safe for audit and the read model)."""

    outcome: str
    reason_code: str | None = None
    record_id: uuid.UUID | None = None
    evidence_hash: str | None = None
    reused: bool = False


def _manifest_organization(session: Session, manifest_id: uuid.UUID) -> uuid.UUID | None:
    """The manifest's organization, for audit scoping only. It derives no binding and contacts
    nothing — it exists so a SEALED refusal is still recorded inside its organization's audit."""
    from secp_api.models import ProvisioningManifest

    manifest = session.get(ProvisioningManifest, manifest_id)
    return None if manifest is None else manifest.organization_id


def _terminal_record(session: Session, binding: ReadinessBinding):
    """The TERMINAL (``ready``) record already written for this EXACT operation, or ``None``.

    Only a ``ready`` record is a TERMINAL result. A NON-ready attempt (``not_ready`` /
    ``unverifiable`` / ``unavailable``) must NOT short-circuit a retry — otherwise one transient
    backend blip would permanently poison the operation and the bounded retry budget would be
    unreachable. Non-ready attempts therefore append as immutable attempt history, and only a
    ``ready`` record is exact-once (enforced by a PARTIAL unique index).
    """
    from secp_api.models import RemoteStateReadinessRecord

    return (
        session.query(RemoteStateReadinessRecord)
        .filter(
            RemoteStateReadinessRecord.provisioning_manifest_id
            == uuid.UUID(binding.provisioning_manifest_id),
            RemoteStateReadinessRecord.operation_fingerprint == binding.operation_fingerprint(),
            RemoteStateReadinessRecord.outcome == RemoteStateReadinessOutcome.ready,
        )
        .one_or_none()
    )


def run_remote_state_readiness(
    session: Session,
    *,
    manifest_id: uuid.UUID,
    composition: ReadinessComposition | None = None,
    now: datetime | None = None,
) -> RemoteStateReadinessResult:
    """Run the sealed-by-default remote-state readiness operation, then STOP.

    On any gate refusal it contacts nothing, persists no evidence, and records a secret-free
    ``remote_state_readiness_refused`` audit with a closed reason code.
    """
    composition = composition or sealed_readiness_composition()
    now = now or datetime.now(UTC)

    binding: ReadinessBinding | None = None
    # Org scope for the refusal audit ONLY. Reading the manifest row is not a privileged boundary:
    # it contacts nothing, builds no adapter, and derives no binding. Without it a sealed refusal
    # would be recorded with a NULL organization and fall outside org-scoped audit review.
    organization_id: uuid.UUID | None = _manifest_organization(session, manifest_id)

    def refuse(reason: ReadinessReason) -> RemoteStateReadinessResult:
        audit.record(
            session,
            action=AuditAction.remote_state_readiness_refused,
            resource_type="provisioning_manifest",
            resource_id=manifest_id,
            organization_id=organization_id,
            actor="worker",
            outcome="refused",
            data={
                "operation_kind": ReadinessOperationKind.remote_state_readiness.value,
                "provisioning_manifest_id": str(manifest_id),
                "reason_code": reason.value,
                "adapter_contract_version": REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
            },
        )
        return RemoteStateReadinessResult(
            outcome=RemoteStateReadinessOutcome.refused.value, reason_code=reason.value
        )

    try:
        # 0. SEAL — a disabled gate refuses before any adapter exists or any record is loaded.
        if not composition.gate.enabled:
            raise RemoteStateReadinessRefused(_R.sealed)

        # 0b. REVIEWED ACTIVATION — the adapter and its deployment-local activation are BOTH
        #     required. A self-declared ``contract_version`` is never provenance (B1B-PR4 §3), and
        #     the fail-closed dossier PLACEHOLDER can never authorize anything (§4).
        adapter = composition.state_adapter
        activation = composition.state_adapter_activation
        if adapter is None:
            raise RemoteStateReadinessRefused(_R.adapter_unavailable)
        if activation is None:
            raise RemoteStateReadinessRefused(_R.adapter_capability_missing)
        if is_placeholder_dossier(activation.activation_dossier_hash):
            raise RemoteStateReadinessRefused(_R.activation_dossier_placeholder)

        # 1. AUTHORITATIVE BINDING — derived from the records, never from a caller. It fails closed
        #    unless the CURRENT live eligibility evidence is live_verified + eligible + current +
        #    unexpired + undrifted + hash-valid; the toolchain profile is active, valid,
        #    hash-consistent and REMOTE-state-backed; a DURABLE toolchain ATTESTATION exists; and
        #    the target has an ACTIVE opaque credential binding. The REVIEWED dossier hash from the
        #    activation is folded into the operation fingerprint.
        result = load_readiness_binding(
            session,
            manifest_id=manifest_id,
            operation_kind=ReadinessOperationKind.remote_state_readiness,
            now=now,
            activation_dossier_hash=activation.activation_dossier_hash,
        )
        if result.binding is None or result.toolchain is None or result.attestation is None:
            raise RemoteStateReadinessRefused(result.reason or _R.gate_incomplete)
        binding = result.binding
        organization_id = uuid.UUID(binding.organization_id)

        # 2. TERMINAL REPLAY — an exact retry within the TTL returns the durable TERMINAL
        #    (``ready``) record with no second backend contact and no duplicate audit. A NON-ready
        #    attempt never short-circuits: a retry is legitimate and appends a NEW immutable record.
        #    An EXPIRED ready record is NEVER replayed as fresh readiness and is NEVER mutated (the
        #    readiness TTL equals the eligibility TTL, and readiness is collected AFTER eligibility,
        #    so an expired readiness record always implies an already-refused eligibility binding).
        existing = _terminal_record(session, binding)
        if existing is not None:
            expired = as_utc(existing.expires_at) <= now
            return RemoteStateReadinessResult(
                outcome=(
                    RemoteStateReadinessOutcome.expired.value
                    if expired
                    else getattr(existing.outcome, "value", str(existing.outcome))
                ),
                record_id=existing.id,
                evidence_hash=existing.evidence_hash,
                reused=True,
            )

        # 3. STARTED — every gate has passed; the backend contact is about to happen exactly once.
        audit.record(
            session,
            action=AuditAction.remote_state_readiness_started,
            resource_type="provisioning_manifest",
            resource_id=manifest_id,
            organization_id=organization_id,
            actor="worker",
            data={
                "operation_kind": ReadinessOperationKind.remote_state_readiness.value,
                "provisioning_manifest_id": str(manifest_id),
                "operation_fingerprint": binding.operation_fingerprint(),
                # The immutable PROFILE hash + a UUID-derived namespace identity. Never a digest of
                # the backend reference (that would be an offline confirmation oracle for it).
                "toolchain_profile_hash": binding.toolchain_profile_hash,
                "state_namespace_hash": binding.state_namespace_identity,
                "adapter_contract_version": REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
            },
        )

        # 4. ADAPTER PROVENANCE CAPABILITY — the adapter's own ``contract_version`` is NEVER
        #    sufficient. The reviewed activation must pin the exact IMPLEMENTATION digest, a
        #    non-placeholder dossier, and exactly this operation's org/target/onboarding/manifest/
        #    plan/worker-identity. A fake adapter that claims the right version and returns all-pass
        #    evidence obtains no capability and is refused here.
        if getattr(adapter, "contract_version", "") != REMOTE_STATE_ADAPTER_CONTRACT_VERSION:
            raise RemoteStateReadinessRefused(_R.adapter_contract_mismatch)
        issue = (
            issue_test_only_capability
            if composition.test_only_capability
            else issue_readiness_adapter_capability
        )
        try:
            capability = issue(
                activation=activation,
                binding=binding,
                adapter=adapter,
                operation_kind=ReadinessOperationKind.remote_state_readiness,
                now=now,
            )
        except AdapterCapabilityRefused as exc:
            raise RemoteStateReadinessRefused(
                ReadinessReason(exc.reason_code)
                if exc.reason_code in {r.value for r in ReadinessReason}
                else _R.adapter_capability_invalid
            ) from exc

        # Structural defence: an adapter exposing a state-body / force-unlock surface is refused
        # BEFORE it is ever invoked.
        try:
            assert_no_state_body_surface(adapter)
        except RemoteStateReadinessUnavailable as exc:
            raise RemoteStateReadinessRefused(_R.state_body_access_attempted) from exc

        # The worker-local typed binding: the raw backend kind + opaque reference never leave here.
        spec = validate_toolchain_profile(result.toolchain.content)
        adapter_binding = RemoteStateReadinessBinding(
            binding=binding,
            state_backend_kind=spec.state_backend.kind,
            state_backend_reference=spec.state_backend.reference,
        )

        # 5. THE ONLY BACKEND CONTACT — bounded control-metadata validation. No state body is read
        #    or written; there is no interface through which one could be.
        try:
            report = adapter.evaluate(adapter_binding, now=now)
        except RemoteStateReadinessUnavailable as exc:
            raise RemoteStateReadinessRefused(_R.adapter_unavailable) from exc
        except Exception as exc:
            # A backend exception body / stack trace is NEVER surfaced, audited, or persisted.
            raise RemoteStateReadinessRefused(_R.adapter_report_invalid) from exc
        if not isinstance(report, RemoteStateAdapterReport):
            raise RemoteStateReadinessRefused(_R.adapter_report_invalid)

        # 6. TYPED EVALUATION — every mandatory facet explicitly; unprovable facts fail closed.
        evaluation = evaluate_remote_state_readiness(binding=binding, report=report, now=now)

        # 7. IMMUTABLE PERSISTENCE — only AFTER the typed evaluation. Worker-only recorder.
        from secp_worker.readiness.recorder import (
            ReadinessRecordingRefused,
            record_remote_state_readiness,
        )

        try:
            row = record_remote_state_readiness(
                session,
                binding=binding,
                evaluation=evaluation,
                capability=capability,
                attestation_id=result.attestation.id,
                now=now,
            )
        except ReadinessRecordingRefused as exc:
            raise RemoteStateReadinessRefused(_R.evidence_too_large) from exc

        # 8. STOP. Readiness does not create a plan, mint a grant, or dispatch anything.
        return RemoteStateReadinessResult(
            outcome=evaluation.outcome,
            record_id=row.id,
            evidence_hash=row.evidence_hash,
        )
    except RemoteStateReadinessRefused as exc:
        return refuse(exc.reason)
