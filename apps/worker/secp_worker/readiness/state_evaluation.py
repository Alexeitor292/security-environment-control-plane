"""Pure, deterministic remote-state readiness evaluation (B1B-PR4 / ADR-021 §D).

Given the authoritative binding and one TYPED adapter report, it evaluates EVERY mandatory facet
explicitly and returns a single closed outcome. There is no partial credit and no score:

* ``ready`` requires every mandatory facet to ``pass`` explicitly;
* any explicit violation is ``not_ready``;
* any fact that cannot be PROVEN (an absent proof, unavailable scope evidence, an undeterminable
  namespace occupancy) fails closed to ``unverifiable`` — never a fabricated pass;
* a stale proof is ``expired``; a binding disagreement is ``drifted``.

It performs no I/O, contacts nothing, and imports no adapter implementation, transport, HTTP,
subprocess, or secret code.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from secp_api.enums import (
    ReadinessFacetStatus,
    ReadinessReason,
    RemoteStateReadinessFacet,
    RemoteStateReadinessOutcome,
)
from secp_api.readiness_contract import (
    BACKEND_CLASS_LOCAL,
    BACKEND_CLASS_REMOTE,
    BACKEND_CLASS_UNKNOWN,
    FORBIDDEN_STATE_ACTIONS,
    LOCAL_STATE_TOKENS,
    MAX_EVIDENCE_REASONS,
    PLAN_ALLOWED_STATE_ACTIONS,
    STATE_PROOF_MAX_AGE,
    TLS_MODE_VERIFIED,
    TRUSTED_IDENTITY_POLICIES,
    ReadinessBinding,
    as_utc,
    is_opaque_proof_id,
    state_namespace_marker,
)

from secp_worker.readiness.state_adapter import (
    LockCapabilityProof,
    RemoteStateAdapterReport,
    StateProof,
)

_F = RemoteStateReadinessFacet
_S = ReadinessFacetStatus
_R = ReadinessReason

# Proof ids and issuers MUST be UUIDs — never free labels (see ``is_opaque_proof_id``).

# The CLOSED set of backend classes that may become durable evidence.
_BACKEND_CLASSES = frozenset({BACKEND_CLASS_REMOTE, BACKEND_CLASS_LOCAL, BACKEND_CLASS_UNKNOWN})


def _safe_backend_class(value: object) -> str:
    """Map the adapter-supplied class onto the CLOSED set; anything else becomes ``unknown``."""
    if isinstance(value, str) and value in _BACKEND_CLASSES:
        return value
    return BACKEND_CLASS_UNKNOWN


@dataclass(frozen=True)
class FacetResult:
    facet: str
    status: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemoteStateEvaluation:
    """The closed, secret-free evaluation of one remote-state readiness attempt."""

    outcome: str
    facets: tuple[FacetResult, ...]
    reason_codes: tuple[str, ...]
    backend_class: str
    # UUIDs (or None) — never labels, never digests of labels.
    encryption_proof_id: uuid.UUID | None = None
    lock_proof_id: uuid.UUID | None = None
    backup_proof_id: uuid.UUID | None = None
    restore_proof_id: uuid.UUID | None = None

    def facet_payload(self) -> list[dict]:
        return [{"facet": f.facet, "status": f.status} for f in self.facets]


def _is_safe_label(value: object) -> bool:
    """True iff ``value`` is an OPAQUE proof id (a UUID)."""
    return value is not None and is_opaque_proof_id(str(value))


def _persisted_proof_id(label: object) -> uuid.UUID | None:
    """The proof id persisted verbatim — it is a UUID, so it can never BE a backend locator.

    A free label (``acme-tfstate.s3.amazonaws.com``) would be a locator, and an unsalted DIGEST of a
    label would be a confirmation oracle for one. Requiring a UUID removes both.
    """
    return uuid.UUID(str(label)) if _is_safe_label(label) else None


def _proof_is_bound(proof: StateProof, binding: ReadinessBinding) -> bool:
    return (
        proof.toolchain_profile_hash == binding.toolchain_profile_hash
        and proof.namespace_hash == binding.state_namespace_identity
    )


def _proof_is_fresh(
    proof: StateProof | LockCapabilityProof, now: datetime, max_age: timedelta
) -> bool:
    """A proof is fresh when it has not passed its own expiry AND is within the policy max age."""
    expires_at = getattr(proof, "expires_at", None)
    if expires_at is not None and as_utc(expires_at) <= now:
        return False
    performed_at = as_utc(proof.performed_at)
    if performed_at > now:
        return False  # a future-dated proof is never accepted
    return (now - performed_at) <= max_age


def _proof_metadata_is_safe(proof: StateProof | LockCapabilityProof) -> bool:
    return _is_safe_label(proof.proof_id) and _is_safe_label(proof.issuer)


def evaluate_remote_state_readiness(  # noqa: C901,PLR0912,PLR0915 - one explicit branch per facet
    *,
    binding: ReadinessBinding,
    report: RemoteStateAdapterReport,
    now: datetime,
) -> RemoteStateEvaluation:
    """Evaluate every mandatory remote-state facet explicitly and return one closed outcome."""
    facets: list[FacetResult] = []
    reasons: list[str] = []

    def add(facet: _F, status: _S, *facet_reasons: ReadinessReason) -> None:
        codes = tuple(r.value for r in facet_reasons)
        facets.append(FacetResult(facet=facet.value, status=status.value, reasons=codes))
        reasons.extend(codes)

    # --- 1. backend_class: remote only; exact agreement with the ToolchainProfile binding ---------
    backend_reasons: list[ReadinessReason] = []
    kind_token = str(report.backend_kind or "").strip().lower()
    if report.backend_class == BACKEND_CLASS_LOCAL or kind_token in LOCAL_STATE_TOKENS:
        backend_reasons.append(_R.state_backend_local)
    elif report.backend_class != BACKEND_CLASS_REMOTE:
        backend_reasons.append(_R.state_backend_missing)
    if report.toolchain_profile_hash != binding.toolchain_profile_hash:
        # The adapter was activated against a DIFFERENT toolchain profile — i.e. a different pinned
        # backend. Backend substitution fails closed.
        backend_reasons.append(_R.state_backend_reference_drift)
    if backend_reasons:
        add(_F.backend_class, _S.failed, *backend_reasons)
    else:
        add(_F.backend_class, _S.passed)

    # --- 2. transport_security -------------------------------------------------------------------
    tls_reasons: list[ReadinessReason] = []
    if report.tls_mode != TLS_MODE_VERIFIED or not report.certificate_validation_enabled:
        tls_reasons.append(_R.state_tls_disabled)
    if report.trusted_identity_policy not in TRUSTED_IDENTITY_POLICIES:
        tls_reasons.append(_R.state_tls_disabled)
    if report.proxy_inheritance_enabled:
        tls_reasons.append(_R.state_trust_env_enabled)
    if report.redirect_observed:
        tls_reasons.append(_R.state_redirect_observed)
    if not report.destination_stable:
        tls_reasons.append(_R.state_destination_unstable)
    if tls_reasons:
        add(_F.transport_security, _S.failed, *tls_reasons)
    else:
        add(_F.transport_security, _S.passed)

    # --- 3. namespace_identity: deterministic, server-derived, collision-resistant, org-scoped ----
    if not report.namespace_identity:
        add(_F.namespace_identity, _S.unverifiable, _R.state_namespace_unknown)
    elif report.namespace_identity != binding.state_namespace_identity:
        # The adapter would use a namespace SECP did not derive — a caller-selected state key, a
        # display-name-derived path, or another organization's namespace. All fail closed.
        add(_F.namespace_identity, _S.failed, _R.state_namespace_mismatch)
    else:
        add(_F.namespace_identity, _S.passed)

    # --- 4. encryption_at_rest: explicit backend-derived proof; never inferred from HTTPS/type ----
    encryption_id = None
    proof = report.encryption
    if proof is None:
        add(_F.encryption_at_rest, _S.unverifiable, _R.state_encryption_proof_absent)
    elif not _proof_metadata_is_safe(proof):
        add(_F.encryption_at_rest, _S.failed, _R.state_proof_id_not_opaque)
    elif not _proof_is_bound(proof, binding):
        add(_F.encryption_at_rest, _S.failed, _R.state_encryption_proof_unbound)
    elif not _proof_is_fresh(proof, now, STATE_PROOF_MAX_AGE):
        add(_F.encryption_at_rest, _S.failed, _R.state_encryption_proof_stale)
    else:
        encryption_id = _persisted_proof_id(proof.proof_id)
        add(_F.encryption_at_rest, _S.passed)

    # --- 5. locking: explicit capability + contention detection; no force-unlock; probe released --
    lock_id = None
    lock = report.locking
    if lock is None:
        add(_F.locking, _S.unverifiable, _R.state_lock_unavailable)
    elif not _proof_metadata_is_safe(lock):
        add(_F.locking, _S.failed, _R.state_proof_id_not_opaque)
    elif (
        lock.namespace_hash != binding.state_namespace_identity
        or lock.toolchain_profile_hash != binding.toolchain_profile_hash
    ):
        # A lock proof issued against a DIFFERENT backend (or a different namespace) proves nothing
        # about THIS backend's locking — exactly as for the encryption/backup/restore proofs.
        add(_F.locking, _S.failed, _R.state_lock_proof_unbound)
    elif not _proof_is_fresh(lock, now, STATE_PROOF_MAX_AGE):
        add(_F.locking, _S.failed, _R.state_lock_unavailable)
    else:
        lock_reasons: list[ReadinessReason] = []
        if not lock.lock_capability:
            lock_reasons.append(_R.state_lock_unavailable)
        if not lock.contention_detected:
            # Lock contention MUST be correctly detected; a backend that silently grants a second
            # lock is unsafe. A documentation flag is never sufficient.
            lock_reasons.append(_R.state_lock_contention_undetected)
        if lock.force_unlock_available:
            lock_reasons.append(_R.state_lock_force_unlock_available)
        if lock.caller_supplied_owner:
            lock_reasons.append(_R.state_lock_owner_caller_supplied)
        if not lock.probe_released:
            # The bounded ephemeral probe was not released in a ``finally``: a leaked readiness lock
            # is a durable side effect. Fail closed rather than leave it held.
            lock_reasons.append(_R.state_lock_probe_not_released)
        if lock_reasons:
            add(_F.locking, _S.failed, *lock_reasons)
        else:
            lock_id = _persisted_proof_id(lock.proof_id)
            add(_F.locking, _S.passed)

    # --- 6/7. backup_proof + restore_proof: VALIDATED external proofs; PR4 performs neither -------
    backup_id = _evaluate_state_proof(
        report.backup,
        facet=_F.backup_proof,
        binding=binding,
        now=now,
        absent=_R.state_backup_proof_absent,
        stale=_R.state_backup_proof_stale,
        unbound=_R.state_backup_proof_unbound,
        add=add,
    )
    restore_id = _evaluate_state_proof(
        report.restore,
        facet=_F.restore_proof,
        binding=binding,
        now=now,
        absent=_R.state_restore_proof_absent,
        stale=_R.state_restore_proof_stale,
        unbound=_R.state_restore_proof_unbound,
        add=add,
        require_restore_tested=True,
    )

    # --- 8. least_privileged_access: EXACT allowed actions; a metadata read is never proof --------
    if not report.scope_evidence_available or not report.allowed_actions:
        add(_F.least_privileged_access, _S.unverifiable, _R.state_least_privilege_unproven)
    else:
        actions = {str(a).strip().lower() for a in report.allowed_actions}
        excessive = (actions & FORBIDDEN_STATE_ACTIONS) or (actions - PLAN_ALLOWED_STATE_ACTIONS)
        if excessive:
            # Delete / force-unlock / admin / bucket-wide / wildcard grants are never required by a
            # plan-only operation. Excess privilege fails closed (the reason code names no action).
            add(_F.least_privileged_access, _S.failed, _R.state_privilege_excessive)
        else:
            add(_F.least_privileged_access, _S.passed)

    # --- 9. empty_or_expected_namespace: metadata/version identity only; the body is NEVER read ---
    if report.namespace_state_present is None:
        add(_F.empty_or_expected_namespace, _S.unverifiable, _R.state_namespace_unknown)
    elif not report.namespace_state_present:
        add(_F.empty_or_expected_namespace, _S.passed)
    elif report.expected_namespace_marker == state_namespace_marker(
        binding.state_namespace_identity
    ):
        # The ONE marker that may excuse an occupied namespace, and it is SERVER-DERIVED: the
        # adapter must present exactly the value derived from THIS operation's server-derived
        # namespace identity. It cannot self-attest its way past an occupied namespace with a marker
        # of its own choosing. The decision uses metadata/version identity only — no state body is
        # read.
        add(_F.empty_or_expected_namespace, _S.passed)
    else:
        add(_F.empty_or_expected_namespace, _S.failed, _R.state_namespace_occupied)

    # --- 10. no_local_fallback -------------------------------------------------------------------
    if report.local_fallback_available:
        add(_F.no_local_fallback, _S.failed, _R.state_local_fallback_available)
    else:
        add(_F.no_local_fallback, _S.passed)

    # Bounded, closed adapter-supplied reason codes (free text / oversized values are dropped, so an
    # adapter can never smuggle a backend URL, key, or response body into durable evidence).
    for code in report.reason_codes[:MAX_EVIDENCE_REASONS]:
        try:
            reasons.append(ReadinessReason(str(code)).value)
        except ValueError:
            reasons.append(_R.adapter_report_invalid.value)

    statuses = {f.status for f in facets}
    if _S.failed.value in statuses:
        outcome = RemoteStateReadinessOutcome.not_ready
    elif _S.unverifiable.value in statuses:
        outcome = RemoteStateReadinessOutcome.unverifiable
    else:
        outcome = RemoteStateReadinessOutcome.ready

    # ``ready`` requires EVERY mandatory facet to be present AND passing — a report that omits a
    # facet entirely can never be ready.
    if outcome is RemoteStateReadinessOutcome.ready and {f.facet for f in facets} != {
        f.value for f in RemoteStateReadinessFacet
    }:  # pragma: no cover - defensive; every facet is emitted above
        outcome = RemoteStateReadinessOutcome.unverifiable

    return RemoteStateEvaluation(
        outcome=outcome.value,
        facets=tuple(facets),
        reason_codes=tuple(dict.fromkeys(reasons))[:MAX_EVIDENCE_REASONS],
        backend_class=_safe_backend_class(report.backend_class),
        encryption_proof_id=encryption_id,
        lock_proof_id=lock_id,
        backup_proof_id=backup_id,
        restore_proof_id=restore_id,
    )


def _evaluate_state_proof(
    proof: StateProof | None,
    *,
    facet: _F,
    binding: ReadinessBinding,
    now: datetime,
    absent: ReadinessReason,
    stale: ReadinessReason,
    unbound: ReadinessReason,
    add,  # noqa: ANN001 - a local closure
    require_restore_tested: bool = False,
) -> uuid.UUID | None:
    """Validate one immutable external proof. PR4 never performs the backup or the restore
    itself."""
    if proof is None:
        add(facet, _S.unverifiable, absent)
        return None
    if not _proof_metadata_is_safe(proof):
        add(facet, _S.failed, _R.state_proof_id_not_opaque)
        return None
    if not _proof_is_bound(proof, binding):
        add(facet, _S.failed, unbound)
        return None
    if not _proof_is_fresh(proof, now, STATE_PROOF_MAX_AGE):
        add(facet, _S.failed, stale)
        return None
    if require_restore_tested and not proof.restore_tested:
        # A restore proof must evidence a SUCCESSFUL TESTED restore — the mere existence of a
        # restore capability is not proof, and PR4 performs no restore against real state.
        add(facet, _S.failed, absent)
        return None
    add(facet, _S.passed)
    return _persisted_proof_id(proof.proof_id)
