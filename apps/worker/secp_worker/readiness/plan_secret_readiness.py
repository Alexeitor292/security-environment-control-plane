"""Worker-owned plan-secret readiness orchestration (B1B-PR4 / ADR-021 §H, §I, §J).

The single worker seam that proves the JUST-IN-TIME secret path is ready for a FUTURE plan-only
operation and then **STOPS**. It is **sealed by default**: the shipped composition disables the gate
and injects no resolver self-test, so no shipped runtime path can reach a real secret manager.

Ordering (fail closed; every privileged seam runs only AFTER its gate):

  seal → AUTHORITATIVE BINDING + independent worker re-verification (current eligible eligibility,
  current remote-state readiness, exact toolchain/dossier/manifest/plan/target/onboarding agreement)
  → EXACT plan-secret AUTHORIZATION (approved, unexpired, plan-read purpose, complete evidence
  fingerprint, exact operation-identity fingerprint) → worker identity / admission → supported
  credential-reference scheme + authoritative reference re-derivation → operation fingerprint →
  terminal-replay short-circuit → started audit → resolver-contract check → **acquire_lease** →
  **begin_attempt** (the ONLY budget-consuming transition; no secret-manager contact may happen
  before it) → **THE ONLY SECRET-BACKEND CONTACT** (the resolver SELF-TEST — it returns no target
  credential) → JIT environment-projection contract with an INERT sentinel → typed evaluation →
  immutable persistence → mark_consumed (only on a successful handling) → completed audit → STOP.

**The actual target provisioning credential is NOT resolved.** ``WorkerSecretResolver.resolve()`` is
never called here. Readiness proves (a) the worker can AUTHENTICATE to the backend, and (b) opaque
material projects into exactly the allowlisted environment. Both are proven without revealing a
target credential.

It runs no OpenTofu, executes no subprocess, renders no workspace, mints no activation
grant, creates no plan, never reads or mutates ``os.environ``, and never persists / logs /
audits / returns / serializes / hashes a secret or a secret reference.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    PlanSecretPurpose,
    PlanSecretReadinessOutcome,
    ReadinessOperationKind,
    ReadinessReason,
)
from secp_api.readiness_binding import load_readiness_binding
from secp_api.readiness_contract import (
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    PLAN_SECRET_SELF_TEST_POLICY_VERSION,
    PurposeNotPermitted,
    ReadinessBinding,
    as_utc,
    assert_plan_only_purpose,
    is_placeholder_dossier,
)
from secp_api.secret_refs import InvalidSecretRefError, parse_secret_ref
from sqlalchemy.orm import Session

from secp_worker.readiness.canary import inert_canary_material
from secp_worker.readiness.capability import (
    AdapterCapabilityRefused,
    issue_readiness_adapter_capability,
    issue_test_only_capability,
)
from secp_worker.readiness.composition import ReadinessComposition, sealed_readiness_composition
from secp_worker.readiness.plan_env import (
    PlanSecretEnvContract,
    PlanSecretEnvViolation,
    build_plan_secret_env,
    env_contract_is_satisfied,
)
from secp_worker.readiness.plan_secret_evaluation import evaluate_plan_secret_readiness
from secp_worker.readiness.plan_secret_lease import (
    PlanSecretLeaseRefused,
    PlanSecretOperationKey,
    acquire_lease,
    begin_attempt,
    mark_consumed,
)

_R = ReadinessReason

# The reference schemes a plan-read provisioning credential may use. ``env:`` is a development-only
# scheme and is NOT supported for a real plan-read credential.
SUPPORTED_PLAN_SECRET_SCHEMES = frozenset({"vault"})


class PlanSecretReadinessRefused(Exception):
    """Internal control-flow signal carrying a closed, secret-free reason code."""

    def __init__(self, reason: ReadinessReason) -> None:
        super().__init__(f"plan-secret readiness refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True)
class PlanSecretReadinessResult:
    """Closed, secret-free outcome of one attempt (safe for audit and the read model)."""

    outcome: str
    reason_code: str | None = None
    record_id: uuid.UUID | None = None
    evidence_hash: str | None = None
    reused: bool = False


def _manifest_organization(session: Session, manifest_id: uuid.UUID) -> uuid.UUID | None:
    """The manifest's organization, for audit scoping only. It derives no binding, builds no
    resolver, acquires no lease, and contacts nothing."""
    from secp_api.models import ProvisioningManifest

    manifest = session.get(ProvisioningManifest, manifest_id)
    return None if manifest is None else manifest.organization_id


def _terminal_record(session: Session, binding: ReadinessBinding):
    """The TERMINAL (``ready``) record already written for this EXACT operation, or ``None``.

    Only a ``ready`` record is a TERMINAL result. A NON-ready attempt (``not_ready`` /
    ``unavailable``) must NOT short-circuit a retry — otherwise one transient secret-backend blip
    would permanently poison the operation and the bounded N=3 retry budget would be unreachable.
    Non-ready attempts therefore append as immutable attempt history, and only a ``ready`` record is
    exact-once (enforced by a PARTIAL unique index).
    """
    from secp_api.models import PlanSecretReadinessRecord

    return (
        session.query(PlanSecretReadinessRecord)
        .filter(
            PlanSecretReadinessRecord.provisioning_manifest_id
            == uuid.UUID(binding.provisioning_manifest_id),
            PlanSecretReadinessRecord.operation_fingerprint == binding.operation_fingerprint(),
            PlanSecretReadinessRecord.outcome == PlanSecretReadinessOutcome.ready,
        )
        .one_or_none()
    )


def _evidence_fingerprint_matches(session: Session, authorization) -> bool:
    """Recompute the human-review evidence fingerprint and compare it to the approved value."""
    from secp_api.models import PlanSecretReadinessEvidence
    from secp_api.services.plan_secret_authorization import (
        compute_plan_secret_evidence_fingerprint,
        plan_secret_evidence_is_complete,
    )
    from sqlalchemy import select

    rows = list(
        session.execute(
            select(PlanSecretReadinessEvidence).where(
                PlanSecretReadinessEvidence.authorization_id == authorization.id
            )
        )
        .scalars()
        .all()
    )
    if not plan_secret_evidence_is_complete(rows):
        return False
    return compute_plan_secret_evidence_fingerprint(rows) == authorization.evidence_fingerprint


def _authoritative_reference_scheme(session: Session, binding: ReadinessBinding) -> str:
    """Re-derive the credential-reference SCHEME from the AUTHORITATIVE target row, in this session.

    The reference itself is a local: it is never returned, persisted, audited, logged, hashed, or
    placed in an exception. Only its bounded scheme leaves this function.

    **Reference-binding truth (documented honestly).** The provisioning path has NO third,
    independent copy of the credential reference: ``ProvisioningManifest`` is secret-free BY
    DESIGN, so — unlike the read-only preflight path, which has a separate
    ``LiveReadCollectionBinding.credential_ref`` — there is no third source to compare. PR4
    therefore enforces the strongest binding that is
    actually TRUE: the candidate reference is re-derived from the ExecutionTarget row reached ONLY
    through the manifest's pinned ``target_config_hash`` (so a substituted target fails the binding
    first), and its SCHEME must equal the scheme a human reviewed and pinned on the authorization.
    A genuine third reference source (e.g. a dossier-bound credential reference) is an explicit
    implementation prerequisite for B1B-PR5, not something fabricated here.
    """
    from secp_api.models import ExecutionTarget

    target = session.get(ExecutionTarget, uuid.UUID(binding.execution_target_id))
    if target is None:
        raise PlanSecretReadinessRefused(_R.secret_authorization_binding_invalid)
    if target.config_hash != binding.target_config_hash:
        raise PlanSecretReadinessRefused(_R.target_config_drift)
    reference = target.secret_ref or ""
    if not reference:
        raise PlanSecretReadinessRefused(_R.credential_reference_missing)
    try:
        scheme, _locator = parse_secret_ref(reference)
    except InvalidSecretRefError:
        raise PlanSecretReadinessRefused(_R.credential_reference_scheme_unsupported) from None
    if scheme not in SUPPORTED_PLAN_SECRET_SCHEMES:
        raise PlanSecretReadinessRefused(_R.credential_reference_scheme_unsupported)
    return scheme


def run_plan_secret_readiness(  # noqa: C901,PLR0912,PLR0915 - one explicit branch per gate
    session: Session,
    *,
    manifest_id: uuid.UUID,
    composition: ReadinessComposition | None = None,
    now: datetime | None = None,
) -> PlanSecretReadinessResult:
    """Run the sealed-by-default plan-secret readiness operation, then STOP."""
    composition = composition or sealed_readiness_composition()
    now = now or datetime.now(UTC)

    # Org scope for the refusal audit ONLY (see the remote-state seam): reading the manifest row is
    # not a privileged boundary, and without it a SEALED refusal would carry a NULL organization.
    organization_id: uuid.UUID | None = _manifest_organization(session, manifest_id)

    def refuse(reason: ReadinessReason) -> PlanSecretReadinessResult:
        audit.record(
            session,
            action=AuditAction.plan_secret_readiness_refused,
            resource_type="provisioning_manifest",
            resource_id=manifest_id,
            organization_id=organization_id,
            actor="worker",
            outcome="refused",
            data={
                "operation_kind": ReadinessOperationKind.plan_secret_readiness.value,
                "provisioning_manifest_id": str(manifest_id),
                "secret_purpose": PlanSecretPurpose.plan_read.value,
                "reason_code": reason.value,
                "resolver_contract_version": PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
            },
        )
        return PlanSecretReadinessResult(
            outcome=PlanSecretReadinessOutcome.refused.value, reason_code=reason.value
        )

    try:
        # 0. SEAL — before any authorization load, resolver, lease, or secret-backend contact.
        if not composition.gate.enabled:
            raise PlanSecretReadinessRefused(_R.sealed)

        # 1. AUTHORITATIVE BINDING + INDEPENDENT WORKER RE-VERIFICATION. This single call re-derives
        #    everything from the records (never from a caller or a Temporal arg) and fails closed
        #    unless: eligibility is CURRENT + eligible; remote-state readiness is CURRENT; the exact
        #    plan-secret authorization is APPROVED, unexpired, plan-read purpose, evidence-complete,
        #    and bound to this exact manifest/plan/target/onboarding/profile/dossier/worker identity
        #    AND to this exact operation-identity fingerprint.
        # 0b. REVIEWED ACTIVATION — the self-test AND its deployment-local activation are BOTH
        #     required; the fail-closed dossier placeholder can never authorize anything.
        self_test = composition.resolver_self_test
        activation = composition.plan_secret_adapter_activation
        if self_test is None:
            raise PlanSecretReadinessRefused(_R.resolver_sealed)
        if activation is None:
            raise PlanSecretReadinessRefused(_R.adapter_capability_missing)
        if is_placeholder_dossier(activation.activation_dossier_hash):
            raise PlanSecretReadinessRefused(_R.activation_dossier_placeholder)

        result = load_readiness_binding(
            session,
            manifest_id=manifest_id,
            operation_kind=ReadinessOperationKind.plan_secret_readiness,
            now=now,
            activation_dossier_hash=activation.activation_dossier_hash,
        )
        if (
            result.binding is None
            or result.authorization is None
            or result.attestation is None
            or result.credential_binding is None
        ):
            raise PlanSecretReadinessRefused(result.reason or _R.gate_incomplete)
        binding = result.binding
        authorization = result.authorization
        organization_id = uuid.UUID(binding.organization_id)

        # 2. PLAN-ONLY PURPOSE — apply and destroy purposes are unrepresentable AND refused here.
        assert_plan_only_purpose(authorization.purpose)

        # 2b. EVIDENCE FINGERPRINT — RECOMPUTED from the current evidence rows and compared to the
        # value bound at approval. The evidence rows are already immutable once the authorization
        # leaves draft (an ORM guard + a PostgreSQL trigger), so this is defence in depth — and it
        # mirrors the reviewed sibling contract (``load_and_verify_activation_capability``).
        if not _evidence_fingerprint_matches(session, authorization):
            raise PlanSecretReadinessRefused(_R.secret_evidence_fingerprint_mismatch)

        # 3. WORKER IDENTITY / ADMISSION — before any lease. The binding already required
        #    exactly one approved, unexpired registration for the org AND its exact agreement
        #    with the authorization; re-assert the version explicitly (defence in depth).
        worker_identity = result.worker_identity
        if (
            worker_identity is None
            or worker_identity.id != authorization.worker_identity_registration_id
            or worker_identity.identity_version != authorization.worker_identity_version
        ):
            raise PlanSecretReadinessRefused(_R.worker_identity_untrusted)

        # 4. CREDENTIAL-REFERENCE BINDING — re-derived from the AUTHORITATIVE target row reached
        #    only through the manifest's pinned config hash; its scheme must equal the
        #    human-reviewed scheme on the authorization. The reference never leaves that function.
        scheme = _authoritative_reference_scheme(session, binding)
        if scheme != authorization.credential_reference_scheme:
            raise PlanSecretReadinessRefused(_R.credential_reference_scheme_mismatch)

        # 5. TERMINAL REPLAY — an exact retry within the TTL returns the durable TERMINAL
        #    (``ready``) record with no second secret-backend contact, no new lease attempt, and no
        #    duplicate audit. A NON-ready attempt never short-circuits: a retry is legitimate and is
        #    bounded by the durable N=3 lease budget. An EXPIRED ready record is never replayed as
        #    fresh readiness and is never mutated.
        existing = _terminal_record(session, binding)
        if existing is not None:
            expired = as_utc(existing.expires_at) <= now
            return PlanSecretReadinessResult(
                outcome=(
                    PlanSecretReadinessOutcome.expired.value
                    if expired
                    else getattr(existing.outcome, "value", str(existing.outcome))
                ),
                record_id=existing.id,
                evidence_hash=existing.evidence_hash,
                reused=True,
            )

        # 6. STARTED.
        audit.record(
            session,
            action=AuditAction.plan_secret_readiness_started,
            resource_type="provisioning_manifest",
            resource_id=manifest_id,
            organization_id=organization_id,
            actor="worker",
            data={
                "operation_kind": ReadinessOperationKind.plan_secret_readiness.value,
                "provisioning_manifest_id": str(manifest_id),
                "authorization_id": str(authorization.id),
                "authorization_version": authorization.authorization_version,
                "secret_purpose": PlanSecretPurpose.plan_read.value,
                "operation_fingerprint": binding.operation_fingerprint(),
                "resolver_contract_version": PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
                "self_test_policy_version": PLAN_SECRET_SELF_TEST_POLICY_VERSION,
            },
        )

        # 7. RESOLVER CONTRACT + ADAPTER PROVENANCE CAPABILITY. The self-test's self-declared
        #    contract version is never sufficient: the reviewed activation must pin its exact
        #    IMPLEMENTATION digest, a non-placeholder dossier, and this operation's authoritative
        #    world. A fake self-test that claims the right version obtains no capability.
        if composition.resolver_contract_version != PLAN_SECRET_RESOLVER_CONTRACT_VERSION:
            raise PlanSecretReadinessRefused(_R.resolver_contract_mismatch)
        issue = (
            issue_test_only_capability
            if composition.test_only_capability
            else issue_readiness_adapter_capability
        )
        try:
            capability = issue(
                activation=activation,
                binding=binding,
                adapter=self_test,
                operation_kind=ReadinessOperationKind.plan_secret_readiness,
                now=now,
            )
        except AdapterCapabilityRefused as exc:
            raise PlanSecretReadinessRefused(
                ReadinessReason(exc.reason_code)
                if exc.reason_code in {r.value for r in ReadinessReason}
                else _R.adapter_capability_invalid
            ) from exc

        # 8. LEASE — durable, single-use, CAS-guarded, bounded retry budget. NO secret-manager
        #    contact has happened yet.
        key = PlanSecretOperationKey(
            authorization_id=authorization.id,
            authorization_version=authorization.authorization_version,
            operation_fingerprint=binding.operation_fingerprint(),
        )
        try:
            lease = acquire_lease(
                session,
                organization_id=organization_id,
                key=key,
                worker_identity_id=str(worker_identity.id),
                authorization_expiry=authorization.authorization_expiry,
                now=now,
            )
            # 9. BEGIN ATTEMPT — the ONLY budget-consuming transition, IMMEDIATELY before the secret
            #    boundary. No secret-manager contact may happen before this line.
            lease = begin_attempt(session, lease, now=now)
        except PlanSecretLeaseRefused as exc:
            raise PlanSecretReadinessRefused(_R.lease_refused) from exc

        # 10. THE ONLY SECRET-BACKEND CONTACT — the reviewed resolver SELF-TEST. It proves the
        #     worker can AUTHENTICATE; it returns NO target provisioning secret, surfaces NO
        #     secret reference, and its body is never persisted. ``resolve()`` is NEVER called.
        try:
            self_test_result = self_test.run(now=now)
            self_test_ok = bool(getattr(self_test_result, "ok", False))
            self_test_reason = str(getattr(self_test_result, "reason_code", "") or "")
            # The proof id is a DISTINCT, explicit field — never the failure reason code — and it
            # must be an opaque UUID, never a label (a label could BE a Vault mount or a hostname).
            # A self-test that reports success but issues no proof UUID yields nothing durable to
            # record, so readiness fails closed to ``unverifiable`` rather than fabricating a pass.
            self_test_proof = getattr(self_test_result, "proof_id", None)
        except Exception as exc:
            # A backend exception body / stack trace is NEVER surfaced, audited, or persisted.
            raise PlanSecretReadinessRefused(_R.resolver_self_test_unavailable) from exc

        # 11. JIT INJECTION CONTRACT — exercised with an INERT, worker-generated sentinel. It is NOT
        #     a target credential, never comes from the backend, is never persisted, and lives only
        #     inside this function. No process runs; ``os.environ`` is neither read nor mutated.
        env_contract = PlanSecretEnvContract()
        jit_ok = False
        jit_reason: ReadinessReason | None = None
        try:
            sentinel = inert_canary_material()
            projected = build_plan_secret_env(sentinel, contract=env_contract)
            jit_ok = env_contract_is_satisfied(projected, contract=env_contract)
            if not jit_ok:
                jit_reason = _R.jit_env_contract_violation
            # Minimize lifetime + references. Python strings are immutable and cannot be reliably
            # zeroized (documented in ``plan_env``); we drop every reference immediately instead.
            del projected
            del sentinel
        except PlanSecretEnvViolation:
            jit_ok = False
            jit_reason = _R.jit_env_contract_violation

        # 12. TYPED EVALUATION.
        evaluation = evaluate_plan_secret_readiness(
            self_test_ok=self_test_ok,
            self_test_reason_code=self_test_reason,
            self_test_proof_id=self_test_proof,
            jit_env_ok=jit_ok,
            jit_reason=jit_reason,
        )

        # 13. IMMUTABLE PERSISTENCE — only AFTER the typed evaluation. Worker-only recorder.
        from secp_worker.readiness.recorder import (
            ReadinessRecordingRefused,
            record_plan_secret_readiness,
        )

        try:
            row = record_plan_secret_readiness(
                session,
                binding=binding,
                evaluation=evaluation,
                authorization_evidence_fingerprint=authorization.evidence_fingerprint,
                lease_id=lease.lease_id,
                capability=capability,
                attestation_id=result.attestation.id,
                credential_binding=result.credential_binding,
                now=now,
            )
        except ReadinessRecordingRefused as exc:
            raise PlanSecretReadinessRefused(_R.evidence_too_large) from exc

        # 14. CONSUME — only after a SUCCESSFUL readiness handling. A failure never becomes a
        #     consumed success: a non-``ready`` outcome leaves the lease active so the bounded retry
        #     budget (and only that budget) governs a further attempt.
        if evaluation.outcome == PlanSecretReadinessOutcome.ready.value:
            try:
                mark_consumed(session, lease, now=now)
            except PlanSecretLeaseRefused as exc:
                raise PlanSecretReadinessRefused(_R.lease_refused) from exc

        # 15. STOP. Readiness creates no plan, mints no grant, and dispatches nothing.
        return PlanSecretReadinessResult(
            outcome=evaluation.outcome,
            record_id=row.id,
            evidence_hash=row.evidence_hash,
        )
    except PlanSecretReadinessRefused as exc:
        return refuse(exc.reason)
    except PurposeNotPermitted:
        # An apply/destroy secret purpose reached the row somehow (it is unrepresentable through the
        # API). Fail closed; the rejected value is never echoed.
        return refuse(_R.secret_authorization_purpose_invalid)
