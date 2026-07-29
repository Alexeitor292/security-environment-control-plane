"""Immutable management-plane identity + strict bootstrap evidence (SECP-PR5E).

Both documents are strict (``extra='forbid'``, ``frozen``, ``strict``), canonical, digest-bearing,
and
NONSECRET — they carry only identities, digests, topology-safe path bindings, queue names, seal
states, and effect booleans. A raw filesystem path is never stored; each is a
``path_binding_digest(role, abs_path)`` (mirroring the commissioning evidence idiom). No credential,
token, private key, password, secret path, database URI, target endpoint, Proxmox value, or OpenBao
reference may appear (enforced by the forbidden-secret scan in the loaders). ``secpctl status``
independently revalidates evidence against re-observed host state — the booleans are never trusted
alone.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from secp_commissioning.canonical import (
    canonical_json,
    is_sha256_digest,
    sha256_bytes,
    sha256_digest,
)
from secp_commissioning.descriptor import scan_forbidden

from secp_management import BOOTSTRAP_CONTRACT_VERSION, PLANE_MANAGEMENT, ManagementError
from secp_management.topology import OPERATOR_TASK_QUEUE, ORDINARY_TASK_QUEUE

MODE_INSTALLED = "installed"
MODE_ADOPTED = "adopted"
_MODES = frozenset({MODE_INSTALLED, MODE_ADOPTED})
_ROLES = frozenset({"controller", "worker"})

# Domain-separated schema identities (2b-3c). The bootstrap binding digest is the explicit,
# versioned pre-finalization binding the controller identity activation + enablement marker bind;
# it is NEVER a silent partial of BootstrapEvidence.digest().
_BOOTSTRAP_BINDING_SCHEMA = "secp.management.bootstrap-binding/v1"
FINALIZATION_SCHEMA_VERSION = "secp.management.finalization-evidence/v1"
# The closed controller-install classifications (2b-3c). Every other pre-existing state refuses.
# The two-phase finalization commit states (2b-3c-c / R5). A PREPARED checkpoint is a durable,
# attested record written BEFORE cleanup, so it may never claim the journal/staging objects are
# absent; only a COMMITTED record — written after cleanup is performed AND absence-observed — may.
FINALIZATION_STATE_PREPARED = "prepared"
FINALIZATION_STATE_COMMITTED = "committed"
_FINALIZATION_STATES = frozenset({FINALIZATION_STATE_PREPARED, FINALIZATION_STATE_COMMITTED})
CLASSIFY_FRESH = "fresh"
CLASSIFY_EXACT_SAME_RELEASE = "exact_same_release"
CLASSIFY_MANAGED_UPGRADE = "managed_upgrade"
_FINALIZATION_CLASSIFICATIONS = frozenset(
    {CLASSIFY_FRESH, CLASSIFY_EXACT_SAME_RELEASE, CLASSIFY_MANAGED_UPGRADE}
)

# The closed set of root-controlled management documents a transaction owns. Every
# bootstrap/adoption
# records ONE ManagedObjectRecord per kind; rollback is content-bound to exactly these FIVE. The
# detached evidence attestation is a first-class owned document: its content is NOT self-digested
# inside evidence (its Ed25519 signature is independently verified), but its fixed binding, UID,
# GID,
# mode, type, link count and created/adopted classification ARE authenticated by the ownership
# record.
OBJECT_IDENTITY = "identity"
OBJECT_RELEASE_MANIFEST = "release_manifest"
OBJECT_RELEASE_SIGNATURE = "release_signature"
OBJECT_EVIDENCE = "evidence"
OBJECT_EVIDENCE_ATTESTATION = "evidence_attestation"
# the two SELF/independently-verified records that carry no embedded content digest
_SELF_RECORD_KINDS = frozenset({OBJECT_EVIDENCE, OBJECT_EVIDENCE_ATTESTATION})
_OBJECT_KINDS = frozenset(
    {
        OBJECT_IDENTITY,
        OBJECT_RELEASE_MANIFEST,
        OBJECT_RELEASE_SIGNATURE,
        OBJECT_EVIDENCE,
        OBJECT_EVIDENCE_ATTESTATION,
    }
)
CLASSIFICATION_CREATED = "created"
CLASSIFICATION_ADOPTED = "adopted"
_CLASSIFICATIONS = frozenset({CLASSIFICATION_CREATED, CLASSIFICATION_ADOPTED})

_Str = Annotated[str, Field(min_length=1, max_length=200, strict=True)]
_OptStr = Annotated[str, Field(min_length=1, max_length=200, strict=True)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def path_binding_digest(role: str, abs_path: str) -> str:
    """Topology-safe binding of a role + absolute path; the raw path is never stored/echoed."""
    return sha256_digest({"v": "secp.management.path/v1", "role": role, "path": abs_path})


def health_command_identity(argv: tuple[str, ...]) -> str:
    return sha256_digest({"v": "secp.management.health/v1", "argv": list(argv)})


class ManagementPlaneIdentity(_Strict):
    """The immutable management-plane identity document (nonsecret)."""

    bootstrap_contract_version: _Str
    plane: _Str
    role: _Str
    installation_id: _Str
    organization_site: _OptStr | None = None
    release_digest: _Str
    source_sha: _Str
    source_tree_sha: _Str
    parent_sha: _OptStr | None = None
    installed_artifact_digests: tuple[str, ...]
    created_at: _Str

    @field_validator("installed_artifact_digests", mode="before")
    @classmethod
    def _coerce(cls, v: object) -> object:
        return tuple(v) if isinstance(v, list) else v

    def canonical(self) -> dict:
        return self.model_dump(mode="json")

    def digest(self) -> str:
        return sha256_digest(self.canonical())


class ManagedObjectRecord(_Strict):
    """A strict, content-bound ownership record for ONE root-controlled management document, so
    rollback verifies the on-disk object's type, ownership, mode, link-count AND exact content
    before
    removal. ``content_sha256`` is None ONLY for the self-binding ``evidence`` record (its own
    digest
    cannot be embedded in itself; rollback re-canonicalizes the parsed evidence to verify it)."""

    role: _Str
    kind: _Str  # one of _OBJECT_KINDS
    binding: _Str  # path_binding_digest(role, abs_path)
    content_sha256: _OptStr | None = None
    uid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    gid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    mode: Annotated[int, Field(ge=0, le=0o7777, strict=True)]
    classification: _Str  # created | adopted

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


class FinalizationEffectRecord(_Strict):
    """One PUBLIC per-effect record of a controller-enrollment finalization host/DB effect. It
    mirrors
    only the public fields of ``FinalizationEffectReceipt`` (effect name, fixed object identity,
    pre-mutation disposition, candidate public digest) — never a secret byte or restore handle."""

    effect: _Str  # one of FINALIZATION_EFFECTS
    object_identity: _Str
    disposition: _Str
    candidate_digest: _OptStr | None = None

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


class FinalizationEvidence(_Strict):
    """Strict PUBLIC evidence of the controller-enrollment finalization: the authenticated
    generation, the closed classification, the domain-separated bootstrap binding digest, and the
    marker/identity/runtime facts a later status independently revalidates. Present ONLY for a
    driven
    controller install; ``None`` for worker/adopt/legacy installs. It carries ONLY public
    identities,
    digests, and safety booleans — never a plaintext credential, verifier, private key, token
    secret,
    DSN, or raw path (the loader's forbidden-secret scan enforces this)."""

    schema_version: _Str  # == FINALIZATION_SCHEMA_VERSION
    role: _Str  # == the evidence role (controller)
    mode: _Str  # == installed
    classification: _Str  # one of _FINALIZATION_CLASSIFICATIONS
    generation: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    # bindings
    transaction_id_digest: _Str
    bootstrap_binding_digest: _Str
    finalization_receipt_digest: _Str
    # TLS / locator
    canonical_origin_digest: _Str
    tls_mode: _Str
    tls_policy_identity: _Str
    locator_ca_digest: _Str  # the ACTUAL installed CA-bundle digest
    # signer role + credential (public bindings only)
    signer_role_identity: _Str
    signer_login_binding_digest: _OptStr | None = None
    # enrollment key (public identity)
    enrollment_key_id: _Str
    enrollment_key_proof_id: _Str
    # broker
    broker_unit_identity: _Str
    broker_transport_identity: _Str
    # active identity + activation (concurrency facts kept as digests)
    active_identity_row_id: _Str
    activation_concurrency_digest: _Str
    activation_operation_digest: _Str
    # marker + runtime
    marker_identity: _Str
    runtime_observation_identity: _Str
    # proofs
    # two-phase commit state (R5): 'prepared' (pre-cleanup checkpoint) or 'committed' (post-cleanup)
    finalization_commit_state: _Str
    recovery_journal_absent: bool
    staging_objects_absent: bool
    marker_last: bool
    api_runtime_proven: bool
    no_mixed_generation: bool
    operator_sealed: bool
    controlled_live_sealed: bool
    isolation_boundaries_proven: bool
    # per-effect dispositions
    effects: tuple[FinalizationEffectRecord, ...]

    @field_validator("effects", mode="before")
    @classmethod
    def _coerce_effects(cls, v: object) -> object:
        return tuple(v) if isinstance(v, list) else v

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


class BootstrapEvidence(_Strict):
    """Strict nonsecret bootstrap evidence for a controller or worker install/adoption."""

    bootstrap_contract_version: _Str
    mode: _Str
    role: _Str
    plane: _Str
    installation_id: _Str
    release_aggregate_digest: _Str
    signing_anchor_id: _Str
    source_sha: _Str
    source_tree_sha: _Str
    parent_sha: _OptStr | None = None
    image_digests: tuple[str, ...]
    wheel_digests: tuple[str, ...]
    implementation_aggregate: _Str
    path_bindings: tuple[str, ...]
    container_identities: tuple[str, ...]
    service_identities: tuple[str, ...]
    # installed-artifact identities revalidated by final reobservation + later status (blocker 2)
    config_identity: _Str
    unit_identity: _Str
    deployment_package_aggregate: _OptStr | None = None  # worker only
    expected_components: tuple[str, ...] = ()  # controller only
    component_image_identity: _OptStr | None = None  # controller only
    runtime_uid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    runtime_gid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    ordinary_task_queue: _Str
    operator_task_queue: _Str
    health_command_identity: _Str
    # content-bound per-object ownership records for exactly the 5 managed documents (identity,
    # release manifest, release signature, evidence, evidence attestation)
    object_records: tuple[ManagedObjectRecord, ...]
    # OPTIONAL controller-enrollment finalization evidence (2b-3c). None for worker/adopt/legacy;
    # the key is DROPPED from canonical() when None so pre-existing evidence stays byte-identical
    # (no migration). Excluded from digest() so the value bound BEFORE the receipt exists is stable.
    finalization: FinalizationEvidence | None = None
    commissioning_evidence_digest: _OptStr | None = None
    operator_activation_sealed: bool
    plan_only_process_sealed: bool
    b1a_subprocess_sealed_activation: bool
    b1a_subprocess_sealed_executor: bool
    transaction_timestamp: _Str
    external_contacts_performed: bool
    workflows_submitted: bool
    run_plan_generation_called: bool
    opentofu_executed: bool
    proxmox_contacted: bool

    @field_validator(
        "image_digests",
        "wheel_digests",
        "path_bindings",
        "container_identities",
        "service_identities",
        "expected_components",
        "object_records",
        mode="before",
    )
    @classmethod
    def _coerce_tuples(cls, v: object) -> object:
        return tuple(v) if isinstance(v, list) else v

    def canonical(self) -> dict:
        data = self.model_dump(mode="json")
        if data.get("finalization") is None:
            # DROP the optional key when absent so legacy/worker/adopted evidence canonicalizes
            # byte-identically to before this field existed (sorted keys → an absent key changes
            # nothing) — the attestation over canonical_bytes(ev) stays valid without a migration.
            data.pop("finalization", None)
        return data

    def digest(self) -> str:
        # The evidence content identity: every semantic field EXCEPT transaction_timestamp. This
        # BINDS the finalization extension when present (a changed FinalizationEvidence changes this
        # digest and therefore the attestation) — it is NOT redefined as a partial digest.
        payload = {k: v for k, v in self.canonical().items() if k != "transaction_timestamp"}
        return sha256_digest(payload)

    def bootstrap_binding_digest(self) -> str:
        """The domain-separated PRE-FINALIZATION bootstrap binding: every semantic evidence field
        EXCEPT ``transaction_timestamp`` and the ``finalization`` extension, under a versioned
        schema
        identity. This is the exact value the controller identity activation and the enablement
        marker bind as ``bootstrap_evidence_digest`` — so it is IDENTICAL whether computed before
        the
        finalization receipt exists (from the pre-finalization ``ev0``) or from the final written
        evidence (which additionally carries the authenticated ``FinalizationEvidence``). It is a
        distinct, explicitly named binding — never a silent partial of :meth:`digest`."""
        binding = {
            k: v
            for k, v in self.canonical().items()
            if k not in ("transaction_timestamp", "finalization")
        }
        return sha256_digest({"v": _BOOTSTRAP_BINDING_SCHEMA, "binding": binding})

    def created_records(self) -> tuple[ManagedObjectRecord, ...]:
        return tuple(r for r in self.object_records if r.classification == CLASSIFICATION_CREATED)

    def record_for(self, kind: str) -> ManagedObjectRecord | None:
        for r in self.object_records:
            if r.kind == kind:
                return r
        return None


def _assert_identity_semantics(ident: ManagementPlaneIdentity) -> None:
    if ident.bootstrap_contract_version != BOOTSTRAP_CONTRACT_VERSION:
        raise ManagementError("identity_contract_version_invalid")
    if ident.plane != PLANE_MANAGEMENT:
        raise ManagementError("identity_plane_invalid")
    if ident.role not in _ROLES:
        raise ManagementError("identity_role_invalid")
    _assert_tz_aware(ident.created_at, "identity_created_at_invalid")


def _assert_evidence_semantics(ev: BootstrapEvidence) -> None:
    if ev.bootstrap_contract_version != BOOTSTRAP_CONTRACT_VERSION:
        raise ManagementError("evidence_contract_version_invalid")
    if ev.plane != PLANE_MANAGEMENT:
        raise ManagementError("evidence_plane_invalid")
    if ev.role not in _ROLES:
        raise ManagementError("evidence_role_invalid")
    if ev.mode not in _MODES:
        raise ManagementError("evidence_mode_invalid")
    if ev.ordinary_task_queue != ORDINARY_TASK_QUEUE:
        raise ManagementError("evidence_ordinary_queue_invalid")
    if ev.operator_task_queue != OPERATOR_TASK_QUEUE:
        raise ManagementError("evidence_operator_queue_invalid")
    if ev.ordinary_task_queue == ev.operator_task_queue:
        raise ManagementError("evidence_queue_not_distinct")
    if not is_sha256_digest(ev.implementation_aggregate):
        raise ManagementError("evidence_implementation_aggregate_invalid")
    # The four safety seals must be observed in their reviewed posture.
    if ev.operator_activation_sealed is not True:
        raise ManagementError("evidence_operator_activation_seal_invalid")
    if ev.plan_only_process_sealed is not False:
        raise ManagementError("evidence_plan_only_seal_invalid")
    if ev.b1a_subprocess_sealed_activation is not True:
        raise ManagementError("evidence_b1a_activation_seal_invalid")
    if ev.b1a_subprocess_sealed_executor is not True:
        raise ManagementError("evidence_b1a_executor_seal_invalid")
    # Every effect boolean must be False (no infrastructure/workflow/plan-gen/OpenTofu/Proxmox
    # action).
    for flag_name in (
        "external_contacts_performed",
        "workflows_submitted",
        "run_plan_generation_called",
        "opentofu_executed",
        "proxmox_contacted",
    ):
        if getattr(ev, flag_name) is not False:
            raise ManagementError("evidence_effect_flag_invalid")
    _assert_object_records(ev)
    _assert_finalization_semantics(ev)
    _assert_tz_aware(ev.transaction_timestamp, "evidence_timestamp_invalid")


def _assert_finalization_semantics(ev: BootstrapEvidence) -> None:
    """Validate the OPTIONAL finalization extension. Skipped entirely when absent (worker/adopt/
    legacy), so pre-existing evidence is unaffected. When present, the install MUST be an installed
    controller, the classification MUST be closed, every digest MUST be well-formed, and every
    finalization safety predicate MUST hold — so a forged or worker/adopt/legacy evidence cannot
    smuggle a finalization extension past authentication."""
    fin = ev.finalization
    if fin is None:
        return
    from .finalization import FINALIZATION_EFFECTS  # local import avoids any module cycle

    if fin.schema_version != FINALIZATION_SCHEMA_VERSION:
        raise ManagementError("evidence_finalization_schema_invalid")
    if ev.role != "controller" or ev.mode != MODE_INSTALLED:
        raise ManagementError("evidence_finalization_role_invalid")
    if fin.role != ev.role or fin.mode != ev.mode:
        raise ManagementError("evidence_finalization_binding_mismatch")
    if fin.classification not in _FINALIZATION_CLASSIFICATIONS:
        raise ManagementError("evidence_finalization_classification_invalid")
    if fin.generation < 0:
        raise ManagementError("evidence_finalization_generation_invalid")
    for name, value in (
        ("transaction_id_digest", fin.transaction_id_digest),
        ("bootstrap_binding_digest", fin.bootstrap_binding_digest),
        ("finalization_receipt_digest", fin.finalization_receipt_digest),
        ("canonical_origin_digest", fin.canonical_origin_digest),
        ("tls_policy_identity", fin.tls_policy_identity),
        ("locator_ca_digest", fin.locator_ca_digest),
        ("signer_role_identity", fin.signer_role_identity),
        ("broker_unit_identity", fin.broker_unit_identity),
        ("broker_transport_identity", fin.broker_transport_identity),
        ("activation_concurrency_digest", fin.activation_concurrency_digest),
        ("activation_operation_digest", fin.activation_operation_digest),
        ("marker_identity", fin.marker_identity),
        ("runtime_observation_identity", fin.runtime_observation_identity),
    ):
        if not is_sha256_digest(value):
            raise ManagementError(f"evidence_finalization_digest_invalid:{name}")
    if fin.signer_login_binding_digest is not None and not is_sha256_digest(
        fin.signer_login_binding_digest
    ):
        raise ManagementError("evidence_finalization_digest_invalid:signer_login_binding_digest")
    if fin.finalization_commit_state not in _FINALIZATION_STATES:
        raise ManagementError("evidence_finalization_commit_state_invalid")
    if fin.finalization_commit_state == FINALIZATION_STATE_PREPARED:
        # a PREPARED checkpoint must NOT claim cleanup it has not performed/observed yet, and it is
        # never an installation-complete record.
        if fin.recovery_journal_absent or fin.staging_objects_absent:
            raise ManagementError("evidence_finalization_prepared_claims_cleanup")
        for pred in ("marker_last", "api_runtime_proven", "no_mixed_generation"):
            if getattr(fin, pred) is not True:
                raise ManagementError(f"evidence_finalization_predicate_invalid:{pred}")
        for pred in ("operator_sealed", "controlled_live_sealed", "isolation_boundaries_proven"):
            if getattr(fin, pred) is not True:
                raise ManagementError(f"evidence_finalization_predicate_invalid:{pred}")
        return
    # every COMMITTED finalization safety predicate must be TRUE (no false success)
    for pred in (
        "recovery_journal_absent",
        "staging_objects_absent",
        "marker_last",
        "api_runtime_proven",
        "no_mixed_generation",
        "operator_sealed",
        "controlled_live_sealed",
        "isolation_boundaries_proven",
    ):
        if getattr(fin, pred) is not True:
            raise ManagementError(f"evidence_finalization_predicate_invalid:{pred}")
    seen = set()
    for rec in fin.effects:
        if rec.effect not in FINALIZATION_EFFECTS:
            raise ManagementError("evidence_finalization_effect_invalid")
        seen.add(rec.effect)
    if "marker" not in seen or "identity_activation" not in seen:
        raise ManagementError("evidence_finalization_incomplete")


def _assert_object_records(ev: BootstrapEvidence) -> None:
    """The object records must cover EXACTLY the five managed documents, one per kind, all for this
    role, with a coherent classification: an installed transaction created all five; an adoption
    created none (all adopted). The two SELF/independently-verified records (evidence and evidence
    attestation) carry no embedded content digest; the other three must."""
    kinds = [r.kind for r in ev.object_records]
    if sorted(kinds) != sorted(_OBJECT_KINDS):
        raise ManagementError("evidence_object_records_incomplete")
    expected_class = CLASSIFICATION_CREATED if ev.mode == MODE_INSTALLED else CLASSIFICATION_ADOPTED
    for r in ev.object_records:
        if r.role != ev.role:
            raise ManagementError("evidence_object_record_role_mismatch")
        if r.kind not in _OBJECT_KINDS:
            raise ManagementError("evidence_object_record_kind_invalid")
        if r.classification not in _CLASSIFICATIONS:
            raise ManagementError("evidence_object_record_classification_invalid")
        if r.classification != expected_class:
            raise ManagementError("evidence_object_record_classification_mismatch")
        if r.kind in _SELF_RECORD_KINDS:
            if r.content_sha256 is not None:
                raise ManagementError("evidence_self_record_digest_present")
        else:
            if r.content_sha256 is None or not is_sha256_digest(r.content_sha256):
                raise ManagementError("evidence_object_record_digest_invalid")


def _assert_tz_aware(value: str, reason: str) -> None:
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ManagementError(reason) from None
    if parsed.tzinfo is None:
        raise ManagementError(reason)


def identity_from_dict(data: object) -> ManagementPlaneIdentity:
    obj = _strict_object(data, "identity")
    try:
        ident = ManagementPlaneIdentity.model_validate(obj)
    except ValidationError as exc:
        raise ManagementError("identity_invalid:" + _safe_field(exc)) from None
    _assert_identity_semantics(ident)
    return ident


def evidence_from_dict(data: object) -> BootstrapEvidence:
    obj = _strict_object(data, "evidence")
    try:
        ev = BootstrapEvidence.model_validate(obj)
    except ValidationError as exc:
        raise ManagementError("evidence_invalid:" + _safe_field(exc)) from None
    _assert_evidence_semantics(ev)
    return ev


def parse_document_bytes(raw: bytes, loader, what: str):  # noqa: ANN001, ANN201
    """Strict UTF-8 + duplicate-key-rejecting JSON parse, then ``loader`` (identity/evidence)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ManagementError(f"{what}_not_utf8") from None
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise ManagementError(f"{what}_duplicate_key") from None
    except ValueError:
        raise ManagementError(f"{what}_not_json") from None
    return loader(parsed)


def _strict_object(data: object, what: str) -> dict:
    if not isinstance(data, dict):
        raise ManagementError(f"{what}_not_object")
    try:
        scan_forbidden(data)
    except Exception:
        raise ManagementError(f"{what}_forbidden_secret") from None
    return data


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey()
        seen.add(key)
    return dict(pairs)


def canonical_bytes(document: object) -> bytes:
    """Canonical JSON bytes of an identity/evidence document, for a hardened atomic write."""
    return canonical_json(document.canonical()).encode("utf-8")  # type: ignore[attr-defined]


# --------------------------------------------------------------------- detached evidence
# attestation


class EvidenceAttestation(_Strict):
    """The detached signature envelope over the canonical evidence-attestation message. Evidence is
    NOT trusted until this attestation verifies against a reviewed/provisioned anchor."""

    algorithm: _Str
    key_id: _Str
    signature: Annotated[str, Field(min_length=128, max_length=128, strict=True)]  # 64-byte hex

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


def evidence_attestation_message(
    ev: BootstrapEvidence, identity_bytes: bytes, release_aggregate: str
) -> bytes:
    """The EXACT bytes the evidence attestation covers: the canonical evidence digest, the
    canonical identity digest, the signed release aggregate, the role, the installation id, the
    install/adopt mode, the transaction timestamp, and EVERY ManagedObjectRecord. Signing this binds
    all of them, so a rewrite (adopted→installed, or a forged record) is caught."""
    return canonical_json(
        {
            "v": "secp.management.evidence-attestation/v1",
            "evidence_sha256": sha256_bytes(canonical_bytes(ev)),
            "identity_sha256": sha256_bytes(identity_bytes),
            "release_aggregate": release_aggregate,
            "role": ev.role,
            "installation_id": ev.installation_id,
            "mode": ev.mode,
            "transaction_timestamp": ev.transaction_timestamp,
            "object_records": [r.canonical() for r in ev.object_records],
        }
    ).encode("utf-8")


def attestation_from_dict(data: object) -> EvidenceAttestation:
    obj = _strict_object(data, "attestation")
    try:
        att = EvidenceAttestation.model_validate(obj)
    except ValidationError as exc:
        raise ManagementError("attestation_invalid:" + _safe_field(exc)) from None
    if att.algorithm != "ed25519":
        raise ManagementError("attestation_algorithm_unsupported")
    try:
        bytes.fromhex(att.signature)
    except ValueError:
        raise ManagementError("attestation_not_hex") from None
    return att


def attestation_bytes(algorithm: str, key_id: str, signature: str) -> bytes:
    return canonical_json(
        {"algorithm": algorithm, "key_id": key_id, "signature": signature}
    ).encode("utf-8")


def _safe_field(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "document"
    err = errors[0]
    loc = err.get("loc", ())
    if err.get("type") == "extra_forbidden":
        parent = ".".join(str(p) for p in loc[:-1] if isinstance(p, str)) or "document"
        return "unknown_field." + re.sub(r"[^A-Za-z0-9_.]", "", parent)[:48]
    field = ".".join(str(p) for p in loc if isinstance(p, str)) or "document"
    return re.sub(r"[^A-Za-z0-9_.]", "", field)[:48]
