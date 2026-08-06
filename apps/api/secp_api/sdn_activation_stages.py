"""The five-stage SDN activation model, with ownership derived and disclosure non-authoritative.

Proxmox commits SDN configuration with ``PUT /cluster/sdn``, which applies **every** pending change
on the cluster. There is no scoping attribute on the applier and no per-object apply in the API, so
SECP cannot commit only its own objects. The model does not pretend to scope it; it makes the real
blast radius explicit and refuses whenever the pending set is not exclusively this operation's.

======= ==========================================================================================
Stage 1 Prepare SECP-owned SDN configuration. Nothing is activated.
Stage 2 Rediscover and hash the COMPLETE cluster-wide pending state.
Stage 3 Separately authorise that exact activation.
Stage 4 Activate, after recomputing everything.
Stage 5 Verify the active SDN, and only then deploy guests.
======= ==========================================================================================

**Three records, separated by authority.** The earlier version collapsed them, and the collapse was
the defect: an ``ActivationAuthorization`` accepted ``disclosed_counts`` from its caller, so an
all-zero summary offered against a contaminated document survived construction and was only caught
by a later recompute.

:class:`PendingSdnDocument`
    What the target said. Canonical, observed, signed. Contains **no ownership claim at all** —
    ownership is not a property of the cluster's pending state, it is a conclusion SECP draws.
:class:`PendingSdnOwnershipProofSet`
    One derived proof per object, keyed one-to-one. Carries the evidence and the classification it
    yields.
:class:`PendingSdnDisclosure`
    The operator-facing summary. **Derived only**, from the two above, and authoritative over
    nothing. It cannot be handed to the authorization constructor because the constructor has no
    parameter for it.

**Two digests, because they protect different facts.** ``pending_sdn_hash`` proves the target's
pending configuration did not change. ``ownership_provenance_digest`` proves the classification and
its supporting evidence did not change. Raw objects can stay byte-identical while a provenance
record disappears underneath them — one hash cannot see both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import NoReturn

from secp_commissioning.canonical import sha256_digest

STAGE_PREPARED = "prepared"
STAGE_PENDING_OBSERVED = "pending_observed"
STAGE_ACTIVATION_AUTHORIZED = "activation_authorized"
STAGE_ACTIVATED = "activated"
STAGE_VERIFIED = "verified"

STAGE_ORDER: tuple[str, ...] = (
    STAGE_PREPARED,
    STAGE_PENDING_OBSERVED,
    STAGE_ACTIVATION_AUTHORIZED,
    STAGE_ACTIVATED,
    STAGE_VERIFIED,
)

DEFAULT_PENDING_OBSERVATION_TTL = timedelta(minutes=10)


class SdnActivationRefused(Exception):
    """Activation refused. A closed reason code, never a host or credential."""


class SdnObjectOwnership(str, Enum):
    """How a pending SDN object relates to the operation being authorised.

    Deliberately not a boolean, and deliberately not settable on the object: ownership is a
    conclusion drawn from proof, and a value anyone can assign is not a conclusion.
    """

    current_operation = "current_operation"
    other_secp_operation = "other_secp_operation"
    foreign = "foreign"
    unknown = "unknown"
    unclassified = "unclassified"


NON_EXCLUSIVE_OWNERSHIP: frozenset[SdnObjectOwnership] = frozenset(
    {
        SdnObjectOwnership.other_secp_operation,
        SdnObjectOwnership.foreign,
        SdnObjectOwnership.unknown,
        SdnObjectOwnership.unclassified,
    }
)


# ==================================================================================================
# A. The canonical pending document — what the TARGET said. No ownership claims.
# ==================================================================================================


@dataclass(frozen=True)
class PendingSdnObject:
    """One staged SDN change, as observed. Carries no ownership field by construction."""

    family: str
    object_id: str
    #: The DERIVED action — create | change | delete | unchanged | ambiguous — not the target's own
    #: annotation. Proxmox's ``state`` is one source's summary of the same pair of views; the pair
    #: is what SECP classifies from, and the annotation is retained separately as evidence.
    action: str
    normalized_active_representation: str = ""
    normalized_pending_representation: str = ""
    source_endpoint: str = ""
    observation_state: str = ""
    raw_result_digest: str = ""
    #: What the target annotated the row with, kept apart from the derived action so a disagreement
    #: between the two is visible rather than resolved silently.
    target_state: str = ""
    #: Why the action could not be resolved, when it is ``ambiguous``.
    ambiguity_reason: str = ""
    active_present: bool = False
    pending_present: bool = False

    @property
    def key(self) -> tuple[str, str]:
        """The one-to-one join key with a proof result."""
        return (self.family, self.object_id)

    def canonical(self) -> dict:
        return {
            "family": self.family,
            "object_id": self.object_id,
            "action": self.action,
            "target_state": self.target_state,
            "ambiguity_reason": self.ambiguity_reason,
            "active_present": self.active_present,
            "pending_present": self.pending_present,
            "active": self.normalized_active_representation,
            "pending": self.normalized_pending_representation,
            "source_endpoint": self.source_endpoint,
            "observation_state": self.observation_state,
            "raw_result_digest": self.raw_result_digest,
        }


_PENDING_CONTENT_TOKEN = object()


def pending_content_token() -> object:
    """Handed to the one function permitted to authenticate pending content.

    A function rather than a public constant so the token is not importable as data; the module that
    authenticates content calls it, and nothing else has a reason to.
    """
    return _PENDING_CONTENT_TOKEN


class AuthenticatedPendingContent:
    """Proof that a pending document's content is exactly what a registered worker signed.

    This type exists because ``signature_verified: bool`` was a field, and a field is something a
    caller assigns. It is produced only by
    :func:`secp_api.sdn_pending_observation.authenticate_pending_content`, which recomputes the fact
    commitment and refuses unless the digest equals the signed ``facts_hash``.

    It carries ``pending_sdn_state`` — the state the WORKER signed for that fact — so the document's
    visibility claim is read from inside the signature rather than recomputed by whoever is asking.
    """

    __slots__ = ("__facts_hash", "__pending_sdn_state")

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        raise SdnActivationRefused("AuthenticatedPendingContent cannot be subclassed")

    def __new__(cls, token: object = None, **kwargs: object) -> AuthenticatedPendingContent:
        if token is not _PENDING_CONTENT_TOKEN:
            raise SdnActivationRefused(
                "AuthenticatedPendingContent cannot be constructed directly; it is produced only "
                "by authenticating content against a verified snapshot"
            )
        return super().__new__(cls)

    def __init__(self, token: object, *, facts_hash: str, pending_sdn_state: str) -> None:
        if token is not _PENDING_CONTENT_TOKEN:
            raise SdnActivationRefused("AuthenticatedPendingContent cannot be constructed directly")
        object.__setattr__(self, "_AuthenticatedPendingContent__facts_hash", facts_hash)
        object.__setattr__(
            self, "_AuthenticatedPendingContent__pending_sdn_state", pending_sdn_state
        )

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise SdnActivationRefused("AuthenticatedPendingContent is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise SdnActivationRefused("AuthenticatedPendingContent is immutable")

    @property
    def facts_hash(self) -> str:
        return object.__getattribute__(self, "_AuthenticatedPendingContent__facts_hash")  # type: ignore[no-any-return]

    @property
    def pending_sdn_state(self) -> str:
        return object.__getattribute__(  # type: ignore[no-any-return]
            self, "_AuthenticatedPendingContent__pending_sdn_state"
        )

    def __repr__(self) -> str:
        return f"AuthenticatedPendingContent(facts_hash={self.facts_hash!r})"

    def __getstate__(self) -> NoReturn:
        raise SdnActivationRefused("AuthenticatedPendingContent cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise SdnActivationRefused("AuthenticatedPendingContent cannot be pickled")


def _authenticated_facts_hash(authentication: object) -> str:
    """The signed facts hash a real authentication carries, or "" for anything else.

    Reading the slot is what distinguishes a genuinely issued carrier from an ``object.__new__``
    allocation of the same type: the allocation passes ``isinstance`` and raises on every attribute.
    """
    if not isinstance(authentication, AuthenticatedPendingContent):
        return ""
    try:
        return authentication.facts_hash
    except AttributeError:
        return ""


@dataclass(frozen=True)
class PendingSdnDocument:
    """The complete cluster-wide pending state at one instant, with its own bindings.

    ``signature_verified`` and ``visibility_complete`` are PROPERTIES, not fields. They used to be
    booleans a builder could stamp, and the activation gate reads both — so stamping them was the
    whole attack. There is now no keyword to pass and no attribute to assign; both answer from an
    :class:`AuthenticatedPendingContent` that only content matching a signed ``facts_hash``
    produces.
    """

    observed_at: datetime
    target_identity: str
    cluster_fingerprint: str
    observation_identity: str
    worker_installation_id: str
    worker_release_fingerprint: str
    objects: tuple[PendingSdnObject, ...] = ()
    authentication: AuthenticatedPendingContent | None = None
    unreadable_families: tuple[tuple[str, str], ...] = ()

    @property
    def signature_verified(self) -> bool:
        """True only when the content authenticated against a registered worker's signature.

        ``isinstance`` alone is NOT the check, and that is not a nicety. ``object.__new__(cls)``
        allocates an instance without running ``__new__`` or ``__init__`` — Python offers no way to
        forbid it — and such an object satisfies every ``isinstance`` its consumers make. What it
        cannot do is have its slots set, so the guard reads the state real construction produces
        and treats an unreadable carrier as unauthenticated.
        """
        return bool(_authenticated_facts_hash(self.authentication))

    @property
    def visibility_complete(self) -> bool:
        """True only when the WORKER SIGNED that the pending SDN read was observed.

        Not the caller's projection of the same question. A binding declaring ``permission_denied``
        cannot produce a document claiming complete pending visibility, because the claim is read
        out of the signature rather than alongside it.
        """
        if not self.signature_verified:
            return False
        try:
            return self.authentication.pending_sdn_state == "observed"  # type: ignore[union-attr]
        except AttributeError:
            return False

    def pending_sdn_hash(self) -> str:
        """Hash of what the TARGET reported. Nothing about ownership enters here.

        Keeping ownership out is what makes the two digests independent: a classification change
        with byte-identical target state must move the OTHER digest and not this one, so the pair
        can distinguish "the cluster changed" from "our evidence changed".
        """
        return sha256_digest(
            {
                "target_identity": self.target_identity,
                "cluster_fingerprint": self.cluster_fingerprint,
                "observation_identity": self.observation_identity,
                "objects": sorted(
                    (obj.canonical() for obj in self.objects),
                    key=lambda row: (row["family"], row["object_id"]),
                ),
            }
        )

    @property
    def keys(self) -> tuple[tuple[str, str], ...]:
        return tuple(obj.key for obj in self.objects)


# ==================================================================================================
# B. The ownership proof set — SECP's conclusion, and the evidence behind it.
# ==================================================================================================


@dataclass(frozen=True)
class OperationBinding:
    """What the current Stage 1 operation is, as the thing ownership is proven AGAINST."""

    target_identity: str
    cluster_fingerprint: str
    range_identity: str
    operation_identity: str
    operation_generation: int
    stage1_workspace_hash: str
    stage1_plan_hash: str
    stage1_authorization_id: str
    stage1_execution_receipt: str


@dataclass(frozen=True)
class OwnershipProofResult:
    """One object's classification and the evidence digests behind it.

    Explicitly NOT evidence, and absent from this structure on purpose: a SECP name prefix, a VNet
    alias, an HCL comment, attribute equality alone, creation-like timing alone, or "appeared after
    Stage 1" alone. Each is reproducible by another actor or is a coincidence, and none appears as
    a field here — so none can be offered as proof.
    """

    object_key: tuple[str, str]
    #: What the SUBMITTER claims. Deliberately NOT the answer: :func:`classify_ownership` derives
    #: the outcome from the evidence digests below, and every consumer must use the derived value.
    #: The claim is retained because one case reads it as evidence — a submitter asserting
    #: ``foreign`` with a complete proof is volunteering that the object is somebody else's, which
    #: is stronger information than our binding failing, and nobody gains by claiming it falsely.
    ownership: SdnObjectOwnership
    classification_reason: str
    range_identity: str = ""
    operation_identity: str = ""
    operation_generation: int = -1
    stage1_desired_object_digest: str = ""
    stage1_workspace_hash: str = ""
    stage1_plan_hash: str = ""
    stage1_execution_receipt_digest: str = ""
    pre_stage1_absence_evidence_digest: str = ""
    durable_ownership_provenance_digest: str = ""
    target_identity: str = ""
    cluster_fingerprint: str = ""
    proof_complete: bool = False

    def canonical(self) -> dict:
        return {
            "object_key": list(self.object_key),
            "ownership": self.ownership.value,
            "classification_reason": self.classification_reason,
            "range_identity": self.range_identity,
            "operation_identity": self.operation_identity,
            "operation_generation": self.operation_generation,
            "stage1_desired_object_digest": self.stage1_desired_object_digest,
            "stage1_workspace_hash": self.stage1_workspace_hash,
            "stage1_plan_hash": self.stage1_plan_hash,
            "stage1_execution_receipt_digest": self.stage1_execution_receipt_digest,
            "pre_stage1_absence_evidence_digest": self.pre_stage1_absence_evidence_digest,
            "durable_ownership_provenance_digest": self.durable_ownership_provenance_digest,
            "target_identity": self.target_identity,
            "cluster_fingerprint": self.cluster_fingerprint,
            "proof_complete": self.proof_complete,
        }


@dataclass(frozen=True)
class PendingSdnOwnershipProofSet:
    """Exactly one proof per pending object, no more and no fewer."""

    results: tuple[OwnershipProofResult, ...] = ()

    def ownership_provenance_digest(self) -> str:
        return sha256_digest(
            {
                "results": sorted(
                    (r.canonical() for r in self.results), key=lambda row: row["object_key"]
                )
            }
        )

    @property
    def keys(self) -> tuple[tuple[str, str], ...]:
        return tuple(r.object_key for r in self.results)

    def by_key(self) -> dict[tuple[str, str], OwnershipProofResult]:
        return {r.object_key: r for r in self.results}


def classify_ownership(
    obj: PendingSdnObject, proof: OwnershipProofResult, operation: OperationBinding
) -> SdnObjectOwnership:
    """Derive ownership from evidence. ``unknown`` on any incomplete or disagreeing binding.

    Never returns ``current_operation`` on the strength of a name, an alias, a comment, matching
    attributes or timing — none of those is a parameter here, so none can be supplied.
    """
    if proof.ownership is SdnObjectOwnership.foreign and proof.proof_complete:
        # Positive proof it belongs to somebody else is stronger information than our binding
        # failing, and the operator should be told the stronger thing.
        return SdnObjectOwnership.foreign

    if (
        proof.range_identity
        and proof.operation_identity
        and (
            proof.range_identity != operation.range_identity
            or proof.operation_identity != operation.operation_identity
            or proof.operation_generation != operation.operation_generation
        )
    ):
        return SdnObjectOwnership.other_secp_operation

    required_non_empty = (
        proof.target_identity,
        proof.cluster_fingerprint,
        proof.range_identity,
        proof.operation_identity,
        proof.stage1_workspace_hash,
        proof.stage1_plan_hash,
        proof.stage1_execution_receipt_digest,
    )
    # Two empty strings compare equal, so equality alone is not proof. Without this, an object with
    # no evidence measured against an unconfigured operation would satisfy every `==`.
    if not all(required_non_empty):
        return SdnObjectOwnership.unknown

    if not (
        proof.target_identity == operation.target_identity
        and proof.cluster_fingerprint == operation.cluster_fingerprint
        and proof.range_identity == operation.range_identity
        and proof.operation_identity == operation.operation_identity
        and proof.operation_generation == operation.operation_generation
        and proof.stage1_workspace_hash == operation.stage1_workspace_hash
        and proof.stage1_plan_hash == operation.stage1_plan_hash
        and proof.proof_complete
    ):
        return SdnObjectOwnership.unknown

    if obj.action == "create":
        # Otherwise SECP could adopt somebody else's object that happened to share the identifier.
        # Note this reads the DERIVED action, not the target's ``new`` annotation: an object the
        # target labels new but whose active view is populated is not a create, and treating the
        # label as the answer is how an adoption passes as a creation.
        return (
            SdnObjectOwnership.current_operation
            if proof.pre_stage1_absence_evidence_digest
            else SdnObjectOwnership.unknown
        )

    # A change or delete touches something that already existed, so name and attribute agreement
    # cannot establish who created it.
    return (
        SdnObjectOwnership.current_operation
        if proof.durable_ownership_provenance_digest
        else SdnObjectOwnership.unknown
    )


# ==================================================================================================
# C. The disclosure — derived, presentational, authoritative over nothing.
# ==================================================================================================


@dataclass(frozen=True)
class PendingSdnDisclosure:
    """The operator-facing summary. Built ONLY by :func:`derive_disclosure`.

    It carries the two source digests so it cannot be transplanted onto a different document: a
    disclosure derived from one pending state and offered alongside another is detectable, which
    matters because this object is the one an operator actually reads.
    """

    pending_sdn_hash: str
    ownership_provenance_digest: str
    ownership_counts: dict[str, int]
    action_counts: dict[str, int]
    family_counts: dict[str, int]
    classification_complete: bool
    exclusive_to_current_operation: bool


#: The fixed projection. Explicit rather than derived from enum members, so renaming or adding an
#: ownership classification cannot silently change the manifest contract an operator reads.
_OWNERSHIP_FIELDS: tuple[tuple[str, SdnObjectOwnership], ...] = (
    ("current_operation", SdnObjectOwnership.current_operation),
    ("other_secp_operation", SdnObjectOwnership.other_secp_operation),
    ("foreign", SdnObjectOwnership.foreign),
    ("unknown", SdnObjectOwnership.unknown),
    ("unclassified", SdnObjectOwnership.unclassified),
)

#: The DERIVED action vocabulary. ``unchanged`` and ``ambiguous`` are counted too: an object whose
#: effect nobody can state must appear in the operator's summary, not fall out of it.
_ACTION_FIELDS: tuple[tuple[str, str], ...] = (
    ("create", "create"),
    ("change", "change"),
    ("delete", "delete"),
    ("unchanged", "unchanged"),
    ("ambiguous", "ambiguous"),
)


def derive_disclosure(
    document: PendingSdnDocument,
    proofs: PendingSdnOwnershipProofSet,
    operation: OperationBinding,
) -> PendingSdnDisclosure:
    """Compute the disclosure. The only way one comes into existence.

    ``operation`` is required, and its absence was a critical defect: this function used to count
    ``result.ownership`` — a plain field the submitter fills in — so the exclusivity gate standing
    between SECP and a cluster-wide ``PUT /cluster/sdn`` was decided by the value the submitter
    declared, and :func:`classify_ownership`, written precisely to derive that value from evidence,
    was called by nothing outside its own tests.
    """
    by_key = proofs.by_key()
    counts = {name: 0 for name, _ in _OWNERSHIP_FIELDS}
    for obj in document.objects:
        result = by_key.get(obj.key)
        classification = (
            classify_ownership(obj, result, operation)
            if result is not None
            else SdnObjectOwnership.unclassified
        )
        for name, member in _OWNERSHIP_FIELDS:
            if classification is member:
                counts[name] += 1
                break

    total = len(document.objects)
    ownership_counts = {"total_pending": total, **counts}

    action_counts = {name: 0 for name, _ in _ACTION_FIELDS}
    for obj in document.objects:
        for name, action in _ACTION_FIELDS:
            if obj.action == action:
                action_counts[name] += 1
                break

    family_counts: dict[str, int] = {}
    for obj in document.objects:
        family_counts[obj.family] = family_counts.get(obj.family, 0) + 1

    classification_complete = counts["unknown"] == 0 and counts["unclassified"] == 0
    exclusive = (
        total == counts["current_operation"]
        and counts["other_secp_operation"] == 0
        and counts["foreign"] == 0
        and counts["unknown"] == 0
        and counts["unclassified"] == 0
    )

    return PendingSdnDisclosure(
        pending_sdn_hash=document.pending_sdn_hash(),
        ownership_provenance_digest=proofs.ownership_provenance_digest(),
        ownership_counts=ownership_counts,
        action_counts=action_counts,
        family_counts=family_counts,
        classification_complete=classification_complete,
        exclusive_to_current_operation=exclusive,
    )


def object_manifest(
    document: PendingSdnDocument,
    proofs: PendingSdnOwnershipProofSet,
    operation: OperationBinding,
) -> tuple[dict, ...]:
    """Every pending object, individually. A summary is not a manifest.

    An operator refused an activation needs to see WHICH object blocked it; a count tells them how
    many and nothing else.

    The classification shown is the DERIVED one, for the same reason the counts are: an operator
    reading a manifest that echoes the submitter's claim is reading the submitter, not the cluster.
    Where the two differ, both are shown — a claim that does not survive derivation is worth
    seeing.
    """
    by_key = proofs.by_key()
    rows = []
    for obj in document.objects:
        result = by_key.get(obj.key)
        derived = (
            classify_ownership(obj, result, operation)
            if result is not None
            else SdnObjectOwnership.unclassified
        )
        rows.append(
            {
                "family": obj.family,
                "identifier": obj.object_id,
                "action": obj.action,
                "ownership_classification": derived.value,
                "submitted_classification": (
                    result.ownership.value if result is not None else "none_submitted"
                ),
                "classification_reason": (
                    result.classification_reason if result is not None else "no_proof_submitted"
                ),
                "range_binding": result.range_identity if result is not None else "",
                "operation_binding": result.operation_identity if result is not None else "",
                "generation_binding": result.operation_generation if result is not None else -1,
                "active_representation_digest": obj.normalized_active_representation,
                "pending_representation_digest": obj.normalized_pending_representation,
                "source_endpoint": obj.source_endpoint,
                "observation_state": obj.observation_state,
            }
        )
    return tuple(rows)


# ==================================================================================================
# The authorization — derives everything, accepts no summary.
# ==================================================================================================


@dataclass(frozen=True)
class ActivationAuthorization:
    """An operator's approval of one exact activation.

    Construct with :func:`issue_activation_authorization`. There is deliberately no counts
    parameter, no disclosure parameter and no ownership boolean anywhere on this type: a caller can
    supply the evidence classification is derived from, never the classification outcome.
    """

    pending_sdn_hash: str
    ownership_provenance_digest: str
    disclosure: PendingSdnDisclosure
    authorized_at: datetime
    authorized_by: str
    target_identity: str
    cluster_fingerprint: str
    range_identity: str
    operation_identity: str
    operation_generation: int
    worker_installation_id: str
    worker_release_fingerprint: str
    observation_ttl: timedelta = DEFAULT_PENDING_OBSERVATION_TTL


def issue_activation_authorization(
    *,
    document: PendingSdnDocument,
    proofs: PendingSdnOwnershipProofSet,
    operation: OperationBinding,
    authorized_at: datetime,
    authorized_by: str,
    observation_ttl: timedelta = DEFAULT_PENDING_OBSERVATION_TTL,
) -> ActivationAuthorization:
    """Validate, derive, enforce exclusivity, and bind. Refuses rather than returning a weak one.

    The MVP invariant is enforced here, at the only place an authorization can come into being: a
    non-exclusive pending set produces no authorization at all, so there is nothing for a later
    check to be persuaded to skip. Accepting the foreign-object residual is deliberately not
    available through this path — a mixed-owner activation is a different operation kind with its
    own contract.
    """
    if not document.signature_verified:
        raise SdnActivationRefused("sdn_pending_document_unsigned")
    if not document.visibility_complete:
        raise SdnActivationRefused("sdn_pending_document_visibility_incomplete")

    doc_keys = list(document.keys)
    proof_keys = list(proofs.keys)
    if len(set(doc_keys)) != len(doc_keys):
        raise SdnActivationRefused("sdn_pending_document_duplicate_object")
    if len(set(proof_keys)) != len(proof_keys):
        raise SdnActivationRefused("sdn_ownership_proof_duplicated")
    if set(doc_keys) != set(proof_keys):
        raise SdnActivationRefused("sdn_ownership_proof_set_mismatch")

    if not document.objects:
        # An activation of nothing is meaningless and can conceal an observation or composition
        # failure that produced an empty document. An operation with nothing pending does not need
        # cluster-wide activation and must not manufacture an authorization for one.
        raise SdnActivationRefused("sdn_activation_empty_pending_set")

    for binding in (
        operation.target_identity,
        operation.cluster_fingerprint,
        operation.range_identity,
        operation.operation_identity,
    ):
        if not binding or not str(binding).strip():
            raise SdnActivationRefused("sdn_activation_operation_binding_blank")

    if document.target_identity != operation.target_identity:
        raise SdnActivationRefused("sdn_activation_target_mismatch")
    if document.cluster_fingerprint != operation.cluster_fingerprint:
        raise SdnActivationRefused("sdn_activation_cluster_mismatch")

    for reason in sdn_differential_refusals(document, proofs):
        raise SdnActivationRefused(reason)

    disclosure = derive_disclosure(document, proofs, operation)

    if not disclosure.classification_complete:
        raise SdnActivationRefused(
            "cluster_pending_sdn_not_exclusive_to_operation:"
            + _counts_detail(disclosure.ownership_counts)
        )
    if not disclosure.exclusive_to_current_operation:
        raise SdnActivationRefused(
            "cluster_pending_sdn_not_exclusive_to_operation:"
            + _counts_detail(disclosure.ownership_counts)
        )

    return ActivationAuthorization(
        pending_sdn_hash=disclosure.pending_sdn_hash,
        ownership_provenance_digest=disclosure.ownership_provenance_digest,
        disclosure=disclosure,
        authorized_at=authorized_at,
        authorized_by=authorized_by,
        target_identity=operation.target_identity,
        cluster_fingerprint=operation.cluster_fingerprint,
        range_identity=operation.range_identity,
        operation_identity=operation.operation_identity,
        operation_generation=operation.operation_generation,
        worker_installation_id=document.worker_installation_id,
        worker_release_fingerprint=document.worker_release_fingerprint,
        observation_ttl=observation_ttl,
    )


def sdn_differential_refusals(
    document: PendingSdnDocument, proofs: PendingSdnOwnershipProofSet
) -> tuple[str, ...]:
    """Every reason this pending set's active/pending differential may not be acted on.

    Separate from the ownership gate because they answer different questions: ownership asks WHOSE
    an object is, the differential asks WHAT activation would do to it. An object can be provably
    ours and still be one whose effect nobody can state.
    """
    from secp_api.sdn_differential import ACTION_AMBIGUOUS, ACTION_CREATE, ACTION_DELETE

    by_key = proofs.by_key()
    reasons: list[str] = []
    seen: dict[tuple[str, str], int] = {}

    for obj in document.objects:
        seen[obj.key] = seen.get(obj.key, 0) + 1

        if obj.action == ACTION_AMBIGUOUS:
            reasons.append(
                f"sdn_object_action_ambiguous:{obj.family}:"
                f"{obj.object_id or '<unidentified>'}:{obj.ambiguity_reason or 'unclassified'}"
            )
        if obj.action == ACTION_CREATE:
            proof = by_key.get(obj.key)
            if proof is None or not proof.pre_stage1_absence_evidence_digest:
                # Without proof it was absent before Stage 1, a "create" may be an existing object
                # SECP is about to adopt because it happens to share an identifier.
                reasons.append(f"sdn_create_without_absence_evidence:{obj.family}:{obj.object_id}")
        if obj.action == ACTION_DELETE and not obj.normalized_active_representation:
            reasons.append(f"sdn_delete_without_active_evidence:{obj.family}:{obj.object_id}")

    for (family, object_id), count in sorted(seen.items()):
        if count > 1:
            # The object-to-proof join is one-to-one by construction; a duplicated identifier
            # cannot be matched to one proof and must not be resolved by picking either.
            reasons.append(f"sdn_identifier_not_unique:{family}:{object_id or '<unidentified>'}")

    return tuple(dict.fromkeys(reasons))


def _counts_detail(counts: dict[str, int]) -> str:
    """Every count in the refusal.

    One foreign object and eleven objects from an abandoned run are the same refusal and very
    different next actions, so the message carries the whole breakdown rather than a total.
    """
    parts = [f"total_pending={counts.get('total_pending', 0)}"]
    parts.extend(f"{name}={counts.get(name, 0)}" for name, _ in _OWNERSHIP_FIELDS)
    return ",".join(parts)


def activation_refusals(
    *,
    stage: str,
    authorization: ActivationAuthorization | None,
    document: PendingSdnDocument | None,
    proofs: PendingSdnOwnershipProofSet | None,
    operation: OperationBinding,
    now: datetime,
) -> tuple[str, ...]:
    """Stage 4. Rediscover, reclassify, recompute both digests, compare everything.

    All failing reasons are returned, not the first — an operator who re-observes to clear a stale
    hash only to meet a binding mismatch has been told half the truth twice.
    """
    reasons: list[str] = []

    if stage != STAGE_ACTIVATION_AUTHORIZED:
        reasons.append(f"sdn_activation_wrong_stage:{stage}")
    if authorization is None:
        reasons.append("sdn_activation_unauthorized")
    if document is None or proofs is None:
        reasons.append("sdn_activation_no_pending_observation")
    if authorization is None or document is None or proofs is None:
        return tuple(dict.fromkeys(reasons))

    if not document.signature_verified:
        reasons.append("sdn_pending_document_unsigned")
    if not document.visibility_complete:
        reasons.append("sdn_pending_document_visibility_incomplete")
        for family, state in document.unreadable_families:
            reasons.append(f"sdn_pending_family_unreadable:{family}:{state}")

    if set(document.keys) != set(proofs.keys):
        reasons.append("sdn_ownership_proof_set_mismatch")

    # BOTH digests, recomputed. The pending hash catches the cluster changing; the provenance digest
    # catches our evidence changing while the cluster did not — a provenance record disappearing
    # leaves the target-observed bytes identical.
    if document.pending_sdn_hash() != authorization.pending_sdn_hash:
        reasons.append("sdn_activation_pending_state_changed")
    if proofs.ownership_provenance_digest() != authorization.ownership_provenance_digest:
        reasons.append("sdn_activation_ownership_provenance_changed")

    reasons.extend(sdn_differential_refusals(document, proofs))

    disclosure = derive_disclosure(document, proofs, operation)
    if not disclosure.exclusive_to_current_operation or not disclosure.classification_complete:
        reasons.append(
            "cluster_pending_sdn_not_exclusive_to_operation:"
            + _counts_detail(disclosure.ownership_counts)
        )
    if disclosure.ownership_counts != authorization.disclosure.ownership_counts:
        reasons.append("sdn_activation_disclosure_changed")

    age = now - document.observed_at
    if age < timedelta(0):
        reasons.append("sdn_activation_observation_clock_skew")
    elif age > authorization.observation_ttl:
        reasons.append("sdn_activation_observation_expired")

    if authorization.target_identity != operation.target_identity:
        reasons.append("sdn_activation_target_mismatch")
    if authorization.operation_identity != operation.operation_identity:
        reasons.append("sdn_activation_operation_mismatch")
    if authorization.operation_generation != operation.operation_generation:
        reasons.append("sdn_activation_generation_mismatch")

    return tuple(dict.fromkeys(reasons))


def next_stage(current: str) -> str:
    if current not in STAGE_ORDER:
        raise SdnActivationRefused(f"sdn_activation_unknown_stage:{current}")
    index = STAGE_ORDER.index(current)
    if index + 1 >= len(STAGE_ORDER):
        raise SdnActivationRefused("sdn_activation_already_verified")
    return STAGE_ORDER[index + 1]


def guests_may_deploy(stage: str) -> bool:
    """Guests attach to VNets, so they wait for stage 5.

    ``PUT /cluster/sdn`` returning success means the task was accepted, not that every node has
    reloaded and the bridges exist.
    """
    return stage == STAGE_VERIFIED


@dataclass(frozen=True)
class ActivationRecord:
    """What is retained about one activation, for the operator manifest and for audit."""

    stage: str
    pending_sdn_hash_at_authorization: str = ""
    pending_sdn_hash_at_activation: str = ""
    ownership_provenance_digest_at_authorization: str = ""
    ownership_provenance_digest_at_activation: str = ""
    ownership_counts_at_activation: dict[str, int] = field(default_factory=dict)
    activated_at: datetime | None = None
    verified_at: datetime | None = None
    refusal_reasons: tuple[str, ...] = field(default_factory=tuple)
