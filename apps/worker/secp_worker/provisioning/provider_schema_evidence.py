"""Two layers, because recording a fact and having authority over a claim are different jobs.

``provider_schema_validation`` is a safety claim an operator acts on, so the question this module
has to answer is not "did someone say the schema was validated" but "can anyone say it without
having actually validated it". The first version of this module failed that test: it modelled the
facts as one public frozen dataclass and derived the status from them, which removed the
``provider_schema_verified=True`` escape hatch and replaced it with a slightly longer one. A caller
could fill in truthful-looking digests, set four booleans, and get ``verified``. The test fixture
that did exactly that was the proof.

So the layers are split by AUTHORITY, not by convenience:

:class:`ProviderSchemaObservation`
    Public, freely constructible, deliberately incomplete-tolerant. Records what was seen — exit
    statuses, parsed schema, missing types, versions, digests, partial isolation observations — and
    explains what is missing. **It can never produce** ``verified``. Anyone may build one, which is
    the point: an incomplete record is how an operator learns which step did not happen.

:class:`ProviderSchemaAttestation`
    Opaque, token-gated, non-serializable. The ONLY thing that can produce ``verified``. Minting it
    requires the module-private token, so a caller assembling ordinary dataclasses or dictionaries
    cannot make one, and it binds the full provenance of the run that produced it — executor
    identity, toolchain digests, the exact admitted command sequence, the command results, the
    rendered workspace it validated, and the four isolation observations.

Binding the workspace is what stops an attestation being reusable. A valid attestation for plan A
says nothing about plan B, so :func:`schema_validation_status` requires the caller to state which
workspace it is asking about and refuses on any mismatch. The same applies to the executor
identity: an attestation minted against a boundary with a different command grammar is refused, not
trusted.

This module still performs no I/O and spawns no process. It defines who may speak, and about what.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import NoReturn, SupportsIndex

# The two literals the plan document may carry. There is deliberately no third value: an operator
# reading this field is deciding whether to authorise an apply, and a middle term ("partial",
# "degraded") is the kind of hedge that gets read as good enough.
SCHEMA_VALIDATION_VERIFIED = "verified"
SCHEMA_VALIDATION_UNVERIFIED = "unverified"

# The schema format version this contract was written against. `tofu providers schema -json`
# reports its own `format_version`, and a future format could move or rename the very keys the
# coverage check reads. Pinning it means a format change fails closed with a stated reason rather
# than reporting coverage computed from a structure nobody checked.
EXPECTED_SCHEMA_FORMAT_VERSION = "1.0"

# The exact command sequence an attestation must record, in order. Schema inspection is meaningless
# without the init that placed the pinned provider in the workspace, so the sequence is bound as a
# whole rather than as three independent successes.
REVIEWED_COMMAND_SEQUENCE = ("init", "validate", "providers")

# Module-private minting token. An attestation cannot be built without it, and it is not exported
# by name from anywhere a caller would ordinarily look. `test_provider_schema_authority.py` asserts
# that no shipped module outside this one reaches it — the same containment the plan-only
# capability token relies on, reused rather than reinvented.
_SCHEMA_ATTESTATION_TOKEN = object()


class ProviderSchemaAttestationRefused(Exception):
    """An attestation could not be minted, or does not bind the plan it was offered for."""


# ==================================================================================================
# Layer 1 — the public observation. Records; never authorises.
# ==================================================================================================


@dataclass(frozen=True)
class IsolationObservations:
    """The four negative facts, observed separately.

    Separate fields rather than one ``isolated: bool`` because they fail for different reasons and a
    single flag hides which. ``providers schema -json`` LAUNCHES THE PROVIDER PLUGIN to ask for its
    schema, so provider code really does execute — these four are what make that acceptable, and a
    summary would obscure the one that matters.

    Every field defaults to ``False``: an unobserved isolation property is not isolation.
    """

    backend_disabled: bool = False
    no_provider_credentials_present: bool = False
    network_egress_denied: bool = False
    no_proxmox_endpoint_configured: bool = False

    def unmet(self) -> tuple[str, ...]:
        """The names of the proofs not observed, in a stable order."""
        return tuple(f.name for f in fields(self) if not getattr(self, f.name))


@dataclass(frozen=True)
class ProviderSchemaObservation:
    """What a schema-inspection run saw. Freely constructible, and authoritative over nothing.

    Every field has a default, because the honest record of a run that failed at step one is a
    mostly-empty observation — not an exception, and not silence. :meth:`reasons` is what makes that
    record useful.
    """

    opentofu_version: str = ""
    opentofu_executable_digest: str = ""
    provider_source: str = ""
    provider_version: str = ""
    provider_package_digest: str = ""
    lockfile_digest: str = ""
    mirror_digest: str = ""
    rendered_workspace_hash: str = ""

    offline_init_succeeded: bool = False
    configuration_validation_succeeded: bool = False
    schema_extraction_succeeded: bool = False
    schema_format_version: str = ""

    types_required_by_rendered_modules: frozenset[str] = frozenset()
    types_present_in_provider_schema: frozenset[str] = frozenset()

    isolation: IsolationObservations = IsolationObservations()

    def missing_types(self) -> tuple[str, ...]:
        """Types the rendered modules use that the pinned provider's schema does not offer.

        The check the whole exercise exists for. A pin can satisfy every digest and still be the
        wrong provider version — one that simply does not have
        ``proxmox_virtual_environment_sdn_vnet``, say — and the failure would otherwise surface as
        an apply-time error against real infrastructure rather than a refusal before the operator is
        ever asked to authorise anything.
        """
        return tuple(
            sorted(self.types_required_by_rendered_modules - self.types_present_in_provider_schema)
        )

    def reasons(self) -> tuple[str, ...]:
        """Everything about this observation that falls short of a complete run.

        An empty tuple means the observation is COMPLETE. It does not mean the status is
        ``verified`` — only an attestation can say that, and this method deliberately cannot mint
        one. Completeness is a precondition for minting, checked again at minting time.
        """
        reasons: list[str] = []

        blanks = tuple(
            name
            for name, value in (
                ("opentofu_version", self.opentofu_version),
                ("opentofu_executable_digest", self.opentofu_executable_digest),
                ("provider_source", self.provider_source),
                ("provider_version", self.provider_version),
                ("provider_package_digest", self.provider_package_digest),
                ("lockfile_digest", self.lockfile_digest),
                ("mirror_digest", self.mirror_digest),
                ("rendered_workspace_hash", self.rendered_workspace_hash),
            )
            if not str(value).strip()
        )
        if blanks:
            reasons.append("unpinned or unnamed toolchain identity: " + ", ".join(blanks))

        if not self.offline_init_succeeded:
            reasons.append("offline initialization did not succeed")
        if not self.configuration_validation_succeeded:
            reasons.append("`validate -json` did not succeed for the rendered configuration")
        if not self.schema_extraction_succeeded:
            reasons.append("`providers schema -json` did not produce a parseable schema")

        if self.schema_format_version != EXPECTED_SCHEMA_FORMAT_VERSION:
            reasons.append(
                f"schema format version {self.schema_format_version!r} is not the expected "
                f"{EXPECTED_SCHEMA_FORMAT_VERSION!r}"
            )

        # An empty required set is a failure, not trivially-satisfied coverage. A configuration that
        # used no provider types would not need a provider at all, so an empty set means the
        # collection step did not run — and "nothing was required, so everything is covered" is
        # precisely the vacuous pass this must not give. Set subtraction alone would allow it.
        if not self.types_required_by_rendered_modules:
            reasons.append("no provider types were collected from the rendered modules")
        else:
            missing = self.missing_types()
            if missing:
                reasons.append(
                    "the pinned provider schema is missing types the rendered modules use: "
                    + ", ".join(missing)
                )

        unmet = self.isolation.unmet()
        if unmet:
            reasons.append("isolation was not proven: " + ", ".join(unmet))

        return tuple(reasons)


# ==================================================================================================
# Layer 2 — the attestation. The only thing that can authorise `verified`.
# ==================================================================================================


@dataclass(frozen=True)
class SchemaAttestationBinding:
    """The provenance an attestation carries.

    Constructing one of these is harmless: it is inert data and cannot authorise anything on its
    own. Authority comes from :class:`ProviderSchemaAttestation`, which only the private token can
    mint, and which re-checks this binding against the plan and the live executor identity at every
    read.
    """

    # Who ran it — bound so an attestation cannot outlive the boundary it was reviewed against.
    executor_implementation_id: str
    executor_implementation_digest: str

    # What ran it.
    opentofu_version: str
    opentofu_executable_digest: str
    provider_source: str
    provider_version: str
    provider_package_digest: str
    lockfile_digest: str
    mirror_digest: str

    # What it ran against, and what it did.
    rendered_workspace_hash: str
    command_sequence: tuple[str, ...]
    command_result_digests: tuple[str, ...]

    # What it found.
    schema_format_version: str
    types_required_by_rendered_modules: frozenset[str]
    types_present_in_provider_schema: frozenset[str]

    # What it proved about the surroundings.
    isolation: IsolationObservations


class ProviderSchemaAttestation:
    """An opaque, non-serializable proof that a real schema inspection ran and answered.

    Modelled on ``PlanOnlyCapability`` deliberately: same private-token construction, same refusal
    to serialize, same redacted repr. A second trust mechanism would be a second thing to get right.

    Serialization is refused rather than merely unimplemented. A picklable authority object is a
    file, and a file is a thing that can be produced by something other than the run it describes.
    """

    __slots__ = ("__binding",)

    def __init__(self, token: object, binding: SchemaAttestationBinding) -> None:
        if token is not _SCHEMA_ATTESTATION_TOKEN:
            raise TypeError(
                "ProviderSchemaAttestation cannot be constructed directly; it is minted only by "
                "the attested schema-inspection producer, via issue_provider_schema_attestation"
            )
        object.__setattr__(self, "_ProviderSchemaAttestation__binding", binding)

    @property
    def binding(self) -> SchemaAttestationBinding:
        return object.__getattribute__(self, "_ProviderSchemaAttestation__binding")  # type: ignore[no-any-return]

    def __repr__(self) -> str:
        return "ProviderSchemaAttestation(<redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __getstate__(self) -> NoReturn:
        raise TypeError("ProviderSchemaAttestation cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderSchemaAttestation cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ProviderSchemaAttestation cannot be pickled")


def issue_provider_schema_attestation(
    token: object,
    binding: SchemaAttestationBinding,
    *,
    observation: ProviderSchemaObservation,
    expected_executor_implementation_id: str,
    expected_executor_implementation_digest: str,
) -> ProviderSchemaAttestation:
    """Mint an attestation, or refuse.

    ``token`` is the module-private minting token. It is the first check rather than the last
    because everything after it is only meaningful once the caller is the producer.

    The observation is required alongside the binding and must be COMPLETE and must AGREE with it.
    That redundancy is the point: the binding is what the attestation will assert, the observation
    is what the run actually saw, and requiring both to say the same thing means a producer cannot
    mint an attestation more confident than its own record.
    """
    if token is not _SCHEMA_ATTESTATION_TOKEN:
        raise ProviderSchemaAttestationRefused(
            "only the attested schema-inspection producer may mint a schema attestation"
        )

    for f in fields(binding):
        value = getattr(binding, f.name)
        if isinstance(value, str) and not value.strip():
            raise ProviderSchemaAttestationRefused(f"attestation field {f.name} is empty")

    if binding.executor_implementation_id != expected_executor_implementation_id:
        raise ProviderSchemaAttestationRefused("executor implementation id is not the reviewed one")
    if binding.executor_implementation_digest != expected_executor_implementation_digest:
        raise ProviderSchemaAttestationRefused(
            "executor implementation digest is not the reviewed one"
        )

    if binding.command_sequence != REVIEWED_COMMAND_SEQUENCE:
        raise ProviderSchemaAttestationRefused(
            "attestation does not record the exact reviewed command sequence"
        )
    # One result digest per command: an attestation claiming three commands and carrying two
    # results has not recorded what one of them returned.
    if len(binding.command_result_digests) != len(REVIEWED_COMMAND_SEQUENCE):
        raise ProviderSchemaAttestationRefused(
            "attestation must carry one command-result digest per admitted command"
        )
    if any(not d.strip() for d in binding.command_result_digests):
        raise ProviderSchemaAttestationRefused("attestation carries an empty command-result digest")

    incomplete = observation.reasons()
    if incomplete:
        raise ProviderSchemaAttestationRefused(
            "observation is incomplete: " + "; ".join(incomplete)
        )

    # The binding may not claim anything the observation did not see.
    disagreements = tuple(
        name
        for name, mine, theirs in (
            ("opentofu_version", binding.opentofu_version, observation.opentofu_version),
            (
                "opentofu_executable_digest",
                binding.opentofu_executable_digest,
                observation.opentofu_executable_digest,
            ),
            ("provider_source", binding.provider_source, observation.provider_source),
            ("provider_version", binding.provider_version, observation.provider_version),
            (
                "provider_package_digest",
                binding.provider_package_digest,
                observation.provider_package_digest,
            ),
            ("lockfile_digest", binding.lockfile_digest, observation.lockfile_digest),
            ("mirror_digest", binding.mirror_digest, observation.mirror_digest),
            (
                "rendered_workspace_hash",
                binding.rendered_workspace_hash,
                observation.rendered_workspace_hash,
            ),
            (
                "schema_format_version",
                binding.schema_format_version,
                observation.schema_format_version,
            ),
            (
                "types_required_by_rendered_modules",
                binding.types_required_by_rendered_modules,
                observation.types_required_by_rendered_modules,
            ),
            (
                "types_present_in_provider_schema",
                binding.types_present_in_provider_schema,
                observation.types_present_in_provider_schema,
            ),
            ("isolation", binding.isolation, observation.isolation),
        )
        if mine != theirs
    )
    if disagreements:
        raise ProviderSchemaAttestationRefused(
            "attestation disagrees with the observation it was minted from: "
            + ", ".join(disagreements)
        )

    return ProviderSchemaAttestation(_SCHEMA_ATTESTATION_TOKEN, binding)


# ==================================================================================================
# The gate the plan document reads.
# ==================================================================================================


def schema_validation_reasons(
    attestation: object | None,
    observation: ProviderSchemaObservation | None = None,
    *,
    expected_workspace_hash: str = "",
    expected_executor_implementation_id: str = "",
    expected_executor_implementation_digest: str = "",
) -> tuple[str, ...]:
    """Every reason the status is not ``verified``. Empty means it is.

    ``attestation`` is typed ``object`` on purpose. A caller offering a look-alike — a dataclass, a
    dict, a namespace with a ``.binding`` — must be refused by TYPE rather than by duck-typed
    attribute access, and a narrower annotation would only document that intent while the runtime
    check is what enforces it.

    ``observation`` contributes reasons but never authority, so an operator gets a useful
    explanation in the ordinary case where the run happened and fell short.
    """
    if attestation is None:
        if observation is not None:
            recorded = observation.reasons()
            if recorded:
                return recorded
            # A complete observation with no attestation is the interesting case: the run looks
            # finished, but nothing minted authority for it. Saying so is more useful than listing
            # nothing.
            return ("a complete observation was recorded but no attestation was minted for it",)
        return ("no schema-validation evidence was recorded",)

    if not isinstance(attestation, ProviderSchemaAttestation):
        return ("schema-validation authority was offered by something that is not an attestation",)

    binding = attestation.binding
    reasons: list[str] = []

    # Re-checked at READ time, not only at mint time. An attestation minted against an earlier
    # boundary must not verify a plan produced by this one.
    if binding.executor_implementation_id != expected_executor_implementation_id:
        reasons.append("attestation was minted against a different executor implementation id")
    if binding.executor_implementation_digest != expected_executor_implementation_digest:
        reasons.append("attestation was minted against a different executor implementation digest")

    # The binding that makes an attestation non-transferable: it names the workspace it validated.
    if not expected_workspace_hash:
        reasons.append("no workspace hash was supplied to check the attestation against")
    elif binding.rendered_workspace_hash != expected_workspace_hash:
        reasons.append("attestation was minted for a different rendered workspace")

    if binding.command_sequence != REVIEWED_COMMAND_SEQUENCE:
        reasons.append("attestation does not record the exact reviewed command sequence")
    if binding.schema_format_version != EXPECTED_SCHEMA_FORMAT_VERSION:
        reasons.append(
            f"schema format version {binding.schema_format_version!r} is not the expected "
            f"{EXPECTED_SCHEMA_FORMAT_VERSION!r}"
        )

    if not binding.types_required_by_rendered_modules:
        reasons.append("no provider types were collected from the rendered modules")
    else:
        missing = tuple(
            sorted(
                binding.types_required_by_rendered_modules
                - binding.types_present_in_provider_schema
            )
        )
        if missing:
            reasons.append(
                "the pinned provider schema is missing types the rendered modules use: "
                + ", ".join(missing)
            )

    unmet = binding.isolation.unmet()
    if unmet:
        reasons.append("isolation was not proven: " + ", ".join(unmet))

    return tuple(reasons)


def schema_validation_status(
    attestation: object | None,
    observation: ProviderSchemaObservation | None = None,
    *,
    expected_workspace_hash: str = "",
    expected_executor_implementation_id: str = "",
    expected_executor_implementation_digest: str = "",
) -> str:
    """``"verified"`` only from a valid attestation that binds THIS plan; otherwise
    ``"unverified"``.

    Fail-closed by construction: the ``verified`` branch is reachable only through an empty reason
    list, so a check added to :func:`schema_validation_reasons` tightens this automatically.
    """
    return (
        SCHEMA_VALIDATION_VERIFIED
        if not schema_validation_reasons(
            attestation,
            observation,
            expected_workspace_hash=expected_workspace_hash,
            expected_executor_implementation_id=expected_executor_implementation_id,
            expected_executor_implementation_digest=expected_executor_implementation_digest,
        )
        else SCHEMA_VALIDATION_UNVERIFIED
    )
