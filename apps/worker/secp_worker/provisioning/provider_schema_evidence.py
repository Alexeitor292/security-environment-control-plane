"""The only gate through which ``provider_schema_validation`` may read ``verified``.

``plan_document.py`` used to take a bare ``provider_schema_verified: bool``. A bool is exactly the
wrong shape for this field: it lets a caller assert the conclusion, and the conclusion is a safety
claim an operator acts on. What an operator needs to know when they read ``verified`` is not that
somebody passed ``True`` — it is that a specific, pinned, offline toolchain was actually run against
a specific rendered configuration and answered.

So this module models the FACTS and derives the status from them. Every fact is required, and the
two that could most easily be faked by assertion are computed instead:

* schema coverage is a set comparison — the types the rendered modules use against the types the
  provider's own schema reported — rather than a "we checked" flag;
* the isolation proofs are four separate observations, because "it was isolated" as a single bool
  is a summary of someone's reasoning, not evidence.

The result is that producing ``verified`` requires having actually run the commands. There is no
argument you can pass to this module that skips them.

Nothing here performs I/O, spawns a process or imports a transport. It is pure data plus one
derivation, so it is testable without a toolchain and cannot itself become a way to reach one.
"""

from __future__ import annotations

from dataclasses import dataclass

# The two literals the plan document may carry. There is deliberately no third value: an operator
# reading this field is deciding whether to authorise an apply, and a middle term ("partial",
# "degraded") is the kind of hedge that gets read as good enough.
SCHEMA_VALIDATION_VERIFIED = "verified"
SCHEMA_VALIDATION_UNVERIFIED = "unverified"

# The schema format version this evidence contract was written against. `tofu providers schema
# -json` reports its own `format_version`, and a future format could move or rename the very keys
# the coverage check reads. Pinning it means a format change fails closed as `unverified` with a
# stated reason, rather than silently reporting coverage computed from a structure nobody checked.
EXPECTED_SCHEMA_FORMAT_VERSION = "1.0"


class ProviderSchemaEvidenceError(ValueError):
    """A fact required to reason about schema validation is missing or self-contradictory."""


@dataclass(frozen=True)
class IsolationProofs:
    """The four negative facts, each observed separately.

    They are separate fields rather than one ``isolated: bool`` because they fail for different
    reasons and a single flag hides which. ``providers schema`` in particular LAUNCHES THE PROVIDER
    PLUGIN to ask for its schema, so provider code really does execute here — these four are what
    make that acceptable, and collapsing them into a summary would obscure the one that matters.
    """

    backend_disabled: bool
    """``init`` ran with ``-backend=false``: no backend was configured, read, locked or written."""

    no_provider_credentials_present: bool
    """No Proxmox credential of any kind was placed in the child's environment or workspace."""

    network_egress_denied: bool
    """Egress was denied for the child process, not merely unused."""

    no_proxmox_endpoint_configured: bool
    """No Proxmox endpoint was configured, so there was nothing for the plugin to reach."""

    def unmet(self) -> tuple[str, ...]:
        """The names of the proofs that were not observed, in a stable order."""
        return tuple(
            name
            for name, held in (
                ("backend_disabled", self.backend_disabled),
                ("no_provider_credentials_present", self.no_provider_credentials_present),
                ("network_egress_denied", self.network_egress_denied),
                ("no_proxmox_endpoint_configured", self.no_proxmox_endpoint_configured),
            )
            if not held
        )


@dataclass(frozen=True)
class ProviderSchemaEvidence:
    """Everything that must hold before the plan document may say ``verified``.

    Constructing this object does NOT mean the status is verified — :func:`schema_validation_status`
    decides that, and it refuses on any unmet fact. The split is deliberate: evidence should be
    recordable even when it is incomplete, because an incomplete record is how an operator learns
    *which* step did not happen.
    """

    # --- the toolchain identity ------------------------------------------------------------------
    opentofu_version: str
    opentofu_executable_digest: str
    provider_source: str
    provider_version: str
    provider_package_digest: str
    lockfile_digest: str
    mirror_digest: str

    # --- what was actually validated -------------------------------------------------------------
    rendered_workspace_hash: str
    """The hash of the exact configuration that was validated. Binds the answer to the question."""

    # --- what the three commands did -------------------------------------------------------------
    offline_init_succeeded: bool
    configuration_validation_succeeded: bool
    """``validate -json`` returned success for the exact rendered configuration."""
    schema_extraction_succeeded: bool
    """``providers schema -json`` returned a parseable document."""
    schema_format_version: str

    # --- coverage, as sets rather than a claim ---------------------------------------------------
    types_required_by_rendered_modules: frozenset[str]
    """Every provider resource and data-source type the rendered configuration actually uses."""
    types_present_in_provider_schema: frozenset[str]
    """Every type the provider's own schema document reported."""

    # --- the negative facts ----------------------------------------------------------------------
    isolation: IsolationProofs

    def missing_types(self) -> tuple[str, ...]:
        """Types the rendered modules use that the pinned provider's schema does not offer.

        This is the check the whole exercise exists for. A pin can satisfy every digest and still be
        the wrong provider version — one that simply does not have ``proxmox_virtual_environment_
        sdn_vnet``, say — and the failure would otherwise surface as an apply-time error against
        real infrastructure instead of a refusal before the operator is ever asked to authorise.
        """
        return tuple(
            sorted(self.types_required_by_rendered_modules - self.types_present_in_provider_schema)
        )


def _blank_identity_fields(evidence: ProviderSchemaEvidence) -> tuple[str, ...]:
    """Identity fields that are empty or whitespace, in declaration order.

    Checked by value rather than by presence: a digest field carrying ``""`` is not an absent digest
    that someone will fill in later, it is a plan document that would claim a pinned toolchain it
    cannot name.
    """
    return tuple(
        name
        for name, value in (
            ("opentofu_version", evidence.opentofu_version),
            ("opentofu_executable_digest", evidence.opentofu_executable_digest),
            ("provider_source", evidence.provider_source),
            ("provider_version", evidence.provider_version),
            ("provider_package_digest", evidence.provider_package_digest),
            ("lockfile_digest", evidence.lockfile_digest),
            ("mirror_digest", evidence.mirror_digest),
            ("rendered_workspace_hash", evidence.rendered_workspace_hash),
        )
        if not str(value).strip()
    )


def schema_validation_reasons(evidence: ProviderSchemaEvidence | None) -> tuple[str, ...]:
    """Every reason the status is not ``verified``. Empty means it is.

    Returning the reasons rather than a bool is what lets the plan document and the operator
    manifest say *why* the provider schema is unverified. "unverified" with no reason is the
    failure mode described in ``plan_document``'s own docstring: a field an operator cannot act on.
    """
    if evidence is None:
        return ("no schema-validation evidence was recorded",)

    reasons: list[str] = []

    blanks = _blank_identity_fields(evidence)
    if blanks:
        reasons.append("unpinned or unnamed toolchain identity: " + ", ".join(blanks))

    if not evidence.offline_init_succeeded:
        reasons.append("offline initialization did not succeed")
    if not evidence.configuration_validation_succeeded:
        reasons.append("`validate -json` did not succeed for the rendered configuration")
    if not evidence.schema_extraction_succeeded:
        reasons.append("`providers schema -json` did not produce a parseable schema")

    if evidence.schema_format_version != EXPECTED_SCHEMA_FORMAT_VERSION:
        reasons.append(
            f"schema format version {evidence.schema_format_version!r} is not the expected "
            f"{EXPECTED_SCHEMA_FORMAT_VERSION!r}"
        )

    # An empty required set is treated as a failure, not as trivially-satisfied coverage. A rendered
    # configuration that uses no provider types would not need a provider at all, so an empty set
    # here means the extraction step did not run or did not find anything -- and "nothing was
    # required, so everything is covered" is precisely the vacuous pass this check must not give.
    if not evidence.types_required_by_rendered_modules:
        reasons.append("no provider types were collected from the rendered modules")
    else:
        missing = evidence.missing_types()
        if missing:
            reasons.append(
                "the pinned provider schema is missing types the rendered modules use: "
                + ", ".join(missing)
            )

    unmet = evidence.isolation.unmet()
    if unmet:
        reasons.append("isolation was not proven: " + ", ".join(unmet))

    return tuple(reasons)


def schema_validation_status(evidence: ProviderSchemaEvidence | None) -> str:
    """``"verified"`` only when every recorded fact holds; otherwise ``"unverified"``.

    Fail-closed by construction: the ``verified`` branch is reachable only through an empty reason
    list, so a fact added to :func:`schema_validation_reasons` in future tightens this function
    automatically rather than needing a matching edit here.
    """
    return (
        SCHEMA_VALIDATION_VERIFIED
        if not schema_validation_reasons(evidence)
        else SCHEMA_VALIDATION_UNVERIFIED
    )
