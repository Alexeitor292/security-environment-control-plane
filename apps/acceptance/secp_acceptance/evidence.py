"""The structured two-host acceptance evidence document.

Written to the same rules as the management plane's own evidence
(:mod:`secp_management.evidence`): strict pydantic (``extra='forbid'``, ``frozen``, ``strict``),
canonical JSON, digest-bearing, and NONSECRET. It carries identities, digests, closed vocabulary
members and booleans — never a host path, container id, origin, token, certificate, private key,
DSN, or raw command output. The loader re-applies the forbidden-secret scan and re-checks every
closed-vocabulary membership, so a document that reaches a reader has already been re-derived
rather than merely trusted.

WHAT A READER MAY CONCLUDE FROM IT
----------------------------------
A ``passed`` run means: every check declared in :data:`~secp_acceptance.reasons.CHECKS_BY_STAGE`
for every attempted stage was recorded, and each was ``observed`` (the positive observation was
made) or ``refused`` with the reason code the scenario expected. It does NOT mean the product is
correct in general, and it does not mean anything about stages that were not attempted — an
unattempted stage is absent from ``stages_attempted`` and its checks are absent from ``checks``.
:meth:`AcceptanceEvidence.coverage_complete` is the only predicate that says the attempted stages
were fully covered; read it rather than inferring completeness from the absence of failures.

Every fidelity substitution is a first-class :class:`GapRecord` in ``gaps``. A gap is not a defect
report and not an apology — it is the statement that a named part of the acceptance was proven
against a substitute rather than against the real thing, so a reader knows exactly which sentences
in a green run are weaker than they look.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_digest
from secp_commissioning.descriptor import scan_forbidden

from secp_acceptance import ACCEPTANCE_CONTRACT_VERSION, AcceptanceError
from secp_acceptance.reasons import (
    ALL_REASONS,
    CHECKS,
    CHECKS_BY_STAGE,
    OUTCOME_OBSERVED,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
    OUTCOMES,
    PASSING_OUTCOMES,
    RUN_FAILED,
    RUN_OUTCOMES,
    RUN_PASSED,
    STAGES,
)

#: The versioned schema identity. Bound into the document AND into every derived digest, so a
#: document from a future schema can never be read as if it were this one.
ACCEPTANCE_EVIDENCE_SCHEMA = "secp.acceptance.two-host-evidence/v1"

#: Domain separation for the run identity. A run id is a digest of the run's fixed inputs, never a
#: random value, so two runs of the same harness over the same fleet shape are comparable.
_RUN_IDENTITY_SCHEMA = "secp.acceptance.run-identity/v1"

#: Domain separation for a bounded observation's content address. The raw observation (command
#: output, container inspection, HTTP body) is NEVER stored; only this digest is.
_OBSERVATION_SCHEMA = "secp.acceptance.observation/v1"

_MAX_CHECKS = 512
_MAX_GAPS = 64

_Str = Annotated[str, Field(min_length=1, max_length=200, strict=True)]
_Text = Annotated[str, Field(min_length=1, max_length=1000, strict=True)]

#: A closed identifier grammar for every vocabulary member the document carries. The closed sets are
#: already checked by name; this additionally bounds the SHAPE, so a member that somehow reached the
#: document from a future vocabulary still cannot carry punctuation, a path separator, or a space.
_IDENT = re.compile(r"[a-z][a-z0-9_]{0,63}")

#: A git commit identity. The release lineage carries source shas, and they are the one place a
#: 40-hex string is legitimate.
_SOURCE_SHA = re.compile(r"[0-9a-f]{40}")

#: The roles a release bundle may carry. Closed, because ``role`` decides which host a bundle is
#: allowed to install onto, and a run that installed a controller bundle on the worker is a
#: different run from the one the document claims.
_RELEASE_ROLES: frozenset[str] = frozenset({"worker", "controller"})


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def observation_digest(payload: object) -> str:
    """The content address of ONE bounded observation.

    The harness observes real hosts, so the raw material — container inspections, systemd unit
    state, HTTP bodies, CLI reports — routinely contains paths, ids and origins. None of it belongs
    in an evidence document that gets attached to a PR. The caller reduces its observation to a
    bounded, secret-free projection and stores only this digest; the projection itself is what the
    check's assertion runs against, in memory, at the moment it is made.
    """
    return sha256_digest({"v": _OBSERVATION_SCHEMA, "observation": payload})


def run_identity(*, harness_version: str, fleet_identity: str, release_identity: str) -> str:
    """The deterministic run identity: harness contract + fleet shape + release lineage."""
    return sha256_digest(
        {
            "v": _RUN_IDENTITY_SCHEMA,
            "harness_version": harness_version,
            "fleet_identity": fleet_identity,
            "release_identity": release_identity,
        }
    )


class CheckRecord(_Strict):
    """One recorded acceptance check.

    ``reason_code`` is REQUIRED for ``refused`` and ``unproven`` and FORBIDDEN for ``observed``: a
    positive observation that also carries a refusal reason is incoherent, and a refusal without a
    bounded code is exactly the unreadable outcome the closed vocabulary exists to prevent.
    """

    check: _Str
    stage: _Str
    outcome: _Str
    reason_code: _Str | None = None
    observation_digest: _Str

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


class GapRecord(_Strict):
    """One explicitly named fidelity gap.

    ``substitute`` says what actually ran; ``why`` says what local disposable infrastructure could
    not reach. Both are required, because a gap whose reason is not written down cannot be told
    apart from an oversight the next reader will assume was deliberate.

    A GAP IS A SUBSTITUTION, NOT A FAILURE
    --------------------------------------
    This is the distinction to hold on to, because the wrong choice here is quiet. A gap says "this
    was proven against a stand-in"; it does NOT say "this could not be proven". If the product
    REFUSED, or the harness could not make an observation, that belongs in a :class:`CheckRecord` as
    ``refused`` / ``unproven`` / ``violated`` with a bounded reason code — never in a gap.

    Filing a refusal as a gap would move a real finding out of ``checks``, where the verdict is
    derived from it, into ``gaps``, where nothing computes on it. The run would still pass. That is
    the whole failure mode, and it is why ``weakens`` must name real check ids: a gap is a footnote
    ON a claim, not a replacement FOR one.
    """

    gap: _Str
    stage: _Str
    substitute: _Text
    why: _Text
    weakens: tuple[str, ...]

    @field_validator("weakens", mode="before")
    @classmethod
    def _coerce(cls, v: object) -> object:
        return tuple(v) if isinstance(v, list) else v

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


class FleetRecord(_Strict):
    """The disposable fleet's identity — shapes and digests only, never an id or an address."""

    host_image_identity: _Str
    controller_host_identity: _Str
    worker_host_identity: _Str
    network_identity: _Str
    hosts_created: Annotated[int, Field(ge=0, le=64, strict=True)]
    hosts_destroyed: Annotated[int, Field(ge=0, le=64, strict=True)]
    nested_container_runtime: bool
    real_service_manager: bool

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


class ReleaseRecord(_Strict):
    """The signed worker release lineage the run installed and upgraded across."""

    role: _Str
    baseline_aggregate: _Str
    successor_aggregate: _Str | None = None
    baseline_source_sha: _Str
    successor_source_sha: _Str | None = None
    successor_parent_sha: _Str | None = None
    signing_anchor_id: _Str
    test_only_anchor: bool

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


class AcceptanceEvidence(_Strict):
    """The complete, strict, nonsecret two-host acceptance evidence document."""

    schema_version: _Str
    harness_contract_version: _Str
    run_id: _Str
    outcome: _Str
    started_at: _Str
    completed_at: _Str
    stages_attempted: tuple[str, ...]
    fleet: FleetRecord
    release: ReleaseRecord
    checks: tuple[CheckRecord, ...]
    gaps: tuple[GapRecord, ...]
    # The four prohibitions the harness operates under, recorded as observed facts rather than as
    # prose. They are re-asserted by the loader: a document claiming a run that contacted a provider
    # or ran OpenTofu is refused outright rather than read.
    #
    # ``ephemeral_material_only`` is the one stated positively (it must be True): every anchor,
    # certificate and authorization the run used was generated by the harness for that run and
    # destroyed with the fleet. Its counterpart is deliberately NOT called
    # ``production_credentials_used`` — the forbidden-secret scan that guards this document rejects
    # any field name containing ``credential``, and a document that cannot pass its own loader is
    # worse than a slightly less obvious name.
    proxmox_contacted: bool
    opentofu_executed: bool
    ephemeral_material_only: bool
    trust_roots_modified: bool

    @field_validator("stages_attempted", "checks", "gaps", mode="before")
    @classmethod
    def _coerce(cls, v: object) -> object:
        return tuple(v) if isinstance(v, list) else v

    def canonical(self) -> dict:
        return self.model_dump(mode="json")

    def digest(self) -> str:
        """The content identity of the evidence: every field EXCEPT the two wall-clock timestamps.

        Two runs that observed exactly the same things over the same fleet and release produce the
        same digest, which is what makes an acceptance run comparable across days.
        """
        payload = {
            k: v for k, v in self.canonical().items() if k not in ("started_at", "completed_at")
        }
        return sha256_digest({"v": ACCEPTANCE_EVIDENCE_SCHEMA, "evidence": payload})

    def check_for(self, check: str) -> CheckRecord | None:
        for record in self.checks:
            if record.check == check:
                return record
        return None

    def missing_checks(self) -> tuple[str, ...]:
        """Checks that the attempted stages declare but the document does not carry.

        This is the predicate that makes ``coverage_complete`` mean something. A run that attempted
        a stage and recorded three of its six checks is INCOMPLETE, not partially passed.
        """
        recorded = {record.check for record in self.checks}
        expected: set[str] = set()
        for stage in self.stages_attempted:
            expected.update(CHECKS_BY_STAGE.get(stage, ()))
        return tuple(sorted(expected - recorded))

    def coverage_complete(self) -> bool:
        return not self.missing_checks()

    def unproven(self) -> tuple[str, ...]:
        return tuple(sorted(r.check for r in self.checks if r.outcome == OUTCOME_UNPROVEN))

    def violated(self) -> tuple[str, ...]:
        """Checks where the harness POSITIVELY OBSERVED the state the check rules out.

        Read this before :meth:`unproven` when triaging a failed run: these are proven product
        defects, whereas ``unproven`` is the harness failing to look. They are the two opposite
        reasons a run can fail and they call for opposite responses.
        """
        return tuple(sorted(r.check for r in self.checks if r.outcome == OUTCOME_VIOLATED))

    def not_passing(self) -> tuple[str, ...]:
        """Every recorded check whose outcome is not an admissible PASSING outcome.

        The predicate a passing run is judged against. Stated over the allowlist
        :data:`~secp_acceptance.reasons.PASSING_OUTCOMES` rather than by naming the bad outcomes, so
        an outcome added to the vocabulary later cannot become a passing one by default.
        """
        return tuple(sorted(r.check for r in self.checks if r.outcome not in PASSING_OUTCOMES))


# --------------------------------------------------------------------------- semantics


def _assert_tz_aware(value: str, reason: str) -> None:
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise AcceptanceError(reason) from None
    if parsed.tzinfo is None:
        raise AcceptanceError(reason)


def _assert_ident(value: str) -> None:
    if not _IDENT.fullmatch(value):
        raise AcceptanceError("acceptance_evidence_invalid")


def _assert_check_semantics(record: CheckRecord) -> None:
    _assert_ident(record.check)
    _assert_ident(record.stage)
    if record.stage not in STAGES:
        raise AcceptanceError("acceptance_evidence_unknown_stage")
    if record.check not in CHECKS:
        raise AcceptanceError("acceptance_evidence_unknown_check")
    # a check is valid only under the stage that declares it
    if record.check not in CHECKS_BY_STAGE[record.stage]:
        raise AcceptanceError("acceptance_evidence_unknown_check")
    if record.outcome not in OUTCOMES:
        raise AcceptanceError("acceptance_evidence_invalid")
    if record.outcome == OUTCOME_OBSERVED:
        if record.reason_code is not None:
            raise AcceptanceError("acceptance_evidence_invalid")
    else:
        if record.reason_code is None:
            raise AcceptanceError("acceptance_evidence_invalid")
        if record.reason_code not in ALL_REASONS:
            raise AcceptanceError("acceptance_evidence_unknown_reason")
    if not is_sha256_digest(record.observation_digest):
        raise AcceptanceError("acceptance_evidence_invalid")


def _assert_digest(value: str) -> None:
    if not is_sha256_digest(value):
        raise AcceptanceError("acceptance_evidence_public_value_not_permitted")


def _assert_fleet_semantics(fleet: FleetRecord) -> None:
    """The fleet record carries DIGESTS and COUNTS. Nothing else is admissible.

    Nothing inspected this record at all until now — it was reachable only through pydantic's
    ``_Str`` (any string, 1..200 chars). Measured on the unmodified parent: a ``passed`` document
    was accepted carrying ``network_identity`` as a raw docker network name, ``controller_host_
    identity`` as an absolute host path, and ``host_image_identity`` as an internal registry origin.

    Each identity is a content address by construction (:func:`observation_digest`), so requiring
    the digest SHAPE is an allowlist rather than a denylist: a path, an origin, a container id, a
    queue name or a hostname all fail it without anyone having to enumerate them.
    """
    for value in (
        fleet.host_image_identity,
        fleet.controller_host_identity,
        fleet.worker_host_identity,
        fleet.network_identity,
    ):
        _assert_digest(value)
    if fleet.hosts_destroyed > fleet.hosts_created:
        # More destroyed than created describes a run that tore down something it did not build.
        raise AcceptanceError("acceptance_evidence_invalid")


def _assert_release_semantics(release: ReleaseRecord) -> None:
    """The release lineage: a closed role, digests for aggregates, git shas for sources.

    ``test_only_anchor`` is NOT checked here — it is a PROHIBITION, handled with the other four in
    :func:`_assert_evidence_semantics`, because it says what the harness was permitted to do rather
    than what it observed.
    """
    if release.role not in _RELEASE_ROLES:
        raise AcceptanceError("acceptance_evidence_public_value_not_permitted")
    for value in (
        release.baseline_aggregate,
        release.successor_aggregate,
        release.signing_anchor_id,
    ):
        if value is not None:
            _assert_digest(value)
    for value in (
        release.baseline_source_sha,
        release.successor_source_sha,
        release.successor_parent_sha,
    ):
        if value is not None and not _SOURCE_SHA.fullmatch(value):
            raise AcceptanceError("acceptance_evidence_public_value_not_permitted")


def _assert_gap_semantics(record: GapRecord) -> None:
    _assert_ident(record.gap)
    _assert_ident(record.stage)
    if record.stage not in STAGES:
        raise AcceptanceError("acceptance_evidence_unknown_stage")
    if not record.weakens:
        # A gap that weakens nothing is not a gap; it is decoration. Requiring the named checks
        # keeps every gap connected to the exact claims a reader should discount.
        raise AcceptanceError("acceptance_evidence_invalid")
    for check in record.weakens:
        if check not in CHECKS:
            raise AcceptanceError("acceptance_evidence_unknown_check")


def _assert_evidence_semantics(ev: AcceptanceEvidence) -> None:
    if ev.schema_version != ACCEPTANCE_EVIDENCE_SCHEMA:
        raise AcceptanceError("acceptance_evidence_invalid")
    if ev.harness_contract_version != ACCEPTANCE_CONTRACT_VERSION:
        raise AcceptanceError("acceptance_evidence_invalid")
    if not is_sha256_digest(ev.run_id):
        raise AcceptanceError("acceptance_evidence_invalid")
    if ev.outcome not in RUN_OUTCOMES:
        raise AcceptanceError("acceptance_evidence_invalid")
    _assert_tz_aware(ev.started_at, "acceptance_evidence_invalid")
    _assert_tz_aware(ev.completed_at, "acceptance_evidence_invalid")
    if not ev.stages_attempted:
        raise AcceptanceError("acceptance_evidence_incomplete")
    for stage in ev.stages_attempted:
        _assert_ident(stage)
        if stage not in STAGES:
            raise AcceptanceError("acceptance_evidence_unknown_stage")
    if len(set(ev.stages_attempted)) != len(ev.stages_attempted):
        raise AcceptanceError("acceptance_evidence_invalid")
    if len(ev.checks) > _MAX_CHECKS or len(ev.gaps) > _MAX_GAPS:
        raise AcceptanceError("acceptance_evidence_invalid")
    seen: set[str] = set()
    for record in ev.checks:
        _assert_check_semantics(record)
        if record.check in seen:
            # Exactly one record per check. Two records for the same check would let a later
            # ``observed`` quietly overwrite an earlier ``unproven`` in any reader that takes the
            # last match.
            raise AcceptanceError("acceptance_evidence_duplicate_check")
        seen.add(record.check)
        if record.stage not in ev.stages_attempted:
            raise AcceptanceError("acceptance_evidence_unknown_stage")
    for gap in ev.gaps:
        _assert_gap_semantics(gap)
    # The four prohibitions are recorded facts, and only ONE value is admissible for each: three
    # must be False (nothing was contacted, executed, or changed) and the fourth must be True (only
    # ephemeral, run-scoped material was used). A document that says otherwise describes a run this
    # harness is not permitted to have made, so it is refused rather than read.
    for flag in ("proxmox_contacted", "opentofu_executed", "trust_roots_modified"):
        if getattr(ev, flag) is not False:
            raise AcceptanceError("acceptance_evidence_forbidden_value")
    if ev.ephemeral_material_only is not True:
        raise AcceptanceError("acceptance_evidence_forbidden_value")
    # ``test_only_anchor`` is a FIFTH prohibition, not an observation. The harness is never
    # permitted to use a production signing anchor, so a document asserting it did describes a run
    # this harness may not have made — refused outright rather than read, exactly like the four
    # above. It sat outside this block until now: a document claiming a PRODUCTION trust anchor
    # loaded clean and reported ``passed``.
    if ev.release.test_only_anchor is not True:
        raise AcceptanceError("acceptance_evidence_forbidden_value")
    _assert_fleet_semantics(ev.fleet)
    _assert_release_semantics(ev.release)
    # A ``passed`` run must be complete and must contain ONLY passing outcomes. ``failed`` carries
    # no such requirement — a failed run is expected to be partial, and forcing it to be complete
    # would push the harness toward not recording the failure at all.
    #
    # Stated as an ALLOWLIST (`not_passing`), never as "no unproven". The denylist form silently
    # promotes every newly-added outcome to a passing one: with it, marking a check ``violated``
    # produced a document carrying a proven violation that still loaded as ``passed``.
    if ev.outcome == RUN_PASSED:
        # ALL NINE stages, not merely "the ones this run chose to attempt". `missing_checks` is
        # computed over `stages_attempted`, so without this a run that opened ONE stage and covered
        # it seals `passed` — a single-stage run wearing the word this whole document exists to
        # earn. The docstring above already warns a reader that `passed` says nothing about
        # unattempted stages; this makes the document refuse to say it at all.
        if set(ev.stages_attempted) != STAGES:
            raise AcceptanceError("acceptance_evidence_incomplete")
        if ev.missing_checks():
            raise AcceptanceError("acceptance_evidence_incomplete")
        if ev.not_passing():
            raise AcceptanceError("acceptance_evidence_incomplete")
        # The fleet PREMISE, required only of a passing run. A failed run may legitimately report
        # both False — that is what a fleet which never built looks like, and forcing it to claim
        # otherwise would be the lie. But a run cannot pass a TWO-HOST acceptance while recording
        # that it had neither two real machines nor a real service manager: every isolation claim
        # in the document is a claim about one machine unless these hold.
        if not (ev.fleet.nested_container_runtime and ev.fleet.real_service_manager):
            raise AcceptanceError("acceptance_evidence_incomplete")
        # Nothing leaked. `hosts_destroyed == hosts_created` was measured to be violable while
        # still reporting `passed`: a document saying it created two privileged hosts and destroyed
        # none is the most expensive thing this harness can leave behind, and it read as green.
        if ev.fleet.hosts_destroyed != ev.fleet.hosts_created:
            raise AcceptanceError("acceptance_evidence_incomplete")


# --------------------------------------------------------------------------- loader


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey()
        seen.add(key)
    return dict(pairs)


def evidence_from_dict(data: object) -> AcceptanceEvidence:
    """Load + revalidate an acceptance evidence document from a parsed object."""
    if not isinstance(data, dict):
        raise AcceptanceError("acceptance_evidence_invalid")
    try:
        scan_forbidden(data)
    except Exception:  # noqa: BLE001 - a credential-shaped field/value refuses, bounded
        raise AcceptanceError("acceptance_evidence_forbidden_value") from None
    try:
        ev = AcceptanceEvidence.model_validate(data)
    except ValidationError:
        raise AcceptanceError("acceptance_evidence_invalid") from None
    _assert_evidence_semantics(ev)
    return ev


def evidence_from_bytes(raw: bytes) -> AcceptanceEvidence:
    """Strict UTF-8 + duplicate-key-rejecting parse, then the full revalidation above."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AcceptanceError("acceptance_evidence_invalid") from None
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise AcceptanceError("acceptance_evidence_invalid") from None
    except ValueError:
        raise AcceptanceError("acceptance_evidence_invalid") from None
    return evidence_from_dict(parsed)


def canonical_bytes(ev: AcceptanceEvidence) -> bytes:
    return canonical_json(ev.canonical()).encode("utf-8")


__all__ = [
    "ACCEPTANCE_EVIDENCE_SCHEMA",
    "AcceptanceEvidence",
    "CheckRecord",
    "FleetRecord",
    "GapRecord",
    "ReleaseRecord",
    "canonical_bytes",
    "evidence_from_bytes",
    "evidence_from_dict",
    "observation_digest",
    "run_identity",
    "RUN_FAILED",
    "RUN_PASSED",
    "OUTCOME_OBSERVED",
    "OUTCOME_REFUSED",
    "OUTCOME_UNPROVEN",
    "OUTCOME_VIOLATED",
]
