"""The first-MVP production discovery composition. HTTPS only, and structurally so.

This module is the seam the whole vertical slice runs through, and the properties worth stating are
the ones that are true by CONSTRUCTION rather than by check:

* it imports no SSH executor, no legacy probe union and no legacy collector, so there is no route to
  them — not a disabled route, no route;
* it has no configuration switch selecting a transport, so a deployment cannot re-enable the legacy
  path by setting something;
* it has **no fallback**. An HTTPS failure produces an exact observation failure and stops. Falling
  back to SSH after an HTTPS failure would mean the safest configuration silently becomes the least
  safe one at exactly the moment something is already wrong;
* the credential arrives as an opaque reference and is resolved only inside the privileged worker,
  for one exact purpose and one exact target.

``run_full_discovery`` takes its transport factory, resolver and signer as parameters rather than
constructing them, so a test can supply bounded fakes without the module growing a mode switch. What
it does NOT take is a choice of transport KIND, a binding, or any identity that goes inside the
signature — the operation types and the evidence they produce are HTTPS-shaped, and there is no
branch that could produce anything else.

It is the ONLY signed entry point. There was briefly a second, ``run_signed_discovery``, which took
a caller-supplied ``binding_factory``; a caller able to build the binding can attest to any
organization, target, worker, role or release it likes, so it was removed rather than fixed in
place. ``run_version_discovery`` likewise runs through the one sequencer instead of keeping its own
evidence builder: two builders for one signed document is how the two quietly stop agreeing.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from secp_api.discovery_fact_commitment import (
    FactContribution,
    canonical_value,
    contribution_of,
)
from secp_api.discovery_observation import Observation
from secp_api.discovery_operation_evidence import (
    DiscoveryOperationEvidence,
    DiscoveryOperationManifest,
    TransportKind,
)
from secp_commissioning.canonical import sha256_digest

from secp_worker.proxmox_discovery_operations import (
    GetVersionOperation,
)
from secp_worker.proxmox_discovery_projection import observe

#: The transport this composition uses. A constant, not a setting: a deployment cannot select
#: another, and a test asserting the production transport set reads this rather than a caller's
#: claim about it.
PRODUCTION_TRANSPORT_KIND = TransportKind.proxmox_https_api

DISCOVERY_COMPOSITION_VERSION = "secp.proxmox-discovery-composition/v1"


class DiscoveryTransport(Protocol):
    """The narrow shape this composition needs. Deliberately not the transport class itself, so a
    bounded fake is a first-class citizen and no test needs a real socket."""

    def get(self, path: str, params: dict | None = None) -> object: ...


class TransportFactory(Protocol):
    """Builds the hardened transport from resolved material.

    A factory rather than a ready transport, because the token must not exist before it is needed
    and must not outlive the call: the composition resolves, builds, uses and drops it inside one
    function body.
    """

    def build(self, *, base_url: str, ca_path: str, token: str) -> DiscoveryTransport: ...


class WorkerLocalSigner(Protocol):
    """The installed worker's own identity and signing key.

    Deliberately NOT a generic ``sign(digest, key)``: there is no key parameter, because the key is
    a property of the installation and must never arrive from orchestration. The production
    implementation reads the enrolled worker's local key; a test injects an explicit fake.

    ``role`` and ``release_fingerprint`` are here for the same reason. They go inside the signature
    and are checked against the registered worker anchor, so a caller able to supply them could
    attest to a role it was not enrolled with, or to a release it is not running.
    """

    def installation_id(self) -> str: ...

    def key_fingerprint(self) -> str: ...

    def role(self) -> str: ...

    def release_fingerprint(self) -> str: ...

    def sign_discovery_binding(self, *, digest: str) -> object: ...


class DiscoveryCompositionError(Exception):
    """A closed reason code. Never a host, path, credential or backend error."""


@dataclass(frozen=True)
class VersionDiscoveryResult:
    """What a discovery run produced: observations, evidence, and every source's contribution.

    ``contributions`` is not a debugging aid. The merge decides which answer a field code carries;
    this records what every operation actually said, INCLUDING the ones that failed, so a refusal
    another source overwrote is still visible and still signed.
    """

    observations: dict[str, Observation]
    manifest: DiscoveryOperationManifest
    failed: bool = False
    failure_reason: str = ""
    contributions: dict[str, tuple[FactContribution, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class SignedDiscoveryResult:
    """A completed discovery run: observations, evidence, and the worker's detached signature.

    ``observations`` are the RAW per-field observations and ``required_facts`` is their projection
    into the vocabulary the compiler gates on. Both are carried because they answer different
    questions: the raw set says what each endpoint reported, the projection says whether the cluster
    as a whole is known — and the difference between them is where a one-node answer stops standing
    in for a three-node cluster.
    """

    observations: dict[str, Observation]
    manifest: DiscoveryOperationManifest
    binding: object
    attestation: object
    failed: bool = False
    failure_reason: str = ""
    required_facts: dict[str, Observation] = field(default_factory=dict)
    contributions: dict[str, tuple[FactContribution, ...]] = field(default_factory=dict)


def run_full_discovery(
    *,
    resolver,
    resolution_request,
    resolution_expectation,
    transport_factory: TransportFactory,
    signer: WorkerLocalSigner,
    base_url: str,
    ca_path: str,
    target_authority_identity: str,
    expected_worker_installation_id: str,
    expected_worker_key_fingerprint: str,
    control_plane_facts,
    freshness_bound_seconds: int,
    now: datetime,
    started_at: datetime,
    completed_at: datetime,
) -> SignedDiscoveryResult:
    """The whole first-MVP discovery, end to end: resolve, plan, execute, project, bind, sign.

    This is the ONLY production entry point that reaches every guarded component, and it exists in
    that shape deliberately. Each of the resolver, the plan validator, the payload parsers, the
    required-fact projection and the worker-local signer is individually correct and individually
    tested; the recurring defect in this system has been a component that is all of those and
    reached by nothing. A single composition that a test can drive with spies is how "it is wired"
    becomes an observation rather than a claim.

    The projection happens BEFORE signing, so what the worker attests to is the derived
    required-fact state — not a raw field set that a later consumer would have to re-derive with
    code the signature does not cover.

    There is no ``binding_factory`` parameter. The binding names the organization, the target, the
    operation, the worker, its role and its release; a caller able to supply it could attest to any
    of them. Every field is taken from the resolution expectation, the installation or the run
    itself, and :func:`build_discovery_binding` is the only thing that assembles one.
    """
    from secp_api.discovery_fact_projection import project_required_facts

    prepared = _prepare_transport(
        resolver=resolver,
        resolution_request=resolution_request,
        resolution_expectation=resolution_expectation,
        transport_factory=transport_factory,
        signer=signer,
        base_url=base_url,
        ca_path=ca_path,
        expected_worker_installation_id=expected_worker_installation_id,
        expected_worker_key_fingerprint=expected_worker_key_fingerprint,
        now=now,
    )
    if isinstance(prepared, str):
        return _resolution_failure(prepared)

    execution = run_operation_plan(
        transport=prepared,
        target_authority_identity=target_authority_identity,
        started_at=started_at,
        completed_at=completed_at,
    )
    required_facts = project_required_facts(
        execution.observations, control_plane_facts=control_plane_facts
    )

    binding = build_discovery_binding(
        expectation=resolution_expectation,
        signer=signer,
        requested_target_authority=target_authority_identity,
        observations=execution.observations,
        manifest=execution.manifest,
        required_facts=required_facts,
        contributions=execution.contributions,
        cluster_fingerprint=cluster_fingerprint_of(execution.observations),
        started_at=started_at,
        completed_at=completed_at,
        freshness_bound_seconds=freshness_bound_seconds,
    )
    attestation = signer.sign_discovery_binding(digest=binding.digest())

    return SignedDiscoveryResult(
        observations=execution.observations,
        manifest=execution.manifest,
        binding=binding,
        attestation=attestation,
        failed=execution.failed,
        failure_reason=execution.failure_reason,
        required_facts=required_facts,
        contributions=execution.contributions,
    )


def cluster_fingerprint_of(observations: dict[str, Observation]) -> str:
    """A stable fingerprint of WHICH cluster this was, derived from the observed identity.

    Derived rather than supplied for the same reason everything else in the binding is: a caller
    able to name the cluster could bind a snapshot taken from one cluster to an operation targeting
    another, and the identity is precisely what the substitution would change.

    Empty when the identity was not usable — an unobserved cluster has no fingerprint, and inventing
    a placeholder would let two different unidentified clusters compare equal.
    """
    identity = observations.get("cluster_identity")
    if identity is None or not identity.is_usable:
        return ""
    return sha256_digest({"cluster_identity": canonical_value(identity.value)})


def build_discovery_binding(
    *,
    expectation,
    signer: WorkerLocalSigner,
    requested_target_authority: str,
    observations: dict[str, Observation],
    manifest: DiscoveryOperationManifest,
    required_facts: dict[str, Observation],
    contributions: dict[str, tuple[FactContribution, ...]],
    cluster_fingerprint: str,
    started_at: datetime,
    completed_at: datetime,
    freshness_bound_seconds: int,
):
    """Assemble the document the worker signs. The ONLY thing that builds one.

    Every field comes from a source the worker cannot choose freely:

    * organization, target, operation identity and generation come from the resolution
      **expectation** — the contract independently derived by the control plane, not the request the
      worker sent. A worker that resolved a credential for target A cannot attest about target B;
    * installation id, key fingerprint, role and release fingerprint come from the installation
      itself, so a worker cannot claim a role it was not enrolled with or a release it is not
      running — both of which the registered anchor is checked against;
    * the hashes are computed here from the run's own products.

    ``facts_hash`` is the digest of the full :class:`FactCommitment` — every fact's VALUE, state,
    scope, reason, missing privilege and per-source contribution, plus the target, cluster,
    organization, operation and generation it was observed under. It previously covered
    ``(code, state)`` pairs only, which left every VMID, VLAN tag, CIDR, subnet, bridge, VNet,
    storage id and pending SDN object outside the signature: rewriting any of them changed nothing a
    verifier could see. ``operation_manifest_hash`` remains separate so an edited fact set and an
    edited request set stay two distinct, separately attributable tampering events.
    """
    from secp_api.discovery_fact_commitment import build_fact_commitment
    from secp_api.discovery_fact_projection import (
        REQUIRED_FACT_PROJECTION_ID,
        required_fact_states,
    )
    from secp_api.discovery_verification import DISCOVERY_CONTRACT_VERSION, DiscoverySnapshotBinding

    commitment = build_fact_commitment(
        observations=observations,
        required_facts=required_facts,
        contributions=contributions,
        organization_identity=str(expectation.organization_id),
        target_identity=str(expectation.execution_target_id),
        cluster_fingerprint=cluster_fingerprint,
        operation_identity=expectation.operation_identity,
        operation_generation=expectation.operation_generation,
    )

    return DiscoverySnapshotBinding(
        discovery_contract_version=DISCOVERY_CONTRACT_VERSION,
        operation_identity=expectation.operation_identity,
        operation_generation=expectation.operation_generation,
        organization_identity=str(expectation.organization_id),
        target_identity=str(expectation.execution_target_id),
        requested_target_authority=requested_target_authority,
        worker_installation_id=signer.installation_id(),
        worker_role=signer.role(),
        worker_release_fingerprint=signer.release_fingerprint(),
        signer_fingerprint=signer.key_fingerprint(),
        observation_started_at=started_at.isoformat(),
        observation_completed_at=completed_at.isoformat(),
        freshness_bound_seconds=freshness_bound_seconds,
        facts_hash=commitment.digest(),
        operation_manifest_hash=sha256_digest({"manifest": manifest.canonical()}),
        projection_implementation_id=REQUIRED_FACT_PROJECTION_ID,
        required_fact_observation_states=required_fact_states(required_facts),
    )


def _prepare_transport(
    *,
    resolver,
    resolution_request,
    resolution_expectation,
    transport_factory: TransportFactory,
    signer: WorkerLocalSigner,
    base_url: str,
    ca_path: str,
    expected_worker_installation_id: str,
    expected_worker_key_fingerprint: str,
    now: datetime,
) -> DiscoveryTransport | str:
    """Resolve, check the signer, build the transport — or return a closed refusal reason.

    Ordered so nothing exists before it is earned, and so the signer identity is checked BEFORE any
    request goes out: a misbound worker must never contact the target at all, rather than contacting
    it and producing a signature nobody can use.
    """
    from secp_worker.preflight.secret_resolution import (
        SecretResolutionError,
        assert_discovery_resolution_authorized,
    )

    try:
        assert_discovery_resolution_authorized(resolution_request, resolution_expectation)
        material = resolver.resolve(resolution_request, expectation=resolution_expectation, now=now)
    except SecretResolutionError as exc:
        return str(getattr(exc, "reason_code", "credential_unavailable"))
    except Exception:  # noqa: BLE001 - never surface a resolver's raw error
        return "credential_unavailable"

    if signer.installation_id() != expected_worker_installation_id:
        return "discovery_signer_installation_mismatch"
    if signer.key_fingerprint() != expected_worker_key_fingerprint:
        return "discovery_signer_key_mismatch"

    return transport_factory.build(
        base_url=base_url, ca_path=ca_path, token=material.reveal_secret()
    )


def run_operation_plan(
    *,
    transport: DiscoveryTransport,
    target_authority_identity: str,
    parse: Callable[[object, object], dict[str, Observation]] = observe,
    started_at: datetime,
    completed_at: datetime,
    phases: Sequence[Callable[..., Sequence[object]]] | None = None,
) -> VersionDiscoveryResult:
    """Run every phase of the production plan against ONE manifest.

    The phases exist because ``/nodes/{node}/storage`` needs a node name that does not exist before
    the run starts. Each phase is planned from what the previous ones observed, and every dynamic
    segment carries the response it came from — so a well-formed identifier nothing observed is
    refused exactly like a malformed one.

    A planning failure stops further phases but keeps everything already observed. Discarding the
    evidence gathered so far would turn "the cluster is larger than this plan allows" into "nothing
    is known about this cluster", which is a strictly worse answer to give an operator.
    """
    from secp_worker.proxmox_discovery_plan import PHASES, DiscoveryPlanError

    observations: dict[str, Observation] = {}
    records: list[DiscoveryOperationEvidence] = []
    contributions: dict[str, tuple[FactContribution, ...]] = {}
    failure = ""

    for index, plan in enumerate(phases if phases is not None else PHASES):
        try:
            operations = plan() if index == 0 else plan(observations)
        except DiscoveryPlanError as exc:
            failure = str(exc.args[0])
            break
        if not operations:
            continue
        reason = _execute_into(
            observations=observations,
            records=records,
            contributions=contributions,
            transport=transport,
            operations=operations,
            target_authority_identity=target_authority_identity,
            parse=parse,
            started_at=started_at,
            completed_at=completed_at,
        )
        failure = failure or reason

    return VersionDiscoveryResult(
        observations=observations,
        manifest=DiscoveryOperationManifest(operations=tuple(records)),
        failed=bool(failure),
        failure_reason=failure,
        contributions=contributions,
    )


def run_operation_sequence(
    *,
    transport: DiscoveryTransport,
    operations: Sequence[object],
    target_authority_identity: str,
    parse: Callable[[object, object], dict[str, Observation]],
    started_at: datetime,
    completed_at: datetime,
) -> VersionDiscoveryResult:
    """Execute a sequence of typed operations, appending each to ONE canonical manifest.

    The manifest is shared on purpose. A second manifest per operation family would mean the
    signature covers several documents that could each be swapped independently, and "which of the
    four manifests was this fact in" is a question no operator should have to answer.

    A failing operation does not abort the sequence. Its fields become ``probe_failed`` and the run
    continues, because a discovery that stops at the first refusal reports a target as far less
    observable than it is — and the required-fact evaluator needs to know which specific facts are
    missing, not merely that something went wrong.

    Later operations may depend on earlier results; that ordering is the caller's, and every dynamic
    identifier is validated at operation construction rather than here.
    """
    observations: dict[str, Observation] = {}
    records: list[DiscoveryOperationEvidence] = []
    contributions: dict[str, tuple[FactContribution, ...]] = {}
    reason = _execute_into(
        observations=observations,
        records=records,
        contributions=contributions,
        transport=transport,
        operations=operations,
        target_authority_identity=target_authority_identity,
        parse=parse,
        started_at=started_at,
        completed_at=completed_at,
    )
    return VersionDiscoveryResult(
        observations=observations,
        manifest=DiscoveryOperationManifest(operations=tuple(records)),
        failed=bool(reason),
        failure_reason=reason,
        contributions=contributions,
    )


def _execute_into(
    *,
    observations: dict[str, Observation],
    records: list[DiscoveryOperationEvidence],
    contributions: dict[str, tuple[FactContribution, ...]],
    transport: DiscoveryTransport,
    operations: Sequence[object],
    target_authority_identity: str,
    parse: Callable[[object, object], dict[str, Observation]],
    started_at: datetime,
    completed_at: datetime,
) -> str:
    """Execute operations into an EXISTING observation set and manifest; return the first failure.

    Accumulating in place is what lets several planning phases share one manifest and one merged
    observation set. A manifest per phase would put the signature over three documents that could
    each be swapped independently.
    """
    first_reason = ""

    for operation in operations:
        # Checked BEFORE the request: an operation that cannot name the code interpreting its
        # payload must not reach the target at all, let alone produce evidence.
        _parser_identity(operation, "parser_implementation_id")
        _parser_identity(operation, "normalizer_implementation_id")

        path = operation.rendered_path()  # type: ignore[attr-defined]
        params = dict(operation.query_parameters()) or None  # type: ignore[attr-defined]
        try:
            payload = transport.get(path, params)
        except Exception as exc:  # noqa: BLE001 - mapped to a closed reason
            reason = _closed_reason(exc)
            first_reason = first_reason or reason
            failure: Observation = Observation.probe_failed(reason)
            for code in operation.observation_field_codes:  # type: ignore[attr-defined]
                # The contribution is recorded UNCONDITIONALLY, even when the merge keeps another
                # source's answer. A refusal that leaves no trace is a refusal an operator is never
                # told about, and it is the thing the signature most needs to admit.
                _record_contribution(contributions, code, operation, failure)
                observations[code] = _merge_observation(code, observations.get(code), failure)
            records.append(
                _sequence_evidence(
                    operation, target_authority_identity, "refused", b"", started_at, completed_at
                )
            )
            continue

        raw = repr(payload).encode("utf-8")
        records.append(
            _sequence_evidence(
                operation, target_authority_identity, "2xx", raw, started_at, completed_at
            )
        )
        for code, obs in parse(operation, payload).items():
            _record_contribution(contributions, code, operation, obs)
            observations[code] = _merge_observation(code, observations.get(code), obs)

    return first_reason


def _record_contribution(
    contributions: dict[str, tuple[FactContribution, ...]],
    code: str,
    operation: object,
    observation: Observation,
) -> None:
    """Append what this operation said about this fact. Never replaces an earlier entry."""
    entry = contribution_of(
        operation_code=operation.operation_code,  # type: ignore[attr-defined]
        rendered_path=operation.rendered_path(),  # type: ignore[attr-defined]
        observation=observation,
    )
    contributions[code] = (*contributions.get(code, ()), entry)


def _sequence_evidence(
    operation: object,
    target_authority_identity: str,
    status: str,
    body: bytes,
    started_at: datetime,
    completed_at: datetime,
) -> DiscoveryOperationEvidence:
    return DiscoveryOperationEvidence(
        operation_code=operation.operation_code,  # type: ignore[attr-defined]
        transport_kind=PRODUCTION_TRANSPORT_KIND,
        target_authority_identity=target_authority_identity,
        request_method="GET",
        canonical_path_template=operation.path_template,  # type: ignore[attr-defined]
        canonical_rendered_path=operation.rendered_path(),  # type: ignore[attr-defined]
        canonical_query_parameters=operation.query_parameters(),  # type: ignore[attr-defined]
        request_body_present=False,
        response_status_classification=status,
        response_content_type="application/json" if status == "2xx" else "",
        response_size=len(body),
        response_digest=sha256_digest({"body": body.decode("utf-8", errors="replace")}),
        parser_implementation_id=_parser_identity(operation, "parser_implementation_id"),
        normalizer_implementation_id=_parser_identity(operation, "normalizer_implementation_id"),
        observation_field_codes=operation.observation_field_codes,  # type: ignore[attr-defined]
        started_at=started_at.isoformat(),
        completed_at=completed_at.isoformat(),
    )


def _merge_observation(
    code: str, existing: Observation | None, incoming: Observation
) -> Observation:
    """Combine two observations of the SAME fact from two different operations.

    "First usable wins" is wrong for the facts that matter most here. Per-node facts —
    ``node_capacity``, ``bridges``, ``storage_ids`` — carry one field code but many nodes, so
    keeping the first would silently report a three-node cluster's first node as the whole cluster.
    A fact that looks complete and describes one node is worse than no fact at all.

    So mappings MERGE: each operation contributes its own keys. Everything else must AGREE, and two
    sources that disagree about one fact make it ``observed_malformed`` rather than picking a winner
    — the disagreement is itself the finding, and silently preferring either source would hide a
    target that is answering inconsistently.
    """
    if existing is None:
        return incoming
    if not incoming.is_usable:
        # A failing source never overwrites — not a good answer from another source, and not an
        # earlier failure either: the run reports the FIRST reason, and a second one for the same
        # field would silently relabel why an operator is being asked to act.
        return existing
    if not existing.is_usable:
        return incoming

    try:
        merged = _deep_merge(existing.value, incoming.value, path=code)
    except _Disagreement as exc:
        return Observation.malformed(f"source_disagreement:{exc.path}")
    return existing if merged == existing.value else Observation.observed(merged)


class _Disagreement(Exception):
    """Two sources gave different answers for the same path within one fact."""

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.path = path


def _deep_merge(old: object, new: object, *, path: str) -> object:
    """Merge two values for one fact, or raise at the exact path where they disagree.

    Recursive rather than shallow because per-source structure nests: the cluster SDN index and the
    per-node runtime view both describe zone ``z1``, contributing different sub-keys under it. A
    shallow merge would compare the two sub-objects whole and call an entirely complementary pair of
    observations a contradiction — turning the partial-visibility differential, which is the point
    of reading both, into a malformed fact.

    Disagreement is reported with the path so a reviewer is told which node, storage or zone the two
    sources fell out over rather than only which fact.
    """
    if isinstance(old, dict) and isinstance(new, dict):
        merged = dict(old)
        for key, value in new.items():
            merged[key] = (
                _deep_merge(merged[key], value, path=f"{path}.{key}") if key in merged else value
            )
        return merged
    if old != new:
        raise _Disagreement(path)
    return old


def _parser_identity(operation: object, attribute: str) -> str:
    """Read an operation's own parser identity, refusing rather than defaulting.

    Every operation must name the code that interprets ITS payload. A shared constant across all of
    them would put a false statement into signed evidence — a snapshot claiming the version parser
    read the SDN zones response — and a ``getattr`` default would let a newly added operation
    inherit somebody else's identity silently, which is the exact failure the ids exist to prevent.
    """
    value = getattr(operation, attribute, "")
    if not isinstance(value, str) or not value:
        code = getattr(operation, "operation_code", "unknown")
        raise DiscoveryCompositionError(f"operation_parser_unidentified:{code}:{attribute}")
    return value


def _resolution_failure(reason: str) -> SignedDiscoveryResult:
    """Refuse before execution, with no manifest — nothing ran, so nothing is attested."""
    return SignedDiscoveryResult(
        observations={
            code: Observation.source_unavailable(reason)
            for code in GetVersionOperation.observation_field_codes
        },
        manifest=DiscoveryOperationManifest(),
        binding=None,
        attestation=None,
        failed=True,
        failure_reason=reason,
    )


def run_version_discovery(
    *,
    transport: DiscoveryTransport,
    operation: GetVersionOperation,
    target_authority_identity: str,
    started_at: datetime,
    completed_at: datetime,
) -> VersionDiscoveryResult:
    """Execute the typed ``/version`` operation and produce observations plus signed-ready evidence.

    On failure this returns observations in a failure STATE rather than raising past the caller —
    the distinction between "the probe failed" and "the fact is absent" is the whole point of the
    observation vocabulary, and an exception collapses it.

    Implemented as a one-operation sequence rather than its own execution path. It once had a second
    evidence builder that happened to agree with the sequencer's; two builders for one document is
    how the two quietly stop agreeing, and the disagreement would live inside a signature.
    """
    return run_operation_sequence(
        transport=transport,
        operations=(operation,),
        target_authority_identity=target_authority_identity,
        parse=observe,
        started_at=started_at,
        completed_at=completed_at,
    )


def _closed_reason(exc: Exception) -> str:
    """Map a transport failure to a closed reason code.

    The exception is not chained and its text is not reused: the hardened transport already raises
    closed codes, and anything else could carry a URL or a header.
    """
    code = getattr(exc, "args", [""])[0]
    known = {
        "proxmox_discovery_permission_denied",
        "proxmox_discovery_unauthenticated",
        "proxmox_discovery_endpoint_absent",
        "proxmox_discovery_endpoint_unsupported",
        "proxmox_discovery_request_refused",
        "proxmox_discovery_transport_failed",
    }
    return str(code) if code in known else "proxmox_discovery_transport_failed"
