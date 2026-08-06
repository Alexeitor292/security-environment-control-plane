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

``run_version_discovery`` takes its transport and resolver as parameters rather than constructing
them, so a test can supply bounded fakes without the module growing a mode switch. What it does NOT
take is a choice of transport KIND — the operation types and the evidence they produce are
HTTPS-shaped, and there is no branch that could produce anything else.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from secp_api.discovery_observation import Observation
from secp_api.discovery_operation_evidence import (
    DiscoveryOperationEvidence,
    DiscoveryOperationManifest,
    TransportKind,
)
from secp_commissioning.canonical import sha256_digest

from secp_worker.proxmox_discovery_operations import (
    VERSION_NORMALIZER_IMPLEMENTATION_ID,
    VERSION_PARSER_IMPLEMENTATION_ID,
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
    """Signs a canonical binding digest with the installed worker's own key.

    Deliberately NOT a generic ``sign(digest, key)``: there is no key parameter, because the key is
    a property of the installation and must never arrive from orchestration. The production
    implementation reads the enrolled worker's local key; a test injects an explicit fake.
    """

    def installation_id(self) -> str: ...

    def key_fingerprint(self) -> str: ...

    def sign_discovery_binding(self, *, digest: str) -> object: ...


class DiscoveryCompositionError(Exception):
    """A closed reason code. Never a host, path, credential or backend error."""


@dataclass(frozen=True)
class VersionDiscoveryResult:
    """What one ``/version`` discovery produced: observations, and the evidence for them."""

    observations: dict[str, Observation]
    manifest: DiscoveryOperationManifest
    failed: bool = False
    failure_reason: str = ""


@dataclass(frozen=True)
class SignedDiscoveryResult:
    """A completed discovery run: observations, evidence, and the worker's detached signature."""

    observations: dict[str, Observation]
    manifest: DiscoveryOperationManifest
    binding: object
    attestation: object
    failed: bool = False
    failure_reason: str = ""


def run_signed_discovery(
    *,
    resolver,
    resolution_request,
    resolution_expectation,
    transport_factory: TransportFactory,
    signer: WorkerLocalSigner,
    base_url: str,
    ca_path: str,
    target_authority_identity: str,
    binding_factory,
    expected_worker_installation_id: str,
    expected_worker_key_fingerprint: str,
    now: datetime,
    started_at: datetime,
    completed_at: datetime,
) -> SignedDiscoveryResult:
    """The whole production path: resolve, execute, observe, bind, sign.

    Ordered so nothing exists before it is earned. The credential is resolved immediately before the
    transport is built and is not referenced again; the signer is checked against the selected
    worker BEFORE it signs, so a mismatch refuses rather than producing a signature nobody can use.

    There is no fallback at any step. A resolution failure does not try the environment, and a
    transport failure does not try SSH — both would mean the safest configuration silently degrades
    at exactly the moment something is already wrong.
    """
    from secp_worker.preflight.secret_resolution import (
        SecretResolutionError,
        assert_discovery_resolution_authorized,
    )

    # 1. The request must match the independently derived expectation before anything is resolved.
    try:
        assert_discovery_resolution_authorized(resolution_request, resolution_expectation)
        material = resolver.resolve(resolution_request, expectation=resolution_expectation, now=now)
    except SecretResolutionError as exc:
        return _resolution_failure(str(getattr(exc, "reason_code", "credential_unavailable")))
    except Exception:  # noqa: BLE001 - never surface a resolver's raw error
        return _resolution_failure("credential_unavailable")

    # 2. The signer must BE the selected worker. Checked before any request goes out, so a
    #    misbound worker never contacts the target at all.
    if signer.installation_id() != expected_worker_installation_id:
        return _resolution_failure("discovery_signer_installation_mismatch")
    if signer.key_fingerprint() != expected_worker_key_fingerprint:
        return _resolution_failure("discovery_signer_key_mismatch")

    # 3. Build the transport from the resolved token. The token exists only inside this call.
    transport = transport_factory.build(
        base_url=base_url, ca_path=ca_path, token=material.reveal_secret()
    )

    execution = run_version_discovery(
        transport=transport,
        operation=GetVersionOperation(),
        target_authority_identity=target_authority_identity,
        started_at=started_at,
        completed_at=completed_at,
    )

    # 4. Bind and sign. The binding is built by the caller's factory from the observations and the
    #    manifest, so the signature covers what actually happened rather than what was intended.
    binding = binding_factory(execution.observations, execution.manifest)
    attestation = signer.sign_discovery_binding(digest=binding.digest())

    return SignedDiscoveryResult(
        observations=execution.observations,
        manifest=execution.manifest,
        binding=binding,
        attestation=attestation,
        failed=execution.failed,
        failure_reason=execution.failure_reason,
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
    any_failure = False
    first_reason = ""

    for operation in operations:
        # Checked BEFORE the request: an operation that cannot name the code interpreting its
        # payload must not reach the target at all, let alone produce evidence.
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
            any_failure = True
            first_reason = first_reason or reason
            for code in operation.observation_field_codes:  # type: ignore[attr-defined]
                # Do NOT overwrite a field an earlier operation observed successfully: several
                # operations contribute to the same fact, and one failing source must not erase a
                # good answer from another.
                observations.setdefault(code, Observation.probe_failed(reason))
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
            observations[code] = _merge_observation(code, observations.get(code), obs)

    return VersionDiscoveryResult(
        observations=observations,
        manifest=DiscoveryOperationManifest(operations=tuple(records)),
        failed=any_failure,
        failure_reason=first_reason,
    )


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
    """
    path = operation.rendered_path()
    started = started_at.isoformat()

    try:
        payload = transport.get(path)
    except Exception as exc:  # noqa: BLE001 - mapped to a closed reason below
        reason = _closed_reason(exc)
        return VersionDiscoveryResult(
            observations={
                code: Observation.probe_failed(reason) for code in operation.observation_field_codes
            },
            manifest=DiscoveryOperationManifest(
                operations=(
                    _evidence(
                        operation=operation,
                        target_authority_identity=target_authority_identity,
                        status_classification="refused",
                        content_type="",
                        body=b"",
                        started=started,
                        completed=completed_at.isoformat(),
                    ),
                )
            ),
            failed=True,
            failure_reason=reason,
        )

    raw = repr(payload).encode("utf-8")
    evidence = _evidence(
        operation=operation,
        target_authority_identity=target_authority_identity,
        status_classification="2xx",
        content_type="application/json",
        body=raw,
        started=started,
        completed=completed_at.isoformat(),
    )

    observations = observe(operation, payload)
    return VersionDiscoveryResult(
        observations=observations, manifest=DiscoveryOperationManifest(operations=(evidence,))
    )


def _evidence(
    *,
    operation: GetVersionOperation,
    target_authority_identity: str,
    status_classification: str,
    content_type: str,
    body: bytes,
    started: str,
    completed: str,
) -> DiscoveryOperationEvidence:
    return DiscoveryOperationEvidence(
        operation_code=operation.operation_code,
        transport_kind=PRODUCTION_TRANSPORT_KIND,
        target_authority_identity=target_authority_identity,
        request_method="GET",
        canonical_path_template=operation.path_template,
        canonical_rendered_path=operation.rendered_path(),
        canonical_query_parameters=operation.query_parameters(),
        request_body_present=False,
        response_status_classification=status_classification,
        response_content_type=content_type,
        response_size=len(body),
        response_digest=sha256_digest({"body": body.decode("utf-8", errors="replace")}),
        parser_implementation_id=VERSION_PARSER_IMPLEMENTATION_ID,
        normalizer_implementation_id=VERSION_NORMALIZER_IMPLEMENTATION_ID,
        observation_field_codes=operation.observation_field_codes,
        started_at=started,
        completed_at=completed,
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
