"""The production entry point for an authorized Proxmox discovery run. Worker-only.

``run_full_discovery`` is the signed composition. Until this module existed its only callers were
tests: it took a resolver, a transport factory, a signer, an expected worker installation and an
expected key fingerprint as parameters, and every one of them was supplied by a fixture. So the
whole HTTPS discovery engine — twenty-four typed operations, the derived transport grammar, the
canonical fact commitment, the worker-local signature — was reachable from no runtime entry point
at all.

This module is that entry point, and it is deliberately thin. It composes; it decides nothing.

WHAT IT COMPOSES, AND WHERE EACH PIECE COMES FROM
--------------------------------------------------
``authority``   :func:`secp_api.discovery_authority_loader.load_discovery_authority`, from durable
                rows. The caller supplies an admission id and an organization scope; the target,
                the operation, the generation, the selected worker, its anchor, its release and the
                credential reference are all read.
``signer``      the installed worker's own key, through
                :class:`secp_worker.enrollment_key.LocalWorkerEnrollmentKeySeam` — the same
                protected fixed-path pair enrollment uses. There is one worker key.
``resolver``    injected. The shipped default is
                :class:`SealedDiscoveryCredentialResolver`, which always fails closed.
``transport``   :class:`HardenedDiscoveryTransportFactory`, which builds the CA-pinned read-only
                client and refuses any request outside the typed operation grammar.

WHAT THE CALLER MAY SUPPLY, WHICH IS ALMOST NOTHING
-----------------------------------------------------
An admission id, an organization id, a CA path and a clock. Not a target, not a worker, not a role,
not a key, not a release, not a generation, not a credential, and not a signature. Every one of
those is loaded or derived, because a discovery run whose expected authority a caller could choose
is a discovery run that verifies against whatever it was told.

WHY THE SEALED RESOLVER IS THE SHIPPED DEFAULT
-----------------------------------------------
No Proxmox credential backend is configured in this repository, and configuring one is an operator
decision that follows Authorization Packet 1. With the sealed default in place this path is
complete and fail-closed: it loads real authority, builds a real transport factory, and then
refuses at the credential step — **before a socket is opened**, which the composition already
guarantees and this module does not weaken. That is the correct posture for code that must be
finished and reviewable before it is ever permitted to run.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

#: How long an observation may be trusted, in seconds. A property of the discovery contract rather
#: than of a caller: a run that could widen its own freshness window could present an arbitrarily
#: old cluster view as current.
DISCOVERY_FRESHNESS_BOUND_SECONDS = 1800

#: The reviewed deployment-local CA bundle path is an INSTALLATION fact, supplied by the operator's
#: configuration. There is no default: an unpinned CA must not be constructible, and a default here
#: would be the fallback the transport refuses to have.
DISCOVERY_RUNTIME_VERSION = "secp.proxmox-discovery-runtime/v1"


class DiscoveryRuntimeError(Exception):
    """A closed reason code. Never a host, a path, a credential or a backend error."""


class LocalWorkerDiscoverySigner:
    """The production :class:`WorkerLocalSigner`, over what the worker OBSERVES about itself.

    Every value it reports is host-local: the key from the protected enrollment pair, the
    installation id and release digest from the management plane's installed-worker documents via
    :func:`read_installed_worker_record`, which refuses a drifted or mismatched identity/evidence
    pair rather than believing half of it.

    **None of it comes from the control plane, and that is the point.** These values go inside the
    signature and the control plane compares them against what it durably registered. A signer that
    took its installation id or release from the loaded authority would be attesting to exactly
    what the verifier already expects — the comparison would pass by construction, which is the
    supplied-expectation hole the whole chain exists to close.

    ``role`` returns the discovery contract's required role. That is not a claim that the role is
    TRUE: it goes inside the signature and is checked against the same constant, so a worker that
    is not in fact privileged signs a false claim rather than escaping the check. What matters here
    is only that orchestration cannot supply it.

    Nothing is cached. A key rotated or an installation removed between calls is observed rather
    than remembered.
    """

    __slots__ = ("_seam", "_fs")

    def __init__(self, seam: object, *, filesystem: object) -> None:
        self._seam = seam
        self._fs = filesystem

    def __repr__(self) -> str:  # never the key, the path, or the seam's internals
        return "LocalWorkerDiscoverySigner(<redacted>)"

    def _signer(self) -> object:
        try:
            return self._seam.load_or_create()  # type: ignore[attr-defined]
        except Exception:
            raise DiscoveryRuntimeError("discovery_worker_key_unavailable") from None

    def _record(self) -> object:
        from secp_worker.enrollment_health_probes import read_installed_worker_record

        record = read_installed_worker_record(self._fs)  # type: ignore[arg-type]
        if record is None:
            # Absent, drifted, mismatched, or not a worker install. All four are the same refusal:
            # this host cannot say what it is, so it must not sign a claim about what it is.
            raise DiscoveryRuntimeError("discovery_worker_installation_unobservable")
        return record

    def installation_id(self) -> str:
        return str(self._record().installation_id)  # type: ignore[attr-defined]

    def key_fingerprint(self) -> str:
        return str(self._signer().worker_key_id)  # type: ignore[attr-defined]

    def role(self) -> str:
        from secp_api.discovery_verification import REQUIRED_WORKER_ROLE

        return REQUIRED_WORKER_ROLE

    def release_fingerprint(self) -> str:
        return str(self._record().release_digest)  # type: ignore[attr-defined]

    def sign_discovery_binding(self, *, digest: str) -> object:
        return self._signer().sign_discovery_snapshot(digest)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class AuthorizedDiscoveryOutcome:
    """What an authorized run produced, plus the authority it was run under.

    The authority is carried so the control plane can VERIFY against the same durable facts it
    authorized — reloading them itself rather than trusting what came back with the result.
    """

    admission_id: uuid.UUID
    result: object
    expected_target_identity: str
    expected_organization_identity: str
    expected_operation_identity: str
    expected_operation_generation: int
    failed: bool
    failure_reason: str


def run_authorized_discovery(
    session: object,
    *,
    admission_id: uuid.UUID,
    organization_id: uuid.UUID,
    ca_path: str,
    resolver: object | None = None,
    key_seam: object | None = None,
    filesystem: object | None = None,
    now: datetime | None = None,
) -> AuthorizedDiscoveryOutcome:
    """Load the durable authority, then run the signed composition under it.

    Nothing here decides what may be read: the plan, the grammar, the merge and the commitment are
    the composition's, and this function's whole job is to make sure the values it passes came from
    rows rather than from a caller.
    """
    from secp_api.discovery_authority_loader import load_discovery_authority

    from secp_worker.preflight.secret_resolution import (
        TrustedCredentialReference,
        build_discovery_resolution_request,
    )
    from secp_worker.proxmox_discovery_composition import run_full_discovery
    from secp_worker.proxmox_discovery_transport import HardenedDiscoveryTransportFactory

    moment = now or datetime.now(UTC)
    authority = load_discovery_authority(
        session,  # type: ignore[arg-type]
        admission_id=admission_id,
        organization_id=organization_id,
        now=moment,
    )
    operation = authority.operation

    if not ca_path or not str(ca_path).strip():
        # Refused HERE rather than at the transport, so the reason names the installation fact an
        # operator must supply rather than surfacing as a generic transport failure.
        raise DiscoveryRuntimeError("discovery_ca_bundle_not_configured")

    fs = filesystem if filesystem is not None else _production_filesystem()
    seam = key_seam if key_seam is not None else _default_key_seam(fs)
    signer = LocalWorkerDiscoverySigner(seam, filesystem=fs)

    request, expectation = build_discovery_resolution_request(
        organization_id=organization_id,
        execution_target_id=uuid.UUID(operation.target_identity),
        worker_installation_id=operation.worker_installation_id,
        operation_identity=operation.operation_identity,
        operation_generation=operation.operation_generation,
        credential_reference=TrustedCredentialReference(operation.credential_reference),
    )

    result = run_full_discovery(
        resolver=resolver if resolver is not None else _default_discovery_resolver(),
        resolution_request=request,
        resolution_expectation=expectation,
        transport_factory=HardenedDiscoveryTransportFactory(),
        signer=signer,
        base_url=operation.target_authority_identity,
        ca_path=ca_path,
        target_authority_identity=operation.target_authority_identity,
        expected_worker_installation_id=authority.registration.worker_installation_id,
        expected_worker_key_fingerprint=authority.registration.verification_anchor_fingerprint,
        control_plane_facts=_control_plane_facts(authority, moment),
        freshness_bound_seconds=DISCOVERY_FRESHNESS_BOUND_SECONDS,
        now=moment,
        started_at=moment,
        completed_at=moment + timedelta(seconds=0),
    )

    return AuthorizedDiscoveryOutcome(
        admission_id=operation.admission_id,
        result=result,
        expected_target_identity=operation.target_identity,
        expected_organization_identity=operation.organization_identity,
        expected_operation_identity=operation.operation_identity,
        expected_operation_generation=operation.operation_generation,
        failed=bool(getattr(result, "failed", False)),
        failure_reason=str(getattr(result, "failure_reason", "")),
    )


def _default_discovery_resolver() -> object:
    """The shipped discovery credential resolver.

    :class:`ProxmoxOperationSecretResolver` constructed FOR the discovery purpose, with no backend
    client — so the shipped posture is unchanged: an authorized run reaches the credential step and
    refuses before a socket is opened. What changed is WHY it refuses. It is no longer a class whose
    only behaviour is to fail; it is the real resolver, missing the one thing an operator supplies
    after Authorization Packet 1.

    Constructed per call rather than held as a module singleton, so a resolver never outlives the
    run that needed it.
    """
    from secp_worker.preflight.proxmox_secret_resolver import ProxmoxOperationSecretResolver
    from secp_worker.preflight.secret_resolution import ResolutionPurpose

    return ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=None
    )


def _control_plane_facts(authority: object, moment: datetime) -> dict:
    """The facts the CONTROL PLANE contributes, taken from the loaded authority.

    They travel inside the signature, so a worker that could invent them could attest to a target
    or a release it was never selected for. Every value here comes from a durable row.
    """
    from secp_api.discovery_observation import Observation

    operation = authority.operation  # type: ignore[attr-defined]
    registration = authority.registration  # type: ignore[attr-defined]
    return {
        "target_identity": Observation.observed(operation.target_identity),
        "observation_timestamp": Observation.observed(moment.isoformat()),
        "worker_identity": Observation.observed(registration.worker_installation_id),
        "evidence_signature": Observation.observed("pending"),
        "worker_release_fingerprint": Observation.observed(registration.worker_release_fingerprint),
        "target_tls_identity": Observation.not_requested("target_tls_identity_not_pinned"),
    }


def _default_key_seam(filesystem: object) -> object:
    """The installed worker's key seam, read-only.

    ``write``/``confirm`` gate CREATION, and they are deliberately left off: a discovery run must
    never provision a worker key. With an already-enrolled worker the seam is a pure read; with no
    key it fails closed rather than minting one nobody authorized.
    """
    from secp_worker.enrollment_key import LocalWorkerEnrollmentKeySeam

    return LocalWorkerEnrollmentKeySeam(filesystem, write=False, confirm=False)  # type: ignore[arg-type]


def _production_filesystem() -> object:
    """The real, root-owned filesystem backend the commissioning runtime already ships.

    Constructed here rather than imported as a module-level singleton so a test can supply an
    in-memory backend without the production one ever being built.
    """
    from secp_commissioning.runtime import RealFilesystem

    return RealFilesystem()
