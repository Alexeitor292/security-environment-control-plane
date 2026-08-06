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

#: The transport this composition uses. A constant, not a setting: a deployment cannot select
#: another, and a test asserting the production transport set reads this rather than a caller's
#: claim about it.
PRODUCTION_TRANSPORT_KIND = TransportKind.proxmox_https_api

DISCOVERY_COMPOSITION_VERSION = "secp.proxmox-discovery-composition/v1"


class DiscoveryTransport(Protocol):
    """The narrow shape this composition needs. Deliberately not the transport class itself, so a
    bounded fake is a first-class citizen and no test needs a real socket."""

    def get(self, path: str, params: dict | None = None) -> object: ...


class CredentialResolver(Protocol):
    """Resolves an opaque reference to secret material. Implemented in production by the guarded
    ``WorkerSecretResolver``; a test supplies an explicit fake."""

    def resolve_for_discovery(self, *, credential_reference: str, target_identity: str) -> str: ...


class DiscoveryCompositionError(Exception):
    """A closed reason code. Never a host, path, credential or backend error."""


@dataclass(frozen=True)
class VersionDiscoveryResult:
    """What one ``/version`` discovery produced: observations, and the evidence for them."""

    observations: dict[str, Observation]
    manifest: DiscoveryOperationManifest
    failed: bool = False
    failure_reason: str = ""


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
    from secp_worker.target_discovery.probes import ProbeError, parse_api_version

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

    observations = _observe_version(payload, parse_api_version, ProbeError)
    return VersionDiscoveryResult(
        observations=observations, manifest=DiscoveryOperationManifest(operations=(evidence,))
    )


def _observe_version(payload: object, parse_api_version, probe_error) -> dict[str, Observation]:
    """Turn one ``/version`` payload into per-field observations.

    A malformed or partial response yields ``observed_malformed`` — never an empty or default
    version. A default would be a fact nobody observed, and a version is precisely the field where
    an invented value silently changes provider compatibility.
    """
    if not isinstance(payload, dict):
        return {
            code: Observation.malformed("version_payload_not_an_object")
            for code in GetVersionOperation.observation_field_codes
        }

    import json

    try:
        major, minor, patch = parse_api_version(json.dumps(payload).encode("utf-8"))
    except probe_error as exc:
        reason = str(getattr(exc, "args", ["malformed_probe_output"])[0])
        return {
            code: Observation.malformed(reason)
            for code in GetVersionOperation.observation_field_codes
        }

    full = str(payload.get("version", ""))
    release = payload.get("release")
    repoid = payload.get("repoid")

    return {
        "pve_version_full": Observation.observed(full),
        "pve_version_major": Observation.observed(major),
        "pve_version_minor": Observation.observed(minor),
        # `None` when the target genuinely reported two parts — never a fabricated 0.
        "pve_version_patch": (
            Observation.observed(patch)
            if patch is not None
            else Observation.malformed("version_reported_without_a_patch_component")
        ),
        "pve_release": (
            Observation.observed(str(release))
            if isinstance(release, str)
            else Observation.malformed("release_absent_or_not_a_string")
        ),
        "pve_repoid": (
            Observation.observed(str(repoid))
            if isinstance(repoid, str)
            else Observation.malformed("repoid_absent_or_not_a_string")
        ),
    }


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
