"""Transport-neutral signed evidence for one discovery operation.

The existing manifest entry binds an exact rendered ``argv``. That describes a host command
truthfully and describes an HTTPS GET not at all, and every way of forcing the fit is worse than the
gap:

* an HTTP-shaped fake argv (``["GET", "/api2/json/version"]``) signs a command that was never run;
* a URL in an argv field puts the target authority — and, one careless refactor later, a query
  string — into a place reviewers read as a shell invocation;
* an empty argv signs nothing and reads as "no command", which is indistinguishable from a probe
  that never executed;
* unsigned HTTP metadata beside a signed shell manifest means the fields an operator actually cares
  about are the ones nobody attested.

So the manifest entry becomes transport-neutral. ``transport_kind`` says what kind of thing ran, and
the fields that only apply to one kind are absent rather than faked.

**What is deliberately NOT signed**, because signing it would put it somewhere durable and readable:
the API token, the ``Authorization`` header, any secret-bearing header, the CA file's filesystem
path, and ambient proxy configuration. TLS identity is bound separately, by CA or certificate
fingerprint, so the evidence proves *which authority answered* without carrying the material used to
reach it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TransportKind(str, Enum):
    """What kind of thing executed an operation."""

    #: The first-MVP production transport: a typed GET against the enrolled target's HTTPS API.
    proxmox_https_api = "proxmox_https_api"
    #: The legacy SSH host-command path. Retained so historical and test records remain
    #: representable, and refused in a first-MVP production manifest.
    legacy_host_command = "legacy_host_command"


#: The only transport a first-MVP production discovery manifest may contain. A mixed manifest is
#: refused rather than merged: "some of this came over HTTPS" is not a property anyone can act on.
FIRST_MVP_TRANSPORTS: frozenset[TransportKind] = frozenset({TransportKind.proxmox_https_api})


class OperationEvidenceError(ValueError):
    """An operation record is internally inconsistent or carries something it must not."""


#: Substrings that must never appear in a signed operation record. Checked on the rendered path and
#: query values, because those are the two fields a caller could most plausibly be talked into
#: widening.
_FORBIDDEN_FRAGMENTS: tuple[str, ...] = (
    "PVEAPIToken",
    "Authorization",
    "authorization",
    "password",
    "secret",
    "token=",
)


@dataclass(frozen=True)
class DiscoveryOperationEvidence:
    """One executed discovery operation, as evidence rather than as a log line.

    Every field answers something a later reviewer must not have to take on trust: what ran,
    against which authority, asking what, getting back what shape, parsed by which
    implementation, when.
    """

    operation_code: str
    transport_kind: TransportKind

    #: WHICH authority answered — an identity, never a URL with credentials in it.
    target_authority_identity: str = ""

    # --- what was asked ---------------------------------------------------------------------------
    request_method: str = ""
    #: The template, e.g. ``/api2/json/nodes/{node}/status``. Signed alongside the rendered form
    #: so a reviewer sees the SHAPE that was permitted, not only the instance that ran.
    canonical_path_template: str = ""
    canonical_rendered_path: str = ""
    canonical_query_parameters: tuple[tuple[str, str], ...] = ()
    request_body_present: bool = False

    # --- what came back ---------------------------------------------------------------------------
    #: A classification (``2xx``/``4xx``/``5xx``/``refused``), not the raw code: the exact status is
    #: rarely the decision and a class is stable across Proxmox versions.
    response_status_classification: str = ""
    response_content_type: str = ""
    response_size: int = 0
    #: Digest of the body. The body itself is never carried — unbounded, and the digest is what lets
    #: a re-run be compared against this one.
    response_digest: str = ""

    # --- who interpreted it -----------------------------------------------------------------------
    parser_implementation_id: str = ""
    normalizer_implementation_id: str = ""
    #: Which observation fields this operation produced. Lets a reviewer trace a fact back to the
    #: request that supplied it without re-deriving the mapping.
    observation_field_codes: tuple[str, ...] = ()

    started_at: str = ""
    completed_at: str = ""

    #: Legacy-only. Present exclusively when ``transport_kind`` is ``legacy_host_command``.
    rendered_argv: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.transport_kind is TransportKind.proxmox_https_api:
            if self.rendered_argv:
                raise OperationEvidenceError(
                    "https operation evidence carries a rendered argv; an HTTP request is not a "
                    "command, and a fake argv signs something that never ran"
                )
            if self.request_method != "GET":
                raise OperationEvidenceError("first-MVP https discovery admits only GET")
            if self.request_body_present:
                raise OperationEvidenceError("a discovery GET carries no request body")
            if not self.canonical_rendered_path:
                raise OperationEvidenceError("https operation evidence must record its exact path")
        elif self.transport_kind is TransportKind.legacy_host_command:
            if not self.rendered_argv:
                raise OperationEvidenceError("legacy operation evidence must record its argv")
            if self.canonical_rendered_path:
                raise OperationEvidenceError("a host command has no request path")

        haystack = " ".join(
            (
                self.canonical_rendered_path,
                self.canonical_path_template,
                *(f"{k}={v}" for k, v in self.canonical_query_parameters),
                *self.rendered_argv,
            )
        )
        for fragment in _FORBIDDEN_FRAGMENTS:
            if fragment in haystack:
                raise OperationEvidenceError(
                    "operation evidence carries credential-shaped material; the token, the "
                    "Authorization header and any secret-bearing value are never signed"
                )

    def canonical(self) -> dict:
        """The signed form. Omits legacy-only fields for an HTTPS record and vice versa."""
        out: dict = {
            "operation_code": self.operation_code,
            "transport_kind": self.transport_kind.value,
            "target_authority_identity": self.target_authority_identity,
            "response_status_classification": self.response_status_classification,
            "response_content_type": self.response_content_type,
            "response_size": self.response_size,
            "response_digest": self.response_digest,
            "parser_implementation_id": self.parser_implementation_id,
            "normalizer_implementation_id": self.normalizer_implementation_id,
            "observation_field_codes": list(self.observation_field_codes),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
        if self.transport_kind is TransportKind.proxmox_https_api:
            out.update(
                {
                    "request_method": self.request_method,
                    "canonical_path_template": self.canonical_path_template,
                    "canonical_rendered_path": self.canonical_rendered_path,
                    "canonical_query_parameters": [
                        list(pair) for pair in self.canonical_query_parameters
                    ],
                    "request_body_present": self.request_body_present,
                }
            )
        else:
            out["rendered_argv"] = list(self.rendered_argv)
        return out


@dataclass(frozen=True)
class DiscoveryOperationManifest:
    """The ordered set of operations one discovery run executed."""

    operations: tuple[DiscoveryOperationEvidence, ...] = ()

    def transport_kinds(self) -> frozenset[TransportKind]:
        return frozenset(op.transport_kind for op in self.operations)

    def canonical(self) -> list[dict]:
        return [op.canonical() for op in self.operations]


def first_mvp_manifest_refusals(manifest: DiscoveryOperationManifest) -> tuple[str, ...]:
    """Why this manifest is not a valid first-MVP production record. Empty means it is.

    Derived from the manifest's own contents rather than from a declared transport field, so a run
    that claims HTTPS while carrying a host command is caught by what it did, not by what it says.
    """
    reasons: list[str] = []
    kinds = manifest.transport_kinds()

    if not manifest.operations:
        # An empty manifest is not a clean run. It is a run that recorded nothing, which is
        # indistinguishable from one that executed nothing.
        reasons.append("discovery_manifest_empty")
        return tuple(reasons)

    if TransportKind.legacy_host_command in kinds:
        reasons.append("discovery_manifest_contains_legacy_host_command")
    unknown = kinds - set(TransportKind)
    if unknown:
        reasons.append("discovery_manifest_unknown_transport")
    if kinds != FIRST_MVP_TRANSPORTS:
        reasons.append(
            "discovery_manifest_transport_set_not_https_only:"
            + ",".join(sorted(k.value for k in kinds))
        )
    return tuple(dict.fromkeys(reasons))


def active_transport_set(manifest: DiscoveryOperationManifest) -> frozenset[TransportKind]:
    """The transports this run actually used.

    Derived from executed operations, never from caller-supplied metadata — a composition that
    declares itself HTTPS-only while running a host command is exactly what this is for.
    """
    return manifest.transport_kinds()
