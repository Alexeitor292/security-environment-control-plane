"""Plane-neutral enrollment-signer READINESS-SURFACE contract (SECP-PR5H-B2, 2b-3c-c, Defect-3 E).

Defect-3 E: the API's readiness surface published every RAW installation fact it had read — the
per-activation token, the identity row id, the installation id, the release digest, the controller
key id, the locator-CA / management-identity / bootstrap-evidence digests and the UDS socket path —
so any peer that reached the surface learned the complete public identity of the install. The
management observer never needed those values: it already holds them independently, from its OWN
authenticated plan, activation receipt and release evidence. It only needs to know whether the
API's view AGREES with its own.

So the surface now publishes DIGESTS, and this module is the ONE place the digests are defined —
imported by the API (which computes them from the parsed marker + the authenticated active identity)
and by the management plane (which recomputes them from its own inputs and compares). Neither plane
re-implements the rule, so the comparison cannot drift into a false match.

Two digests, each DOMAIN-SEPARATED by its own versioned schema literal embedded in the digested
object, so a value that is legitimate under one domain can never be replayed as the other:

* :func:`marker_binding_digest` over the marker's COMPLETE twelve-field binding
  (:data:`MARKER_BINDING_DIGEST_FIELDS` — the same closed set the marker contract requires a
  consumer to compare in full, never a subset);
* :func:`active_identity_binding_digest` over the authenticated ACTIVE-identity facts
  (:data:`ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS`).

This module also owns the readiness surface's TRANSPORT constants — the gate header name and the
fixed host/container gate paths — because the management plane needs them and may never import
``secp_api``. It is PURE and OFFLINE: it opens no socket, touches no filesystem, imports neither
``secp_api`` nor ``secp_management``, and never echoes a value — every refusal is a bounded reason
code optionally suffixed with a code-owned FIELD NAME (never a field VALUE).

A digest is NOT a secret and NOT an authenticator: it is a comparison token over public installation
facts. It is one-way only in the sense that it does not hand the reader the underlying identifiers;
a party that already knows the facts can (and is meant to) recompute it.
"""

from __future__ import annotations

from typing import Any, NoReturn

from secp_commissioning.canonical import sha256_digest
from secp_commissioning.enrollment_signer_marker import (
    ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS,
    EnrollmentSignerMarker,
)
from secp_commissioning.errors import CommissioningError

# --------------------------------------------------------------------------- readiness transport

#: The readiness gate's request header. DISTINCT from the worker-admission proxy gate's header, so
#: neither surface's material is ever presented — let alone accepted — at the other.
ENROLLMENT_SIGNER_READINESS_GATE_HEADER = "X-SECP-Enrollment-Signer-Readiness-Gate"

#: The fixed, code-owned HOST path of the readiness gate secret. The root installer writes it (root
#: owner, API runtime group, mode 0640, exactly 64 lowercase hex + LF) and bind-mounts it read-only
#: into the API container. This constant lives in the commissioning plane precisely because it is
#: the ONE module BOTH planes may import: the management plane needs it to write the file and to
#: present the value, and it may never import ``secp_api``.
ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH = (
    "/etc/secp/controller/enrollment-signer-readiness-gate.secret"
)

#: The fixed, code-owned path the same file appears at INSIDE the API container.
ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH = (
    "/run/secp/enrollment-signer-readiness-gate.secret"
)

#: The ONE accepted on-disk size: 64 lowercase hex characters plus a single trailing LF.
#: the gate VALUE: 256 bits rendered as 64 lowercase hex characters.
ENROLLMENT_SIGNER_READINESS_GATE_HEX_BYTES = 64
#: the gate FILE: those 64 characters plus exactly one trailing LF.
ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES = 65

# --------------------------------------------------------------------------- the digest domains

#: The marker-binding digest domain. A consumer pins this exact string.
ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA = "secp.enrollment-signer-marker-binding-digest/v1"

#: The active-identity-binding digest domain. A consumer pins this exact string.
ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA = (
    "secp.enrollment-signer-active-identity-binding-digest/v1"
)

#: The CLOSED field set of the marker binding digest — exactly the marker contract's complete
#: binding set, imported (never re-listed) so the digest can never cover a subset of it.
MARKER_BINDING_DIGEST_FIELDS: tuple[str, ...] = ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS

#: The CLOSED field set of the active-identity binding digest. The activation GENERATION is
#: deliberately NOT here: it is a monotonic counter the readiness payload reports as its own
#: explicit field, not a fact that identifies the activation.
ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS: tuple[str, ...] = (
    "active_identity_row_id",
    "activation_token",
    "installation_id",
    "release_digest",
    "controller_key_id",
)

_MAX_POSIX_ID = 2**31 - 1
_MAX_FIELD_LEN = 128
_INT_FIELDS = frozenset({"api_uid", "api_gid"})


class EnrollmentSignerBindingDigestError(CommissioningError):
    """A bounded, closed binding-digest refusal — a reason code optionally suffixed with a
    code-owned FIELD NAME. It never carries a field value, an id, or a third-party exception."""


def _reject(reason_code: str) -> NoReturn:
    raise EnrollmentSignerBindingDigestError(reason_code)


def _checked(field: str, value: object) -> Any:
    """Prove one field's exact type + bound before it can enter a digest.

    A digest over unvalidated input would happily absorb ``None``, a bool-as-uid, or an unbounded
    blob and still produce a plausible-looking token, so every field is proven here first."""
    if field in _INT_FIELDS:
        # ``type(...) is int`` excludes ``bool`` EXACTLY (bool is an int subclass): True is never a
        # uid. The enabled API peer is non-root by contract, so 0 is never a legitimate peer.
        if type(value) is not int or not (1 <= value <= _MAX_POSIX_ID):
            _reject(f"enrollment_signer_binding_digest_field_invalid:{field}")
        return value
    if not isinstance(value, str) or not (1 <= len(value) <= _MAX_FIELD_LEN):
        _reject(f"enrollment_signer_binding_digest_field_invalid:{field}")
    return value


def _binding_digest(schema: str, fields: dict[str, Any]) -> str:
    """The ONE digest rule: ``sha256:`` over the canonical JSON of ``{schema, **fields}``.

    The schema literal is part of the digested object, so it is the DOMAIN SEPARATOR: the identical
    field payload digests differently under each domain, and a token minted for one domain can never
    be replayed as the other. It is applied LAST, so a field named ``schema`` could never displace
    it (``_collect`` already restricts the payload to the closed field set — this is belt and
    braces). Key order is irrelevant to the result: the preimage is canonical, sorted JSON."""
    return sha256_digest({**fields, "schema": schema})


def _collect(fields: tuple[str, ...], values: dict[str, Any]) -> dict[str, Any]:
    """Validate EXACTLY the closed field set — an unexpected key in ``values`` is never digested."""
    return {field: _checked(field, values[field]) for field in fields}


# --------------------------------------------------------------------------- marker binding


def marker_binding_digest(
    *,
    installation_id: str,
    release_digest: str,
    active_identity_row_id: str,
    activation_token: str,
    controller_key_id: str,
    management_identity_digest: str,
    bootstrap_evidence_digest: str,
    api_uid: int,
    api_gid: int,
    signer_role_name: str,
    uds_contract_identity: str,
    locator_ca_digest: str,
) -> str:
    """The domain-separated digest of the marker's COMPLETE twelve-field binding.

    The API computes it from the parsed
    :class:`~secp_commissioning.enrollment_signer_marker.EnrollmentSignerMarker` it actually loaded.
    The MANAGEMENT plane computes the identical digest from its OWN independently authenticated
    inputs and compares — it never learns the API's raw values:

    * ``installation_id`` — the controller installation id from the authenticated install plan;
    * ``release_digest`` — ``sha256:<64 hex>`` from the release evidence the plan pinned;
    * ``active_identity_row_id`` — the activation receipt's ``resulting_row_id``;
    * ``activation_token`` — the activation receipt's immutable ``activation_token``
      (``"<row id>|<activated_at>"``);
    * ``controller_key_id`` — ``sha256:<64 hex>`` of the controller enrollment key, from the
      activation receipt / identity evidence;
    * ``management_identity_digest`` / ``bootstrap_evidence_digest`` — ``sha256:<64 hex>`` from the
      management identity + bootstrap evidence documents;
    * ``api_uid`` / ``api_gid`` — the resolved NON-ROOT API runtime peer ids the installer granted;
    * ``signer_role_name`` — the code-owned
      :data:`~secp_commissioning.enrollment_signer_role.ENROLLMENT_SIGNER_DB_ROLE`;
    * ``uds_contract_identity`` — the code-owned
      :data:`~secp_commissioning.controller_enrollment_signer.ENROLLMENT_SIGNER_SOCKET_PATH`;
    * ``locator_ca_digest`` — ``sha256:<64 hex>`` of the locator CA the installer pinned.

    These are exactly the values the installer already wrote into the marker, so a management caller
    that holds a candidate marker binding can simply pass it to :func:`marker_binding_digest_for`.
    """
    return _binding_digest(
        ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA,
        _collect(
            MARKER_BINDING_DIGEST_FIELDS,
            {
                "installation_id": installation_id,
                "release_digest": release_digest,
                "active_identity_row_id": active_identity_row_id,
                "activation_token": activation_token,
                "controller_key_id": controller_key_id,
                "management_identity_digest": management_identity_digest,
                "bootstrap_evidence_digest": bootstrap_evidence_digest,
                "api_uid": api_uid,
                "api_gid": api_gid,
                "signer_role_name": signer_role_name,
                "uds_contract_identity": uds_contract_identity,
                "locator_ca_digest": locator_ca_digest,
            },
        ),
    )


def marker_binding_digest_for(binding: EnrollmentSignerMarker | object) -> str:
    """:func:`marker_binding_digest` for any object carrying the twelve binding attributes.

    That is the API's PARSED marker model, or the management plane's candidate marker binding — the
    same objects :func:`~secp_commissioning.enrollment_signer_marker.marker_binding_matches` accepts
    — so neither plane has to re-list the field set. A missing attribute is a bounded refusal, never
    a silently defaulted digest."""
    values: dict[str, Any] = {}
    for field in MARKER_BINDING_DIGEST_FIELDS:
        if not hasattr(binding, field):
            _reject(f"enrollment_signer_binding_digest_field_missing:{field}")
        values[field] = getattr(binding, field)
    return _binding_digest(
        ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA,
        _collect(MARKER_BINDING_DIGEST_FIELDS, values),
    )


# --------------------------------------------------------------------------- active identity


def active_identity_binding_digest(
    *,
    active_identity_row_id: str,
    activation_token: str,
    installation_id: str,
    release_digest: str,
    controller_key_id: str,
) -> str:
    """The domain-separated digest of the authenticated ACTIVE controller-identity facts.

    The API computes it from the single verified ACTIVE identity row it read (plus that row's
    durable activation receipt). The MANAGEMENT plane computes the identical digest from its OWN
    activation receipt / plan / release evidence:

    * ``active_identity_row_id`` — the activation receipt's ``resulting_row_id``;
    * ``activation_token`` — the receipt's immutable ``activation_token``;
    * ``installation_id`` — the controller installation id from the authenticated plan;
    * ``release_digest`` — ``sha256:<64 hex>`` from the pinned release evidence;
    * ``controller_key_id`` — ``sha256:<64 hex>`` of the controller enrollment key.

    Equal digests prove the running API's authoritative identity row is the very activation
    management performed; unequal digests prove drift, without either side disclosing a value.
    """
    return _binding_digest(
        ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA,
        _collect(
            ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS,
            {
                "active_identity_row_id": active_identity_row_id,
                "activation_token": activation_token,
                "installation_id": installation_id,
                "release_digest": release_digest,
                "controller_key_id": controller_key_id,
            },
        ),
    )


__all__ = [
    "ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS",
    "ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA",
    "ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA",
    "ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH",
    "ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES",
    "ENROLLMENT_SIGNER_READINESS_GATE_HEX_BYTES",
    "ENROLLMENT_SIGNER_READINESS_GATE_HEADER",
    "ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH",
    "MARKER_BINDING_DIGEST_FIELDS",
    "EnrollmentSignerBindingDigestError",
    "active_identity_binding_digest",
    "marker_binding_digest",
    "marker_binding_digest_for",
]
