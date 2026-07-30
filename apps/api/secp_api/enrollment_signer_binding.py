"""Authoritative runtime binding for the enrollment-signer enablement marker (SECP-PR5H-B2, C1).

A structurally-valid, root-owned marker is NOT sufficient to enable the production signer client: a
stale marker from a prior release, identity, key, or installation must never enable signing. This
module constructs a strict, typed :class:`EnrollmentSignerRuntimeBinding` from INDEPENDENTLY
AUTHORITATIVE sources — never from the marker or HTTP — and the caller enables the UDS client ONLY
when the marker's binding EXACTLY equals it (typed, complete-field comparison; no subset).

Authoritative sources:
* the exactly-one verified ACTIVE ``controller_enrollment_identity`` row → installation id, release
  digest, active row id, activation token, controller key id, management-identity +
  bootstrap-evidence digests;
* the running process + code-owned contracts → API effective uid/gid, the fixed signer-role name,
  the fixed UDS contract path;
* the fixed, independently-read controller CA bundle → its content digest (the locator/CA fact).

A missing / ambiguous / unverified identity, an unreadable CA bundle, or a non-POSIX host yields no
binding (``None`` → SEALED). This module reaches no network and trusts no settings/env for identity
facts.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.controller_identity_models import ControllerEnrollmentIdentity

#: The fixed, code-owned controller CA-bundle path the API independently digests for the locator/CA
#: fact (bind-mounted read-only into the API container; the same file the locator records).
CONTROLLER_CA_BUNDLE_PATH = "/etc/secp/controller/tls/ca-bundle.pem"
_MAX_CA_BYTES = 256 * 1024

#: The exact fields the marker must match the running install on (complete set; typed, no subset).
_BOUND_FIELDS = (
    "installation_id",
    "release_digest",
    "active_identity_row_id",
    "activation_token",
    "controller_key_id",
    "management_identity_digest",
    "bootstrap_evidence_digest",
    "api_uid",
    "api_gid",
    "signer_role_name",
    "uds_contract_identity",
    "locator_ca_digest",
)


@dataclass(frozen=True)
class EnrollmentSignerRuntimeBinding:
    """The authoritative runtime facts a valid enablement marker must EXACTLY match. Built only from
    the verified active identity + the running process + fixed code-owned contracts + CA bundle."""

    installation_id: str
    release_digest: str
    active_identity_row_id: str
    activation_token: str
    controller_key_id: str
    management_identity_digest: str
    bootstrap_evidence_digest: str
    api_uid: int
    api_gid: int
    signer_role_name: str
    uds_contract_identity: str
    locator_ca_digest: str


def _ca_bundle_digest(ca_bundle_path: str) -> str | None:
    try:
        with open(ca_bundle_path, "rb") as fh:
            raw = fh.read(_MAX_CA_BYTES + 1)
    except OSError:
        return None
    if not raw or len(raw) > _MAX_CA_BYTES:
        return None
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _process_ids() -> tuple[int, int] | None:
    geteuid = getattr(os, "geteuid", None)
    getegid = getattr(os, "getegid", None)
    if geteuid is None or getegid is None:  # non-POSIX: production identity facts are not provable
        return None
    return int(geteuid()), int(getegid())


def build_runtime_binding(
    session: Session, *, ca_bundle_path: str = CONTROLLER_CA_BUNDLE_PATH
) -> EnrollmentSignerRuntimeBinding | None:
    """Construct the binding from authoritative sources, or ``None`` (→ SEALED) on a missing /
    ambiguous / unverified identity, an unreadable CA bundle, or a non-POSIX host."""
    rows = (
        session.execute(
            select(ControllerEnrollmentIdentity).where(
                ControllerEnrollmentIdentity.status == "active"
            )
        )
        .scalars()
        .all()
    )
    if len(rows) != 1:  # absent or ambiguous → sealed
        return None
    row = rows[0]
    if not bool(row.verified):
        return None
    ids = _process_ids()
    if ids is None:
        return None
    ca_digest = _ca_bundle_digest(ca_bundle_path)
    if ca_digest is None:
        return None
    api_uid, api_gid = ids
    return EnrollmentSignerRuntimeBinding(
        installation_id=str(row.controller_installation_id),
        release_digest=str(row.release_digest),
        active_identity_row_id=str(row.id),
        activation_token=f"{row.id}|{row.activated_at}",
        controller_key_id=str(row.controller_key_id),
        management_identity_digest=str(row.management_identity_digest),
        bootstrap_evidence_digest=str(row.bootstrap_evidence_digest),
        api_uid=api_uid,
        api_gid=api_gid,
        signer_role_name=ENROLLMENT_SIGNER_DB_ROLE,
        uds_contract_identity=ENROLLMENT_SIGNER_SOCKET_PATH,
        locator_ca_digest=ca_digest,
    )


def marker_matches_binding(marker: object, binding: EnrollmentSignerRuntimeBinding) -> bool:
    """Whether the marker's binding EXACTLY equals the authoritative runtime binding on the COMPLETE
    required field set (no subset). Any missing or mismatched field → False (the caller seals)."""
    for field in _BOUND_FIELDS:
        if getattr(marker, field, object()) != getattr(binding, field):
            return False
    return True


__all__ = [
    "CONTROLLER_CA_BUNDLE_PATH",
    "EnrollmentSignerRuntimeBinding",
    "build_runtime_binding",
    "marker_matches_binding",
]
