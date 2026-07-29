"""Fixed, read-only enrollment-signer RUNTIME READINESS surface (SECP-PR5H-B2, 2b-3c-c, R4).

Clean-room review 4803080223 finding R4: the management runtime observer OVERCLAIMED. It derived
``effective_signer_is_fixed_uds`` from MARKER FIELDS (the installer's own intent) and
``broker_reachable`` from a socket inode plus unit bytes — neither is a fact about the RUNNING API
process. The management plane may not import ``secp_api``, has no access to the API's dependency
graph, and cannot connect to a root-owned socket as the API's peer, so those facts can only be
reported BY the running API. This module is that report.

What it is:

* ONE fixed, code-owned route — :data:`SIGNER_READINESS_PATH`. It accepts no path parameter, no
  query parameter and no body, so no caller can select a path, a socket, a key, an operation, or a
  module. It is not mounted on the public ``/api/v1`` surface;
* strictly READ-ONLY — bounded ORM SELECTs (never ``begin()``/``flush()``/``commit()``), one bounded
  marker file read, one ``lstat``, and one bounded no-sign socket exchange. It mutates nothing,
  writes nothing, and exposes NO root operation: every action it performs is one the ordinary
  NON-ROOT API process already performs in normal operation;
* NEVER a signing request — the broker probe deliberately sends an op that is NOT ``sign_offer``
  (see :func:`probe_broker_no_sign`), so the broker's reviewed request validation refuses it before
  the signer, the lease, or the enrollment key is ever reached;
* PRIVATE — reached only through the fixed readiness ORIGIN GATE
  (:mod:`secp_api.signer_readiness_origin`), attached as a ROUTER-level dependency so an
  unauthorized request never reaches the observation, the broker socket, or the no-sign exchange;
* MINIMIZED (2b-3c-c Defect-3 E) — the payload carries NO raw installation identifier. Earlier
  revisions published the activation token, the identity row id, the installation id, the release
  digest, the controller key id, the locator-CA / management-identity / bootstrap-evidence digests
  and the UDS socket path, so any peer that reached the surface learned the install's complete
  public identity. The management observer never needed them: it holds those facts independently.
  The surface now reports only DOMAIN-SEPARATED BINDING DIGESTS
  (:mod:`secp_commissioning.enrollment_signer_binding_digest`) that management recomputes from its
  OWN authenticated plan / activation receipt / release evidence and compares. No key, credential,
  verifier, DSN, header, path or raw exception ever enters the payload either;
* STRICT + VERSIONED + BOUNDED — exactly the closed field set of :data:`SIGNER_READINESS_FIELDS`
  under the single :data:`SIGNER_READINESS_SCHEMA` literal, re-validated against its own strict
  model and refused if it exceeds :data:`SIGNER_READINESS_MAX_BYTES`. There is no negotiation and no
  best-effort upgrade path;
* FAIL-CLOSED — every unprovable fact is ``False`` / ``""`` / ``-1``; nothing is ever defaulted to a
  proven-looking value.

What it reports (all ACTUAL RUNNING PROCESS state, never marker intent):

* the EFFECTIVE signer implementation, resolved from the app's REAL dependency
  (:func:`secp_api.deps.get_enrollment_offer_signer`) by EXACT type identity — ``fixed_uds`` only
  for the reviewed :class:`~secp_api.enrollment_signer_client.UnixSocketEnrollmentOfferSignerClient`
  itself; a sealed default is ``sealed`` and ANY other object (a subclass, a test double, a fake) is
  ``unavailable``. It is never inferred from the marker file;
* that no alternate activation exists: the effective client is bound to the ONE code-owned socket
  constant, its class exposes no socket/path selector, and NO environment variable in the RUNNING
  process would independently enable signing (a stronger fact than a container's declared env);
* whether a marker is loaded, and the DIGEST of its complete twelve-field binding — parsed through
  the ONE shared strict contract (``secp_commissioning.enrollment_signer_marker``) and digested
  through the ONE shared plane-neutral rule, never re-implemented here;
* the DIGEST of the actual ACTIVE controller identity binding, and the durable activation
  GENERATION;
* the API process's effective uid/gid;
* a BOUNDED NO-SIGN UDS probe the API process performs itself against the fixed AF_UNIX broker
  socket, reporting the peer-authorization result and the broker protocol identity, and failing on
  an alternate endpoint, a stale inode, no listener, a wrong peer, a malformed protocol, or a
  timeout.
"""

from __future__ import annotations

import inspect
import json
import os
import socket
import stat
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_commissioning.canonical import canonical_json
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
from secp_commissioning.enrollment_signer_binding_digest import (
    EnrollmentSignerBindingDigestError,
    active_identity_binding_digest,
    marker_binding_digest_for,
)
from secp_commissioning.enrollment_signer_marker import EnrollmentSignerMarker
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.controller_identity_models import (
    CONTROLLER_IDENTITY_ACTIVE,
    ControllerEnrollmentIdentity,
    ControllerIdentityActivationReceipt,
)
from secp_api.enrollment_signer_client import (
    SealedEnrollmentOfferSignerClient,
    UnixSocketEnrollmentOfferSignerClient,
)
from secp_api.enrollment_signer_marker import MARKER_PATH, load_valid_marker

# --------------------------------------------------------------------------- the fixed contract

#: The ONE fixed, code-owned route. No prefix/segment/parameter of it is caller-selectable.
SIGNER_READINESS_PREFIX = "/internal/enrollment-signer"
SIGNER_READINESS_PATH = f"{SIGNER_READINESS_PREFIX}/readiness"

#: The ONE accepted schema/version literal. A consumer pins this exact string. ``/v2`` is the
#: MINIMIZED payload (2b-3c-c Defect-3 E): every raw installation identifier was removed and
#: replaced by two domain-separated binding digests. It is a hard break — a ``/v1`` consumer must
#: refuse it rather than best-effort-parse it, which is exactly what the strict literal enforces.
SIGNER_READINESS_SCHEMA = "secp.api.enrollment-signer-readiness/v2"

#: Bounded response size — the payload is fixed-shape, so this can never grow with install size.
SIGNER_READINESS_MAX_BYTES = 8192

#: The broker's reviewed JSON wire contract identity. Reported ONLY when the live exchange proved
#: it; the management observer pins the same literal (it may not import this module).
ENROLLMENT_SIGNER_BROKER_PROTOCOL = "secp.enrollment-signer-broker/v1"

# --- closed vocabularies --------------------------------------------------------------------------

SIGNER_FIXED_UDS = "fixed_uds"  # the reviewed fixed-UDS broker client, exactly
SIGNER_SEALED = "sealed"  # the shipped sealed default (every sign attempt refuses)
SIGNER_UNAVAILABLE = "unavailable"  # anything else — a fake/double/subclass is never trusted

TRANSPORT_AF_UNIX = "af_unix"
TRANSPORT_NONE = "none"

STATUS_READY = "ready"
STATUS_SEALED = "sealed"

PROBE_OK = "ok"
PROBE_NOT_ATTEMPTED = "not_attempted"  # the effective signer is not the fixed-UDS client
PROBE_UNSUPPORTED = "unsupported"  # no AF_UNIX on this host (never a production controller)
PROBE_ENDPOINT_UNSAFE = "endpoint_unsafe"  # not a root-owned AF_UNIX socket -> alternate endpoint
PROBE_SOCKET_ABSENT = "socket_absent"
PROBE_NO_LISTENER = "no_listener"  # a socket inode with no accept loop (stale inode)
PROBE_TIMEOUT = "timeout"
PROBE_PEER_UNAUTHORIZED = "peer_unauthorized"
PROBE_PROTOCOL_MISMATCH = "protocol_mismatch"  # not the reviewed broker contract

#: The op the probe sends. It is deliberately NOT ``sign_offer``: the broker's EXISTING reviewed
#: request validation (``EnrollmentSignerBroker._sign_request``) authorizes the peer FIRST and then
#: refuses any other op with a bounded code — BEFORE the signer, the identity lease, or the
#: enrollment key is reached. No broker operation is invented, added, or changed by this module.
PROBE_OP = "readiness_probe"

#: The bounded codes the reviewed broker returns on this exchange.
_BROKER_REQUEST_INVALID = "enrollment_signer_request_invalid"
_BROKER_PEER_UNAUTHORIZED = "enrollment_signer_peer_unauthorized"
_BROKER_PEER_CREDENTIALS_UNAVAILABLE = "enrollment_signer_peer_credentials_unavailable"

_PROBE_TIMEOUT_SECONDS = 2.0
_PROBE_MAX_RESPONSE_BYTES = 4096
_MAX_POSIX_ID = 2**31 - 1
_MAX_GENERATION = 1_000_000
_UNPROVEN_GENERATION = -1

_TRUTHY = frozenset({"1", "true", "yes", "on", "t", "y"})

#: The bound + grammar of a rendered ``sha256:<64 hex>`` binding digest. An unproven digest is
#: ``""`` — the payload never carries a partial, truncated, or placeholder digest.
_DIGEST_LEN = 71
_DIGEST_OR_EMPTY = r"^(sha256:[0-9a-f]{64})?$"

#: The CLOSED field set of the MINIMIZED readiness payload (the JSON keys). Missing or extra keys
#: both refuse; ``schema`` is exposed on the model as ``schema_id`` because pydantic reserves
#: ``schema``. Every raw installation identifier that used to live here is gone: what remains is a
#: status vocabulary, the running process's own uid/gid, the activation generation, and two
#: domain-separated BINDING DIGESTS management recomputes from its own authenticated inputs.
SIGNER_READINESS_FIELDS: tuple[str, ...] = (
    "schema",
    "status",
    "effective_signer",
    "signer_transport",
    "no_alternate_signer_activation",
    "process_uid",
    "process_gid",
    "marker_present",
    "marker_binding_matches_runtime",
    "marker_binding_digest",
    "active_identity_present",
    "active_identity_binding_digest",
    "activation_generation",
    "broker_probe",
    "broker_peer_authorized",
    "broker_protocol",
)


class SignerReadinessPayload(BaseModel):
    """The strict, closed, flat readiness payload. Extra/missing fields, wrong types, and any value
    outside a closed vocabulary refuse — the route never returns a payload it cannot re-validate."""

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)

    schema_id: Literal["secp.api.enrollment-signer-readiness/v2"] = Field(alias="schema")
    status: Literal["ready", "sealed"]
    effective_signer: Literal["fixed_uds", "sealed", "unavailable"]
    signer_transport: Literal["af_unix", "none"]
    no_alternate_signer_activation: bool
    process_uid: int = Field(ge=-1, le=_MAX_POSIX_ID)
    process_gid: int = Field(ge=-1, le=_MAX_POSIX_ID)
    marker_present: bool
    marker_binding_matches_runtime: bool
    # a ``sha256:<64 hex>`` binding digest, or ``""`` when unproven. Never a raw installation value.
    marker_binding_digest: str = Field(max_length=_DIGEST_LEN, pattern=_DIGEST_OR_EMPTY)
    active_identity_present: bool
    active_identity_binding_digest: str = Field(max_length=_DIGEST_LEN, pattern=_DIGEST_OR_EMPTY)
    activation_generation: int = Field(ge=_UNPROVEN_GENERATION, le=_MAX_GENERATION)
    broker_probe: Literal[
        "ok",
        "not_attempted",
        "unsupported",
        "endpoint_unsafe",
        "socket_absent",
        "no_listener",
        "timeout",
        "peer_unauthorized",
        "protocol_mismatch",
    ]
    broker_peer_authorized: bool
    broker_protocol: str = Field(max_length=64)


# --------------------------------------------------------------------------- effective signer


@dataclass(frozen=True)
class EffectiveSigner:
    """The ACTUAL signer object the running app resolves, classified by EXACT type identity."""

    identifier: str
    transport: str
    bound_socket_path: str
    selectable_socket: bool


def classify_effective_signer(signer: object) -> EffectiveSigner:
    """Classify the REAL injected signer dependency. Uses ``type(...) is`` (never ``isinstance``) so
    a subclass, a stub, or a test double can never masquerade as the reviewed fixed-UDS client."""
    if type(signer) is UnixSocketEnrollmentOfferSignerClient:
        path = getattr(signer, "_socket_path", "")
        try:
            params = inspect.signature(type(signer).__init__).parameters
        except (TypeError, ValueError):  # pragma: no cover - defensive
            params = {}  # type: ignore[assignment]
        selectable = any(
            name in params for name in ("socket_path", "path", "host", "port", "address")
        )
        return EffectiveSigner(
            identifier=SIGNER_FIXED_UDS,
            transport=TRANSPORT_AF_UNIX,
            bound_socket_path=path if isinstance(path, str) else "",
            selectable_socket=selectable,
        )
    if type(signer) is SealedEnrollmentOfferSignerClient:
        return EffectiveSigner(
            identifier=SIGNER_SEALED,
            transport=TRANSPORT_NONE,
            bound_socket_path="",
            selectable_socket=False,
        )
    return EffectiveSigner(
        identifier=SIGNER_UNAVAILABLE,
        transport=TRANSPORT_NONE,
        bound_socket_path="",
        selectable_socket=False,
    )


def no_process_env_enablement(environ: dict[str, str] | None = None) -> bool:
    """True iff NO environment variable in the RUNNING process would independently enable signing.

    Stronger than the container's declared environment: this is what the process actually holds."""
    env = os.environ if environ is None else environ
    for name, value in env.items():
        upper = name.strip().upper()
        suspicious = upper == "SECP_ENROLLMENT_SIGNER_ENABLED" or (
            "ENROLLMENT" in upper and "SIGNER" in upper and "ENABL" in upper
        )
        if suspicious and value.strip().lower() in _TRUTHY:
            return False
    return True


# --------------------------------------------------------------------------- the no-sign UDS probe


class _ProbeUnavailable(Exception):
    """A bounded probe refusal carrying ONLY a closed status token (never a path or exception)."""

    def __init__(self, status: str) -> None:
        self.status = status
        super().__init__(status)


def _refuse_probe(status: str) -> NoReturn:
    raise _ProbeUnavailable(status)


def _assert_fixed_endpoint() -> None:
    """The ONE code-owned socket must be EXACTLY a root-owned AF_UNIX socket (never a symlink, a
    regular file, a FIFO, or a node the non-root API could have planted). Anything else is an
    ALTERNATE endpoint and refuses. Skipped off POSIX, where the probe is unsupported anyway."""
    path = ENROLLMENT_SIGNER_SOCKET_PATH
    if os.name != "posix":  # pragma: no cover - production runs on POSIX
        return
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        _refuse_probe(PROBE_SOCKET_ABSENT)
    except OSError:
        _refuse_probe(PROBE_ENDPOINT_UNSAFE)
    if not stat.S_ISSOCK(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
        _refuse_probe(PROBE_ENDPOINT_UNSAFE)


def _real_uds_exchange(request: bytes, timeout: float) -> bytes:
    """Connect to the ONE code-owned AF_UNIX socket and perform ONE bounded request/response. Takes
    no path (the location is a module constant), opens no TCP family, and reads no ambient proxy or
    environment setting. Any fault is a bounded closed status."""
    af_unix = getattr(socket, "AF_UNIX", None)
    if af_unix is None:
        _refuse_probe(PROBE_UNSUPPORTED)
    _assert_fixed_endpoint()
    path = ENROLLMENT_SIGNER_SOCKET_PATH
    sock = socket.socket(af_unix, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.connect(path)
        except FileNotFoundError:
            _refuse_probe(PROBE_SOCKET_ABSENT)
        except TimeoutError:
            _refuse_probe(PROBE_TIMEOUT)
        except OSError:  # refused / stale inode with no accept loop / permission
            _refuse_probe(PROBE_NO_LISTENER)
        try:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _PROBE_MAX_RESPONSE_BYTES:
                    _refuse_probe(PROBE_PROTOCOL_MISMATCH)
                chunks.append(chunk)
        except TimeoutError:
            _refuse_probe(PROBE_TIMEOUT)
        except OSError:
            _refuse_probe(PROBE_NO_LISTENER)
        return b"".join(chunks)
    finally:
        sock.close()


@dataclass(frozen=True)
class BrokerProbeResult:
    """The bounded outcome of the no-sign broker exchange. ``protocol`` is non-empty ONLY when the
    reviewed broker contract was genuinely proven."""

    status: str
    peer_authorized: bool
    protocol: str


_PROBE_REQUEST_BYTES = json.dumps(
    {"op": PROBE_OP}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("utf-8")


def _classify_broker_reply(raw: bytes) -> BrokerProbeResult:
    """Classify the broker's reply to the NO-SIGN probe.

    The reviewed broker authorizes the connecting peer's ``SO_PEERCRED`` BEFORE it parses the
    request, and its ``_send`` emits exactly ``canonical`` compact JSON. So:

    * ``enrollment_signer_request_invalid`` proves BOTH that the peer was authorized AND that the
      listener is the reviewed broker's request-validation path (which performs no signing);
    * the two peer codes prove the listener is the broker but refused this peer;
    * anything else — a different code, a different shape, a non-canonical rendering, or a non-JSON
      body — is an unidentified listener and refuses.
    """
    if not raw or len(raw) > _PROBE_MAX_RESPONSE_BYTES:
        return BrokerProbeResult(PROBE_PROTOCOL_MISMATCH, False, "")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return BrokerProbeResult(PROBE_PROTOCOL_MISMATCH, False, "")
    if not isinstance(payload, dict) or set(payload) != {"error"}:
        return BrokerProbeResult(PROBE_PROTOCOL_MISMATCH, False, "")
    code = payload["error"]
    if not isinstance(code, str):
        return BrokerProbeResult(PROBE_PROTOCOL_MISMATCH, False, "")
    # byte-exact protocol identity: the reviewed broker renders compact sorted JSON, nothing else
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    if rendered != raw:
        return BrokerProbeResult(PROBE_PROTOCOL_MISMATCH, False, "")
    if code in (_BROKER_PEER_UNAUTHORIZED, _BROKER_PEER_CREDENTIALS_UNAVAILABLE):
        return BrokerProbeResult(PROBE_PEER_UNAUTHORIZED, False, "")
    if code == _BROKER_REQUEST_INVALID:
        return BrokerProbeResult(PROBE_OK, True, ENROLLMENT_SIGNER_BROKER_PROTOCOL)
    return BrokerProbeResult(PROBE_PROTOCOL_MISMATCH, False, "")


def probe_broker_no_sign(
    *,
    timeout: float = _PROBE_TIMEOUT_SECONDS,
    exchange: Callable[[bytes, float], bytes] | None = None,
) -> BrokerProbeResult:
    """Perform the BOUNDED NO-SIGN broker probe and classify the outcome.

    The request is the fixed :data:`PROBE_OP` document — never ``sign_offer``, never a context,
    never a payload — so no signature can be produced on this path. ``exchange`` is a verified test
    seam (the sibling one-shots expose the same kind); production always uses the fixed AF_UNIX
    round-trip against the code-owned socket constant."""
    transport = exchange if exchange is not None else _real_uds_exchange
    try:
        raw = transport(_PROBE_REQUEST_BYTES, timeout)
    except _ProbeUnavailable as exc:
        return BrokerProbeResult(exc.status, False, "")
    except Exception:  # noqa: BLE001 - any unexpected transport fault is a closed refusal
        return BrokerProbeResult(PROBE_NO_LISTENER, False, "")
    return _classify_broker_reply(raw)


# --------------------------------------------------------------------------- durable identity


@dataclass(frozen=True)
class _ActiveIdentityFacts:
    present: bool
    row_id: str
    activation_token: str
    installation_id: str
    release_digest: str
    controller_key_id: str
    generation: int


_ABSENT_IDENTITY = _ActiveIdentityFacts(
    present=False,
    row_id="",
    activation_token="",
    installation_id="",
    release_digest="",
    controller_key_id="",
    generation=_UNPROVEN_GENERATION,
)


def _observe_active_identity(session: Session) -> _ActiveIdentityFacts:
    """Read the authoritative ACTIVE controller identity + its durable activation GENERATION.

    Read-only ORM SELECTs on a session that is never flushed or committed here. Absent, ambiguous
    (>1), or unverified is a proven ABSENCE (fail closed), never a partial adoption."""
    try:
        rows = (
            session.execute(
                select(ControllerEnrollmentIdentity).where(
                    ControllerEnrollmentIdentity.status == CONTROLLER_IDENTITY_ACTIVE
                )
            )
            .scalars()
            .all()
        )
    except Exception:  # noqa: BLE001 - any DB fault is an unprovable identity
        return _ABSENT_IDENTITY
    if len(rows) != 1:
        return _ABSENT_IDENTITY
    row = rows[0]
    if not bool(row.verified) or row.activated_at is None:
        return _ABSENT_IDENTITY
    generation = _UNPROVEN_GENERATION
    try:
        stored = (
            session.execute(
                select(ControllerIdentityActivationReceipt.generation)
                .where(ControllerIdentityActivationReceipt.resulting_row_id == row.id)
                .order_by(ControllerIdentityActivationReceipt.recorded_at.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
    except Exception:  # noqa: BLE001 - an unreadable receipt leaves the generation unproven
        stored = None
    if type(stored) is int and 0 <= stored <= _MAX_GENERATION:
        generation = stored
    return _ActiveIdentityFacts(
        present=True,
        row_id=str(row.id),
        # the SAME activation-token rule the runtime binding + the durable receipt use
        activation_token=f"{row.id}|{row.activated_at}",
        installation_id=str(row.controller_installation_id),
        release_digest=str(row.release_digest),
        controller_key_id=str(row.controller_key_id),
        generation=generation,
    )


# --------------------------------------------------------------------------- the observation


def _process_ids() -> tuple[int, int]:
    geteuid = getattr(os, "geteuid", None)
    getegid = getattr(os, "getegid", None)
    if geteuid is None or getegid is None:  # non-POSIX dev host: not provable
        return -1, -1
    return int(geteuid()), int(getegid())


def _marker_digest(marker: EnrollmentSignerMarker | None) -> str:
    """The marker's COMPLETE-binding digest, or ``""`` when there is nothing proven to digest.

    The rule lives in the plane-neutral contract, so management's recomputation cannot drift from
    this one. An undigestable binding is ``""`` (fail closed) — never a partial or raw value."""
    if marker is None:
        return ""
    try:
        return marker_binding_digest_for(marker)
    except EnrollmentSignerBindingDigestError:  # pragma: no cover - the parser already bounds these
        return ""


def _identity_digest(identity: _ActiveIdentityFacts) -> str:
    """The ACTIVE identity's binding digest, or ``""`` when no identity was proven."""
    if not identity.present:
        return ""
    try:
        return active_identity_binding_digest(
            active_identity_row_id=identity.row_id,
            activation_token=identity.activation_token,
            installation_id=identity.installation_id,
            release_digest=identity.release_digest,
            controller_key_id=identity.controller_key_id,
        )
    except EnrollmentSignerBindingDigestError:
        return ""


def observe_signer_readiness(
    session: Session,
    signer: object,
    *,
    marker_path: str | None = None,
    probe_timeout: float = _PROBE_TIMEOUT_SECONDS,
    exchange: Callable[[bytes, float], bytes] | None = None,
) -> dict[str, Any]:
    """Build the complete readiness payload from ACTUAL running-process state.

    ``session`` and ``signer`` are the app's REAL injected dependencies. ``marker_path`` /
    ``probe_timeout`` / ``exchange`` are the same kind of verified test seams the sibling one-shots
    expose; nothing on the HTTP route can reach them. ``marker_path`` defaults to the ONE code-owned
    module constant, read HERE (never captured at import) so a test double may patch it while no
    production surface can select a path."""
    effective = classify_effective_signer(signer)
    marker = load_valid_marker(path=MARKER_PATH if marker_path is None else marker_path)
    identity = _observe_active_identity(session)
    uid, gid = _process_ids()

    # The probe is attempted ONLY when the app genuinely resolved the fixed-UDS client: a sealed API
    # must never report a reachable broker, and probing from a sealed app would be a fact about the
    # host, not about the effective signer.
    if effective.identifier == SIGNER_FIXED_UDS:
        probe = probe_broker_no_sign(timeout=probe_timeout, exchange=exchange)
    else:
        probe = BrokerProbeResult(PROBE_NOT_ATTEMPTED, False, "")

    no_alternate = bool(
        no_process_env_enablement()
        and not effective.selectable_socket
        and (
            effective.identifier != SIGNER_FIXED_UDS
            or effective.bound_socket_path == ENROLLMENT_SIGNER_SOCKET_PATH
        )
    )

    # The marker's binding is compared against the marker path's OWN parse only; whether it equals
    # the running install is the API dependency's decision, already reflected in ``effective``.
    binding_matches_runtime = bool(
        marker is not None
        and identity.present
        and marker.active_identity_row_id == identity.row_id
        and marker.activation_token == identity.activation_token
        and marker.installation_id == identity.installation_id
        and marker.release_digest == identity.release_digest
        and marker.controller_key_id == identity.controller_key_id
        and marker.uds_contract_identity == ENROLLMENT_SIGNER_SOCKET_PATH
        and marker.api_uid == uid
        and marker.api_gid == gid
    )

    ready = bool(
        effective.identifier == SIGNER_FIXED_UDS
        and no_alternate
        and marker is not None
        and binding_matches_runtime
        and identity.present
        and probe.status == PROBE_OK
        and probe.peer_authorized
        and probe.protocol == ENROLLMENT_SIGNER_BROKER_PROTOCOL
    )

    return {
        "schema": SIGNER_READINESS_SCHEMA,
        "status": STATUS_READY if ready else STATUS_SEALED,
        "effective_signer": effective.identifier,
        "signer_transport": effective.transport,
        "no_alternate_signer_activation": no_alternate,
        "process_uid": uid,
        "process_gid": gid,
        "marker_present": marker is not None,
        "marker_binding_matches_runtime": binding_matches_runtime,
        "marker_binding_digest": _marker_digest(marker),
        "active_identity_present": identity.present,
        "active_identity_binding_digest": _identity_digest(identity),
        "activation_generation": identity.generation,
        "broker_probe": probe.status,
        "broker_peer_authorized": probe.peer_authorized,
        "broker_protocol": probe.protocol,
    }


def render_signer_readiness(payload: dict[str, Any]) -> bytes:
    """Re-validate the payload against its OWN strict closed model and render the canonical bytes.

    A payload that fails its own schema or exceeds the bound is never served; the caller turns the
    :class:`ValueError` into a bounded closed refusal."""
    if set(payload) != set(SIGNER_READINESS_FIELDS):
        raise ValueError("signer_readiness_payload_invalid")
    try:
        SignerReadinessPayload.model_validate(payload)
    except ValidationError:
        raise ValueError("signer_readiness_payload_invalid") from None
    raw = canonical_json(payload).encode("utf-8")
    if len(raw) > SIGNER_READINESS_MAX_BYTES:
        raise ValueError("signer_readiness_payload_oversize")
    return raw


__all__ = [
    "ENROLLMENT_SIGNER_BROKER_PROTOCOL",
    "PROBE_ENDPOINT_UNSAFE",
    "PROBE_NOT_ATTEMPTED",
    "PROBE_NO_LISTENER",
    "PROBE_OK",
    "PROBE_OP",
    "PROBE_PEER_UNAUTHORIZED",
    "PROBE_PROTOCOL_MISMATCH",
    "PROBE_SOCKET_ABSENT",
    "PROBE_TIMEOUT",
    "PROBE_UNSUPPORTED",
    "SIGNER_FIXED_UDS",
    "SIGNER_READINESS_FIELDS",
    "SIGNER_READINESS_MAX_BYTES",
    "SIGNER_READINESS_PATH",
    "SIGNER_READINESS_PREFIX",
    "SIGNER_READINESS_SCHEMA",
    "SIGNER_SEALED",
    "SIGNER_UNAVAILABLE",
    "STATUS_READY",
    "STATUS_SEALED",
    "TRANSPORT_AF_UNIX",
    "TRANSPORT_NONE",
    "BrokerProbeResult",
    "EffectiveSigner",
    "SignerReadinessPayload",
    "classify_effective_signer",
    "no_process_env_enablement",
    "observe_signer_readiness",
    "probe_broker_no_sign",
    "render_signer_readiness",
]
