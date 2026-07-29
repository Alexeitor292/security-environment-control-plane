"""Authoritative production runtime observer for the controller-enrollment finalization seam.

The corrected finalization adapter (:mod:`secp_management.controller_finalization`) writes the
signer-enablement marker LAST and then requires an authoritative post-restart proof that the
ordinary (non-root) API is genuinely running with exactly the candidate marker. That proof is its
injected ``runtime_observer`` seam. This module builds the REAL observer the root-only install
composition wires in (see ``production.build_real_finalization_factory``); with NO observer the
adapter fails closed on the deliberately-narrow host-only default.

SECP-PR5H-B2 2b-3c-c, clean-room review 4803080223 finding **R4** — the previous observation
OVERCLAIMED and is corrected here:

* ``effective_signer_is_fixed_uds`` was derived from MARKER FIELDS — the installer's own INTENT. A
  marker is a file; it proves nothing about which object the API actually resolved. It is now true
  ONLY when the RUNNING API reports the fixed-UDS client as its EFFECTIVE dependency;
* ``broker_reachable`` proved a socket inode plus unit bytes and NEVER connected. It is now true
  only after the RUNNING API process itself completes a bounded NO-SIGN probe against the fixed
  AF_UNIX socket (peer authorized + reviewed protocol identity), on top of the unchanged structural
  proof that the byte-exact code-rendered broker unit declares no TCP listener;
* the inspected API image was parsed and then UNUSED. It is now compared against the expected
  SIGNED image;
* ``no_mixed_generation`` was "one container + one marker". It now requires AGREEMENT among the
  inspected API image, the expected signed release, the controller stack observation, the ACTIVE
  identity, the marker, and the readiness response.

Every fact is therefore bound to INDEPENDENTLY DERIVED EXPECTATIONS
(:class:`ApiSignerRuntimeExpectations`) supplied by the caller from already-authenticated artefacts
— never to the observation's own inputs. With NO expectations the observer proves NOTHING and
returns a fully fail-closed observation.

Sources, and only these:

* the ordinary API container resolved THROUGH the compose project labels via the pinned container
  runtime, inspected TWICE with a fixed Go-template ``docker inspect`` (running state, exact
  non-root ``uid:gid``, health, image digest, the read-only marker mount, no secret-bearing host
  path, no handoff, no independent signing enablement), with the two samples required to agree;
* host-side posture through the hardened filesystem seam (handoffs absent, enrollment key + signer
  credential not API/world-readable, the broker socket is EXACTLY an AF_UNIX socket, the broker unit
  bytes equal the reviewed rendering);
* the API's OWN fixed readiness surface, fetched over the bootstrap-recorded controller origin with
  the installed CA PINNED, at a fixed path, with a bounded deadline and a bounded response, and
  projected through a STRICT closed schema (extra/missing/mistyped fields refuse).

The management plane NEVER imports ``secp_api``: the readiness contract is consumed as bytes over
the reviewed HTTPS boundary and re-declared here as management-owned literals. Every parse
ambiguity, missing field, mismatch, transport fault, or runner fault sets the RELEVANT bool to
False; the observer NEVER raises and NEVER defaults a bool True without a genuine proof.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from secp_commissioning.controller_enrollment_signer import CONTROLLER_ENROLLMENT_KEY_PATH
from secp_commissioning.enrollment_signer_marker import (
    EnrollmentSignerMarker,
    marker_binding_matches,
    parse_marker_bytes_or_none,
)
from secp_commissioning.runtime import FileStat

from secp_management import ManagementError
from secp_management.controller_api_locator import (
    ControllerApiLocatorProvider,
    FileControllerApiLocatorProvider,
)
from secp_management.controller_compose_contract import (
    api_marker_mount,
    assert_no_secret_reaches_ordinary_api,
    render_broker_reviewed_unit,
)
from secp_management.controller_finalization import ApiSignerRuntimeObservation
from secp_management.finalization import ApiSignerMarker
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import RealAdapterContext
from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID

# --------------------------------------------------------------------------- constants

_ROOT_UID = 0
_ROOT_GID = 0
_MARKER_MODE = 0o644
_MAX_READ = 512 * 1024
# Bounded readiness poll: the finalizer observes immediately after force-recreating the API, so
# a freshly recreated container reports health 'starting' until its first healthcheck passes.
# Fixed attempts x fixed interval (never an unbounded wait); exhausting it fails closed.
_READINESS_ATTEMPTS = 20
_READINESS_INTERVAL_SECONDS = 3.0
_HEALTH_STARTING = "starting"
_INSPECT_TIMEOUT = 20

_EXPECTED_API_USER = f"{API_RUNTIME_UID}:{API_RUNTIME_GID}"

_FULL_CID = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_TRUTHY = frozenset({"1", "true", "yes", "on", "t", "y"})

_COMPOSE_API_SERVICE = "api"
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_COMPOSE_SERVICE_LABEL = "com.docker.compose.service"

# --- the API readiness contract, re-declared as MANAGEMENT-OWNED literals -------------------------
#
# The management plane may not import ``secp_api``; these five literals are the wire contract it
# pins (the API side owns the same values in ``secp_api.signer_readiness``). A response carrying any
# other schema literal, or a probe/signer token outside these vocabularies, refuses.

#: The FIXED readiness path. Management appends nothing and selects nothing.
API_READINESS_PATH = "/internal/enrollment-signer/readiness"
#: The ONE accepted readiness schema/version literal.
API_READINESS_SCHEMA = "secp.api.enrollment-signer-readiness/v1"
#: The reviewed broker wire-protocol identity the API's no-sign probe must have proven.
ENROLLMENT_SIGNER_BROKER_PROTOCOL = "secp.enrollment-signer-broker/v1"
#: The only effective-signer identifier that means "the reviewed fixed-UDS broker client".
API_SIGNER_FIXED_UDS = "fixed_uds"
API_SIGNER_TRANSPORT_AF_UNIX = "af_unix"
#: The only broker-probe outcome that means "the RUNNING API completed the no-sign exchange".
API_BROKER_PROBE_OK = "ok"
API_READINESS_STATUS_READY = "ready"

_READINESS_TIMEOUT_SECONDS = 10.0
_READINESS_MAX_RESPONSE_BYTES = 16384
_READINESS_MAX_FIELD_LEN = 256
_MAX_POSIX_ID = 2**31 - 1
_UNPROVEN_GENERATION = -1

#: The CLOSED readiness field set. A response with an extra or a missing key refuses outright.
_READINESS_STR_FIELDS: tuple[str, ...] = (
    "schema",
    "status",
    "effective_signer",
    "signer_transport",
    "marker_installation_id",
    "marker_release_digest",
    "marker_active_identity_row_id",
    "marker_activation_token",
    "marker_controller_key_id",
    "marker_uds_contract_identity",
    "marker_signer_role_name",
    "marker_locator_ca_digest",
    "marker_management_identity_digest",
    "marker_bootstrap_evidence_digest",
    "active_identity_row_id",
    "active_identity_activation_token",
    "active_identity_installation_id",
    "active_identity_release_digest",
    "active_identity_controller_key_id",
    "broker_probe",
    "broker_protocol",
)
_READINESS_BOOL_FIELDS: tuple[str, ...] = (
    "no_alternate_signer_activation",
    "marker_present",
    "marker_binding_matches_runtime",
    "active_identity_present",
    "broker_peer_authorized",
)
_READINESS_INT_FIELDS: tuple[str, ...] = (
    "process_uid",
    "process_gid",
    "marker_api_uid",
    "marker_api_gid",
    "activation_generation",
)
READINESS_FIELDS: tuple[str, ...] = (
    _READINESS_STR_FIELDS + _READINESS_BOOL_FIELDS + _READINESS_INT_FIELDS
)

# The twelve non-secret binding fields the marker file must carry verbatim from the candidate.
_MARKER_BINDING_FIELDS: tuple[str, ...] = (
    "installation_id",
    "release_digest",
    "active_identity_row_id",
    "activation_token",
    "controller_key_id",
    "uds_contract_identity",
    "api_uid",
    "api_gid",
    "signer_role_name",
    "locator_ca_digest",
    "management_identity_digest",
    "bootstrap_evidence_digest",
)


# --------------------------------------------------------------------------- expectations


@dataclass(frozen=True)
class ApiSignerRuntimeExpectations:
    """The INDEPENDENTLY DERIVED, closed, NONSECRET expectation the observation is bound to.

    Every field comes from an already-authenticated artefact the caller holds BEFORE the
    observation — the signed release manifest, the verified finalization evidence, the authenticated
    plan, and the reviewed code-owned contracts — never from the marker being validated, the
    container runtime, or the API. An observation is only ever compared against this; it is never
    allowed to describe its own expectation.

    ``marker`` is the candidate the caller independently derived: the marker the finalizer passes to
    the closure must equal it on the complete binding, so a swapped/stale candidate refuses.
    """

    api_image_digest: str  # the expected SIGNED api image ("sha256:<64 hex>")
    release_digest: str
    installation_id: str
    finalization_generation: int
    active_identity_row_id: str
    active_identity_activation_token: str
    marker: ApiSignerMarker
    broker_unit_path: str
    broker_socket_path: str
    controller_stack_generation: int


# --------------------------------------------------------------------------- readiness projection


@dataclass(frozen=True)
class ApiSignerReadiness:
    """The strictly projected readiness response.

    ``reachable`` is True only when an HTTP 200 body was genuinely obtained (a transport/TLS fault
    or a non-200 leaves it False, which is the ONLY condition the settling poll retries).
    ``valid`` additionally requires the exact closed schema — a body that WAS obtained but does not
    conform is DEFINITIVE and never retried."""

    reachable: bool
    valid: bool
    schema: str = ""
    status: str = ""
    effective_signer: str = ""
    signer_transport: str = ""
    marker_installation_id: str = ""
    marker_release_digest: str = ""
    marker_active_identity_row_id: str = ""
    marker_activation_token: str = ""
    marker_controller_key_id: str = ""
    marker_uds_contract_identity: str = ""
    marker_signer_role_name: str = ""
    marker_locator_ca_digest: str = ""
    marker_management_identity_digest: str = ""
    marker_bootstrap_evidence_digest: str = ""
    active_identity_row_id: str = ""
    active_identity_activation_token: str = ""
    active_identity_installation_id: str = ""
    active_identity_release_digest: str = ""
    active_identity_controller_key_id: str = ""
    broker_probe: str = ""
    broker_protocol: str = ""
    no_alternate_signer_activation: bool = False
    marker_present: bool = False
    marker_binding_matches_runtime: bool = False
    active_identity_present: bool = False
    broker_peer_authorized: bool = False
    process_uid: int = -1
    process_gid: int = -1
    marker_api_uid: int = 0
    marker_api_gid: int = 0
    activation_generation: int = _UNPROVEN_GENERATION


#: no response was obtainable (connect / TLS / timeout / non-200) — the SETTLING condition.
READINESS_UNREACHABLE = ApiSignerReadiness(reachable=False, valid=False)
#: a body WAS obtained but is not the versioned contract — definitive, never retried.
READINESS_MALFORMED = ApiSignerReadiness(reachable=True, valid=False)


def _typed_readiness(body: object) -> ApiSignerReadiness:
    """Project a decoded readiness body through the STRICT closed contract, or refuse it.

    Requires exactly the closed field set (no extra, no missing key), exact types (a bool is never
    an int), bounded strings, bounded ids, and the pinned schema literal."""
    if not isinstance(body, dict) or set(body) != set(READINESS_FIELDS):
        return READINESS_MALFORMED
    for name in _READINESS_STR_FIELDS:
        value = body[name]
        if not isinstance(value, str) or len(value) > _READINESS_MAX_FIELD_LEN:
            return READINESS_MALFORMED
    for name in _READINESS_BOOL_FIELDS:
        if type(body[name]) is not bool:  # noqa: E721 - bool is an int subclass; exactness matters
            return READINESS_MALFORMED
    for name in _READINESS_INT_FIELDS:
        value = body[name]
        if type(value) is not int or not (-1 <= value <= _MAX_POSIX_ID):  # noqa: E721
            return READINESS_MALFORMED
    if body["schema"] != API_READINESS_SCHEMA:
        return READINESS_MALFORMED  # no version negotiation, ever
    return ApiSignerReadiness(
        reachable=True, valid=True, **{name: body[name] for name in READINESS_FIELDS}
    )


def parse_readiness_response(status: int, raw: bytes) -> ApiSignerReadiness:
    """Interpret one readiness HTTP response. Never raises; never surfaces the body."""
    if status != 200 or not isinstance(raw, bytes):
        return READINESS_UNREACHABLE
    if not (1 <= len(raw) <= _READINESS_MAX_RESPONSE_BYTES):
        return READINESS_UNREACHABLE if len(raw) == 0 else READINESS_MALFORMED
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - a malformed body is DEFINITIVE, never a settling state
        return READINESS_MALFORMED
    return _typed_readiness(body)


def _read_readiness(transport: Callable[[], tuple[int, bytes]]) -> ApiSignerReadiness:
    try:
        status, raw = transport()
    except Exception:  # noqa: BLE001 - connect / TLS / CA / timeout -> no response obtained
        return READINESS_UNREACHABLE
    return parse_readiness_response(status, raw)


def build_readiness_transport(
    ctx: RealAdapterContext,
    *,
    locator_provider: ControllerApiLocatorProvider | None = None,
    timeout: float = _READINESS_TIMEOUT_SECONDS,
) -> Callable[[], tuple[int, bytes]]:
    """The hardened readiness transport: ONE bounded GET on the FIXED path against the
    bootstrap-recorded controller origin with the installed CA PINNED.

    Mirrors the reviewed ``HttpsEnrollmentControllerClient`` posture exactly: HTTPS only; ``verify``
    is an ``ssl.SSLContext`` built from the locator's reviewed CA bundle (never ``True``/``False``/
    system trust); ``trust_env=False`` (no ambient proxy / ``SSL_CERT_*``); ``follow_redirects=
    False``; no cookie; no credential; strict ``Accept-Encoding: identity``; bounded deadline and
    bounded response. The origin and the CA path come ONLY from the protected root-owned locator —
    there is no ``--url``/``--ca``/env/HTTP input anywhere on this path."""
    provider = (
        locator_provider
        if locator_provider is not None
        else FileControllerApiLocatorProvider(ctx.fs)
    )

    def _fetch() -> tuple[int, bytes]:
        locator = provider.locate()  # bootstrap-recorded origin + reviewed CA (validated)
        import ssl

        import httpx

        ssl_context = ssl.create_default_context(cafile=locator.ca_bundle_path)
        with httpx.Client(
            verify=ssl_context,  # pinned CA; never system trust / True / False
            trust_env=False,  # no ambient proxy / SSL_CERT_* / env
            follow_redirects=False,  # a redirect is never valid on this surface
            timeout=timeout,
        ) as client:
            response = client.get(
                locator.canonical_origin + API_READINESS_PATH,
                headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            )
            if response.is_redirect:
                raise ManagementError("api_signer_readiness_response_invalid")
            encodings = response.headers.get_list("content-encoding")
            if any(value.strip().lower() != "identity" for value in encodings):
                raise ManagementError("api_signer_readiness_response_invalid")
            content = response.content
            if len(content) > _READINESS_MAX_RESPONSE_BYTES:
                raise ManagementError("api_signer_readiness_response_invalid")
            return response.status_code, content

    return _fetch


# --------------------------------------------------------------------------- parsed inspect facts


@dataclass(frozen=True)
class _Mount:
    """One parsed bind mount: the host source, the container destination, and whether it is
    read-only (docker reports ``.RW`` — read-only iff ``RW`` is false)."""

    source: str
    destination: str
    read_only: bool


@dataclass(frozen=True)
class _ApiInspect:
    """The parsed ``docker inspect`` facts for the single API container. Frozen so two independent
    samples can be compared by value for generation stability. ``well_formed`` is False on any
    malformed line / id / image so a garbled inspect can never read as a genuine sealed API."""

    container_id: str
    running: bool
    user: str
    image: str
    health: str
    mounts: tuple[_Mount, ...]
    env: tuple[str, ...]
    well_formed: bool


# The fixed Go-template: one ``HEAD`` line (scalars), one ``MOUNT`` line per bind mount, and one
# ``ENV`` line per environment variable. Every separator is a code constant; nothing is caller-fed.
_API_INSPECT_TEMPLATE = (
    "HEAD|{{.Id}}|{{.State.Running}}|{{.Config.User}}|{{.Image}}|"
    "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\n"
    "{{range .Mounts}}MOUNT|{{.Source}}|{{.Destination}}|{{.RW}}\n{{end}}"
    "{{range .Config.Env}}ENV|{{.}}\n{{end}}"
)


# --------------------------------------------------------------------------- fs posture helpers


def _lstat(ctx: RealAdapterContext, path: str) -> FileStat | None:
    try:
        return ctx.fs.lstat(path)
    except Exception:  # noqa: BLE001 - any fs fault is a fail-closed absence
        return None


def _absent(ctx: RealAdapterContext, path: str) -> bool:
    return _lstat(ctx, path) is None


def _read(ctx: RealAdapterContext, path: str) -> bytes | None:
    try:
        return ctx.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=_ROOT_UID)
    except Exception:  # noqa: BLE001 - unreadable / unsafe / absent -> no bytes (fail closed)
        return None


def _marker_posture_ok(ctx: RealAdapterContext, path: str) -> bool:
    st = _lstat(ctx, path)
    return bool(
        st is not None
        and st.is_regular
        and not st.is_symlink
        and st.uid == _ROOT_UID
        and st.gid == _ROOT_GID
        and st.mode == _MARKER_MODE
        and st.nlink == 1
    )


def _not_reachable_by_api(ctx: RealAdapterContext, path: str, mask: int) -> bool:
    """A secret file must be ABSENT or have every ``mask`` bit clear (so the non-root API cannot
    read it) — mirrors the adapter's fail-closed default. A probe fault fails closed to reachable
    (False)."""
    try:
        st = ctx.fs.lstat(path)
    except Exception:  # noqa: BLE001 - a probe fault cannot prove unreachability -> fail closed
        return False
    return st is None or (st.mode & mask) == 0


def _broker_structure_ok(
    ctx: RealAdapterContext, loc: ManagementLocations, expected: ApiSignerRuntimeExpectations
) -> bool:
    """The STRUCTURAL half of the broker proof, bound to the EXPECTED unit + socket contract.

    The socket object must be EXACTLY an AF_UNIX socket (never a regular/other node), and the
    installed unit bytes must equal the byte-exact code-rendered reviewed unit — which is what
    proves the broker declares NO TCP listener. Structure alone is NOT reachability: the live
    no-sign proof comes from the running API (see :func:`_observe`)."""
    if expected.broker_socket_path != loc.broker_socket_path():
        return False  # the expectation must name the reviewed code-owned socket contract
    if expected.broker_unit_path != loc.broker_unit_path():
        return False
    st = _lstat(ctx, expected.broker_socket_path)
    if st is None or not st.is_socket:
        return False
    unit_bytes = _read(ctx, expected.broker_unit_path)
    return unit_bytes is not None and unit_bytes == render_broker_reviewed_unit(loc).content


# --------------------------------------------------------------------------- marker binding


def _load_marker(data: bytes | None) -> EnrollmentSignerMarker | None:
    """Parse the on-disk marker through the ONE plane-neutral STRICT contract (R7): canonical bytes,
    duplicate-key rejection, extra/missing-field rejection, exact types + grammar, fixed role + UDS
    contract. Management therefore accepts and rejects EXACTLY the bytes the API accepts."""
    if data is None:
        return None
    return parse_marker_bytes_or_none(data)


def _binding_ok(parsed: EnrollmentSignerMarker | None, marker: ApiSignerMarker) -> bool:
    """The complete 12-field binding must equal the candidate (no subset)."""
    if parsed is None:
        return False
    return marker_binding_matches(parsed, marker)


def _candidate_agrees_with_expected(marker: ApiSignerMarker, expected: ApiSignerMarker) -> bool:
    """The candidate marker the finalizer passes must equal the INDEPENDENTLY DERIVED expectation on
    the complete binding AND on the fixed marker path — a swapped or stale candidate refuses."""
    if marker.marker_path != expected.marker_path:
        return False
    return all(
        getattr(marker, field) == getattr(expected, field) for field in _MARKER_BINDING_FIELDS
    )


# --------------------------------------------------------------------------- container runtime


def _list_api_containers(ctx: RealAdapterContext) -> tuple[str, ...]:
    """Resolve the API container id(s) THROUGH the compose project labels via the pinned container
    runtime. ``--all`` enumerates stopped containers too, so a leftover prior-generation container
    surfaces as a second id. A malformed listing or runner fault fails closed (empty)."""
    argv = (
        "ps",
        "--all",
        "--no-trunc",
        "--filter",
        f"label={_COMPOSE_PROJECT_LABEL}={ctx.controller_project}",
        "--filter",
        f"label={_COMPOSE_SERVICE_LABEL}={_COMPOSE_API_SERVICE}",
        "--format",
        "{{.ID}}",
    )
    try:
        out = ctx.run(
            ctx.executables.container_runtime,
            argv,
            timeout=_INSPECT_TIMEOUT,
            reason="api_container_list_failed",
        )
    except ManagementError:
        return ()
    ids: list[str] = []
    for line in out.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if _FULL_CID.fullmatch(candidate) is None:
            return ()  # a non-id token -> malformed listing -> fail closed
        ids.append(candidate)
    return tuple(ids)


def _inspect_api(ctx: RealAdapterContext, container_id: str) -> _ApiInspect | None:
    argv = ("inspect", "--format", _API_INSPECT_TEMPLATE, container_id)
    try:
        out = ctx.run(
            ctx.executables.container_runtime,
            argv,
            timeout=_INSPECT_TIMEOUT,
            reason="api_inspect_failed",
        )
    except ManagementError:
        return None
    return _parse_inspect(out)


def _parse_inspect(out: str) -> _ApiInspect | None:
    lines = out.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    head: tuple[str, str, str, str, str] | None = None
    head_count = 0
    mounts: list[_Mount] = []
    env: list[str] = []
    clean = True
    for line in lines:
        if line.startswith("HEAD|"):
            head_count += 1
            parts = line.split("|")
            if len(parts) != 6:
                clean = False
                continue
            head = (parts[1], parts[2], parts[3], parts[4], parts[5])
        elif line.startswith("MOUNT|"):
            parts = line.split("|")
            if len(parts) != 4 or parts[3] not in ("true", "false"):
                clean = False
                continue
            mounts.append(
                _Mount(source=parts[1], destination=parts[2], read_only=parts[3] == "false")
            )
        elif line.startswith("ENV|"):
            env.append(line.partition("|")[2])
        else:
            clean = False  # an unexpected line -> the whole inspect is ambiguous
    if head_count != 1 or head is None:
        return None
    cid, running, user, image, health = head
    well_formed = bool(
        clean
        and _FULL_CID.fullmatch(cid)
        and _IMAGE_ID.fullmatch(image)
        and running in ("true", "false")
    )
    return _ApiInspect(
        container_id=cid,
        running=running == "true",
        user=user,
        image=image,
        health=health,
        mounts=tuple(mounts),
        env=tuple(env),
        well_formed=well_formed,
    )


def _no_secret_reaches(sources: tuple[str, ...], loc: ManagementLocations) -> bool:
    try:
        assert_no_secret_reaches_ordinary_api(sources, locations=loc)
    except ManagementError:
        return False
    return True


def _is_enablement(env_entry: str) -> bool:
    """True iff an environment variable would INDEPENDENTLY enable signing (the marker is the sole
    positive authority, so any such truthy variable is a defect)."""
    key, sep, value = env_entry.partition("=")
    name = key.strip().upper()
    val = (value if sep == "=" else "").strip().lower()
    suspicious = name == "SECP_ENROLLMENT_SIGNER_ENABLED" or (
        "ENROLLMENT" in name and "SIGNER" in name and "ENABL" in name
    )
    return suspicious and val in _TRUTHY


# --------------------------------------------------------------------------- observation


def _fail_closed() -> ApiSignerRuntimeObservation:
    return ApiSignerRuntimeObservation(
        api_present=False,
        api_non_root=False,
        api_healthy=False,
        marker_mounted_readonly=False,
        handoffs_absent=False,
        enrollment_key_not_mounted=False,
        signer_credential_not_mounted=False,
        effective_signer_is_fixed_uds=False,
        binding_equals_marker=False,
        no_env_enablement=False,
        broker_reachable=False,
        no_mixed_generation=False,
    )


def _readiness_effective_signer_ok(
    readiness: ApiSignerReadiness, expected: ApiSignerRuntimeExpectations
) -> bool:
    """The RUNNING API must report the reviewed fixed-UDS client as its EFFECTIVE dependency, over
    an AF_UNIX transport, with no alternate activation, bound to the expected UDS contract."""
    return bool(
        readiness.valid
        and readiness.effective_signer == API_SIGNER_FIXED_UDS
        and readiness.signer_transport == API_SIGNER_TRANSPORT_AF_UNIX
        and readiness.no_alternate_signer_activation
        and readiness.marker_uds_contract_identity == expected.broker_socket_path
    )


def _readiness_broker_ok(readiness: ApiSignerReadiness) -> bool:
    """The RUNNING API must have COMPLETED the bounded no-sign probe: the broker authorized its
    peer credentials and answered with the reviewed protocol identity."""
    return bool(
        readiness.valid
        and readiness.broker_probe == API_BROKER_PROBE_OK
        and readiness.broker_peer_authorized
        and readiness.broker_protocol == ENROLLMENT_SIGNER_BROKER_PROTOCOL
    )


def _readiness_binds_marker(readiness: ApiSignerReadiness, marker: ApiSignerMarker) -> bool:
    """The marker the RUNNING API actually loaded must be the candidate, and its bound API peer must
    be the process the API is actually running as."""
    return bool(
        readiness.valid
        and readiness.marker_present
        and readiness.marker_binding_matches_runtime
        and readiness.marker_installation_id == marker.installation_id
        and readiness.marker_release_digest == marker.release_digest
        and readiness.marker_active_identity_row_id == marker.active_identity_row_id
        and readiness.marker_activation_token == marker.activation_token
        and readiness.marker_controller_key_id == marker.controller_key_id
        and readiness.marker_uds_contract_identity == marker.uds_contract_identity
        and readiness.marker_signer_role_name == marker.signer_role_name
        and readiness.marker_locator_ca_digest == marker.locator_ca_digest
        and readiness.marker_management_identity_digest == marker.management_identity_digest
        and readiness.marker_bootstrap_evidence_digest == marker.bootstrap_evidence_digest
        and readiness.marker_api_uid == marker.api_uid
        and readiness.marker_api_gid == marker.api_gid
        and readiness.process_uid == marker.api_uid
        and readiness.process_gid == marker.api_gid
    )


def _one_generation(
    *,
    sample: _ApiInspect | None,
    marker: ApiSignerMarker,
    parsed: EnrollmentSignerMarker | None,
    readiness: ApiSignerReadiness,
    expected: ApiSignerRuntimeExpectations,
) -> bool:
    """Exactly ONE live generation, proven by AGREEMENT across six independent observations: the
    INSPECTED API image, the expected SIGNED release, the controller stack observation, the ACTIVE
    identity the API reports, the marker on disk, and the readiness response."""
    if sample is None or parsed is None or not readiness.valid:
        return False
    if not _IMAGE_ID.fullmatch(expected.api_image_digest or ""):
        return False  # an unproven expected image can never authorize an inspected one
    if sample.image != expected.api_image_digest:  # R4: the inspected image is now COMPARED
        return False
    if expected.finalization_generation < 0:
        return False
    if expected.controller_stack_generation != expected.finalization_generation:
        return False
    if readiness.activation_generation != expected.finalization_generation:
        return False
    release_ok = (
        marker.release_digest
        == parsed.release_digest
        == readiness.marker_release_digest
        == readiness.active_identity_release_digest
        == expected.release_digest
    )
    installation_ok = (
        marker.installation_id
        == parsed.installation_id
        == readiness.marker_installation_id
        == readiness.active_identity_installation_id
        == expected.installation_id
    )
    identity_ok = bool(
        readiness.active_identity_present
        and readiness.active_identity_row_id
        == marker.active_identity_row_id
        == expected.active_identity_row_id
        and readiness.active_identity_activation_token
        == marker.activation_token
        == expected.active_identity_activation_token
        and readiness.active_identity_controller_key_id == marker.controller_key_id
    )
    return bool(release_ok and installation_ok and identity_ok)


def _observe(
    ctx: RealAdapterContext,
    marker: ApiSignerMarker,
    expected: ApiSignerRuntimeExpectations,
    readiness: ApiSignerReadiness,
    probe: dict[str, str] | None = None,
) -> ApiSignerRuntimeObservation:
    loc = ctx.locations
    marker_mount = api_marker_mount(loc)
    marker_path = marker_mount.host_path

    # ---- the candidate must equal the INDEPENDENTLY DERIVED expectation ----
    candidate_ok = _candidate_agrees_with_expected(marker, expected.marker)

    # ---- fs-only marker posture + binding (independent of the container runtime) ----
    posture_ok = _marker_posture_ok(ctx, marker_path)
    marker_bytes = _read(ctx, marker_path) if posture_ok else None
    marker_present = marker_bytes is not None
    marker_obj = _load_marker(marker_bytes)
    binding_equals_marker = bool(
        candidate_ok
        and _binding_ok(marker_obj, marker)
        and _binding_ok(marker_obj, expected.marker)
        and _readiness_binds_marker(readiness, marker)
    )

    # ---- R4: the EFFECTIVE signer is the RUNNING API's real dependency, never the marker ----
    effective_signer_is_fixed_uds = bool(
        candidate_ok
        and marker.uds_contract_identity == expected.broker_socket_path
        and marker_obj is not None
        and marker_obj.uds_contract_identity == expected.broker_socket_path
        and _readiness_effective_signer_ok(readiness, expected)
    )

    # ---- fs-only broker + secret posture (mirrors the adapter's fail-closed default) ----
    handoff_hosts_absent = _absent(ctx, loc.provisioning_handoff_host_path()) and _absent(
        ctx, loc.activation_handoff_host_path()
    )
    key_not_readable = _not_reachable_by_api(ctx, CONTROLLER_ENROLLMENT_KEY_PATH, 0o007)
    cred_not_readable = _not_reachable_by_api(ctx, loc.enrollment_signer_credential_path(), 0o077)

    # ---- R4: reachability is the RUNNING API's completed no-sign probe, on top of the byte-exact
    #      reviewed unit (which is what proves there is no TCP listener) ----
    broker_reachable = bool(
        _broker_structure_ok(ctx, loc, expected) and _readiness_broker_ok(readiness)
    )

    # ---- container-runtime resolution + double inspect (generation stability) ----
    api_ids = _list_api_containers(ctx)
    single = len(api_ids) == 1
    s1 = _inspect_api(ctx, api_ids[0]) if single else None
    s2 = _inspect_api(ctx, api_ids[0]) if single else None
    sample = s1 if (s1 is not None and s2 is not None and s1 == s2 and s1.well_formed) else None

    api_present = bool(sample is not None and sample.running and sample.container_id == api_ids[0])
    api_non_root = bool(sample is not None and sample.user == _EXPECTED_API_USER)
    api_healthy = bool(sample is not None and sample.health == "healthy")
    if probe is not None:  # report the raw health so the caller can tell SETTLING from failed
        probe["health"] = sample.health if sample is not None else ""

    sources = tuple(m.source for m in sample.mounts) if sample is not None else ()
    dests = tuple(m.destination for m in sample.mounts) if sample is not None else ()
    no_secret_mount = sample is not None and _no_secret_reaches(sources, loc)

    marker_mounted_readonly = bool(
        sample is not None
        and marker_present
        and posture_ok
        and any(
            m.source == marker_mount.host_path
            and m.destination == marker_mount.container_path
            and m.read_only
            for m in sample.mounts
        )
    )

    prov_host = loc.provisioning_handoff_host_path()
    act_host = loc.activation_handoff_host_path()
    prov_container = loc.provisioning_handoff_container_path()
    act_container = loc.activation_handoff_container_path()
    no_handoff_mount = sample is not None and not (
        any(src in (prov_host, act_host) for src in sources)
        or any(dst in (prov_container, act_container) for dst in dests)
    )
    handoffs_absent = bool(handoff_hosts_absent and no_handoff_mount)

    enrollment_key_not_mounted = bool(
        key_not_readable and no_secret_mount and CONTROLLER_ENROLLMENT_KEY_PATH not in sources
    )
    signer_credential_not_mounted = bool(
        cred_not_readable
        and no_secret_mount
        and loc.enrollment_signer_credential_path() not in sources
    )

    no_env_enablement = bool(
        sample is not None and not any(_is_enablement(entry) for entry in sample.env)
    )

    # ---- R4: exactly one live generation, proven by six-way agreement ----
    no_mixed_generation = bool(
        single
        and marker_present
        and candidate_ok
        and _one_generation(
            sample=sample,
            marker=marker,
            parsed=marker_obj,
            readiness=readiness,
            expected=expected,
        )
    )

    return ApiSignerRuntimeObservation(
        api_present=api_present,
        api_non_root=api_non_root,
        api_healthy=api_healthy,
        marker_mounted_readonly=marker_mounted_readonly,
        handoffs_absent=handoffs_absent,
        enrollment_key_not_mounted=enrollment_key_not_mounted,
        signer_credential_not_mounted=signer_credential_not_mounted,
        effective_signer_is_fixed_uds=effective_signer_is_fixed_uds,
        binding_equals_marker=binding_equals_marker,
        no_env_enablement=no_env_enablement,
        broker_reachable=broker_reachable,
        no_mixed_generation=no_mixed_generation,
    )


#: the invariants that can only be proven from the API's readiness response. While the container is
#: genuinely SETTLING its readiness surface is not up yet, so these — and only these — may still be
#: pending during the bounded poll.
_READINESS_DEPENDENT: tuple[str, ...] = (
    "effective_signer_is_fixed_uds",
    "binding_equals_marker",
    "broker_reachable",
    "no_mixed_generation",
)
_HOST_ONLY: tuple[str, ...] = (
    "api_present",
    "api_non_root",
    "marker_mounted_readonly",
    "handoffs_absent",
    "enrollment_key_not_mounted",
    "signer_credential_not_mounted",
    "no_env_enablement",
)


def _only_health_pending(
    obs: ApiSignerRuntimeObservation, health: str, *, readiness_unreachable: bool
) -> bool:
    """True when the container is present, non-root, correctly mounted/sealed and merely still
    SETTLING after the restart. This is the only condition the readiness poll retries; every other
    defect fails closed immediately.

    While health is ``starting`` the API's readiness surface may not be serving yet, so the four
    readiness-dependent invariants may still be pending — but ONLY when NO response was obtainable.
    A response that WAS obtained and disagreed is definitive and is never retried."""
    if health != _HEALTH_STARTING:
        return False  # 'unhealthy'/'none'/unknown is DEFINITIVE, never a settling state
    if obs.api_healthy:
        return False
    if not all(getattr(obs, field) for field in _HOST_ONLY):
        return False
    if readiness_unreachable:
        return True
    return all(getattr(obs, field) for field in _READINESS_DEPENDENT)


def build_api_signer_runtime_observer(
    ctx: RealAdapterContext,
    *,
    expected: ApiSignerRuntimeExpectations | None = None,
    readiness_transport: Callable[[], tuple[int, bytes]] | None = None,
    readiness_timeout: float = _READINESS_TIMEOUT_SECONDS,
    readiness_attempts: int = _READINESS_ATTEMPTS,
    readiness_interval_seconds: float = _READINESS_INTERVAL_SECONDS,
) -> Callable[[ApiSignerMarker], ApiSignerRuntimeObservation]:
    """Build the AUTHORITATIVE runtime observer the finalization ``runtime_observer`` seam calls.

    Returns a closure ``observe(marker) -> ApiSignerRuntimeObservation`` that proves the ordinary
    API is genuinely running with the candidate marker — every fact bound to the INDEPENDENTLY
    DERIVED ``expected``. With ``expected=None`` the observer can prove nothing and returns a fully
    fail-closed observation on every call: an observer without an independent expectation must never
    authorize anything. The closure NEVER raises; any fault falls back to the same fail-closed
    observation.

    ``readiness_transport`` is the verified seam for the API readiness fetch; production defaults to
    :func:`build_readiness_transport` (bootstrap-recorded origin, PINNED installed CA, fixed path,
    bounded deadline + response).

    The finalizer observes IMMEDIATELY after force-recreating the API container, which reports its
    health as ``starting`` until its healthcheck first passes — so a single instantaneous sample
    would fail every real install closed. The closure therefore performs a BOUNDED readiness poll
    (fixed attempts x fixed interval, no unbounded wait) and retries ONLY while health is
    ``starting``; any other defect returns immediately, and exhausting the bound returns the last
    fail-closed observation."""
    transport = (
        readiness_transport
        if readiness_transport is not None
        else build_readiness_transport(ctx, timeout=readiness_timeout)
    )

    def observe(marker: ApiSignerMarker) -> ApiSignerRuntimeObservation:
        if expected is None:  # no independent expectation -> nothing is provable
            return _fail_closed()
        probe: dict[str, str] = {}
        state: dict[str, bool] = {"readiness_unreachable": True}

        def _sample() -> ApiSignerRuntimeObservation:
            probe.clear()
            try:
                readiness = _read_readiness(transport)
                state["readiness_unreachable"] = not readiness.reachable
                return _observe(ctx, marker, expected, readiness, probe)
            except Exception:  # noqa: BLE001 - the observer must never raise into the finalizer
                state["readiness_unreachable"] = (
                    False  # an internal fault is never a settling state
                )
                return _fail_closed()

        obs = _sample()
        attempts = 1
        while (
            not obs.ok
            and attempts < max(1, readiness_attempts)
            # retry ONLY while the container is genuinely still settling (health 'starting') and
            # every other invariant already holds; any other defect fails closed immediately.
            and _only_health_pending(
                obs,
                probe.get("health", ""),
                readiness_unreachable=state["readiness_unreachable"],
            )
        ):
            time.sleep(max(0.0, readiness_interval_seconds))
            obs = _sample()
            attempts += 1
        return obs

    return observe


__all__ = [
    "API_BROKER_PROBE_OK",
    "API_READINESS_PATH",
    "API_READINESS_SCHEMA",
    "API_READINESS_STATUS_READY",
    "API_SIGNER_FIXED_UDS",
    "API_SIGNER_TRANSPORT_AF_UNIX",
    "ENROLLMENT_SIGNER_BROKER_PROTOCOL",
    "READINESS_FIELDS",
    "READINESS_MALFORMED",
    "READINESS_UNREACHABLE",
    "ApiSignerReadiness",
    "ApiSignerRuntimeExpectations",
    "build_api_signer_runtime_observer",
    "build_readiness_transport",
    "parse_readiness_response",
]
