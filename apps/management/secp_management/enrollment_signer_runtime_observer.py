"""Boundary-safe production runtime observer for the controller-enrollment finalization seam.

The corrected finalization adapter (:mod:`secp_management.controller_finalization`) writes the
signer-enablement marker LAST and then requires an authoritative post-restart proof that the
ordinary (non-root) API is genuinely running SEALED with exactly the candidate marker. That proof
is its injected ``runtime_observer`` seam. This module builds the REAL observer the root-only
install composition wires in (see ``production.build_real_finalization_factory``); with NO observer
the adapter fails closed on the deliberately-narrow host-only default.

The observer derives ONE ``ApiSignerRuntimeObservation`` (from ``controller_finalization``) from
MANAGEMENT-OBSERVABLE facts only:

* the ordinary API container is resolved THROUGH the compose project (its
  ``com.docker.compose.project`` / ``com.docker.compose.service`` labels) via the pinned container
  runtime; a single unambiguous ``api`` container must resolve or the observation fails closed;
* that one container is inspected TWICE with a fixed Go-template ``docker inspect`` — running state,
  the exact non-root ``uid:gid``, health status, image digest, the read-only marker mount, the proof
  that NO secret-bearing host path and NO handoff is mounted, and the environment (no independent
  signing enablement) — and the two samples must agree (no mid-observation generation drift);
* host-side posture mirrors the adapter's own fail-closed default: the handoffs are absent, the
  enrollment key + signer credential are not API/world-readable, the broker socket is a genuine
  AF_UNIX socket, and the broker unit bytes equal the reviewed rendering.

The management plane NEVER imports ``secp_api``: every observation is a pinned ``docker`` read or a
hardened-filesystem ``lstat``/``safe_read`` — no compose ``exec``, shell, caller path, or module
selection. Every parse ambiguity, missing field, mismatch, or runner fault sets the RELEVANT bool
to False; the observer NEVER raises and NEVER defaults a bool True without a genuine proof.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from secp_commissioning.controller_enrollment_signer import CONTROLLER_ENROLLMENT_KEY_PATH
from secp_commissioning.runtime import FileStat

from secp_management import ManagementError
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
_INSPECT_TIMEOUT = 20

_MARKER_SCHEMA = "secp.enrollment-signer-enablement/v1"
_EXPECTED_API_USER = f"{API_RUNTIME_UID}:{API_RUNTIME_GID}"

_FULL_CID = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_TRUTHY = frozenset({"1", "true", "yes", "on", "t", "y"})

_COMPOSE_API_SERVICE = "api"
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_COMPOSE_SERVICE_LABEL = "com.docker.compose.service"

# The fixed Go-template: one ``HEAD`` line (scalars), one ``MOUNT`` line per bind mount, and one
# ``ENV`` line per environment variable. Every separator is a code constant; nothing is caller-fed.
_API_INSPECT_TEMPLATE = (
    "HEAD|{{.Id}}|{{.State.Running}}|{{.Config.User}}|{{.Image}}|"
    "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\n"
    "{{range .Mounts}}MOUNT|{{.Source}}|{{.Destination}}|{{.RW}}\n{{end}}"
    "{{range .Config.Env}}ENV|{{.}}\n{{end}}"
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


def _broker_reachable(ctx: RealAdapterContext, loc: ManagementLocations) -> bool:
    st = _lstat(ctx, loc.broker_socket_path())
    if st is None or not st.is_socket:
        return False  # must be EXACTLY an AF_UNIX socket (S_ISSOCK), never a regular/other node
    unit_bytes = _read(ctx, loc.broker_unit_path())
    return unit_bytes is not None and unit_bytes == render_broker_reviewed_unit(loc).content


# --------------------------------------------------------------------------- marker binding


def _load_marker(data: bytes | None) -> dict[str, object] | None:
    if data is None:
        return None
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _binding_ok(obj: dict[str, object] | None, marker: ApiSignerMarker) -> bool:
    if obj is None or obj.get("schema") != _MARKER_SCHEMA:
        return False
    return all(obj.get(field) == getattr(marker, field) for field in _MARKER_BINDING_FIELDS)


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


def _observe(ctx: RealAdapterContext, marker: ApiSignerMarker) -> ApiSignerRuntimeObservation:
    loc = ctx.locations
    socket_path = loc.broker_socket_path()
    marker_mount = api_marker_mount(loc)
    marker_path = marker_mount.host_path

    # ---- fs-only marker posture + binding (independent of the container runtime) ----
    posture_ok = _marker_posture_ok(ctx, marker_path)
    marker_bytes = _read(ctx, marker_path) if posture_ok else None
    marker_present = marker_bytes is not None
    marker_obj = _load_marker(marker_bytes)
    binding_equals_marker = _binding_ok(marker_obj, marker)
    effective_signer_is_fixed_uds = bool(
        marker.uds_contract_identity == socket_path
        and marker_obj is not None
        and marker_obj.get("uds_contract_identity") == socket_path
    )

    # ---- fs-only broker + secret posture (mirrors the adapter's fail-closed default) ----
    handoff_hosts_absent = _absent(ctx, loc.provisioning_handoff_host_path()) and _absent(
        ctx, loc.activation_handoff_host_path()
    )
    key_not_readable = _not_reachable_by_api(ctx, CONTROLLER_ENROLLMENT_KEY_PATH, 0o007)
    cred_not_readable = _not_reachable_by_api(ctx, loc.enrollment_signer_credential_path(), 0o077)
    broker_reachable = _broker_reachable(ctx, loc)

    # ---- container-runtime resolution + double inspect (generation stability) ----
    api_ids = _list_api_containers(ctx)
    single = len(api_ids) == 1
    s1 = _inspect_api(ctx, api_ids[0]) if single else None
    s2 = _inspect_api(ctx, api_ids[0]) if single else None
    sample = s1 if (s1 is not None and s2 is not None and s1 == s2 and s1.well_formed) else None

    api_present = bool(sample is not None and sample.running and sample.container_id == api_ids[0])
    api_non_root = bool(sample is not None and sample.user == _EXPECTED_API_USER)
    api_healthy = bool(sample is not None and sample.health == "healthy")

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

    # exactly one active api generation: a single resolved container, a stable inspect, one marker.
    no_mixed_generation = bool(single and sample is not None and marker_present)

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


def build_api_signer_runtime_observer(
    ctx: RealAdapterContext,
) -> Callable[[ApiSignerMarker], ApiSignerRuntimeObservation]:
    """Build the boundary-safe runtime observer the finalization ``runtime_observer`` seam calls.

    Returns a closure ``observe(marker) -> ApiSignerRuntimeObservation`` that proves the ordinary
    API is genuinely running sealed with the candidate marker from management-observable facts only.
    The closure NEVER raises: any fault falls back to a fully fail-closed observation."""

    def observe(marker: ApiSignerMarker) -> ApiSignerRuntimeObservation:
        try:
            return _observe(ctx, marker)
        except Exception:  # noqa: BLE001 - the observer must never raise into the finalizer
            return _fail_closed()

    return observe


__all__ = ["build_api_signer_runtime_observer"]
