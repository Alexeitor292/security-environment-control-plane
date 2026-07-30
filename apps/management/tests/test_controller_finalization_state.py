"""Hermetic proofs for the read-only live controller-finalization state observer (SECP-PR5H-B2,
2b-3c-c / R3).

Every live seam is faked: a recording pinned runner returns canned ``systemctl is-active`` /
``docker ps`` / ``docker inspect`` stdout, the hardened in-memory filesystem supplies the marker /
credential / socket posture, and the dedicated-role engine, ACTIVE-identity lease provider, role
prober, socket prober, API-signer runtime observer and durable-generation probe are injected. So the
whole observation runs WITHOUT a database, container runtime, systemd or a real host.

The suite proves a fully-correct live state yields NO refusal, that EACH defect refuses with its
exact bounded code, that the observation performs NO mutation (the filesystem and the runner record
no write), and that the module never imports ``secp_api`` (the management-plane boundary).
"""

from __future__ import annotations

import ast
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from secp_commissioning.canonical import canonical_json
from secp_commissioning.controller_enrollment_signer import (
    ENROLLMENT_SIGNER_SOCKET_PATH,
    SigningIdentityLease,
)
from secp_commissioning.enrollment_signer_marker import render_marker_bytes
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management import controller_finalization_state as state_mod
from secp_management.controller_finalization import ApiSignerRuntimeObservation
from secp_management.controller_finalization_state import (
    CONTROLLER_STATE_ACTIVE_IDENTITY_MISMATCH,
    CONTROLLER_STATE_API_SEALED,
    CONTROLLER_STATE_API_UNHEALTHY,
    CONTROLLER_STATE_BROKER_UNREACHABLE,
    CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED,
    CONTROLLER_STATE_GENERATION_DISAGREEMENT,
    CONTROLLER_STATE_IMAGE_UNEXPECTED,
    CONTROLLER_STATE_MARKER_STALE,
    CONTROLLER_STATE_REASONS,
    CONTROLLER_STATE_ROLE_DRIFTED,
    CONTROLLER_STATE_SOCKET_STALE,
    ControllerFinalizationStateObserver,
    ControllerStateContext,
    ExpectedControllerState,
    build_controller_finalization_state_observer,
)
from secp_management.enrollment_signer_db import ENROLLMENT_SIGNER_DB_ROLE
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID
from secp_operator_deployment.host_process import CommandResult
from secp_operator_deployment.pinned_exec import ExecutablePin

_LOC = ManagementLocations()
_MARKER_PATH = _LOC.api_signer_marker_path()
_CRED_PATH = _LOC.enrollment_signer_credential_path()
_SOCKET_PATH = _LOC.broker_socket_path()
_BROKER_UNIT = _LOC.broker_unit_path().rsplit("/", 1)[-1]

_PROJECT = "secp-controller"
_PIN = ExecutablePin(path="/usr/bin/docker", digest="sha256:" + "1" * 64)
_CID = "a" * 64
_CID2 = "b" * 64

_PASSWORD = "a1b2c3d4" * 8  # the reviewed 64-lowercase-hex signer secret grammar
_GENERATION = 3

_ROW_ID = "42"
_TOKEN = "42|2026-07-28 00:00:00+00:00"
_INSTALLATION = "secp-controller-0001"
_KEY_ID = "sha256:" + "1" * 64
_ANCHOR = "2" * 64
_ORIGIN = "https://controller.example.test"
_RELEASE = "sha256:" + "3" * 64
_MGMT_DIGEST = "sha256:" + "4" * 64
_BINDING_DIGEST = "sha256:" + "5" * 64
_PROOF_ID = "enrkp:" + "6" * 64
_LOCATOR_CA = "sha256:" + "7" * 64
_API_IMAGE = "sha256:" + "e" * 64
_OTHER_IMAGE = "sha256:" + "f" * 64

_EXPECTED = ExpectedControllerState(
    generation=_GENERATION,
    installation_id=_INSTALLATION,
    release_digest=_RELEASE,
    controller_key_id=_KEY_ID,
    active_identity_row_id=_ROW_ID,
    management_identity_digest=_MGMT_DIGEST,
    bootstrap_binding_digest=_BINDING_DIGEST,
    enrollment_key_proof_id=_PROOF_ID,
    locator_ca_digest=_LOCATOR_CA,
    api_image_digest=_API_IMAGE,
)


# --------------------------------------------------------------------------- fixture builders


def _lease(**overrides: str) -> SigningIdentityLease:
    fields: dict[str, str] = {
        "row_id": _ROW_ID,
        "activation_token": _TOKEN,
        "controller_installation_id": _INSTALLATION,
        "controller_key_id": _KEY_ID,
        "controller_trust_anchor_hex": _ANCHOR,
        "controller_origin": _ORIGIN,
        "release_digest": _RELEASE,
        "management_identity_digest": _MGMT_DIGEST,
        "bootstrap_evidence_digest": _BINDING_DIGEST,
        "enrollment_key_proof_id": _PROOF_ID,
    }
    fields.update(overrides)
    return SigningIdentityLease(**fields)  # type: ignore[arg-type]


def _marker_bytes(**overrides: object) -> bytes:
    obj: dict[str, object] = {
        "schema": "secp.enrollment-signer-enablement/v1",
        "installation_id": _INSTALLATION,
        "release_digest": _RELEASE,
        "active_identity_row_id": _ROW_ID,
        "activation_token": _TOKEN,
        "controller_key_id": _KEY_ID,
        "uds_contract_identity": ENROLLMENT_SIGNER_SOCKET_PATH,
        "api_uid": API_RUNTIME_UID,
        "api_gid": API_RUNTIME_GID,
        "signer_role_name": ENROLLMENT_SIGNER_DB_ROLE,
        "locator_ca_digest": _LOCATOR_CA,
        "management_identity_digest": _MGMT_DIGEST,
        "bootstrap_evidence_digest": _BINDING_DIGEST,
        "recorded_at": "2026-07-28T00:00:00Z",
    }
    obj.update(overrides)
    if not overrides:
        # the CONFORMANT baseline is rendered through the ONE shared strict contract, so the fixture
        # can never drift from what production writes.
        return render_marker_bytes(**{k: v for k, v in obj.items() if k != "schema"})
    # A drift/hostile case deliberately carries values the fixed contract forbids (a foreign schema,
    # a non-reviewed role/UDS path, a root api uid/gid...). Such bytes can only come from a
    # hand-crafted file, so they are emitted canonically WITHOUT the strict renderer — the strict
    # PARSER refusing them (marker unproven -> stale) is exactly the behaviour under test.
    return canonical_json(obj).encode("utf-8")


def _observation(**overrides: bool) -> ApiSignerRuntimeObservation:
    fields: dict[str, bool] = {
        "api_present": True,
        "api_non_root": True,
        "api_healthy": True,
        "marker_mounted_readonly": True,
        "handoffs_absent": True,
        "enrollment_key_not_mounted": True,
        "signer_credential_not_mounted": True,
        "effective_signer_is_fixed_uds": True,
        "binding_equals_marker": True,
        "no_env_enablement": True,
        "broker_reachable": True,
        "no_mixed_generation": True,
    }
    fields.update(overrides)
    return ApiSignerRuntimeObservation(**fields)


class _RecordingFs:
    """Delegates every READ to the hardened in-memory backend and RECORDS (never performs) any
    mutating call, so a single assertion proves the observation is mutation-free."""

    def __init__(self, inner: InMemoryFilesystem) -> None:
        self.inner = inner
        self.writes: list[str] = []

    # --- reads (delegated) ---
    def lstat(self, path: str):  # noqa: ANN201
        return self.inner.lstat(path)

    def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes:
        return self.inner.safe_read(path, max_bytes=max_bytes, expected_uid=expected_uid)

    def sha256(self, path: str) -> str:
        return self.inner.sha256(path)

    def list_dir(self, path: str):  # noqa: ANN201
        return self.inner.list_dir(path)

    # --- mutations (recorded, never performed) ---
    def atomic_install(self, path: str, data: bytes, *, uid: int, gid: int, mode: int) -> None:
        self.writes.append(f"atomic_install:{path}")

    def exclusive_install(self, path: str, data: bytes, *, uid: int, gid: int, mode: int) -> None:
        self.writes.append(f"exclusive_install:{path}")

    def makedir(self, path: str, *, uid: int, gid: int, mode: int) -> None:
        self.writes.append(f"makedir:{path}")

    def remove_file(self, path: str) -> None:
        self.writes.append(f"remove_file:{path}")

    def remove_dir(self, path: str) -> None:
        self.writes.append(f"remove_dir:{path}")

    def remove_created_file(self, receipt: object) -> bool:
        self.writes.append("remove_created_file")
        return False

    def created_file_matches(self, receipt: object) -> bool:
        return False


#: every argv verb the observer is permitted to run — all strictly read-only queries.
_READ_ONLY_VERBS = frozenset({"is-active", "ps", "inspect"})


class _FakeRunner:
    """Records every argv; returns canned ``is-active`` / ``ps`` / ``inspect`` stdout."""

    def __init__(
        self,
        *,
        service_state: str = "active",
        service_exit: int = 0,
        ps_ids: tuple[str, ...] = (_CID,),
        image: str = _API_IMAGE,
        raise_on: str | None = None,
    ) -> None:
        self._service_state = service_state
        self._service_exit = service_exit
        self._ps_stdout = "".join(f"{i}\n" for i in ps_ids)
        self._image = image
        self._raise_on = raise_on
        self.calls: list[tuple[str, ...]] = []

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001,ANN201
        argv = tuple(argv_tail)
        self.calls.append(argv)
        if self._raise_on is not None and argv and argv[0] == self._raise_on:
            raise RuntimeError("injected runner fault")
        if argv and argv[0] == "is-active":
            return CommandResult(self._service_exit, self._service_state + "\n")
        if argv and argv[0] == "ps":
            return CommandResult(0, self._ps_stdout)
        if argv and argv[0] == "inspect":
            return CommandResult(0, self._image + "\n")
        return CommandResult(1, "")


class _FakeEngine:
    def __init__(self, password: str, *, dialect: str = "postgresql") -> None:
        self.password = password
        self.dialect = type("_D", (), {"name": dialect})()
        self.disposed = False

    def dispose(self) -> None:
        self.disposed = True


class _FakeLeaseProvider:
    """Mirrors ``DbActiveControllerSigningIdentityProvider``: ``lease()`` is a context manager that
    yields the single verified ACTIVE identity, or raises a bounded closed refusal."""

    lease_value: Any = None
    lease_error: Exception | None = None

    def __init__(self, engine: object) -> None:
        self.engine = engine

    @contextmanager
    def lease(self):  # noqa: ANN201
        if _FakeLeaseProvider.lease_error is not None:
            raise _FakeLeaseProvider.lease_error
        yield _FakeLeaseProvider.lease_value


def _build_fs(
    *,
    marker: bytes | None = None,
    marker_mode: int = 0o644,
    marker_uid: int = 0,
    credential: bytes | None = b"%s\n" % _PASSWORD.encode("ascii"),
    credential_mode: int = 0o600,
    socket: str = "socket",  # socket | regular | special | absent
    socket_mode: int = 0o660,
    socket_gid: int = API_RUNTIME_GID,
) -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for directory in (
        "/etc/secp/controller",
        "/etc/secp/controller/credentials",
        "/etc/systemd",
        "/etc/systemd/system",
    ):
        fs.seed_dir(directory)
    fs.seed_file(
        _MARKER_PATH,
        _marker_bytes() if marker is None else marker,
        uid=marker_uid,
        mode=marker_mode,
    )
    if credential is not None:
        fs.seed_file(_CRED_PATH, credential, mode=credential_mode)
    if socket == "socket":
        fs.seed_socket(_SOCKET_PATH, gid=socket_gid, mode=socket_mode)
    elif socket == "regular":
        fs.seed_file(_SOCKET_PATH, b"not-a-socket", gid=socket_gid, mode=socket_mode)
    elif socket == "special":
        fs.seed_special(_SOCKET_PATH, gid=socket_gid)
    return fs


def _ctx(
    fs: InMemoryFilesystem | _RecordingFs,
    runner: _FakeRunner,
    *,
    observation: ApiSignerRuntimeObservation | None = None,
    observer_error: Exception | None = None,
    role_reason: str | None = None,
    role_error: Exception | None = None,
    socket_error: Exception | None = None,
    generation: int | None = _GENERATION,
    generation_error: Exception | None = None,
) -> ControllerStateContext:
    def runtime_observer(marker):  # noqa: ANN001,ANN202
        if observer_error is not None:
            raise observer_error
        return observation if observation is not None else _observation()

    def role_prober(engine):  # noqa: ANN001,ANN202
        if role_error is not None:
            raise role_error
        return role_reason

    def socket_prober(path, *, expected_peer):  # noqa: ANN001,ANN202
        if socket_error is not None:
            raise socket_error

    def generation_probe():  # noqa: ANN202
        if generation_error is not None:
            raise generation_error
        return generation

    return ControllerStateContext(
        host=RealAdapterContext(
            locations=_LOC,
            fs=fs,  # type: ignore[arg-type]
            runner=runner,  # type: ignore[arg-type]
            executables=PinnedExecutables(
                container_runtime=_PIN, compose_runtime=_PIN, service_manager=_PIN
            ),
            controller_project=_PROJECT,
        ),
        runtime_observer=runtime_observer,
        generation_probe=generation_probe,
        lease_provider_factory=_FakeLeaseProvider,
        engine_factory=_FakeEngine,
        role_prober=role_prober,
        socket_prober=socket_prober,
    )


def _observe(ctx: ControllerStateContext, expected: ExpectedControllerState = _EXPECTED):  # noqa: ANN202
    return ControllerFinalizationStateObserver(ctx).observe(expected=expected)


@pytest.fixture(autouse=True)
def _reset_lease() -> None:
    _FakeLeaseProvider.lease_value = _lease()
    _FakeLeaseProvider.lease_error = None


# --------------------------------------------------------------------------- the correct case


def test_fully_correct_live_state_yields_no_refusal() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) is None
    assert st.ok_for(_EXPECTED) is True


def test_every_proof_is_genuinely_true_and_the_live_facts_are_bound() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner()))
    for field_name in (
        "single_active_identity",
        "active_identity_matches_expected",
        "generation_agrees",
        "marker_binding_exact",
        "credential_authenticated",
        "signer_role_exact",
        "runtime_observed",
        "api_live",
        "api_unsealed",
        "api_image_expected",
        "broker_service_active",
        "broker_socket_exact",
        "broker_transport_ready",
    ):
        assert getattr(st, field_name) is True, field_name
    assert st.active_identity_row_id == _ROW_ID
    assert st.activation_token == _TOKEN
    assert st.marker_activation_token == _TOKEN
    assert st.installation_id == _INSTALLATION
    assert st.release_digest == _RELEASE
    assert st.controller_key_id == _KEY_ID
    assert st.management_identity_digest == _MGMT_DIGEST
    assert st.bootstrap_binding_digest == _BINDING_DIGEST
    assert st.enrollment_key_proof_id == _PROOF_ID
    assert st.durable_generation == _GENERATION
    assert st.api_image_observed == _API_IMAGE


def test_build_factory_returns_the_same_observation_callable() -> None:
    observe = build_controller_finalization_state_observer(_ctx(_build_fs(), _FakeRunner()))
    assert observe(expected=_EXPECTED).refusal_reason(_EXPECTED) is None


def test_api_container_is_resolved_through_the_compose_project_labels() -> None:
    runner = _FakeRunner()
    _observe(_ctx(_build_fs(), runner))
    ps = next(c for c in runner.calls if c and c[0] == "ps")
    assert f"label=com.docker.compose.project={_PROJECT}" in ps
    assert "label=com.docker.compose.service=api" in ps
    inspect = next(c for c in runner.calls if c and c[0] == "inspect")
    assert inspect == ("inspect", "--format", "{{.Image}}", _CID)
    # the broker state query names EXACTLY the fixed code-owned unit (never a caller-chosen name)
    assert next(c for c in runner.calls if c and c[0] == "is-active") == ("is-active", _BROKER_UNIT)


# --------------------------------------------------------------------------- broker defects


def test_stopped_broker_refuses_broker_unreachable() -> None:
    runner = _FakeRunner(service_state="inactive", service_exit=3)
    st = _observe(_ctx(_build_fs(), runner))
    assert st.broker_service_active is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_BROKER_UNREACHABLE


def test_unqueryable_broker_service_refuses_broker_unreachable() -> None:
    runner = _FakeRunner(raise_on="is-active")
    st = _observe(_ctx(_build_fs(), runner))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_BROKER_UNREACHABLE


def test_unreachable_broker_transport_refuses_broker_unreachable() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), socket_error=ManagementError("unreachable"))
    st = _observe(ctx)
    assert st.broker_socket_exact is True and st.broker_transport_ready is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_BROKER_UNREACHABLE


def test_runtime_broker_posture_defect_refuses_broker_unreachable() -> None:
    # the runtime observer independently re-proves the socket type + broker-unit bytes
    ctx = _ctx(_build_fs(), _FakeRunner(), observation=_observation(broker_reachable=False))
    assert _observe(ctx).refusal_reason(_EXPECTED) == CONTROLLER_STATE_BROKER_UNREACHABLE


# --------------------------------------------------------------------------- socket defects


@pytest.mark.parametrize("kind", ["absent", "regular", "special"])
def test_socket_that_is_not_exactly_an_af_unix_socket_refuses_socket_stale(kind: str) -> None:
    st = _observe(_ctx(_build_fs(socket=kind), _FakeRunner()))
    assert st.broker_socket_exact is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_SOCKET_STALE


def test_socket_with_drifted_mode_refuses_socket_stale() -> None:
    st = _observe(_ctx(_build_fs(socket_mode=0o666), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_SOCKET_STALE


def test_socket_with_foreign_group_refuses_socket_stale() -> None:
    st = _observe(_ctx(_build_fs(socket_gid=API_RUNTIME_GID + 7), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_SOCKET_STALE


# --------------------------------------------------------------------------- credential + role


def test_credential_that_does_not_authenticate_refuses_credential_unauthenticated() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), role_reason=CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED)
    st = _observe(ctx)
    assert st.credential_authenticated is False and st.signer_role_exact is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED


def test_absent_credential_refuses_credential_unauthenticated() -> None:
    st = _observe(_ctx(_build_fs(credential=None), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED


def test_group_readable_credential_refuses_credential_unauthenticated() -> None:
    st = _observe(_ctx(_build_fs(credential_mode=0o640), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED


def test_malformed_credential_refuses_credential_unauthenticated() -> None:
    st = _observe(_ctx(_build_fs(credential=b"not-a-hex-secret\n"), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED


def test_role_prober_fault_refuses_credential_unauthenticated() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), role_error=RuntimeError("db fault"))
    assert _observe(ctx).refusal_reason(_EXPECTED) == CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED


def test_drifted_role_posture_refuses_role_drifted() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), role_reason=CONTROLLER_STATE_ROLE_DRIFTED)
    st = _observe(ctx)
    assert st.credential_authenticated is True and st.signer_role_exact is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_ROLE_DRIFTED


# --------------------------------------------------------------------------- active identity


def test_absent_active_identity_refuses_active_identity_mismatch() -> None:
    _FakeLeaseProvider.lease_error = ManagementError("controller_enrollment_identity_unavailable")
    st = _observe(_ctx(_build_fs(), _FakeRunner()))
    assert st.single_active_identity is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_ACTIVE_IDENTITY_MISMATCH


@pytest.mark.parametrize(
    "override",
    [
        {"row_id": "99"},
        {"controller_installation_id": "secp-controller-9999"},
        {"release_digest": "sha256:" + "9" * 64},
        {"controller_key_id": "sha256:" + "8" * 64},
        {"management_identity_digest": "sha256:" + "b" * 64},
        {"bootstrap_evidence_digest": "sha256:" + "c" * 64},
        {"enrollment_key_proof_id": "enrkp:" + "d" * 64},
    ],
)
def test_live_identity_that_differs_refuses_active_identity_mismatch(
    override: dict[str, str],
) -> None:
    _FakeLeaseProvider.lease_value = _lease(**override)
    st = _observe(_ctx(_build_fs(), _FakeRunner()))
    assert st.active_identity_matches_expected is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_ACTIVE_IDENTITY_MISMATCH


# --------------------------------------------------------------------------- marker defects


def test_marker_that_no_longer_binds_the_live_identity_refuses_marker_stale() -> None:
    # the DB identity rotated behind the marker: the marker's token is a PRIOR activation
    _FakeLeaseProvider.lease_value = _lease(activation_token="42|2026-08-01 00:00:00+00:00")
    st = _observe(_ctx(_build_fs(), _FakeRunner()))
    assert st.marker_binding_exact is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_MARKER_STALE


@pytest.mark.parametrize(
    "override",
    [
        {"locator_ca_digest": "sha256:" + "0" * 64},
        {"signer_role_name": "postgres"},
        {"uds_contract_identity": "/run/secp/rogue.sock"},
        {"api_uid": 0},
        {"api_gid": 0},
    ],
)
def test_marker_binding_drift_refuses_marker_stale(override: dict[str, object]) -> None:
    st = _observe(_ctx(_build_fs(marker=_marker_bytes(**override)), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_MARKER_STALE


def test_absent_marker_refuses_marker_stale() -> None:
    fs = _build_fs()
    fs.remove_file(_MARKER_PATH)
    st = _observe(_ctx(fs, _FakeRunner()))
    assert st.marker_binding_exact is False and st.runtime_observed is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_MARKER_STALE


def test_unsafe_marker_posture_refuses_marker_stale() -> None:
    st = _observe(_ctx(_build_fs(marker_uid=1000), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_MARKER_STALE


def test_malformed_marker_refuses_marker_stale() -> None:
    st = _observe(_ctx(_build_fs(marker=b"{not json"), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_MARKER_STALE


def test_marker_with_foreign_schema_refuses_marker_stale() -> None:
    st = _observe(_ctx(_build_fs(marker=_marker_bytes(schema="forged/v9")), _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_MARKER_STALE


# --------------------------------------------------------------------------- API runtime defects


@pytest.mark.parametrize("defect", ["api_present", "api_non_root", "api_healthy"])
def test_unhealthy_api_refuses_api_unhealthy(defect: str) -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), observation=_observation(**{defect: False}))
    st = _observe(ctx)
    assert st.api_live is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_API_UNHEALTHY


def test_runtime_observer_fault_refuses_api_unhealthy() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), observer_error=RuntimeError("observer fault"))
    assert _observe(ctx).refusal_reason(_EXPECTED) == CONTROLLER_STATE_API_UNHEALTHY


@pytest.mark.parametrize(
    "defect",
    [
        "marker_mounted_readonly",
        "binding_equals_marker",
        "effective_signer_is_fixed_uds",
        "no_env_enablement",
        "handoffs_absent",
        "enrollment_key_not_mounted",
        "signer_credential_not_mounted",
    ],
)
def test_sealed_or_missealed_api_refuses_api_sealed(defect: str) -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), observation=_observation(**{defect: False}))
    st = _observe(ctx)
    assert st.api_unsealed is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_API_SEALED


# --------------------------------------------------------------------------- image defects


def test_old_image_running_refuses_image_unexpected() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner(image=_OTHER_IMAGE)))
    assert st.api_image_observed == _OTHER_IMAGE and st.api_image_expected is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_IMAGE_UNEXPECTED


def test_malformed_image_refuses_image_unexpected() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner(image="not-a-digest")))
    assert st.api_image_observed == ""
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_IMAGE_UNEXPECTED


def test_ambiguous_api_container_refuses_image_unexpected() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner(ps_ids=(_CID, _CID2))))
    assert st.api_image_observed == ""
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_IMAGE_UNEXPECTED


def test_container_probe_fault_refuses_image_unexpected() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner(raise_on="inspect")))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_IMAGE_UNEXPECTED


# --------------------------------------------------------------------------- generation defects


def test_durable_generation_that_disagrees_refuses_generation_disagreement() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner(), generation=_GENERATION + 1))
    assert st.durable_generation == _GENERATION + 1 and st.generation_agrees is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_GENERATION_DISAGREEMENT


def test_stale_durable_generation_refuses_generation_disagreement() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner(), generation=_GENERATION - 1))
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_GENERATION_DISAGREEMENT


def test_unprovable_durable_generation_refuses_generation_disagreement() -> None:
    st = _observe(_ctx(_build_fs(), _FakeRunner(), generation=None))
    assert st.durable_generation == -1
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_GENERATION_DISAGREEMENT


def test_generation_probe_fault_refuses_generation_disagreement() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), generation_error=RuntimeError("probe fault"))
    st = _observe(ctx)
    assert st.durable_generation == -1
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_GENERATION_DISAGREEMENT


def test_mixed_api_generation_refuses_generation_disagreement() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner(), observation=_observation(no_mixed_generation=False))
    st = _observe(ctx)
    assert st.generation_agrees is False
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_GENERATION_DISAGREEMENT


def test_state_observed_for_one_expectation_refuses_for_another() -> None:
    # refusal_reason RE-checks the equalities, so a state can never be reused across expectations
    st = _observe(_ctx(_build_fs(), _FakeRunner()))
    other = ExpectedControllerState(
        generation=_GENERATION + 5,
        installation_id=_INSTALLATION,
        release_digest=_RELEASE,
        controller_key_id=_KEY_ID,
        active_identity_row_id=_ROW_ID,
        management_identity_digest=_MGMT_DIGEST,
        bootstrap_binding_digest=_BINDING_DIGEST,
        enrollment_key_proof_id=_PROOF_ID,
        locator_ca_digest=_LOCATOR_CA,
        api_image_digest=_API_IMAGE,
    )
    assert st.refusal_reason(_EXPECTED) is None
    assert st.refusal_reason(other) == CONTROLLER_STATE_GENERATION_DISAGREEMENT


# --------------------------------------------------------------------------- closed reason set


def test_every_produced_reason_is_in_the_closed_set() -> None:
    contexts = (
        _ctx(_build_fs(), _FakeRunner(service_state="inactive", service_exit=3)),
        _ctx(_build_fs(socket="regular"), _FakeRunner()),
        _ctx(_build_fs(), _FakeRunner(), socket_error=ManagementError("x")),
        _ctx(_build_fs(credential=None), _FakeRunner()),
        _ctx(_build_fs(), _FakeRunner(), role_reason=CONTROLLER_STATE_ROLE_DRIFTED),
        _ctx(_build_fs(marker=b"{oops"), _FakeRunner()),
        _ctx(_build_fs(), _FakeRunner(), observation=_observation(api_healthy=False)),
        _ctx(_build_fs(), _FakeRunner(image=_OTHER_IMAGE)),
        _ctx(_build_fs(), _FakeRunner(), observation=_observation(binding_equals_marker=False)),
        _ctx(_build_fs(), _FakeRunner(), generation=None),
    )
    produced = {_observe(c).refusal_reason(_EXPECTED) for c in contexts}
    assert None not in produced
    assert produced <= set(CONTROLLER_STATE_REASONS)
    assert len(CONTROLLER_STATE_REASONS) == len(set(CONTROLLER_STATE_REASONS)) == 10


# --------------------------------------------------------------------------- mutation freedom


def test_observation_performs_no_filesystem_mutation() -> None:
    inner = _build_fs()
    before = inner.paths()
    recording = _RecordingFs(inner)
    st = _observe(_ctx(recording, _FakeRunner()))
    assert st.refusal_reason(_EXPECTED) is None
    assert recording.writes == []
    assert inner.paths() == before
    assert inner.safe_read(_MARKER_PATH, max_bytes=65536, expected_uid=0) == _marker_bytes()


def test_observation_runs_only_read_only_host_queries() -> None:
    runner = _FakeRunner()
    _observe(_ctx(_build_fs(), runner))
    assert runner.calls, "the observation must actually query the host"
    for argv in runner.calls:
        assert argv[0] in _READ_ONLY_VERBS, argv


def test_a_refusing_observation_still_performs_no_mutation() -> None:
    inner = _build_fs(socket="regular", credential=None, marker=b"{oops")
    before = inner.paths()
    recording = _RecordingFs(inner)
    assert (
        _observe(_ctx(recording, _FakeRunner(raise_on="is-active"))).refusal_reason(_EXPECTED)
        == CONTROLLER_STATE_BROKER_UNREACHABLE
    )
    assert recording.writes == []
    assert inner.paths() == before


# --------------------------------------------------------------------------- never raises


def test_observer_never_raises_on_a_faulting_filesystem() -> None:
    class _BrokenFs:
        def lstat(self, path: str):  # noqa: ANN202
            raise RuntimeError("fs fault")

        def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes:
            raise RuntimeError("fs fault")

    st = _observe(_ctx(_BrokenFs(), _FakeRunner()))  # type: ignore[arg-type]
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_SOCKET_STALE
    assert st.durable_generation == -1 or st.durable_generation == _GENERATION


def test_observer_never_raises_on_a_faulting_engine_factory() -> None:
    ctx = _ctx(_build_fs(), _FakeRunner())
    broken = ControllerStateContext(
        host=ctx.host,
        runtime_observer=ctx.runtime_observer,
        generation_probe=ctx.generation_probe,
        lease_provider_factory=_FakeLeaseProvider,
        engine_factory=lambda password: (_ for _ in ()).throw(RuntimeError("engine fault")),
        role_prober=ctx.role_prober,
        socket_prober=ctx.socket_prober,
    )
    st = _observe(broken)
    assert st.refusal_reason(_EXPECTED) == CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED


def test_engine_is_always_disposed() -> None:
    created: list[_FakeEngine] = []

    def factory(password: str) -> _FakeEngine:
        engine = _FakeEngine(password)
        created.append(engine)
        return engine

    ctx = _ctx(_build_fs(), _FakeRunner())
    disposing = ControllerStateContext(
        host=ctx.host,
        runtime_observer=ctx.runtime_observer,
        generation_probe=ctx.generation_probe,
        lease_provider_factory=_FakeLeaseProvider,
        engine_factory=factory,
        role_prober=ctx.role_prober,
        socket_prober=ctx.socket_prober,
    )
    _observe(disposing)
    assert created and all(e.disposed for e in created)


# --------------------------------------------------------------------------- plane boundary


def test_module_never_imports_secp_api() -> None:
    # mirrors test_enrollment_signer_runtime_observer: no secp_api import and no secp_api identifier
    tree = ast.parse(Path(state_mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("secp_api") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("secp_api")
        elif isinstance(node, ast.Name):
            assert not node.id.startswith("secp_api")
        elif isinstance(node, ast.Attribute):
            assert not node.attr.startswith("secp_api")
