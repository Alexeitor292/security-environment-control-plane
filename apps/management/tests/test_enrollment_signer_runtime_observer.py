"""Hermetic proofs for the boundary-safe API signer runtime observer (SECP-PR5H-B2, 2b-3c).

A fake pinned runner returns canned ``docker ps``/``docker inspect`` stdout and the hardened
in-memory filesystem (``seed_dir``/``seed_file``/``seed_socket``) supplies the host posture, so the
observer's every fact is exercised WITHOUT a container runtime or a real host. The suite proves the
fully-correct composition yields ``.ok is True`` and that EACH defect fails closed (never raises,
never rubber-stamps), and that the module never imports ``secp_api`` (the management-plane boundary,
mirroring ``test_controller_finalization_wiring``'s new-production-module import guard).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    ENROLLMENT_SIGNER_SOCKET_PATH,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import enrollment_signer_runtime_observer as obs_mod
from secp_management.controller_compose_contract import render_broker_reviewed_unit
from secp_management.enrollment_signer_runtime_observer import build_api_signer_runtime_observer
from secp_management.finalization import ApiSignerMarker
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_operator_deployment.host_process import CommandResult
from secp_operator_deployment.pinned_exec import ExecutablePin

_LOC = ManagementLocations()
_MARKER_PATH = _LOC.api_signer_marker_path()
_SOCKET_PATH = _LOC.broker_socket_path()
_CRED_PATH = _LOC.enrollment_signer_credential_path()
_BROKER_UNIT_PATH = _LOC.broker_unit_path()
_PROV_HOST = _LOC.provisioning_handoff_host_path()
_ACT_HOST = _LOC.activation_handoff_host_path()
_PROV_CONTAINER = _LOC.provisioning_handoff_container_path()
_ACT_CONTAINER = _LOC.activation_handoff_container_path()
_BROKER_UNIT_BYTES = render_broker_reviewed_unit(_LOC).content

_CID = "a" * 64
_CID2 = "b" * 64
_GOOD_IMAGE = "sha256:" + "e" * 64
_OTHER_IMAGE = "sha256:" + "f" * 64
_PIN = ExecutablePin(path="/usr/bin/docker", digest="sha256:" + "1" * 64)

_MARKER = ApiSignerMarker(
    marker_path=_MARKER_PATH,
    installation_id="inst-0001",
    release_digest="sha256:" + "a" * 64,
    active_identity_row_id="42",
    activation_token="tok-abcdef",
    controller_key_id="ckid-1",
    uds_contract_identity=ENROLLMENT_SIGNER_SOCKET_PATH,
    api_uid=10001,
    api_gid=10001,
    signer_role_name="secp_enrollment_signer",
    locator_ca_digest="sha256:" + "b" * 64,
    management_identity_digest="sha256:" + "c" * 64,
    bootstrap_evidence_digest="sha256:" + "d" * 64,
)


# --------------------------------------------------------------------------- fixture builders


def _marker_bytes(marker: ApiSignerMarker = _MARKER, **overrides: object) -> bytes:
    obj: dict[str, object] = {"schema": "secp.enrollment-signer-enablement/v1"}
    for field in (
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
    ):
        obj[field] = getattr(marker, field)
    obj["recorded_at"] = "2026-07-28T00:00:00Z"
    obj.update(overrides)
    return json.dumps(obj).encode("utf-8")


def _render_inspect(
    *,
    cid: str = _CID,
    running: str = "true",
    user: str = "10001:10001",
    image: str = _GOOD_IMAGE,
    health: str = "healthy",
    mounts: tuple[tuple[str, str, str], ...] | None = None,
    env: tuple[str, ...] | None = None,
) -> str:
    if mounts is None:
        mounts = ((_MARKER_PATH, _MARKER_PATH, "false"),)
    if env is None:
        env = ("PATH=/usr/local/bin", "SECP_APP_ENV=production")
    lines = [f"HEAD|{cid}|{running}|{user}|{image}|{health}"]
    lines += [f"MOUNT|{src}|{dst}|{rw}" for src, dst, rw in mounts]
    lines += [f"ENV|{entry}" for entry in env]
    return "\n".join(lines) + "\n"


class _FakeRunner:
    """Records every argv; returns canned ``ps`` stdout and a queue of ``inspect`` stdouts (the
    observer inspects twice, so a two-element queue models a mid-observation image drift)."""

    def __init__(
        self,
        *,
        ps_ids: tuple[str, ...] = (_CID,),
        inspects: tuple[str, ...] | None = None,
        ps_exit: int = 0,
        raise_on: str | None = None,
    ) -> None:
        self._ps_stdout = "".join(f"{i}\n" for i in ps_ids)
        self._inspects = list(inspects) if inspects is not None else [_render_inspect()]
        self._ps_exit = ps_exit
        self._raise_on = raise_on
        self._i = 0
        self.calls: list[tuple[str, ...]] = []

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001,ANN201
        argv = tuple(argv_tail)
        self.calls.append(argv)
        if self._raise_on is not None and argv and argv[0] == self._raise_on:
            raise RuntimeError("injected runner fault")
        if argv and argv[0] == "ps":
            return CommandResult(self._ps_exit, self._ps_stdout)
        if argv and argv[0] == "inspect":
            if not self._inspects:
                return CommandResult(1, "")
            out = self._inspects[min(self._i, len(self._inspects) - 1)]
            self._i += 1
            return CommandResult(0, out)
        return CommandResult(0, "")


def _build_fs(
    *,
    marker: bytes | None = None,
    marker_mode: int = 0o644,
    seed_socket: bool = True,
    socket_regular: bool = False,
    key_mode: int = 0o600,
    cred_mode: int = 0o600,
    broker_unit: bytes | None = _BROKER_UNIT_BYTES,
    handoff_files: tuple[str, ...] = (),
) -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for directory in (
        "/etc/secp/controller",
        "/etc/secp/controller/credentials",
        "/etc/systemd",
        "/etc/systemd/system",
    ):
        fs.seed_dir(directory)
    fs.seed_file(_MARKER_PATH, _marker_bytes() if marker is None else marker, mode=marker_mode)
    if broker_unit is not None:
        fs.seed_file(_BROKER_UNIT_PATH, broker_unit, mode=0o644)
    fs.seed_file(CONTROLLER_ENROLLMENT_KEY_PATH, b"KEYBYTES", mode=key_mode)
    fs.seed_file(_CRED_PATH, b"CREDBYTES", mode=cred_mode)
    if seed_socket:
        if socket_regular:
            fs.seed_file(_SOCKET_PATH, b"", mode=0o660)  # a regular file, NOT an AF_UNIX socket
        else:
            fs.seed_socket(_SOCKET_PATH)
    for path in handoff_files:
        fs.seed_file(path, b"HANDOFF", mode=0o640)
    return fs


def _ctx(fs: InMemoryFilesystem, runner: _FakeRunner) -> RealAdapterContext:
    return RealAdapterContext(
        locations=_LOC,
        fs=fs,
        runner=runner,  # type: ignore[arg-type]
        executables=PinnedExecutables(
            container_runtime=_PIN, compose_runtime=_PIN, service_manager=_PIN
        ),
        controller_project="secp-controller",
    )


def _observe(fs: InMemoryFilesystem, runner: _FakeRunner, *, attempts: int = 1):  # noqa: ANN202
    # attempts=1 + a 0s interval keeps the defect proofs instant: the bounded readiness poll is
    # exercised explicitly by the two settling tests below, never implicitly by every defect case.
    return build_api_signer_runtime_observer(
        _ctx(fs, runner), readiness_attempts=attempts, readiness_interval_seconds=0.0
    )(_MARKER)


# --------------------------------------------------------------------------- the correct case


def test_fully_correct_composition_is_ok() -> None:
    observation = _observe(_build_fs(), _FakeRunner())
    assert observation.ok is True
    # every individual invariant genuinely proven (no bool defaulted True)
    for field in (
        "api_present",
        "api_non_root",
        "api_healthy",
        "marker_mounted_readonly",
        "handoffs_absent",
        "enrollment_key_not_mounted",
        "signer_credential_not_mounted",
        "effective_signer_is_fixed_uds",
        "binding_equals_marker",
        "no_env_enablement",
        "broker_reachable",
        "no_mixed_generation",
    ):
        assert getattr(observation, field) is True, field


def test_observer_resolves_the_api_container_through_the_compose_project() -> None:
    runner = _FakeRunner()
    _observe(_build_fs(), runner)
    ps = next(c for c in runner.calls if c and c[0] == "ps")
    assert "label=com.docker.compose.project=secp-controller" in ps
    assert "label=com.docker.compose.service=api" in ps
    assert ps[-2:] == ("--format", "{{.ID}}")
    inspects = [c for c in runner.calls if c and c[0] == "inspect"]
    assert len(inspects) == 2 and all(c[-1] == _CID for c in inspects)  # stability double-read


# ------------------------------------------------------------------------- each defect fails closed


def test_wrong_api_uid_gid_fails_closed() -> None:
    runner = _FakeRunner(inspects=(_render_inspect(user="0:0"),))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_non_root is False


def test_unhealthy_api_fails_closed() -> None:
    # a container still 'starting' when the bounded readiness poll is exhausted fails closed
    runner = _FakeRunner(inspects=(_render_inspect(health="starting"),))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_healthy is False


def test_definitively_unhealthy_api_fails_closed_without_polling() -> None:
    # 'unhealthy' is DEFINITIVE (not a settling state): the observer must not burn its readiness
    # budget on it — one sample (2 inspects) and out.
    runner = _FakeRunner(inspects=(_render_inspect(health="unhealthy"),))
    observation = _observe(_build_fs(), runner, attempts=5)
    assert observation.ok is False and observation.api_healthy is False
    assert len([c for c in runner.calls if c and c[0] == "inspect"]) == 2  # exactly ONE sample


def test_settling_api_becomes_healthy_within_the_readiness_poll() -> None:
    # the real finalizer observes IMMEDIATELY after force-recreating the API, so the first samples
    # report 'starting'; the bounded poll must let it settle and then prove it genuinely healthy.
    starting = _render_inspect(health="starting")
    healthy = _render_inspect(health="healthy")
    runner = _FakeRunner(inspects=(starting, starting, healthy, healthy))
    observation = _observe(_build_fs(), runner, attempts=5)
    assert observation.ok is True and observation.api_healthy is True


def test_not_running_api_fails_closed() -> None:
    runner = _FakeRunner(inspects=(_render_inspect(running="false"),))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_present is False


def test_wrong_image_between_samples_fails_closed() -> None:
    # two inspects disagree on the image digest -> unstable/mixed generation -> fail closed
    runner = _FakeRunner(inspects=(_render_inspect(), _render_inspect(image=_OTHER_IMAGE)))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_present is False
    assert observation.no_mixed_generation is False


def test_malformed_image_fails_closed() -> None:
    runner = _FakeRunner(inspects=(_render_inspect(image="not-a-digest"),))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_present is False


def test_marker_not_read_only_fails_closed() -> None:
    rw_mount = ((_MARKER_PATH, _MARKER_PATH, "true"),)
    runner = _FakeRunner(inspects=(_render_inspect(mounts=rw_mount),))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.marker_mounted_readonly is False


def test_marker_mount_absent_fails_closed() -> None:
    runner = _FakeRunner(inspects=(_render_inspect(mounts=()),))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.marker_mounted_readonly is False


def test_marker_bytes_mismatch_fails_closed() -> None:
    # a marker file whose binding disagrees with the candidate marker
    fs = _build_fs(marker=_marker_bytes(installation_id="tampered"))
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.binding_equals_marker is False


def test_marker_missing_on_host_fails_closed() -> None:
    fs = _build_fs()
    fs.remove_file(_MARKER_PATH)
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.marker_mounted_readonly is False
    assert observation.no_mixed_generation is False
    assert observation.binding_equals_marker is False


def test_marker_uds_not_fixed_socket_fails_closed() -> None:
    fs = _build_fs(marker=_marker_bytes(uds_contract_identity="/run/secp/rogue.sock"))
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.binding_equals_marker is False


def test_secret_enrollment_key_mount_fails_closed() -> None:
    mounts = (
        (_MARKER_PATH, _MARKER_PATH, "false"),
        (CONTROLLER_ENROLLMENT_KEY_PATH, "/run/secp/key", "false"),
    )
    observation = _observe(_build_fs(), _FakeRunner(inspects=(_render_inspect(mounts=mounts),)))
    assert observation.ok is False
    assert observation.enrollment_key_not_mounted is False


def test_secret_credential_mount_fails_closed() -> None:
    mounts = (
        (_MARKER_PATH, _MARKER_PATH, "false"),
        (_CRED_PATH, "/run/secp/cred", "false"),
    )
    observation = _observe(_build_fs(), _FakeRunner(inspects=(_render_inspect(mounts=mounts),)))
    assert observation.ok is False
    assert observation.signer_credential_not_mounted is False


def test_enrollment_key_world_readable_fails_closed() -> None:
    fs = _build_fs(key_mode=0o644)  # world-readable -> the non-root API could read it
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.enrollment_key_not_mounted is False


def test_credential_group_readable_fails_closed() -> None:
    fs = _build_fs(cred_mode=0o640)  # group-readable -> reachable by the API group
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.signer_credential_not_mounted is False


def test_handoff_mount_present_fails_closed() -> None:
    # a bind whose destination is the fixed handoff container path (source is not itself a secret)
    mounts = (
        (_MARKER_PATH, _MARKER_PATH, "false"),
        ("/var/lib/secp/bootstrap/handoff/x.json", _PROV_CONTAINER, "false"),
    )
    observation = _observe(_build_fs(), _FakeRunner(inspects=(_render_inspect(mounts=mounts),)))
    assert observation.ok is False
    assert observation.handoffs_absent is False


def test_handoff_file_present_on_host_fails_closed() -> None:
    fs = _build_fs(handoff_files=(_ACT_HOST,))
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.handoffs_absent is False


def test_env_enablement_variable_fails_closed() -> None:
    env = ("PATH=/usr/local/bin", "SECP_ENROLLMENT_SIGNER_ENABLED=true")
    observation = _observe(_build_fs(), _FakeRunner(inspects=(_render_inspect(env=env),)))
    assert observation.ok is False
    assert observation.no_env_enablement is False


def test_non_socket_broker_object_fails_closed() -> None:
    fs = _build_fs(socket_regular=True)  # a regular file at the socket path, not S_ISSOCK
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_absent_broker_socket_fails_closed() -> None:
    fs = _build_fs(seed_socket=False)
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_broker_unit_bytes_mismatch_fails_closed() -> None:
    fs = _build_fs(broker_unit=b"[Unit]\nDescription=forged\n")
    observation = _observe(fs, _FakeRunner())
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_mixed_generation_second_container_fails_closed() -> None:
    runner = _FakeRunner(ps_ids=(_CID, _CID2))  # a leftover prior-generation api container
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.no_mixed_generation is False
    assert observation.api_present is False


def test_no_api_container_fails_closed() -> None:
    runner = _FakeRunner(ps_ids=())
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_present is False
    assert observation.no_mixed_generation is False


# --------------------------------------------------------------------------- never raises


def test_runner_fault_fails_closed_without_raising() -> None:
    runner = _FakeRunner(raise_on="ps")
    observation = _observe(_build_fs(), runner)  # must NOT raise
    assert observation.ok is False
    assert observation.api_present is False
    # host-only posture the runner cannot affect is still independently proven
    assert observation.broker_reachable is True
    assert observation.binding_equals_marker is True


def test_inspect_fault_fails_closed_without_raising() -> None:
    runner = _FakeRunner(raise_on="inspect")
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_present is False


# --------------------------------------------------------------------------- plane boundary


def test_module_never_imports_secp_api() -> None:
    # mirrors test_controller_finalization_wiring.test_new_production_modules_never_import_secp_api:
    # no import of secp_api and no secp_api identifier is referenced anywhere in the code (the only
    # textual occurrences are the module docstring's prose describing the boundary).
    tree = ast.parse(Path(obs_mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("secp_api") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("secp_api")
        elif isinstance(node, ast.Name):
            assert not node.id.startswith("secp_api")
        elif isinstance(node, ast.Attribute):
            assert not node.attr.startswith("secp_api")
