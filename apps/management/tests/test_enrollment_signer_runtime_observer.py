"""Hermetic proofs for the AUTHORITATIVE API signer runtime observer (SECP-PR5H-B2, 2b-3c-c, R4).

A fake pinned runner returns canned ``docker ps``/``docker inspect`` stdout, the hardened in-memory
filesystem (``seed_dir``/``seed_file``/``seed_socket``) supplies the host posture, and a fake
bounded transport returns the API's readiness bytes — so every fact the observer claims is exercised
WITHOUT a container runtime, a real host, or a live controller.

Clean-room review 4803080223 finding R4 is the subject: the observation must be bound to
INDEPENDENTLY DERIVED expectations, ``effective_signer_is_fixed_uds`` must come from the API's REAL
effective dependency (never the marker file), ``broker_reachable`` must require the RUNNING API's
completed bounded NO-SIGN probe (never a socket inode plus unit bytes), the inspected API image must
be COMPARED against the expected signed image, and ``no_mixed_generation`` must require six-way
agreement. The suite proves the fully-correct composition yields ``.ok is True``, that EACH defect
fails closed (never raises, never rubber-stamps), that a definitive readiness disagreement is never
retried, and that the module never imports ``secp_api``.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from secp_commissioning.canonical import canonical_json
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    ENROLLMENT_SIGNER_SOCKET_PATH,
)
from secp_commissioning.enrollment_signer_binding_digest import (
    active_identity_binding_digest,
    marker_binding_digest_for,
)
from secp_commissioning.enrollment_signer_marker import render_marker_bytes
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import enrollment_signer_runtime_observer as obs_mod
from secp_management.controller_compose_contract import render_broker_reviewed_unit
from secp_management.enrollment_signer_runtime_observer import (
    ApiSignerRuntimeExpectations,
    build_api_signer_runtime_observer,
)
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
    activation_token="11111111-1111-1111-1111-111111111111|2026-07-28 00:00:00+00:00",
    controller_key_id="sha256:1111111111111111111111111111111111111111111111111111111111111111",
    uds_contract_identity=ENROLLMENT_SIGNER_SOCKET_PATH,
    api_uid=10001,
    api_gid=10001,
    signer_role_name="secp_enrollment_signer",
    locator_ca_digest="sha256:" + "b" * 64,
    management_identity_digest="sha256:" + "c" * 64,
    bootstrap_evidence_digest="sha256:" + "d" * 64,
)

#: The INDEPENDENTLY DERIVED expectation the caller supplies (signed release manifest + verified
#: finalization evidence + authenticated plan + code-owned contracts). Nothing in it is read back
#: from the observation.
_EXPECTED = ApiSignerRuntimeExpectations(
    api_image_digest=_GOOD_IMAGE,
    release_digest=_MARKER.release_digest,
    installation_id=_MARKER.installation_id,
    finalization_generation=0,
    active_identity_row_id=_MARKER.active_identity_row_id,
    active_identity_activation_token=_MARKER.activation_token,
    marker=_MARKER,
    broker_unit_path=_BROKER_UNIT_PATH,
    broker_socket_path=_SOCKET_PATH,
    controller_stack_generation=0,
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
    if not overrides:
        # the CONFORMANT baseline goes through the ONE shared strict renderer.
        return render_marker_bytes(**{k: v for k, v in obj.items() if k != "schema"})
    # A hostile/drift case may carry values the fixed contract forbids (a non-reviewed UDS path, a
    # foreign schema...). Those bytes can only come from a hand-crafted file, so emit them
    # canonically WITHOUT the strict renderer — the strict PARSER refusing them is the behaviour
    # under test.
    return canonical_json(obj).encode("utf-8")


def _readiness_body(marker: ApiSignerMarker = _MARKER, **over: object) -> dict[str, object]:
    """The API's conformant readiness payload for ``marker``: a RUNNING API that resolved the
    fixed-UDS client and completed the bounded no-sign broker probe."""
    body: dict[str, object] = {
        "schema": "secp.api.enrollment-signer-readiness/v2",
        "status": "ready",
        "effective_signer": "fixed_uds",
        "signer_transport": "af_unix",
        "no_alternate_signer_activation": True,
        "process_uid": marker.api_uid,
        "process_gid": marker.api_gid,
        "marker_present": True,
        "marker_binding_matches_runtime": True,
        # v2: DIGESTS, never the raw activation token / row id / installation binding.
        "marker_binding_digest": marker_binding_digest_for(marker),
        "active_identity_binding_digest": active_identity_binding_digest(
            active_identity_row_id=marker.active_identity_row_id,
            activation_token=marker.activation_token,
            installation_id=marker.installation_id,
            release_digest=marker.release_digest,
            controller_key_id=marker.controller_key_id,
        ),
        "active_identity_present": True,
        "activation_generation": 0,
        "broker_probe": "ok",
        "broker_peer_authorized": True,
        "broker_protocol": "secp.enrollment-signer-broker/v1",
    }
    body.update(over)
    return body


class _FakeReadiness:
    """A bounded readiness transport double: a queue of ``(status, bytes)`` responses, or a raised
    fault (an unreachable controller, a TLS/CA mismatch, a deadline)."""

    def __init__(
        self,
        *,
        responses: tuple[tuple[int, bytes], ...] | None = None,
        raises: BaseException | None = None,
    ) -> None:
        if responses is None:
            responses = ((200, json.dumps(_readiness_body()).encode("utf-8")),)
        self._responses = list(responses)
        self._raises = raises
        self.calls = 0

    def __call__(self) -> tuple[int, bytes]:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return self._responses[min(self.calls - 1, len(self._responses) - 1)]


def _readiness(**over: object) -> _FakeReadiness:
    return _FakeReadiness(responses=((200, json.dumps(_readiness_body(**over)).encode("utf-8")),))


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

    def set_inspects(self, *outs: str) -> None:
        """Re-arm the ``inspect`` queue (used when one world is observed repeatedly)."""
        self._inspects = list(outs)
        self._i = 0

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


class _RecordingFilesystem(InMemoryFilesystem):
    """The same hardened in-memory backend, recording every probe it is asked for, so a test can
    prove WHICH host objects an observation genuinely touched (not merely that it returned True)."""

    def __init__(self) -> None:
        super().__init__()
        self.probes: list[tuple[str, str]] = []

    def lstat(self, path: str):  # noqa: ANN201 - the backend's own FileStat | None
        self.probes.append(("lstat", path))
        return super().lstat(path)

    def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes:
        self.probes.append(("safe_read", path))
        return super().safe_read(path, max_bytes=max_bytes, expected_uid=expected_uid)


def _seed_fs(
    fs: InMemoryFilesystem,
    *,
    marker: bytes | None = None,
    marker_obj: ApiSignerMarker = _MARKER,
    marker_mode: int = 0o644,
    seed_socket: bool = True,
    socket_regular: bool = False,
    key_mode: int = 0o600,
    cred_mode: int = 0o600,
    broker_unit: bytes | None = _BROKER_UNIT_BYTES,
    handoff_files: tuple[str, ...] = (),
) -> None:
    """Seed the host posture the observation reads. ``marker_obj`` is the candidate whose CONFORMANT
    bytes land at the fixed marker path (``marker`` overrides them with hostile/drifted bytes)."""
    for directory in (
        "/etc/secp/controller",
        "/etc/secp/controller/credentials",
        "/etc/systemd",
        "/etc/systemd/system",
    ):
        fs.seed_dir(directory)
    fs.seed_file(
        _MARKER_PATH, _marker_bytes(marker_obj) if marker is None else marker, mode=marker_mode
    )
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


def _build_fs(*, record: bool = False, **over: object) -> InMemoryFilesystem:
    fs = _RecordingFilesystem() if record else InMemoryFilesystem()
    _seed_fs(fs, **over)  # type: ignore[arg-type]
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


def _observe(  # noqa: ANN202
    fs: InMemoryFilesystem,
    runner: _FakeRunner,
    *,
    attempts: int = 1,
    readiness: _FakeReadiness | None = None,
    expected: ApiSignerRuntimeExpectations | None = _EXPECTED,
    marker: ApiSignerMarker = _MARKER,
):
    # attempts=1 + a 0s interval keeps the defect proofs instant: the bounded readiness poll is
    # exercised explicitly by the settling tests below, never implicitly by every defect case.
    return build_api_signer_runtime_observer(
        _ctx(fs, runner),
        expected=expected,
        readiness_transport=readiness if readiness is not None else _FakeReadiness(),
        readiness_attempts=attempts,
        readiness_interval_seconds=0.0,
    )(marker)


class LiveApiWorld:
    """A hermetic LIVE-API world the REAL production observer composition can be pointed at.

    The production seam (``production.PlanBoundApiSignerRuntimeObserver`` /
    ``production._runtime_observation_for``) builds its OWN readiness transport, so this world
    exposes one through :meth:`install` (a monkeypatch of the module's transport builder) and counts
    every build + fetch — that count is how a test proves the readiness surface was genuinely
    contacted rather than assumed.

    :meth:`seed_for` renders a fully COHERENT host + container-runtime + readiness world for exactly
    one candidate marker at exactly one finalization generation, so the only variable left is the
    INDEPENDENTLY DERIVED expectation the plan/installed release carries — which is what the R4
    install/upgrade/replay regressions vary. ``image`` may be a fixed digest or a callable, so a
    world can follow a stack the transaction itself switches.
    """

    def __init__(
        self,
        *,
        image: object = _GOOD_IMAGE,
        readiness_over: dict[str, object] | None = None,
        **fs_over: object,
    ) -> None:
        self._image = image
        self._readiness_over = dict(readiness_over or {})
        self._fs_over = fs_over
        self.fs = _RecordingFilesystem()
        self.runner = _FakeRunner()
        self.ctx = _ctx(self.fs, self.runner)
        self.transport_builds: list[object] = []
        self.fetches = 0
        self.seeded: list[tuple[ApiSignerMarker, int]] = []
        self._body: dict[str, object] = _readiness_body()

    def current_image(self) -> str:
        return str(self._image() if callable(self._image) else self._image)

    def seed_for(self, marker: ApiSignerMarker, *, generation: int = 0) -> None:
        _seed_fs(self.fs, marker_obj=marker, **self._fs_over)  # type: ignore[arg-type]
        self.runner.set_inspects(_render_inspect(image=self.current_image()))
        self._body = _readiness_body(
            marker, activation_generation=generation, **self._readiness_over
        )
        self.seeded.append((marker, generation))

    # ---- the readiness transport seam the production observer builds for itself ----
    def build_transport(self, ctx: object, **_kwargs: object):  # noqa: ANN202
        self.transport_builds.append(ctx)
        return self.fetch

    def fetch(self) -> tuple[int, bytes]:
        self.fetches += 1
        return 200, json.dumps(self._body).encode("utf-8")

    def install(self, monkeypatch) -> LiveApiWorld:  # noqa: ANN001
        monkeypatch.setattr(obs_mod, "build_readiness_transport", self.build_transport)
        return self


class RecordingExpectations:
    """Wraps the REAL :class:`ApiSignerRuntimeExpectations` so a test can prove exactly WHEN — and
    from what — the complete expectation is constructed. It stubs nothing: every call returns a
    genuine frozen expectation, so the observation underneath is the production observation.

    Install with ``monkeypatch.setattr(obs_mod, "ApiSignerRuntimeExpectations", recorder)``."""

    def __init__(self) -> None:
        self.built: list[dict] = []

    def __call__(self, **kwargs: object) -> ApiSignerRuntimeExpectations:
        self.built.append(dict(kwargs))
        return ApiSignerRuntimeExpectations(**kwargs)  # type: ignore[arg-type]


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


def test_without_independent_expectations_nothing_is_proven() -> None:
    """An observer with no INDEPENDENTLY DERIVED expectation must authorize nothing at all."""
    readiness = _FakeReadiness()
    observation = _observe(_build_fs(), _FakeRunner(), readiness=readiness, expected=None)
    assert observation.ok is False
    for field in (
        "api_present",
        "api_healthy",
        "effective_signer_is_fixed_uds",
        "binding_equals_marker",
        "broker_reachable",
        "no_mixed_generation",
    ):
        assert getattr(observation, field) is False, field
    assert readiness.calls == 0  # it never even reaches the controller


def test_a_candidate_marker_that_disagrees_with_the_expectation_fails_closed() -> None:
    import dataclasses

    swapped = dataclasses.replace(_MARKER, installation_id="inst-9999")
    observation = _observe(_build_fs(), _FakeRunner(), marker=swapped)
    assert observation.ok is False
    assert observation.binding_equals_marker is False
    assert observation.effective_signer_is_fixed_uds is False
    assert observation.no_mixed_generation is False


# ----------------------------------------------- R4: the effective signer is the RUNNING dependency


def test_marker_says_fixed_uds_but_the_api_effective_signer_is_sealed() -> None:
    """The R4 defect, directly: a perfect marker on disk must NOT prove the API's effective signer.
    A SEALED running API fails closed even though every marker field is exactly right."""
    observation = _observe(
        _build_fs(),
        _FakeRunner(),
        readiness=_readiness(
            effective_signer="sealed",
            signer_transport="none",
            broker_probe="not_attempted",
            broker_peer_authorized=False,
            broker_protocol="",
            status="sealed",
        ),
    )
    assert observation.ok is False
    assert observation.effective_signer_is_fixed_uds is False
    assert observation.broker_reachable is False


def test_a_fake_effective_signer_fails_closed() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_readiness(effective_signer="unavailable")
    )
    assert observation.ok is False
    assert observation.effective_signer_is_fixed_uds is False


def test_an_alternate_signer_activation_fails_closed() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_readiness(no_alternate_signer_activation=False)
    )
    assert observation.ok is False
    assert observation.effective_signer_is_fixed_uds is False


def test_a_non_af_unix_signer_transport_fails_closed() -> None:
    observation = _observe(_build_fs(), _FakeRunner(), readiness=_readiness(signer_transport="tcp"))
    assert observation.ok is False
    assert observation.effective_signer_is_fixed_uds is False


# ----------------------------------------------- R4: reachability is the RUNNING no-sign probe


def test_a_stale_socket_inode_with_no_listener_fails_closed() -> None:
    """The socket object exists and the reviewed unit bytes are installed — the OLD proof would
    have passed. The RUNNING API could not reach an accept loop, so it fails closed."""
    fs = _build_fs()  # a genuine AF_UNIX socket node is present on the host
    observation = _observe(
        fs,
        _FakeRunner(),
        readiness=_readiness(
            broker_probe="no_listener", broker_peer_authorized=False, broker_protocol=""
        ),
    )
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_an_unauthorized_broker_peer_fails_closed() -> None:
    observation = _observe(
        _build_fs(),
        _FakeRunner(),
        readiness=_readiness(
            broker_probe="peer_unauthorized", broker_peer_authorized=False, broker_protocol=""
        ),
    )
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_a_foreign_broker_protocol_identity_fails_closed() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_readiness(broker_protocol="rogue/v9")
    )
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_expectations_must_name_the_reviewed_socket_and_unit_contract() -> None:
    import dataclasses

    for drift in (
        dataclasses.replace(_EXPECTED, broker_socket_path="/run/secp/rogue.sock"),
        dataclasses.replace(_EXPECTED, broker_unit_path="/etc/systemd/system/rogue.service"),
    ):
        observation = _observe(_build_fs(), _FakeRunner(), expected=drift)
        assert observation.ok is False
        assert observation.broker_reachable is False


# ----------------------------------------------- R4: the inspected image is COMPARED


def test_wrong_api_image_fails_closed() -> None:
    """The inspected image was previously parsed and then IGNORED. A running container on an image
    that is not the expected SIGNED api image now refuses."""
    runner = _FakeRunner(inspects=(_render_inspect(image=_OTHER_IMAGE),))
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.no_mixed_generation is False


def test_prior_image_with_the_candidate_marker_fails_closed() -> None:
    """The upgrade hazard: the NEW marker is in place and the API answers readiness, but the
    container is still the PRIOR release's image. Six-way agreement refuses it."""
    import dataclasses

    prior = "sha256:" + "9" * 64
    runner = _FakeRunner(inspects=(_render_inspect(image=prior),))
    expected = dataclasses.replace(_EXPECTED, api_image_digest=_GOOD_IMAGE)
    observation = _observe(_build_fs(), runner, expected=expected)
    assert observation.ok is False
    assert observation.no_mixed_generation is False
    # the marker/binding half is untouched: the refusal is specifically the generation disagreement
    assert observation.binding_equals_marker is True
    assert observation.effective_signer_is_fixed_uds is True


def test_an_unproven_expected_image_can_never_authorize_an_inspected_one() -> None:
    import dataclasses

    observation = _observe(
        _build_fs(), _FakeRunner(), expected=dataclasses.replace(_EXPECTED, api_image_digest="")
    )
    assert observation.ok is False
    assert observation.no_mixed_generation is False


# ----------------------------------------------- R4: six-way generation agreement


def test_generation_disagreement_fails_closed() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_readiness(activation_generation=1)
    )
    assert observation.ok is False
    assert observation.no_mixed_generation is False


def test_controller_stack_generation_disagreement_fails_closed() -> None:
    import dataclasses

    observation = _observe(
        _build_fs(),
        _FakeRunner(),
        expected=dataclasses.replace(_EXPECTED, controller_stack_generation=1),
    )
    assert observation.ok is False
    assert observation.no_mixed_generation is False


# ------------------------------------- R4/E: finalization <-> controller-stack generation binding

_OBSERVATION_FIELDS: tuple[str, ...] = (
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
)


def _generation_case(*, finalization: int, stack: int, live: int):  # noqa: ANN202
    """One generation world: the INDEPENDENTLY DERIVED expectation's finalization + controller-stack
    generations against the generation the RUNNING API reports. Everything else is the conformant
    baseline, so a refusal can only ever be the generation binding."""
    import dataclasses

    expected = dataclasses.replace(
        _EXPECTED, finalization_generation=finalization, controller_stack_generation=stack
    )
    return _observe(
        _build_fs(),
        _FakeRunner(),
        expected=expected,
        readiness=_readiness(activation_generation=live),
    )


def test_matching_finalization_and_controller_stack_generations_are_proven() -> None:
    for generation in (0, 1, 7):
        observation = _generation_case(finalization=generation, stack=generation, live=generation)
        assert observation.ok is True, generation
        assert observation.no_mixed_generation is True, generation


def test_a_stale_finalization_generation_fails_closed() -> None:
    # the authenticated plan/evidence still claims N while the RUNNING API has moved to N+1 ...
    behind = _generation_case(finalization=0, stack=0, live=1)
    assert behind.ok is False
    assert behind.no_mixed_generation is False
    # ... and the mirror image (the expectation ahead of the API that is actually serving)
    ahead = _generation_case(finalization=1, stack=1, live=0)
    assert ahead.ok is False
    assert ahead.no_mixed_generation is False


def test_a_stale_controller_stack_generation_fails_closed() -> None:
    # the identity / marker / readiness world is coherently at generation 1, but the controller
    # STACK that was applied AND proven before finalization is still generation 0 -> mixed.
    stale_stack = _generation_case(finalization=1, stack=0, live=1)
    assert stale_stack.ok is False
    assert stale_stack.no_mixed_generation is False
    # a stack AHEAD of the finalization is equally a mixed generation
    ahead_stack = _generation_case(finalization=0, stack=1, live=0)
    assert ahead_stack.ok is False
    assert ahead_stack.no_mixed_generation is False


def test_an_unproven_generation_can_never_authorize() -> None:
    for finalization, stack in ((-1, -1), (-1, 0), (0, -1)):
        observation = _generation_case(finalization=finalization, stack=stack, live=-1)
        assert observation.ok is False, (finalization, stack)
        assert observation.no_mixed_generation is False, (finalization, stack)


def test_the_marker_world_alone_cannot_override_the_expected_stack_generation() -> None:
    """The marker on disk carries NO generation and the API's own readiness can be coherently at
    generation N — neither may stand in for the INDEPENDENTLY expected controller-stack generation.
    The ONLY difference between the proven and the refused world is that one expectation field."""
    proven = _generation_case(finalization=1, stack=1, live=1)
    refused = _generation_case(finalization=1, stack=0, live=1)
    assert proven.ok is True
    assert refused.ok is False
    assert refused.no_mixed_generation is False
    for field in _OBSERVATION_FIELDS:
        if field == "no_mixed_generation":
            continue
        assert getattr(refused, field) is True, field
        assert getattr(proven, field) is True, field


def test_active_identity_disagreement_fails_closed() -> None:
    for over in (
        {"active_identity_row_id": "43"},
        {"active_identity_activation_token": "43|2026-07-28 00:00:00+00:00"},
        {"active_identity_release_digest": "sha256:" + "9" * 64},
        {"active_identity_installation_id": "inst-9999"},
        {"active_identity_present": False},
    ):
        observation = _observe(_build_fs(), _FakeRunner(), readiness=_readiness(**over))
        assert observation.ok is False, over
        assert observation.no_mixed_generation is False, over


def test_expected_release_disagreement_fails_closed() -> None:
    import dataclasses

    observation = _observe(
        _build_fs(),
        _FakeRunner(),
        expected=dataclasses.replace(_EXPECTED, release_digest="sha256:" + "9" * 64),
    )
    assert observation.ok is False
    assert observation.no_mixed_generation is False


def test_the_marker_the_running_api_loaded_must_be_the_candidate() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_readiness(marker_activation_token="43|x")
    )
    assert observation.ok is False
    assert observation.binding_equals_marker is False


def test_a_running_api_on_a_different_peer_than_the_marker_binds_fails_closed() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_readiness(process_uid=0, process_gid=0)
    )
    assert observation.ok is False
    assert observation.binding_equals_marker is False


# ----------------------------------------------- the readiness transport itself


def test_a_tls_or_ca_mismatch_fails_closed() -> None:
    import ssl

    readiness = _FakeReadiness(raises=ssl.SSLCertVerificationError("CA mismatch"))
    observation = _observe(_build_fs(), _FakeRunner(), readiness=readiness)
    assert observation.ok is False
    assert observation.effective_signer_is_fixed_uds is False
    assert observation.broker_reachable is False
    assert observation.no_mixed_generation is False
    # host-only posture the controller cannot affect is still independently observed
    assert observation.api_present is True and observation.api_healthy is True


def test_a_readiness_timeout_fails_closed() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_FakeReadiness(raises=TimeoutError("deadline"))
    )
    assert observation.ok is False
    assert observation.effective_signer_is_fixed_uds is False
    assert observation.broker_reachable is False


def test_a_non_200_readiness_response_fails_closed() -> None:
    readiness = _FakeReadiness(responses=((503, b'{"error":{"code":"unavailable"}}'),))
    observation = _observe(_build_fs(), _FakeRunner(), readiness=readiness)
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_a_malformed_readiness_response_fails_closed() -> None:
    for raw in (
        b"not json",
        b"[]",
        json.dumps({"schema": "secp.api.enrollment-signer-readiness/v1"}).encode(),
        json.dumps({**_readiness_body(), "extra": 1}).encode(),
        json.dumps({k: v for k, v in _readiness_body().items() if k != "status"}).encode(),
        json.dumps({**_readiness_body(), "schema": "secp.api.x/v2"}).encode(),
        json.dumps({**_readiness_body(), "broker_peer_authorized": 1}).encode(),
        json.dumps({**_readiness_body(), "activation_generation": "0"}).encode(),
        json.dumps({**_readiness_body(), "effective_signer": "x" * 300}).encode(),
    ):
        observation = _observe(
            _build_fs(), _FakeRunner(), readiness=_FakeReadiness(responses=((200, raw),))
        )
        assert observation.ok is False, raw[:40]
        assert observation.effective_signer_is_fixed_uds is False, raw[:40]
        assert observation.broker_reachable is False, raw[:40]
        assert observation.no_mixed_generation is False, raw[:40]


def test_readiness_bytes_are_bounded() -> None:
    oversize = json.dumps({**_readiness_body(), "status": "ready"}).encode() + b" " * 32768
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_FakeReadiness(responses=((200, oversize),))
    )
    assert observation.ok is False


def test_the_transport_is_ca_pinned_and_env_free() -> None:
    """The default transport must reach the API only over the bootstrap-recorded origin with the
    installed CA pinned, at the FIXED path, with no ambient env/proxy and no redirect following."""
    source = Path(obs_mod.__file__).read_text(encoding="utf-8")
    assert 'API_READINESS_PATH = "/internal/enrollment-signer/readiness"' in source
    assert "ssl.create_default_context(cafile=locator.ca_bundle_path)" in source
    assert "trust_env=False" in source
    assert "follow_redirects=False" in source
    assert "verify=ssl_context" in source
    # no caller-selected URL/CA anywhere: the locator is the sole source
    assert "canonical_origin + API_READINESS_PATH" in source


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


def test_a_settling_api_whose_readiness_surface_is_not_up_yet_is_retried() -> None:
    """While the container is genuinely 'starting' its readiness surface may not be serving; that —
    and only that — is retried, and the observation succeeds once the API answers."""
    starting = _render_inspect(health="starting")
    healthy = _render_inspect(health="healthy")
    runner = _FakeRunner(inspects=(starting, starting, healthy, healthy))
    readiness = _FakeReadiness(
        responses=((503, b""), (200, json.dumps(_readiness_body()).encode("utf-8")))
    )
    observation = _observe(_build_fs(), runner, attempts=5, readiness=readiness)
    assert observation.ok is True
    assert readiness.calls == 2


def test_a_definitive_readiness_disagreement_is_never_retried() -> None:
    """A response that WAS obtained and disagreed is definitive: the poll must not burn its budget
    waiting for a sealed API to change its mind."""
    starting = _render_inspect(health="starting")
    readiness = _FakeReadiness(
        responses=((200, json.dumps(_readiness_body(effective_signer="sealed")).encode()),)
    )
    observation = _observe(
        _build_fs(), _FakeRunner(inspects=(starting,)), attempts=5, readiness=readiness
    )
    assert observation.ok is False
    assert readiness.calls == 1  # exactly ONE sample


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
    assert observation.effective_signer_is_fixed_uds is False


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
    # the byte-exact code-rendered unit is what proves there is NO TCP listener
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
    # host + readiness posture the runner cannot affect is still independently proven
    assert observation.broker_reachable is True
    assert observation.binding_equals_marker is True


def test_inspect_fault_fails_closed_without_raising() -> None:
    runner = _FakeRunner(raise_on="inspect")
    observation = _observe(_build_fs(), runner)
    assert observation.ok is False
    assert observation.api_present is False


def test_a_readiness_transport_that_explodes_never_raises() -> None:
    observation = _observe(
        _build_fs(), _FakeRunner(), readiness=_FakeReadiness(raises=RuntimeError("boom"))
    )
    assert observation.ok is False


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
