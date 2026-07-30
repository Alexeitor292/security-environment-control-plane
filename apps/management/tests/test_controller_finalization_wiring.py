"""Fixed layout / systemd / compose-contract / composition wiring for finalization (2b-3b-iii).

Proves the fixed paths (broker unit through the strict unit authority; handoffs under an owned root;
marker/locator; /run byte-match to the commissioning + API planes), the broker unit's LoadCredential
+ fixed entrypoint + present-but-disabled AF_UNIX rendering, the one-shot RO mount matrix + the
no-secret-reaches-the-ordinary-API guard, and that the REAL finalization adapter is composed ONLY by
the root-gated install composer while a bare EngineDeps + the steady-state composer stay SEALED.

SECP-PR5H-B2 2b-3c-c finding **R4** adds the PRODUCTION RUNTIME-OBSERVATION composition to that
subject. These proofs never build the observer helper directly: they drive
``build_real_finalization_factory`` (the install seam) and ``_runtime_observation_for`` (the replay
/ upgrade-eligibility seam) against the shared hermetic live-API world, so what is under test is the
composition the root-only installer actually wires — the plan-bound observer, the DEFERRED complete
``ApiSignerRuntimeExpectations``, and the architectural rule that no production-capable factory may
ever build an observer without one.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    ENROLLMENT_SIGNER_SOCKET_PATH,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError, production
from secp_management import controller_compose_contract as cc
from secp_management import enrollment_signer_runtime_observer as obs_mod
from secp_management.controller_finalization import RealControllerEnrollmentFinalizationAdapter
from secp_management.controller_finalization_state import (
    CONTROLLER_STATE_BROKER_UNREACHABLE,
    CONTROLLER_STATE_REASONS,
    ControllerStateContext,
    ExpectedControllerState,
    build_controller_finalization_state_observer,
)
from secp_management.engine import EngineDeps
from secp_management.enrollment_signer_db import ENROLLMENT_SIGNER_CREDENTIAL_ID
from secp_management.enrollment_signer_runtime_observer import ApiSignerRuntimeExpectations
from secp_management.finalization import (
    ControllerEnrollmentFinalizationPlan,
    ReviewedSignerRole,
    SealedControllerEnrollmentFinalizationAdapter,
)
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_management.release_bundle import ControllerTlsPolicy
from secp_management.systemd import render_enrollment_signer_broker_service
from secp_management.topology import BROKER_ENTRYPOINT
from test_enrollment_signer_runtime_observer import (
    _GOOD_IMAGE,
    _MARKER,
    _OTHER_IMAGE,
    LiveApiWorld,
    RecordingExpectations,
)

_LOC = ManagementLocations()


# ---- layout -----------------------------------------------------------------------------------
def test_broker_unit_path_goes_only_through_the_strict_unit_authority():
    assert _LOC.broker_unit_path() == "/etc/systemd/system/secp-enrollment-signer-broker.service"
    _LOC.assert_unit_writable(_LOC.broker_unit_path())  # permitted
    _LOC.assert_unit_writable(_LOC.controller_unit_path())
    with pytest.raises(ManagementError) as e:
        _LOC.assert_unit_writable("/etc/systemd/system/evil.service")
    assert e.value.reason_code == "layout_unit_path_not_fixed"


def test_handoff_host_paths_are_owned_and_container_paths_are_not():
    _LOC.assert_writable(_LOC.provisioning_handoff_host_path())  # under bootstrap_state (owned)
    _LOC.assert_writable(_LOC.activation_handoff_host_path())
    for p in (_LOC.provisioning_handoff_container_path(), _LOC.activation_handoff_container_path()):
        with pytest.raises(ManagementError) as e:
            _LOC.assert_writable(p)  # /run/secp/... is never installer-writable
        assert e.value.reason_code == "layout_path_not_owned"


def test_marker_and_locator_paths_are_fixed_and_owned():
    assert _LOC.api_signer_marker_path() == "/etc/secp/controller/enrollment-signer.enabled"
    assert _LOC.controller_api_locator_path() == "/etc/secp/controller/api-locator.json"
    _LOC.assert_writable(_LOC.api_signer_marker_path())
    _LOC.assert_writable(_LOC.controller_api_locator_path())


def test_run_and_container_paths_byte_match_the_other_planes():
    # management may not import secp_api in PRODUCTION; a test may, to prove the fixed literals
    # match.
    from secp_api.activate_controller_identity_once import HANDOFF_PATH as ACT
    from secp_api.enrollment_signer_marker import MARKER_PATH
    from secp_api.provision_enrollment_signer_role_once import HANDOFF_PATH as PROV

    assert _LOC.broker_socket_path() == ENROLLMENT_SIGNER_SOCKET_PATH
    assert _LOC.provisioning_handoff_container_path() == PROV
    assert _LOC.activation_handoff_container_path() == ACT
    assert _LOC.api_signer_marker_path() == MARKER_PATH


# ---- systemd broker unit ----------------------------------------------------------------------
def test_broker_unit_renders_loadcredential_entrypoint_and_stays_disabled():
    text = render_enrollment_signer_broker_service(
        exec_argv=BROKER_ENTRYPOINT,
        load_credential=(ENROLLMENT_SIGNER_CREDENTIAL_ID, _LOC.enrollment_signer_credential_path()),
    )
    assert "ExecStart=" + " ".join(BROKER_ENTRYPOINT) in text
    assert (
        f"LoadCredential={ENROLLMENT_SIGNER_CREDENTIAL_ID}:"
        f"{_LOC.enrollment_signer_credential_path()}" in text
    )
    assert "RestrictAddressFamilies=AF_UNIX" in text and "AF_INET" not in text
    assert "User=root" in text and "[Install]" not in text  # present-but-disabled, no TCP


def test_broker_credential_id_is_grammar_checked():
    with pytest.raises(ManagementError) as e:
        render_enrollment_signer_broker_service(
            exec_argv=BROKER_ENTRYPOINT, load_credential=("bad:id", "/etc/secp/x")
        )
    assert e.value.reason_code == "systemd_credential_id_unclean"


# ---- compose contract -------------------------------------------------------------------------
def test_one_shot_mounts_are_read_only_and_the_marker_is_host_equals_container():
    prov = cc.provisioning_oneshot_mount(_LOC)
    act = cc.activation_oneshot_mount(_LOC)
    marker = cc.api_marker_mount(_LOC)
    assert prov.read_only and act.read_only and marker.read_only
    assert prov.as_compose_volume().endswith(":ro")
    assert marker.host_path == marker.container_path == _LOC.api_signer_marker_path()


def test_no_secret_reaches_the_ordinary_api_guard():
    # the ordinary API's ONLY finalization mount (the marker) is safe
    cc.assert_no_secret_reaches_ordinary_api((cc.api_marker_mount(_LOC).host_path,), locations=_LOC)
    # every secret-bearing host path is refused
    for secret in (
        CONTROLLER_ENROLLMENT_KEY_PATH,
        _LOC.controller_server_key_path(),
        _LOC.enrollment_signer_credential_path(),
        _LOC.provisioning_handoff_host_path(),
        _LOC.activation_handoff_host_path(),
    ):
        with pytest.raises(ManagementError) as e:
            cc.assert_no_secret_reaches_ordinary_api((secret,), locations=_LOC)
        assert e.value.reason_code == "finalization_secret_mount_reaches_api"


def test_render_broker_reviewed_unit_is_content_bound():
    unit = cc.render_broker_reviewed_unit(_LOC)
    unit.verify()  # identity == sha256(content)
    assert b"LoadCredential=" in unit.content and b"[Install]" not in unit.content


# ---- production composition -------------------------------------------------------------------
def test_bare_engine_deps_and_steady_state_keep_finalization_sealed():
    assert isinstance(
        EngineDeps().finalization_adapter, SealedControllerEnrollmentFinalizationAdapter
    )


def test_build_real_finalization_adapter_returns_the_real_leaf():
    d = "sha256:" + "0" * 64
    from secp_operator_deployment.pinned_exec import ExecutablePin

    p = ExecutablePin(path="/usr/bin/docker", digest=d)
    ctx = RealAdapterContext(
        locations=_LOC,
        fs=InMemoryFilesystem(),
        runner=object(),
        executables=PinnedExecutables(container_runtime=p, compose_runtime=p, service_manager=p),
    )
    adapter = production.build_real_controller_finalization_adapter(ctx)
    assert isinstance(adapter, RealControllerEnrollmentFinalizationAdapter)


def test_install_composer_is_root_gated_first(monkeypatch):
    import secp_management.controller_install as ci

    def _no_root():
        raise ManagementError("controller_install_requires_posix_root")

    monkeypatch.setattr(ci, "assert_posix_root", _no_root)
    with pytest.raises(ManagementError) as e:
        production.controller_install_engine_deps()
    assert e.value.reason_code == "controller_install_requires_posix_root"


# ---- R4: the PRODUCTION runtime-observation composition ----------------------------------------

_R4_ORIGIN = "https://controller.secp.example:8443"
_R4_POLICY = ControllerTlsPolicy(
    allowed_modes=("generated_local_ca", "imported_enterprise_tls"),
    key_algorithm="ecdsa-p256",
    signature_algorithm="ecdsa-with-sha256",
    max_validity_days=825,
    require_san=True,
    server_auth_eku_required=True,
    ca_pathlen_zero=True,
    min_tls_version="1.3",
    allow_ip_origin=False,
    allow_generated_local_ca=True,
)


def _r4_plan(**over) -> ControllerEnrollmentFinalizationPlan:  # noqa: ANN003
    """An already-authenticated finalization plan carrying the R4 static expectations, coherent
    with the hermetic world's candidate marker. ``expected_api_image_digest`` is the SIGNED
    controller/api image the engine derives from the verified release
    (``_expected_api_image_digest``)."""
    plan = ControllerEnrollmentFinalizationPlan(
        role="controller",
        tls_policy=_R4_POLICY,
        canonical_origin=_R4_ORIGIN,
        tls_mode="generated_local_ca",
        signer_role=ReviewedSignerRole(
            role_name=_MARKER.signer_role_name,
            credential_source_path=_LOC.enrollment_signer_credential_path(),
        ),
        broker_unit=cc.render_broker_reviewed_unit(_LOC),
        controller_installation_id=_MARKER.installation_id,
        release_digest=_MARKER.release_digest,
        management_identity_digest=_MARKER.management_identity_digest,
        bootstrap_evidence_digest=_MARKER.bootstrap_evidence_digest,
        generation=0,
        expected_api_image_digest=_GOOD_IMAGE,
        controller_stack_generation=0,
    )
    return dataclasses.replace(plan, **over) if over else plan


def _r4_expected_state(**over) -> ExpectedControllerState:  # noqa: ANN003
    """The AUTHENTICATED installed state a replay / upgrade-eligibility check already proved (the
    verified evidence extension + identity + signed release), which is the only thing the replay
    observation seam is allowed to derive its expectation from."""
    expected = ExpectedControllerState(
        generation=0,
        installation_id=_MARKER.installation_id,
        release_digest=_MARKER.release_digest,
        controller_key_id=_MARKER.controller_key_id,
        active_identity_row_id=_MARKER.active_identity_row_id,
        management_identity_digest=_MARKER.management_identity_digest,
        bootstrap_binding_digest=_MARKER.bootstrap_evidence_digest,
        enrollment_key_proof_id="enrkp:" + "5" * 64,
        locator_ca_digest=_MARKER.locator_ca_digest,
        api_image_digest=_GOOD_IMAGE,
    )
    return dataclasses.replace(expected, **over) if over else expected


def _composed_observer(ctx, plan):  # noqa: ANN001, ANN202
    """The observer PRODUCTION composes for an install: the plan-bound single-use factory builds the
    real adapter, and the adapter's runtime seam IS the plan-bound observer. Never the helper."""
    adapter = production.build_real_finalization_factory(ctx)(plan)
    assert isinstance(adapter, RealControllerEnrollmentFinalizationAdapter)
    observer = adapter._ctx.runtime_observer
    assert isinstance(observer, production.PlanBoundApiSignerRuntimeObserver)
    assert observer.plan is plan  # bound to exactly this authenticated plan
    assert observer.ctx is ctx  # and to the fixed production host context
    return observer


# --- A. the correct signed image is proven through the production composition -------------------


def test_production_composition_proves_the_correct_signed_api_image(monkeypatch):
    world = LiveApiWorld().install(monkeypatch)
    world.seed_for(_MARKER, generation=0)
    plan = _r4_plan()
    recorder = RecordingExpectations()
    monkeypatch.setattr(obs_mod, "ApiSignerRuntimeExpectations", recorder)

    observer = _composed_observer(world.ctx, plan)

    # DEFERRAL: composing the factory + the plan-bound observer builds NO expectation, opens no
    # transport and contacts nothing. The complete expectation exists only once observe(marker) runs
    # AFTER activation, because only then do the post-activation facts exist.
    assert recorder.built == []
    assert world.transport_builds == [] and world.fetches == 0

    observation = observer(_MARKER)

    assert observation.ok is True
    # built EXACTLY once, and only inside observe(marker)
    assert len(recorder.built) == 1
    kw = recorder.built[0]
    # independently authenticated STATIC facts come from the plan / signed release ...
    assert kw["api_image_digest"] == plan.expected_api_image_digest == _GOOD_IMAGE
    assert kw["release_digest"] == plan.release_digest
    assert kw["installation_id"] == plan.controller_installation_id
    assert kw["finalization_generation"] == plan.generation
    assert kw["controller_stack_generation"] == plan.controller_stack_generation
    # ... the fixed code-owned contracts from the locations authority ...
    assert kw["broker_unit_path"] == _LOC.broker_unit_path()
    assert kw["broker_socket_path"] == _LOC.broker_socket_path()
    # ... and ONLY the genuinely post-activation facts from the candidate marker
    assert kw["marker"] is _MARKER
    assert kw["active_identity_row_id"] == _MARKER.active_identity_row_id
    assert kw["active_identity_activation_token"] == _MARKER.activation_token

    # the READINESS surface was genuinely fetched over the composed transport seam ...
    assert world.transport_builds == [world.ctx]
    assert world.fetches == 1
    # ... and the AF_UNIX broker object + the byte-exact reviewed unit were genuinely probed on the
    # host (the structural half of the R4 broker proof)
    assert ("lstat", _LOC.broker_socket_path()) in world.fs.probes
    assert ("safe_read", _LOC.broker_unit_path()) in world.fs.probes

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


def test_production_composition_requires_a_genuine_af_unix_broker_object(monkeypatch):
    # the same coherent world, except the object at the fixed socket path is a regular file: the
    # structural AF_UNIX probe really is consulted, so reachability is not proven.
    world = LiveApiWorld(socket_regular=True).install(monkeypatch)
    world.seed_for(_MARKER, generation=0)
    observation = _composed_observer(world.ctx, _r4_plan())(_MARKER)
    assert observation.ok is False
    assert observation.broker_reachable is False


def test_production_composition_requires_the_running_apis_completed_no_sign_probe(monkeypatch):
    # the host-side socket + unit are perfect; the RUNNING API never completed the bounded no-sign
    # exchange, so the readiness answer really is consulted too.
    world = LiveApiWorld(
        readiness_over={
            "broker_probe": "no_listener",
            "broker_peer_authorized": False,
            "broker_protocol": "",
        }
    ).install(monkeypatch)
    world.seed_for(_MARKER, generation=0)
    observation = _composed_observer(world.ctx, _r4_plan())(_MARKER)
    assert observation.ok is False
    assert observation.broker_reachable is False
    assert world.fetches >= 1


# --- B (observation half). a wrong LIVE image refuses ---------------------------------------------


def test_production_composition_refuses_a_wrong_live_api_image(monkeypatch):
    world = LiveApiWorld(image=_OTHER_IMAGE).install(monkeypatch)
    world.seed_for(_MARKER, generation=0)
    observation = _composed_observer(world.ctx, _r4_plan())(_MARKER)
    assert observation.ok is False
    assert observation.no_mixed_generation is False


# --- C. a wrong SIGNED expectation refuses although the runtime is unchanged ----------------------


def test_a_wrong_signed_expectation_refuses_an_unchanged_runtime(monkeypatch):
    """R4's whole point: the observation is bound to RELEASE AUTHORITY, not to Docker's own account
    of itself. Altering ONLY the plan's signed image expectation — with the running container, the
    marker, the host and the readiness answer all untouched — must refuse."""
    world = LiveApiWorld().install(monkeypatch)
    world.seed_for(_MARKER, generation=0)

    proven = _composed_observer(world.ctx, _r4_plan())(_MARKER)
    refused = _composed_observer(world.ctx, _r4_plan(expected_api_image_digest=_OTHER_IMAGE))(
        _MARKER
    )

    assert proven.ok is True
    assert refused.ok is False
    assert refused.no_mixed_generation is False
    # nothing about the observed world changed, so every other invariant is untouched
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
    ):
        assert getattr(refused, field) is True, field


# --- D. no production-capable composition may build an UNBOUND observer ---------------------------


def _callee_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def test_every_production_capable_observer_call_passes_a_complete_expectation():
    """An ARCHITECTURAL regression (no line numbers): every ``build_api_signer_runtime_observer``
    call in the production composer must pass ``expected=``, except the ONE documented unbound
    fail-closed field at ``ControllerStateContext.runtime_observer`` — which is superseded by the
    expectation-bound ``runtime_observer_for`` seam and can prove nothing on its own."""
    tree = ast.parse(Path(production.__file__).read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _callee_name(node.func) == "build_api_signer_runtime_observer"
    ]
    assert len(calls) >= 3  # the install seam, the replay seam, and the documented unbound field

    unbound = [c for c in calls if not any(kw.arg == "expected" for kw in c.keywords)]
    documented = [
        kw.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _callee_name(node.func) == "ControllerStateContext"
        for kw in node.keywords
        if kw.arg == "runtime_observer"
    ]
    assert len(documented) == 1
    # the ONLY unbound construction anywhere in production.py is that documented field
    assert [id(c) for c in unbound] == [id(documented[0])]
    # and no bound call may pass a literal None expectation
    for call in calls:
        for kw in call.keywords:
            if kw.arg == "expected":
                assert not (isinstance(kw.value, ast.Constant) and kw.value.value is None)


def test_driving_the_production_seams_always_supplies_a_complete_expectation(monkeypatch):
    """The structural rule above, proven by DRIVING both production-capable seams: each observation
    receives a non-None expectation whose every field is genuinely populated."""
    seen: list[object] = []
    real = obs_mod.build_api_signer_runtime_observer

    def _spy(ctx, *, expected=None, **kwargs):  # noqa: ANN001, ANN003, ANN202
        seen.append(expected)
        return real(ctx, expected=expected, **kwargs)

    monkeypatch.setattr(obs_mod, "build_api_signer_runtime_observer", _spy)
    world = LiveApiWorld().install(monkeypatch)
    world.seed_for(_MARKER, generation=0)

    assert _composed_observer(world.ctx, _r4_plan())(_MARKER).ok is True  # the install seam
    assert (
        production._runtime_observation_for(world.ctx)(_r4_expected_state(), _MARKER).ok is True
    )  # the replay / upgrade-eligibility seam

    assert len(seen) == 2
    for expected in seen:
        assert expected is not None
        assert isinstance(expected, ApiSignerRuntimeExpectations)
        assert expected.api_image_digest.startswith("sha256:")
        assert len(expected.api_image_digest) == 71
        assert expected.release_digest and expected.installation_id
        assert expected.active_identity_row_id and expected.active_identity_activation_token
        assert expected.marker is _MARKER
        assert expected.broker_unit_path == _LOC.broker_unit_path()
        assert expected.broker_socket_path == _LOC.broker_socket_path()
        assert expected.finalization_generation >= 0
        assert expected.controller_stack_generation == expected.finalization_generation


# --- G. the exact REPLAY path ---------------------------------------------------------------------


def test_replay_builds_a_complete_expectation_from_the_authenticated_installed_release(monkeypatch):
    recorder = RecordingExpectations()
    monkeypatch.setattr(obs_mod, "ApiSignerRuntimeExpectations", recorder)
    world = LiveApiWorld().install(monkeypatch)
    world.seed_for(_MARKER, generation=0)

    observation = production._runtime_observation_for(world.ctx)(_r4_expected_state(), _MARKER)

    assert observation.ok is True
    assert len(recorder.built) == 1
    kw = recorder.built[0]
    # the AUTHENTICATED installed release's signed api image + identity facts ...
    assert kw["api_image_digest"] == _GOOD_IMAGE
    assert kw["release_digest"] == _MARKER.release_digest
    assert kw["installation_id"] == _MARKER.installation_id
    assert kw["active_identity_row_id"] == _MARKER.active_identity_row_id
    # ... the CURRENT live generation, bound to the stack generation ...
    assert kw["finalization_generation"] == 0
    assert kw["controller_stack_generation"] == 0
    # ... the fixed code-owned contracts, and from the marker ONLY the post-activation token
    assert kw["broker_unit_path"] == _LOC.broker_unit_path()
    assert kw["broker_socket_path"] == _LOC.broker_socket_path()
    assert kw["active_identity_activation_token"] == _MARKER.activation_token
    assert kw["marker"] is _MARKER
    assert world.fetches == 1  # replay genuinely contacted the API's readiness surface


def test_replay_still_refuses_every_live_signer_defect(monkeypatch):
    cases = (
        (
            "dead broker",
            {
                "readiness_over": {
                    "broker_probe": "no_listener",
                    "broker_peer_authorized": False,
                    "broker_protocol": "",
                }
            },
            "broker_reachable",
        ),
        (
            "sealed readiness surface",
            {
                "readiness_over": {
                    "status": "sealed",
                    "effective_signer": "sealed",
                    "signer_transport": "none",
                }
            },
            "effective_signer_is_fixed_uds",
        ),
        (
            "wrong active identity",
            {"readiness_over": {"active_identity_row_id": "9999"}},
            "no_mixed_generation",
        ),
        ("stale socket", {"socket_regular": True}, "broker_reachable"),
        ("wrong image", {"image": _OTHER_IMAGE}, "no_mixed_generation"),
    )
    for label, over, field in cases:
        world = LiveApiWorld(**over)
        monkeypatch.setattr(obs_mod, "build_readiness_transport", world.build_transport)
        world.seed_for(_MARKER, generation=0)
        observation = production._runtime_observation_for(world.ctx)(_r4_expected_state(), _MARKER)
        assert observation.ok is False, label
        assert getattr(observation, field) is False, label


def test_replay_state_observer_prefers_the_expectation_bound_runtime_seam(monkeypatch):
    """The live-state observer the engine consults before a replay/upgrade must take its runtime
    observation through the EXPECTATION-BOUND seam; the unbound fail-closed field must never be
    consulted when the bound one is composed."""
    world = LiveApiWorld().install(monkeypatch)
    world.seed_for(_MARKER, generation=0)
    bound_seam = production._runtime_observation_for(world.ctx)
    unbound_calls: list[object] = []
    bound_calls: list[tuple[object, object]] = []

    def _unbound(marker):  # noqa: ANN001, ANN202
        unbound_calls.append(marker)
        raise AssertionError("the unbound observer must never be consulted in production")

    def _bound(expected, marker):  # noqa: ANN001, ANN202
        bound_calls.append((expected, marker))
        return bound_seam(expected, marker)

    state_ctx = ControllerStateContext(
        host=world.ctx,
        runtime_observer=_unbound,
        runtime_observer_for=_bound,
        generation_probe=lambda: 0,
    )
    expected = _r4_expected_state()
    state = build_controller_finalization_state_observer(state_ctx)(expected=expected)

    assert unbound_calls == []
    assert len(bound_calls) == 1
    assert bound_calls[0][0] is expected  # bound to the AUTHENTICATED expectation, not the marker
    assert bound_calls[0][1].activation_token == _MARKER.activation_token
    # the R4 observation is what credits the live-API half of a replay
    assert state.runtime_observed is True
    assert state.api_live is True
    assert state.api_unsealed is True
    # the remaining live proofs (broker unit activity, credential, dedicated role, DB lease) are not
    # modelled by this hermetic world and are independently tested, so replay still refuses — with a
    # bounded code from the closed set, never a pass.
    reason = state.refusal_reason(expected)
    assert reason in CONTROLLER_STATE_REASONS
    assert reason == CONTROLLER_STATE_BROKER_UNREACHABLE


def test_replay_refuses_when_the_bound_runtime_observation_fails_closed(monkeypatch):
    # the same world with a WRONG signed image expectation: the runtime observation is fail-closed,
    # so the live-API half of the replay state is credited with nothing.
    world = LiveApiWorld(image=_OTHER_IMAGE).install(monkeypatch)
    world.seed_for(_MARKER, generation=0)
    bound_seam = production._runtime_observation_for(world.ctx)
    state_ctx = ControllerStateContext(
        host=world.ctx,
        runtime_observer=lambda marker: (_ for _ in ()).throw(AssertionError("unbound")),
        runtime_observer_for=bound_seam,
        generation_probe=lambda: 0,
    )
    expected = _r4_expected_state()
    state = build_controller_finalization_state_observer(state_ctx)(expected=expected)
    assert state.generation_agrees is False  # no_mixed_generation was refused
    assert state.api_image_expected is False
    assert state.refusal_reason(expected) in CONTROLLER_STATE_REASONS


# ---- plane boundary ---------------------------------------------------------------------------
def test_new_production_modules_never_import_secp_api():
    pkg = Path(production.__file__).parent
    for name in (
        "controller_finalization.py",
        "controller_compose_contract.py",
        "enrollment_signer_broker_serve.py",
        "production.py",
        "layout.py",
        "systemd.py",
        "topology.py",
        "enrollment_signer_db.py",
    ):
        tree = ast.parse((pkg / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not a.name.startswith("secp_api") for a in node.names), name
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("secp_api"), name
