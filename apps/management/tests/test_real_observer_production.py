"""Hermetic proofs for RealManagementHostObserver + the fixed production composition (SECP-PR5G).

A recording pinned runner (simulating the PR5D coherent observation) + the hardened in-memory
filesystem prove: exactly one observe_generation() call per worker observation, no second docker/
systemd generation parser, the structural/ABA/operator/queue/health refusals, the controller
multi-component coherence algorithm, platform pin refusal, and the production loader's fail-closed
sealing (missing/unsafe/wrong-anchor/key-mismatch inputs) with the evidence key-pair proof.  The
real container runtime is exercised only by the Linux-root no-skip CI job.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json

import _mgmt_support as _MGMT
import pytest
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management import production as prod
from secp_management import real_adapters as ra
from secp_management.layout import ManagementLocations
from secp_management.signing import generate_keypair
from secp_management.topology import EXPECTED_CONTROLLER_COMPONENTS
from secp_operator_deployment.host_process import CommandResult

_PINS = ra.PinnedExecutables(
    container_runtime=ra.ExecutablePin("/usr/bin/docker", "sha256:" + "1" * 64),
    compose_runtime=ra.ExecutablePin("/usr/bin/docker-compose", "sha256:" + "2" * 64),
    service_manager=ra.ExecutablePin("/usr/bin/systemctl", "sha256:" + "3" * 64),
)
_CID = "b" * 64
_IMG = "sha256:" + "e" * 64
# The signed worker image digests used by the end-state proofs below. Taken from the SAME fixture
# that builds the manifest those proofs verify against — re-deriving them here would only create a
# second constant to keep in sync, not an independent check.
_ORDINARY_IMAGE = _MGMT.WORKER_ORDINARY_IMAGE
_OPERATOR_IMAGE = _MGMT.WORKER_OPERATOR_IMAGE
_PACKAGE_BYTES = b"deployment package\n"


def _op_show(
    *,
    enabled: bool = False,
    running: bool = False,
    unit_state: str | None = None,
    invocation: str | None = None,
    monotonic: str = "123",
) -> str:
    active = "active" if running else "inactive"
    # the SHIPPED sealed operator unit (render_operator_unit_disabled) has NO [Install], so systemd
    # reports UnitFileState=static (not-enabled) — that is the production not-enabled shape here;
    # 'enabled' is the breach case.
    unit = unit_state if unit_state is not None else ("enabled" if enabled else "static")
    # DEFAULT: the never-started shape. The prepared operator is installed disabled and never run,
    # and systemd reports an EMPTY InvocationID for such a unit. This fixture previously hardcoded
    # a nonempty id, so the real observer was never driven over the posture it actually ships.
    inv = invocation if invocation is not None else (("f" * 32) if running else "")
    return (
        f"LoadState=loaded\nActiveState={active}\nUnitFileState={unit}\n"
        f"InvocationID={inv}\nStateChangeTimestampMonotonic={monotonic}\n"
    )


def _ct_line(*, running: bool = True, restart: str = "0") -> str:
    run = "true" if running else "false"
    return f"{_CID} {run} {restart} 2026-01-01T00:00:00Z 0001-01-01T00:00:00Z 1234"


class ObserverRunner:
    """Serves canned outputs for the PR5D observe_generation() flow (systemctl show + docker
    inspect + health exec) and the observer's extra queries (image inspect, queue probe, controller
    inspect, migration, version).  Knobs inject the refusals; nothing here contacts a real host."""

    def __init__(self, **knobs: object) -> None:
        self.k = knobs
        self.gen_show = 0
        self.gen_inspect = 0
        self.calls: list[tuple[str, ...]] = []

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001,ANN201
        a = tuple(argv_tail)
        self.calls.append(a)
        if self.k.get("pin_fails"):
            raise RuntimeError("pin verification failed")
        head = a[0] if a else ""
        if head == "show":
            self.gen_show += 1
            return CommandResult(
                0,
                _op_show(
                    enabled=bool(self.k.get("op_enabled")),
                    running=bool(self.k.get("op_running")),
                    unit_state=self.k.get("unit_state"),  # type: ignore[arg-type]
                    invocation=self.k.get("op_invocation"),  # type: ignore[arg-type]
                    monotonic=str(self.k.get("op_monotonic", "123")),
                ),
            )
        if head == "image" and len(a) >= 5 and a[1] == "inspect":
            # the operator image-store presence probe: the runtime answers with the id it was asked
            # for when that image is loaded, and fails when it is not.
            if self.k.get("operator_image_absent"):
                return CommandResult(1, "")
            substitute = self.k.get("operator_image_substitute")
            return CommandResult(0, (str(substitute) if substitute else a[4]) + "\n")
        if head == "inspect" and len(a) >= 3 and a[1] == "--format":
            fmt = a[2]
            if fmt.startswith("{{.Id}} {{.State.Running}}"):
                self.gen_inspect += 1
                if self.k.get("incomplete"):
                    return CommandResult(1, "")  # container absent -> incomplete tuple
                drift = bool(self.k.get("aba_drift")) and self.gen_inspect == 2
                return CommandResult(
                    0,
                    _ct_line(
                        running=not bool(self.k.get("ordinary_down")), restart="9" if drift else "0"
                    ),
                )
            if fmt == "{{.Image}}":
                if self.k.get("bad_image"):
                    return CommandResult(1, "")
                return CommandResult(0, str(self.k.get("ordinary_image", _IMG)) + "\n")
            if fmt.startswith("{{.Name}}"):
                return CommandResult(0, "\n".join(self.k.get("controller_lines", [])))  # type: ignore[arg-type]
        if head == "exec":
            if a[-1] == "queues":
                q = (
                    "secp-controlled-live-v1\n"
                    if self.k.get("polls_operator")
                    else "secp-orchestration\n"
                )
                return CommandResult(0, q)
            if "alembic" in a:
                return CommandResult(0, str(self.k.get("migration", "d8f1a2b3c4e5 (head)")))
            return CommandResult(1 if self.k.get("unhealthy") else 0, "")  # ordinary health probe
        if head == "version":
            return CommandResult(0, "27.0.0")
        return CommandResult(0, "")


_SEED_DIRS = (
    "/opt",
    "/opt/secp",
    "/opt/secp/bootstrap",
    "/etc",
    "/etc/secp",
    "/etc/secp/controller",
    "/etc/secp/worker",
    "/etc/secp/operator-deployment",
    "/etc/systemd",
    "/etc/systemd/system",
    "/var",
    "/var/lib",
    "/var/lib/secp",
    "/var/lib/secp/bootstrap",
)


def _fs(*, seed_worker_files: bool = True) -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in _SEED_DIRS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    if seed_worker_files:
        loc = ManagementLocations()
        fs.seed_file(loc.worker_compose_path(), b"worker-config", uid=0, gid=0, mode=0o640)
        fs.seed_file(loc.operator_unit_path(), b"operator-unit", uid=0, gid=0, mode=0o644)
        fs.seed_file(loc.worker_deployment_package_path(), b"pkg", uid=0, gid=0, mode=0o640)
        fs.seed_file(loc.controller_compose_path(), b"ctrl-config", uid=0, gid=0, mode=0o640)
        fs.seed_file(loc.controller_unit_path(), b"ctrl-unit", uid=0, gid=0, mode=0o644)
    return fs


def _observer(
    runner: ObserverRunner, fs: InMemoryFilesystem | None = None
) -> ra.RealManagementHostObserver:
    ctx = ra.RealAdapterContext(
        locations=ManagementLocations(),
        fs=fs if fs is not None else _fs(),
        runner=runner,
        executables=_PINS,
    )
    return ra.RealManagementHostObserver(ctx)


def _reason(exc) -> str:  # noqa: ANN001
    return exc.value.reason_code


# --- worker observation ----------------------------------------------------------------------


def test_worker_prepared_uses_one_observe_generation_call() -> None:
    r = ObserverRunner()
    obs = _observer(r).observe_worker()
    assert obs.coherent and obs.commissioning_status == "prepared"
    assert obs.deployment_status == "sealed_prepared"
    assert not obs.operator_enabled and not obs.operator_running
    assert not obs.ordinary_polls_operator_queue
    # exactly ONE PR5D generation observation: 2 systemctl show + 2 container inspect + 1 health
    assert r.gen_show == 2 and r.gen_inspect == 2


def test_worker_incomplete_generation_tuple_refused() -> None:
    obs = _observer(ObserverRunner(incomplete=True)).observe_worker()
    assert obs.coherent is False and obs.commissioning_status == "not_prepared"


def test_worker_aba_drift_refused() -> None:
    obs = _observer(ObserverRunner(aba_drift=True)).observe_worker()
    assert obs.coherent is False  # before/after container generation differs


def test_worker_operator_enabled_refused() -> None:
    obs = _observer(ObserverRunner(op_enabled=True)).observe_worker()
    assert obs.operator_enabled is True and obs.deployment_status == "not_prepared"
    assert obs.commissioning_status == "not_prepared"


def test_worker_shipped_static_operator_unit_is_observed_prepared() -> None:
    # regression: the SHIPPED sealed operator unit (render_operator_unit_disabled, no [Install])
    # reports UnitFileState=static; it must classify as NOT enabled so a correctly prepared+disabled
    # host is observable as prepared/sealed (a 'disabled' unit must also stay prepared).
    for state in ("static", "disabled"):
        obs = _observer(ObserverRunner(unit_state=state)).observe_worker()
        assert obs.operator_enabled is False, state
        assert obs.commissioning_status == "prepared", state
        assert obs.deployment_status == "sealed_prepared", state


def test_worker_operator_running_refused() -> None:
    obs = _observer(ObserverRunner(op_running=True)).observe_worker()
    assert obs.operator_running is True and obs.deployment_status == "not_prepared"


def test_worker_unhealthy_refused() -> None:
    obs = _observer(ObserverRunner(unhealthy=True)).observe_worker()
    assert obs.ordinary_healthy is False and obs.commissioning_status == "not_prepared"


def test_worker_operator_queue_polling_refused() -> None:
    obs = _observer(ObserverRunner(polls_operator=True)).observe_worker()
    assert obs.ordinary_polls_operator_queue is True and obs.commissioning_status == "not_prepared"


def test_worker_bad_image_refused() -> None:
    obs = _observer(ObserverRunner(bad_image=True)).observe_worker()
    assert obs.ordinary_image_digest == "" and obs.commissioning_status == "not_prepared"


def test_worker_config_identity_reflects_content() -> None:
    base = _observer(ObserverRunner()).observe_worker()
    fs2 = _fs()
    fs2.seed_file(ManagementLocations().worker_compose_path(), b"DRIFTED", uid=0, gid=0, mode=0o640)
    drifted = _observer(ObserverRunner(), fs2).observe_worker()
    assert base.ordinary_config_identity != ""
    assert base.ordinary_config_identity != drifted.ordinary_config_identity


def test_worker_raw_generation_facts_stay_opaque_in_marker() -> None:
    obs = _observer(ObserverRunner()).observe_worker()
    assert obs.generation_marker.startswith("sha256:") and len(obs.generation_marker) == 71
    assert _CID not in obs.generation_marker  # the raw container id is hashed, never embedded
    # deterministic: the same generation yields the same opaque marker
    assert _observer(ObserverRunner()).observe_worker().generation_marker == obs.generation_marker


# --- controller observation ------------------------------------------------------------------


def _ctrl_lines(
    *, images: dict | None = None, privileged: set | None = None, running: bool = True
) -> list[str]:
    privileged = privileged or set()
    out = []
    for c in EXPECTED_CONTROLLER_COMPONENTS:
        img = (images or {}).get(c, "sha256:" + hashlib.sha256(c.encode()).hexdigest())
        priv = "true" if c in privileged else "false"
        out.append(
            f"/secp-controller-{c}|{'a' * 64}|{'true' if running else 'false'}|0|{img}|{priv}"
        )
    return out


def test_controller_coherent_over_exact_component_set() -> None:
    obs = _observer(ObserverRunner(controller_lines=_ctrl_lines())).observe_controller()
    assert obs.coherent and set(obs.container_image_digests) == set(EXPECTED_CONTROLLER_COMPONENTS)
    assert obs.migration_identity == "d8f1a2b3c4e5"


def test_controller_missing_component_refused() -> None:
    obs = _observer(ObserverRunner(controller_lines=_ctrl_lines()[:-1])).observe_controller()
    assert obs.coherent is False


def test_controller_renamed_component_refused() -> None:
    lines = _ctrl_lines()
    lines[0] = lines[0].replace("secp-controller-", "secp-controller-evil-")
    obs = _observer(ObserverRunner(controller_lines=lines)).observe_controller()
    assert obs.coherent is False


def test_controller_malformed_line_refused() -> None:
    lines = [f"/secp-controller-{c}|bad" for c in EXPECTED_CONTROLLER_COMPONENTS]  # 2 fields, not 6
    obs = _observer(ObserverRunner(controller_lines=lines)).observe_controller()
    assert obs.coherent is False


def test_controller_unknown_privileged_component_refused() -> None:
    r = ObserverRunner(controller_lines=_ctrl_lines(privileged={"api"}))
    obs = _observer(r).observe_controller()
    assert obs.coherent is False and "api" in obs.unknown_privileged


def test_controller_image_substitution_changes_marker() -> None:
    base = _observer(ObserverRunner(controller_lines=_ctrl_lines())).observe_controller()
    swapped = _observer(
        ObserverRunner(controller_lines=_ctrl_lines(images={"api": "sha256:" + "7" * 64}))
    ).observe_controller()
    assert base.coherent and swapped.coherent
    assert base.generation_marker != swapped.generation_marker  # engine detects the substitution


def test_controller_migration_reflected_in_marker() -> None:
    good = _observer(ObserverRunner(controller_lines=_ctrl_lines())).observe_controller()
    other = _observer(
        ObserverRunner(controller_lines=_ctrl_lines(), migration="000000000000 (head)")
    ).observe_controller()
    assert good.migration_identity == "d8f1a2b3c4e5" and other.migration_identity == "000000000000"
    assert good.generation_marker != other.generation_marker


def test_controller_before_after_generation_drift_refused() -> None:
    class _Drift(ObserverRunner):
        def __init__(self) -> None:
            super().__init__(controller_lines=_ctrl_lines())
            self._n = 0

        def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001,ANN201
            a = tuple(argv_tail)
            if a[:1] == ("inspect",) and len(a) >= 3 and a[2].startswith("{{.Name}}"):
                self._n += 1
                lines = (
                    _ctrl_lines(images={"api": "sha256:" + "9" * 64})
                    if self._n == 2
                    else _ctrl_lines()
                )
                return CommandResult(0, "\n".join(lines))
            return super().run(
                pin, argv_tail, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes
            )

    obs = _observer(_Drift()).observe_controller()
    assert obs.coherent is False


# --- platform --------------------------------------------------------------------------------


def test_platform_reports_runtime_presence() -> None:
    pf = _observer(ObserverRunner()).platform()
    assert pf.docker_present is True and pf.compose_present is True


def test_platform_executable_pin_failure_reports_absent() -> None:
    pf = _observer(ObserverRunner(pin_fails=True)).platform()
    assert pf.docker_present is False and pf.compose_present is False


# --- production loader ------------------------------------------------------------------------


def _prod_fs(**over: object) -> InMemoryFilesystem:
    fs = _fs(seed_worker_files=False)
    base = ManagementLocations().bootstrap_state
    priv, pub = over.get("keypair") or generate_keypair()  # type: ignore[assignment]  # evidence key K_e
    key_id = "sha256:" + hashlib.sha256(bytes.fromhex(pub)).hexdigest()
    execs = {
        "container_runtime": {"path": "/usr/bin/docker", "digest": "sha256:" + "1" * 64},
        "compose_runtime": {"path": "/usr/bin/docker-compose", "digest": "sha256:" + "2" * 64},
        "service_manager": {"path": "/usr/bin/systemctl", "digest": "sha256:" + "3" * 64},
    }
    # production reality: the RELEASE anchor (K_r) is a DISTINCT key from the evidence key (K_e);
    # release private half is never on the host.  Using one key for both here previously masked the
    # evidence_trust_root mis-wiring.
    _rel_priv, rel_pub = generate_keypair()
    anchor_pub = str(over.get("anchor_pub", rel_pub))
    anchor_id = str(
        over.get("anchor_id") or "sha256:" + hashlib.sha256(bytes.fromhex(anchor_pub)).hexdigest()
    )
    fs.seed_file(f"{base}/production-executables.json", json.dumps(execs).encode(), mode=0o640)
    fs.seed_file(f"{base}/production-expected-identities.json", b'{"components": []}', mode=0o640)
    fs.seed_file(
        f"{base}/release-trust-anchor.json",
        json.dumps({"key_id": anchor_id, "public_key_hex": anchor_pub}).encode(),
        mode=0o640,
    )
    fs.seed_file(
        f"{base}/evidence-signing.key",
        bytes.fromhex(str(over.get("key_priv", priv))),
        mode=int(over.get("key_mode", 0o600)),  # type: ignore[arg-type]
    )
    fs.seed_file(
        f"{base}/evidence-signing.pub.json",
        json.dumps(
            {"key_id": key_id, "public_key_hex": str(over.get("pub_identity", pub))}
        ).encode(),
        mode=0o640,
    )
    return fs


def test_production_happy_path_builds_real_deps() -> None:
    deps = prod.production_engine_deps(fs=_prod_fs(), runner=ObserverRunner())
    assert isinstance(deps.observer, ra.RealManagementHostObserver)
    assert isinstance(deps.controller_adapter, ra.RealControllerBootstrapAdapter)
    assert isinstance(deps.worker_adapter, ra.RealWorkerBootstrapAdapter)
    assert deps.trust_root.test_only is False


def test_production_evidence_trust_root_pins_the_authenticator_not_the_release_anchor() -> None:
    # regression for the evidence_trust_root mis-wiring: the commit gate verifies the evidence
    # attestation (signed by the authenticator's OWN key K_e) against evidence_trust_root, so it
    # pin K_e.  With distinct release (K_r) and evidence (K_e) keys, wiring the release anchor here
    # (the fixed bug) would fail every production commit closed.
    deps = prod.production_engine_deps(fs=_prod_fs(), runner=ObserverRunner())
    auth = deps.evidence_authenticator
    msg = b"secp.management.evidence-attestation-regression"
    sig = auth.attest(msg)
    assert deps.evidence_trust_root.verify(key_id=auth.key_id(), message=msg, signature_hex=sig)
    # the RELEASE trust root does NOT pin the evidence key — proving the two roots are distinct
    assert not deps.trust_root.verify(key_id=auth.key_id(), message=msg, signature_hex=sig)


def test_production_missing_input_seals() -> None:
    fs = _fs(seed_worker_files=False)  # no production inputs seeded
    with pytest.raises(ManagementError) as e:
        prod.production_engine_deps(fs=fs, runner=ObserverRunner())
    assert _reason(e).startswith("production_")


def test_production_wrong_trust_anchor_seals() -> None:
    with pytest.raises(ManagementError) as e:  # anchor id does not derive from its public key
        prod.production_engine_deps(
            fs=_prod_fs(anchor_id="sha256:" + "0" * 64), runner=ObserverRunner()
        )
    assert _reason(e) == "production_trust_anchor_invalid"


def test_production_evidence_key_pair_mismatch_seals() -> None:
    _p2, pub2 = generate_keypair()  # a public identity the private key does not derive
    with pytest.raises(ManagementError) as e:
        prod.production_engine_deps(fs=_prod_fs(pub_identity=pub2), runner=ObserverRunner())
    assert _reason(e) == "production_evidence_key_pair_mismatch"


def test_production_unsafe_key_mode_seals() -> None:
    with pytest.raises(ManagementError) as e:
        prod.production_engine_deps(fs=_prod_fs(key_mode=0o644), runner=ObserverRunner())
    assert _reason(e) == "production_evidence_key_unsafe"


def test_production_symlink_key_seals() -> None:
    fs = _prod_fs()
    base = ManagementLocations().bootstrap_state
    fs._nodes.pop(f"{base}/evidence-signing.key", None)  # type: ignore[attr-defined]
    fs.seed_symlink(f"{base}/evidence-signing.key")
    with pytest.raises(ManagementError) as e:
        prod.production_engine_deps(fs=fs, runner=ObserverRunner())
    assert _reason(e) == "production_evidence_key_unsafe"


# --- default sealed / no import I/O / no forbidden contact ------------------------------------


def test_default_engine_deps_stays_sealed() -> None:
    from secp_management.engine import EngineDeps

    with pytest.raises(ManagementError):
        EngineDeps().observer.platform()


def test_importing_production_performs_no_module_level_io() -> None:
    tree = ast.parse(inspect.getsource(prod))
    for node in tree.body:  # only imports / constant assignments / defs / the docstring
        assert isinstance(
            node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef, ast.ClassDef, ast.Expr)
        ), type(node).__name__
        if isinstance(node, ast.Expr):
            assert isinstance(node.value, ast.Constant)  # module docstring only, no top-level call


def test_no_forbidden_module_imports() -> None:
    for mod in (ra, prod):
        tree = ast.parse(inspect.getsource(mod))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for banned in (
            "socket",
            "requests",
            "httpx",
            "temporalio",
            "boto3",
            "kubernetes",
            "paramiko",
        ):
            assert banned not in imported, (mod.__name__, banned)


# --- the COMPLETE prepared end state, driven through the REAL gate --------------------------------
# Everything above observes. These put the REAL observer's observation in front of the REAL
# `_worker_end_state_reason` predicate, because that pairing is what production actually runs and it
# is exactly where two defects hid: the engine suites used a FakeObserver that disagreed with the
# production leaf on the operator InvocationID and the operator image, so both sides read "green"
# while a correctly prepared host was refused.


def _worker_manifest(operator_image: str | None = None):  # noqa: ANN202
    """The signed worker manifest this host is expected to be on.

    ``implementation_aggregate`` is pinned to the digest of the deployment-package bytes the host is
    seeded with, because the end-state gate compares the two — the shared fixture's placeholder
    constant is unreachable by any real file content.
    """
    from _mgmt_support import default_artifacts, manifest_dict
    from secp_commissioning.canonical import sha256_bytes
    from secp_management.release_bundle import ReleaseManifest

    artifacts = default_artifacts("worker")
    if operator_image is not None:
        for art in artifacts:
            if art.get("purpose") == "worker/operator":
                art["image_digest"] = operator_image
    body = manifest_dict("worker", artifacts)
    body["implementation_aggregate"] = sha256_bytes(_PACKAGE_BYTES)
    return ReleaseManifest.model_validate(body)


def _prepared_worker_fs(*, record: bytes | None) -> InMemoryFilesystem:
    """A host seeded so the OBSERVED identities match what the signed manifest expects."""
    from _mgmt_support import _WORKER_COMPOSE_BYTES
    from secp_management.engine import _operator_unit

    fs = InMemoryFilesystem()
    for d in _SEED_DIRS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    loc = ManagementLocations()
    fs.seed_file(loc.worker_compose_path(), _WORKER_COMPOSE_BYTES, uid=0, gid=0, mode=0o640)
    fs.seed_file(loc.operator_unit_path(), _operator_unit().content, uid=0, gid=0, mode=0o644)
    fs.seed_file(loc.worker_deployment_package_path(), _PACKAGE_BYTES, uid=0, gid=0, mode=0o640)
    if record is not None:
        fs.seed_file(loc.release_record_path("worker"), record, uid=0, gid=0, mode=0o640)
    return fs


def _end_state_reason(runner: ObserverRunner, fs: InMemoryFilesystem, manifest=None):  # noqa: ANN001,ANN202
    from secp_management.engine import _expected_worker, _worker_end_state_reason

    obs = _observer(runner, fs).observe_worker()
    return _worker_end_state_reason(obs, _expected_worker(manifest or _worker_manifest()))


def _prepared_runner(**knobs: object) -> ObserverRunner:
    return ObserverRunner(ordinary_image=_ORDINARY_IMAGE, **knobs)


def test_a_correctly_prepared_worker_host_PASSES_the_real_end_state_gate() -> None:
    """THE regression proof. A fresh install leaves the operator unit present, disabled and NEVER
    started, so systemd reports an empty InvocationID and no operator container exists.

    Both facts were previously fatal: the gate demanded a nonempty InvocationID, and the observer
    hardcoded operator_image_digest="" against a real sha256 expectation. Either alone refuses every
    real host, so this fails if either regresses.
    """
    manifest = _worker_manifest()
    fs = _prepared_worker_fs(record=manifest.canonical().encode("utf-8"))
    runner = _prepared_runner()
    obs = _observer(runner, fs).observe_worker()

    # the never-started posture is REAL in this fixture, not assumed
    assert obs.operator_present and not obs.operator_enabled and not obs.operator_running
    assert obs.operator_invocation_id == "", "the fixture must model a never-started operator"
    # ...and the operator image was OBSERVED, not defaulted
    assert obs.operator_image_digest == _OPERATOR_IMAGE
    # the ordinary worker is running and healthy, and is not polling the operator queue
    assert obs.ordinary_running and obs.ordinary_healthy
    assert not obs.ordinary_polls_operator_queue

    assert _end_state_reason(runner, fs, manifest) is None


def test_the_operator_image_is_refused_when_it_is_not_actually_loaded() -> None:
    """The observation must be a real image-store proof: a host whose release record names the
    operator image but whose runtime does not have it REFUSES. Without this, "observed" would mean
    nothing more than "copied the expectation back"."""
    fs = _prepared_worker_fs(record=_worker_manifest().canonical().encode("utf-8"))
    runner = _prepared_runner(operator_image_absent=True)

    assert _observer(runner, fs).observe_worker().operator_image_digest == ""
    assert _end_state_reason(runner, fs) == "worker_operator_image_unobserved"


def test_an_empty_operator_image_can_never_satisfy_the_gate() -> None:
    """The defect's shape, asserted directly: an unproven (empty) operator image must refuse on its
    own terms and must never reach the equality comparison — not even against an empty expectation,
    where "" == "" would otherwise read as a match."""
    from dataclasses import replace

    from secp_management.engine import _expected_worker, _worker_end_state_reason

    manifest = _worker_manifest()
    fs = _prepared_worker_fs(record=manifest.canonical().encode("utf-8"))
    exp = _expected_worker(manifest)

    # CONTROL first: with a proven image this same host PASSES, so the refusals below are
    # attributable to the operator image and not to some other unsatisfied clause.
    assert _end_state_reason(_prepared_runner(), fs, manifest) is None

    obs = _observer(_prepared_runner(operator_image_absent=True), fs).observe_worker()
    assert obs.operator_image_digest == "", "the premise: the image was NOT observed"
    # The dangerous case FIRST: an empty observation against an empty expectation. A bare equality
    # comparison reads that as a match and returns None — a silent PASS certifying an end state
    # nobody observed. It must refuse on the observation being absent, before any comparison.
    assert (
        _worker_end_state_reason(obs, replace(exp, operator_image=""))
        == "worker_operator_image_unobserved"
    )
    assert _worker_end_state_reason(obs, exp) == "worker_operator_image_unobserved"


def test_a_substituted_operator_image_is_refused() -> None:
    """The runtime answering with a DIFFERENT id than the one asked for is not proof that the signed
    image is loaded."""
    fs = _prepared_worker_fs(record=_worker_manifest().canonical().encode("utf-8"))
    runner = _prepared_runner(operator_image_substitute="sha256:" + "9" * 64)

    assert _observer(runner, fs).observe_worker().operator_image_digest == ""
    assert _end_state_reason(runner, fs) == "worker_operator_image_unobserved"


def test_a_missing_release_record_refuses_rather_than_assuming_the_image() -> None:
    """No record means the observer cannot know which operator image this host should have. That is
    a refusal, never a pass."""
    fs = _prepared_worker_fs(record=None)

    assert _observer(_prepared_runner(), fs).observe_worker().operator_image_digest == ""
    assert _end_state_reason(_prepared_runner(), fs) == "worker_operator_image_unobserved"


def test_a_record_naming_another_release_operator_image_is_a_MISMATCH_not_a_pass() -> None:
    """The engine's comparison stays a real check: a host whose installed release names a different
    operator image than the expected one refuses, and refuses as a MISMATCH — a distinct fact from
    "could not observe", and the reason an operator acts on differently."""
    other = "sha256:" + "7" * 64
    installed = _worker_manifest(operator_image=other)
    fs = _prepared_worker_fs(record=installed.canonical().encode("utf-8"))
    runner = _prepared_runner()

    # the host truthfully reports what IT has installed...
    assert _observer(runner, fs).observe_worker().operator_image_digest == other
    # ...and that is not what the EXPECTED release says it must be
    assert _end_state_reason(runner, fs, _worker_manifest()) == "worker_operator_image_mismatch"


def test_the_operator_generation_still_moves_when_the_operator_is_started() -> None:
    """Accepting an empty InvocationID must not remove the operator from ABA detection. A
    never-started operator contributes a CONSTANT empty id, so the marker has to be carried by
    StateChangeTimestampMonotonic — which advances the moment the unit changes state."""
    fs = _prepared_worker_fs(record=_worker_manifest().canonical().encode("utf-8"))
    never_started = _observer(_prepared_runner(), fs).observe_worker()

    # CONTROL: re-observing an UNCHANGED host reproduces the same marker, so the difference below is
    # a real state change and not per-observation noise.
    assert _observer(_prepared_runner(), fs).observe_worker().generation_marker == (
        never_started.generation_marker
    )

    # The monotonic stamp must move the marker ON ITS OWN. Holding the operator NOT running keeps
    # the InvocationID empty in both observations, so this isolates the monotonic as the only
    # differing operator fact — an earlier version of this test also started the operator, which
    # moved the marker via the InvocationID and would have passed even if the marker ignored the
    # stamp entirely.
    restamped = _observer(_prepared_runner(op_monotonic="124"), fs).observe_worker()
    assert restamped.operator_invocation_id == never_started.operator_invocation_id == ""
    assert restamped.operator_state_change_monotonic != (
        never_started.operator_state_change_monotonic
    )
    assert restamped.generation_marker != never_started.generation_marker

    # ...and starting the operator moves it too (the InvocationID appearing is itself a change).
    started = _observer(_prepared_runner(op_running=True, op_monotonic="125"), fs).observe_worker()
    assert started.generation_marker != never_started.generation_marker
