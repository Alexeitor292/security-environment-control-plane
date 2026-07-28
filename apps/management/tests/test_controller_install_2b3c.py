"""Driven controller-enrollment install integration (SECP-PR5H-B2, 2b-3c-a).

Hermetic end-to-end proofs for the NEW ``controller_install`` write path: a FRESH install drives the
closed 9-op finalization adapter in its exact reviewed order (marker LAST) through the plan-bound,
single-use ``finalization_factory`` seam, binds the domain-separated ``bootstrap_binding_digest``
into the authenticated ``FinalizationEvidence`` + the on-disk enablement marker, replays an exact
same-release state with ZERO finalization mutation, and combines marker-first compensation with the
bootstrap document/host unwind on failure. Steady-state commands (bootstrap/worker/adopt) keep the
finalization seam SEALED (factory stays None).

No source file is edited: the finalization + host effects are simulated by an in-memory hardened
filesystem plus a single closed fake finalization adapter injected through the frozen ``EngineDeps``
via ``dataclasses.replace(deps, finalization_factory=...)`` — the same engine code path production
drives; only the leaf host/DB effects are faked.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from _mgmt_support import (
    WrongKeyAuthenticator,
    default_artifacts,
    deps_for,
    ephemeral_trust_root,
    fresh_controller_world,
    fresh_worker_world,
    manifest_dict,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.canonical import canonical_json
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2 as V2
from secp_management import ManagementError
from secp_management.adapters import CompensationResult
from secp_management.cli import _is_controller_install_group, run
from secp_management.engine import EngineDeps, controller_install
from secp_management.evidence import (
    FINALIZATION_SCHEMA_VERSION,
    FinalizationEvidence,
    canonical_bytes,
    evidence_from_dict,
)
from secp_management.finalization import (
    FINALIZATION_EFFECTS,
    ActivationReceipt,
    ControllerFinalizationReceipt,
    EffectDisposition,
    EnrollmentKeyIdentity,
    FinalizationEffectReceipt,
    SealedControllerEnrollmentFinalizationAdapter,
)
from secp_management.release_bundle import ReleaseManifest, manifest_signing_message
from secp_management.signing import sign_ed25519
from secp_management.transaction import WriteGate

ORIGIN = "https://controller.secp.example:8443"
MODE = "generated_local_ca"
_MAX = 256 * 1024
_ROW = "11111111-1111-1111-1111-111111111111"
_TOKEN = f"{_ROW}|2026-07-28 00:00:00+00:00"

# NOTE (2b-3c-a): an initial run surfaced a source bug — three FinalizationEvidence field names
# tripped the forbidden-secret field scan; the fields were renamed and the driven install now
# commits. These tests exercise the committed path directly.

# The reviewed 9-op finalization order (marker LAST, identity activation PENULTIMATE).
_EXPECTED_OPS = (
    "install_tls_material",
    "record_locator",
    "provision_signer_role",
    "prepare_enrollment_key",
    "install_broker_unit",
    "start_broker",
    "verify_signer_operational",
    "activate_controller_identity",
    "enable_api_signer",
)


def _valid_profile() -> dict:
    """A well-formed v1alpha2 installation profile (platform + runtime pins + TLS policy)."""
    return {
        "platform_profile": {
            "os": "linux",
            "arch": "x86_64",
            "installation_profile_version": "secp.controller-install/v1",
        },
        "runtime_profile": {
            "pins": [
                {
                    "capability": "container_runtime",
                    "path": "/usr/bin/docker",
                    "sha256": "sha256:" + "1" * 64,
                    "invocation": [],
                    "allowed_subcommands": ["load", "image"],
                },
                {
                    "capability": "compose",
                    "path": "/usr/bin/docker",
                    "sha256": "sha256:" + "1" * 64,
                    "invocation": ["compose"],
                    "allowed_subcommands": ["up", "down"],
                },
                {
                    "capability": "service_manager",
                    "path": "/usr/bin/systemctl",
                    "sha256": "sha256:" + "2" * 64,
                    "invocation": [],
                    "allowed_subcommands": ["daemon-reload"],
                },
            ]
        },
        "controller_tls_policy": {
            "allowed_modes": ["generated_local_ca", "imported_enterprise_tls"],
            "key_algorithm": "ecdsa-p256",
            "signature_algorithm": "ecdsa-with-sha256",
            "max_validity_days": 825,
            "require_san": True,
            "server_auth_eku_required": True,
            "ca_pathlen_zero": True,
            "min_tls_version": "1.2",
            "allow_ip_origin": False,
            "allow_generated_local_ca": True,
        },
    }


def _seed_v2_controller_bundle(
    fs: InMemoryFilesystem, bundle_dir: str, key_id: str, priv: str
) -> None:
    """Seed a v1alpha1 controller bundle (dirs + artifact files), then re-sign + overwrite ONLY the
    manifest + signature as a v1alpha2 bundle carrying the signed controller TLS policy the driven
    finalization plan requires (the artifact digests are unchanged)."""
    seed_signed_bundle(fs, bundle_dir, "controller", key_id, priv)
    d = manifest_dict("controller", default_artifacts("controller"))
    d["bootstrap_contract_version"] = V2
    d["signing_anchor_id"] = key_id
    d.update(_valid_profile())
    manifest = ReleaseManifest.model_validate(d)
    sig = sign_ed25519(priv, manifest_signing_message(manifest))
    fs.seed_file(f"{bundle_dir}/release-manifest.json", manifest.canonical().encode(), mode=0o644)
    fs.seed_file(
        f"{bundle_dir}/release-manifest.sig.json",
        canonical_json({"algorithm": "ed25519", "key_id": key_id, "signature": sig}).encode(),
        mode=0o644,
    )


def _seed_etc_controller(fs: InMemoryFilesystem) -> None:
    """Seed the fixed /etc/secp/controller ancestors the CA bundle + marker are written into."""
    for d in (
        "/etc",
        "/etc/secp",
        "/etc/secp/controller",
        "/etc/secp/controller/tls",
        "/etc/secp/controller/credentials",
    ):
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)


class _FakeFinalizationAdapter:
    """A closed, plan-bound fake of the controller-enrollment finalization adapter. It records each
    of the 9 ops in call order, writes a real CA bundle + enablement marker through the hardened fs
    (so the driver's CA re-read and a later replay's marker binding succeed), returns typed public
    receipts, and supports failure injection (``fail_on`` a step) + compensation modes."""

    def __init__(
        self,
        plan: object,
        fs: InMemoryFilesystem,
        loc: object,
        *,
        fail_on: str | None = None,
        compensate_residual: bool = False,
        receipt_raise_on_call: int = 0,
        compensate_raises: bool = False,
    ) -> None:
        self.plan = plan
        self._fs = fs
        self._loc = loc
        self._fail_on = fail_on
        self._compensate_residual = compensate_residual
        self._receipt_raise_on_call = receipt_raise_on_call
        self._compensate_raises = compensate_raises
        self.ops: list[str] = []
        self.committed = False
        self.compensated = False
        self._receipt_calls = 0

    # --- reviewed order ---------------------------------------------------------------------------
    def _step(self, name: str) -> None:
        self.ops.append(name)
        if self._fail_on == name and name != "enable_api_signer":
            raise ManagementError(f"fake_finalization_{name}_failed")

    def install_tls_material(self, *, policy: object, canonical_origin: str, tls_mode: str) -> None:
        self.ops.append("install_tls_material")
        # write a CA bundle so the driver's fs.safe_read of the installed CA succeeds
        self._fs.atomic_install(
            self._loc.controller_ca_bundle_path(),  # type: ignore[attr-defined]
            b"-----BEGIN FAKE CA BUNDLE-----\nfake\n-----END FAKE CA BUNDLE-----\n",
            uid=0,
            gid=0,
            mode=0o644,
        )
        if self._fail_on == "install_tls_material":
            raise ManagementError("fake_finalization_install_tls_material_failed")

    def record_locator(self, *, canonical_origin: str) -> None:
        self._step("record_locator")

    def provision_signer_role(self, role: object) -> None:
        self._step("provision_signer_role")

    def prepare_enrollment_key(self) -> EnrollmentKeyIdentity:
        self._step("prepare_enrollment_key")
        return EnrollmentKeyIdentity(
            controller_key_id="sha256:" + "1" * 64,
            controller_trust_anchor_hex="1" * 64,
            enrollment_key_proof_id="enrkp:" + "5" * 64,
        )

    def install_broker_unit(self, unit: object) -> None:
        self._step("install_broker_unit")

    def start_broker(self) -> None:
        self._step("start_broker")

    def verify_signer_operational(self, *, key_identity: object) -> None:
        self._step("verify_signer_operational")

    def activate_controller_identity(self, activation: object) -> ActivationReceipt:
        self._step("activate_controller_identity")
        return ActivationReceipt(
            operation_id=activation.operation_id,  # type: ignore[attr-defined]
            candidate_digest="sha256:" + "a" * 64,
            resulting_row_id=_ROW,
            activation_token=_TOKEN,
            previous_active_row_id=None,
            created=True,
            resulting_status="active",
            resulting_public_state_digest="sha256:" + "b" * 64,
        )

    def enable_api_signer(self, marker: object) -> None:  # LAST
        self.ops.append("enable_api_signer")
        self._write_marker(marker)  # the candidate marker is written LAST
        if self._fail_on == "enable_api_signer":
            # the real adapter reseals the marker FIRST on its own step failure (marker-first)
            self._reseal_marker()
            raise ManagementError("fake_finalization_enable_api_signer_failed")

    # --- marker on disk ---------------------------------------------------------------------------
    def _write_marker(self, marker: object) -> None:
        payload = {
            "installation_id": marker.installation_id,  # type: ignore[attr-defined]
            "release_digest": marker.release_digest,  # type: ignore[attr-defined]
            "active_identity_row_id": marker.active_identity_row_id,  # type: ignore[attr-defined]
            "controller_key_id": marker.controller_key_id,  # type: ignore[attr-defined]
            "uds_contract_identity": marker.uds_contract_identity,  # type: ignore[attr-defined]
            "signer_role_name": marker.signer_role_name,  # type: ignore[attr-defined]
            "locator_ca_digest": marker.locator_ca_digest,  # type: ignore[attr-defined]
            "bootstrap_evidence_digest": marker.bootstrap_evidence_digest,  # type: ignore[attr-defined]
            "api_uid": marker.api_uid,  # type: ignore[attr-defined]
            "api_gid": marker.api_gid,  # type: ignore[attr-defined]
            "activation_token": marker.activation_token,  # type: ignore[attr-defined]
        }
        data = json.dumps(payload, sort_keys=True).encode("ascii")
        self._fs.atomic_install(
            marker.marker_path,  # type: ignore[attr-defined]
            data,
            uid=0,
            gid=0,
            mode=0o640,
        )

    def _reseal_marker(self) -> None:
        try:
            self._fs.remove_file(self._loc.api_signer_marker_path())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - an already-absent marker is already sealed
            pass

    # --- typed receipt + commit + compensate ------------------------------------------------------
    def _effects(self) -> tuple[FinalizationEffectReceipt, ...]:
        return tuple(
            FinalizationEffectReceipt(
                effect=name,
                transaction_id="tx-fake-0",
                generation=self.plan.generation,  # type: ignore[attr-defined]
                object_identity=name,
                disposition=EffectDisposition.ABSENT.value,
                candidate_digest="sha256:" + "c" * 64,
            )
            for name in FINALIZATION_EFFECTS
        )

    def receipt(self) -> ControllerFinalizationReceipt:
        self._receipt_calls += 1
        if self._receipt_raise_on_call and self._receipt_calls >= self._receipt_raise_on_call:
            raise ManagementError("fake_finalization_receipt_lost")
        return ControllerFinalizationReceipt(
            effects=self._effects(),
            transaction_id="tx-fake-0",
            generation=self.plan.generation,  # type: ignore[attr-defined]
        )

    def commit(self) -> bool:
        self.committed = True
        return True

    def compensate(self, receipt: object) -> CompensationResult:
        self.compensated = True
        if self._compensate_raises:
            raise ManagementError("fake_finalization_compensate_error")
        self._reseal_marker()  # marker-first
        if self._compensate_residual:
            return CompensationResult(proven=False, residual=("marker",))
        return CompensationResult(proven=True)


def _install_deps(
    *,
    world_overrides: dict | None = None,
    authenticator: object | None = None,
    fail_on: str | None = None,
    compensate_residual: bool = False,
    receipt_raise_on_call: int = 0,
    compensate_raises: bool = False,
) -> tuple[EngineDeps, str, InMemoryFilesystem, dict]:
    """Build a driven controller-install ``EngineDeps`` (v1alpha2 bundle + a plan-bound single-use
    fake finalization factory) and a ``state`` dict recording factory calls + the built adapters."""
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/controller"
    _seed_v2_controller_bundle(fs, bd, kid, priv)
    seed_write_ancestors(fs)
    _seed_etc_controller(fs)
    deps = deps_for(fs, fresh_controller_world(**(world_overrides or {})), trust)
    if authenticator is not None:
        deps = dataclasses.replace(deps, evidence_authenticator=authenticator)
    loc = deps.locations
    state: dict = {"calls": 0, "adapters": []}

    def _factory(plan: object) -> _FakeFinalizationAdapter:
        state["calls"] += 1
        adapter = _FakeFinalizationAdapter(
            plan,
            fs,
            loc,
            fail_on=fail_on,
            compensate_residual=compensate_residual,
            receipt_raise_on_call=receipt_raise_on_call,
            compensate_raises=compensate_raises,
        )
        state["adapters"].append(adapter)
        return adapter

    deps = dataclasses.replace(deps, finalization_factory=_factory)
    return deps, bd, fs, state


def _install_argv(bd: str, *, write: bool) -> list[str]:
    argv = ["controller", "install", "--bundle", bd, "--public-origin", ORIGIN, "--tls-mode", MODE]
    if write:
        argv += ["--write", "--confirm"]
    return argv


def _fresh_controller_v1() -> tuple[EngineDeps, str, InMemoryFilesystem]:
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/controller"
    seed_signed_bundle(fs, bd, "controller", kid, priv)
    seed_write_ancestors(fs)
    return deps_for(fs, fresh_controller_world(), trust), bd, fs


def _fresh_worker_v1() -> tuple[EngineDeps, str, InMemoryFilesystem]:
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/worker"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    return deps_for(fs, fresh_worker_world(), trust), bd, fs


def _read_evidence(fs: InMemoryFilesystem, loc: object, role: str) -> dict:
    raw = fs.safe_read(
        loc.evidence_path(role),  # type: ignore[attr-defined]
        max_bytes=_MAX,
        expected_uid=0,
    )
    return json.loads(raw)


def _assert_no_controller_documents(fs: InMemoryFilesystem, loc: object) -> None:
    for path in (
        loc.identity_path("controller"),  # type: ignore[attr-defined]
        loc.release_record_path("controller"),  # type: ignore[attr-defined]
        loc.release_sig_path("controller"),  # type: ignore[attr-defined]
        loc.evidence_path("controller"),  # type: ignore[attr-defined]
        loc.evidence_attestation_path("controller"),  # type: ignore[attr-defined]
    ):
        assert fs.lstat(path) is None


def _synthetic_finalization(*, generation: int = 0) -> FinalizationEvidence:
    """A well-formed, nonsecret FinalizationEvidence built directly (not via the loader, so it is
    never scanned) — used to prove the evidence digest model without depending on a committed
    install."""

    def _d(seed: str) -> str:
        return "sha256:" + (seed * 64)[:64]

    return FinalizationEvidence(
        schema_version=FINALIZATION_SCHEMA_VERSION,
        role="controller",
        mode="installed",
        classification="fresh",
        generation=generation,
        transaction_id_digest=_d("1"),
        bootstrap_binding_digest=_d("2"),
        finalization_receipt_digest=_d("3"),
        canonical_origin_digest=_d("4"),
        tls_mode=MODE,
        tls_policy_identity=_d("5"),
        locator_ca_digest=_d("6"),
        signer_role_identity=_d("7"),
        signer_login_binding_digest=None,
        enrollment_key_id=_d("8"),
        enrollment_key_proof_id="enrkp:" + "9" * 64,
        broker_unit_identity=_d("a"),
        broker_transport_identity=_d("b"),
        active_identity_row_id=_ROW,
        activation_concurrency_digest=_d("c"),
        activation_operation_digest=_d("d"),
        marker_identity=_d("e"),
        runtime_observation_identity=_d("f"),
        recovery_journal_absent=True,
        marker_last=True,
        api_runtime_proven=True,
        no_mixed_generation=True,
        operator_sealed=True,
        controlled_live_sealed=True,
        isolation_boundaries_proven=True,
        effects=(),
    )


# ---------------------------------------------- 1. fresh install drives 9 ops, marker last


def test_fresh_install_drives_nine_finalization_ops_in_reviewed_order():
    # the finalization drive completes (all 9 ops, marker LAST) BEFORE the commit gate — provable
    # even though the commit gate itself is blocked by the FinalizationEvidence naming bug.
    deps, bd, _fs, state = _install_deps()
    run(_install_argv(bd, write=True), deps)
    assert state["calls"] == 1  # exactly one plan-bound adapter built
    adapter = state["adapters"][0]
    assert adapter.ops == list(_EXPECTED_OPS)  # exact reviewed order
    assert adapter.ops[-1] == "enable_api_signer"  # marker LAST


def test_fresh_install_commits_written_evidence():
    deps, bd, fs, state = _install_deps()
    loc = deps.locations
    code, rep = run(_install_argv(bd, write=True), deps)

    assert code == 0
    assert rep["mode"] == "written"
    assert rep["classification"] == "fresh"
    assert rep["idempotent_replay"] is False
    assert rep["finalization_generation"] == 0
    assert state["adapters"][0].committed is True  # commit() ran only AFTER a passed commit gate

    # the WRITTEN evidence carries the authenticated finalization extension (generation 0, fresh)
    ev = _read_evidence(fs, loc, "controller")
    assert ev["finalization"]["generation"] == 0
    assert ev["finalization"]["classification"] == "fresh"
    assert ev["finalization"]["schema_version"] == FINALIZATION_SCHEMA_VERSION
    # the marker LAST really landed on disk
    assert fs.lstat(loc.api_signer_marker_path()) is not None


# ---------------------------------------------- 2. steady state keeps finalization sealed


def test_bare_engine_deps_leaves_finalization_factory_none_and_seals():
    deps = EngineDeps()
    assert deps.finalization_factory is None
    assert isinstance(deps.finalization_adapter, SealedControllerEnrollmentFinalizationAdapter)


def test_controller_bootstrap_does_not_touch_finalization():
    deps, bd, fs = _fresh_controller_v1()
    assert deps.finalization_factory is None
    code, rep = run(["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    ev = _read_evidence(fs, deps.locations, "controller")
    assert "finalization" not in ev  # steady-state evidence carries no finalization extension


def test_worker_bootstrap_does_not_touch_finalization():
    deps, bd, fs = _fresh_worker_v1()
    assert deps.finalization_factory is None
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    ev = _read_evidence(fs, deps.locations, "worker")
    assert "finalization" not in ev


def test_adopt_does_not_touch_finalization():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, prepared_worker_world(), trust)
    assert deps.finalization_factory is None
    code, rep = run(["adopt", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "adopted"
    ev = _read_evidence(fs, deps.locations, "worker")
    assert "finalization" not in ev


def test_controller_install_with_no_factory_refuses_finalization_not_composed():
    deps, bd, fs, _state = _install_deps()
    sealed = dataclasses.replace(deps, finalization_factory=None)
    code, rep = run(_install_argv(bd, write=True), sealed)
    assert code == 2 and rep["reason_code"] == "finalization_not_composed"
    _assert_no_controller_documents(fs, deps.locations)


# ============================================================ 3. digest model + legacy stability


def test_digest_binds_finalization_but_binding_digest_excludes_it():
    # a REAL engine-written base evidence (worker, finalization None) + a synthetic finalization
    # folded on via model_copy proves the digest model without depending on a committed install.
    deps, bd, fs = _fresh_worker_v1()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    ev0 = evidence_from_dict(_read_evidence(fs, deps.locations, "worker"))
    assert ev0.finalization is None

    baseline = ev0.digest()
    binding = ev0.bootstrap_binding_digest()

    with_fin = ev0.model_copy(update={"finalization": _synthetic_finalization(generation=0)})
    other_fin = ev0.model_copy(update={"finalization": _synthetic_finalization(generation=7)})

    # digest() BINDS the finalization extension: adding/changing it changes the digest
    assert with_fin.digest() != baseline
    assert other_fin.digest() != with_fin.digest()
    # bootstrap_binding_digest() EXCLUDES finalization (+ timestamp): stable across those changes
    assert with_fin.bootstrap_binding_digest() == binding
    assert other_fin.bootstrap_binding_digest() == binding


def test_committed_marker_and_activation_carry_the_bootstrap_binding_digest():
    deps, bd, fs, _state = _install_deps()
    run(_install_argv(bd, write=True), deps)
    ev = evidence_from_dict(_read_evidence(fs, deps.locations, "controller"))
    assert ev.finalization is not None
    # the marker/activation bind exactly the (pre-finalization ev0) bootstrap binding digest, and
    # that value is stable/recomputable from the final evidence (excludes finalization + timestamp)
    assert ev.finalization.bootstrap_binding_digest == ev.bootstrap_binding_digest()


def test_legacy_worker_evidence_has_no_finalization_and_reverifies():
    deps, bd, fs = _fresh_worker_v1()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    data = _read_evidence(fs, deps.locations, "worker")
    assert "finalization" not in data
    ev = evidence_from_dict(data)
    assert ev.finalization is None
    assert b"finalization" not in canonical_bytes(ev)  # the absent key is dropped from canonical()
    # the detached attestation still reverifies over the (finalization-free) canonical bytes
    code, st = run(["status", "worker"], deps)
    assert code == 0 and st["ok"] is True


# ============================================================ 4. plan-bound single-use factory


def test_factory_is_called_exactly_once_and_is_plan_bound():
    # the factory is invoked exactly once per transaction (the drive completes before the commit
    # gate), and the built adapter is bound to the derived generation-0 plan.
    deps, bd, _fs, state = _install_deps()
    run(_install_argv(bd, write=True), deps)
    assert state["calls"] == 1  # one fresh adapter per transaction
    adapter = state["adapters"][0]
    assert adapter.plan.generation == 0  # the fake is bound to the derived generation-0 plan


# ============================================================ 5. combined marker-first compensation


@pytest.mark.parametrize(
    "fail_on,reason",
    [
        ("provision_signer_role", "fake_finalization_provision_signer_role_failed"),
        ("enable_api_signer", "fake_finalization_enable_api_signer_failed"),
    ],
)
def test_finalization_step_failure_refuses_and_leaves_no_marker(fail_on, reason):
    deps, bd, fs, state = _install_deps(fail_on=fail_on)
    loc = deps.locations
    code, rep = run(_install_argv(bd, write=True), deps)
    assert code == 2 and rep["reason_code"] == reason
    _assert_no_controller_documents(fs, loc)
    # the candidate marker never remains (never written, or resealed marker-first by the adapter)
    assert fs.lstat(loc.api_signer_marker_path()) is None
    assert state["calls"] == 1


@pytest.mark.parametrize(
    "kwargs,expected,marker_gone",
    [
        # proven compensation → the ORIGINAL commit reason; blocked by the commit bug (the reason
        # is currently evidence_forbidden_secret, not the attestation reason), so xfail(strict).
        pytest.param({}, "evidence_attestation_untrusted", True),
        ({"compensate_residual": True}, "recovery_required", True),  # residual → recovery_required
        ({"receipt_raise_on_call": 2}, "recovery_required", False),  # lost receipt → recovery
        ({"compensate_raises": True}, "recovery_required", False),  # compensate raises → recovery
    ],
)
def test_post_finalization_failure_runs_marker_first_compensation(kwargs, expected, marker_gone):
    # a bad evidence authenticator makes the COMMIT gate fail AFTER finalization committed, so the
    # engine drives the fake's compensate (marker-first) BEFORE the document/host unwind.
    deps, bd, fs, state = _install_deps(authenticator=WrongKeyAuthenticator(), **kwargs)
    loc = deps.locations
    code, rep = run(_install_argv(bd, write=True), deps)
    assert code == 2 and rep["reason_code"] == expected
    _assert_no_controller_documents(fs, loc)  # documents always unwound
    assert state["adapters"][0].ops[-1] == "enable_api_signer"  # finalization did complete first
    if marker_gone:
        assert fs.lstat(loc.api_signer_marker_path()) is None


# ---------------------------------------------- 6. exact same-release idempotent replay


def test_exact_same_release_replay_drives_zero_finalization_ops():
    # requires a COMMITTED first install (the marker + authenticated finalization evidence a replay
    # revalidates); blocked by the commit bug until a driven install can commit.
    deps, bd, fs, state = _install_deps()
    loc = deps.locations
    code1, rep1 = run(_install_argv(bd, write=True), deps)
    assert code1 == 0 and rep1["mode"] == "written" and rep1["idempotent_replay"] is False
    assert state["calls"] == 1

    before = fs.safe_read(loc.evidence_path("controller"), max_bytes=_MAX, expected_uid=0)
    code2, rep2 = run(_install_argv(bd, write=True), deps)
    after = fs.safe_read(loc.evidence_path("controller"), max_bytes=_MAX, expected_uid=0)

    assert code2 == 0 and rep2["mode"] == "written"
    assert rep2["classification"] == "exact_same_release"
    assert rep2["idempotent_replay"] is True
    assert rep2["finalization_generation"] == 0
    # NO new adapter is built and NO finalization op runs on the replay
    assert state["calls"] == 1
    assert len(state["adapters"]) == 1
    assert before == after  # evidence is not rewritten


# ---------------------------------------------- 7. CLI dry-run + arg refusals + grouping


def test_controller_install_dry_run_plans_without_driving_any_op():
    deps, bd, fs, state = _install_deps()
    loc = deps.locations
    code, rep = run(_install_argv(bd, write=False), deps)
    assert code == 0 and rep["mode"] == "dry_run"
    assert rep["classification"] == "fresh"
    assert rep["planned_generation"] == 0
    assert "plan" in rep and "install_options" in rep
    assert state["calls"] == 0  # no finalization adapter constructed on a dry run
    _assert_no_controller_documents(fs, loc)
    assert fs.lstat(loc.api_signer_marker_path()) is None


def test_missing_public_origin_or_tls_mode_refuses():
    deps, bd, _fs, _state = _install_deps()
    gate = WriteGate(write=False, confirm=False)
    code, rep = controller_install(None, MODE, bd, gate, deps)
    assert code == 2 and rep["reason_code"] == "controller_install_origin_required"
    code, rep = controller_install(ORIGIN, None, bd, gate, deps)
    assert code == 2 and rep["reason_code"] == "controller_install_tls_mode_required"


def test_is_controller_install_group_matches_only_controller_install():
    assert _is_controller_install_group(["controller", "install", "--bundle", "x"]) is True
    assert _is_controller_install_group(["--json", "controller", "install"]) is True
    assert _is_controller_install_group(["controller", "install"]) is True
    assert _is_controller_install_group(["controller", "status"]) is False
    assert _is_controller_install_group(["bootstrap", "controller"]) is False
    assert _is_controller_install_group(["controller"]) is False
