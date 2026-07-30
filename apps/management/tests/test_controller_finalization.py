"""RealControllerEnrollmentFinalizationAdapter — upgrade-safe finalization (SECP-PR5H-B2, 2b-3b-iv).

Fail-first + regression proofs for review 4794981971: cryptographic TLS adoption (F2), locator
classify/replace/restore (F3), signer role+credential adopt-unchanged / foreign-refuse (F1/F4),
exact code-rendered broker unit + prior-state restore (F1/F5), AF_UNIX socket proof + transport
probe (F5/F7), authenticated generation (F6), marker-last + post-restart runtime observation
(F4/F8), and typed per-effect receipts with prior-state restoration or recovery_required (F1).

Hermetic: in-memory hardened fs + fake pinned compose runner (reads the RO handoff, returns the
CANONICAL bounded one-shot receipt) + fake dedicated-role lease + no-op DB/socket/runtime seams.
The real-PostgreSQL/root/systemd proofs are the separate zero-skip fences.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from datetime import UTC, datetime  # noqa: E402

import pytest
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.controller_compose_contract import render_broker_reviewed_unit
from secp_management.controller_finalization import (
    ApiSignerRuntimeObservation,
    ControllerFinalizationError,
    FinalizationContext,
    RealControllerEnrollmentFinalizationAdapter,
)
from secp_management.controller_tls import produce_controller_tls
from secp_management.finalization import (
    ApiSignerMarker,
    ControllerEnrollmentFinalizationPlan,
    ControllerFinalizationReceipt,
    ControllerIdentityActivation,
    EffectDisposition,
    ReviewedSignerRole,
)
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_management.release_bundle import ControllerTlsPolicy
from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID

_ORIGIN = "https://controller.secp.example:8443"
_INSTALL = "controller-abc12345"
_RELEASE = "sha256:" + "2" * 64
_MGMT = "sha256:" + "e" * 64
_BOOT = "sha256:" + "f" * 64
_ROW = "11111111-1111-1111-1111-111111111111"
_TOKEN = f"{_ROW}|2026-07-28 00:00:00+00:00"
_NOW = datetime(2026, 7, 28, 0, 0, 30, tzinfo=UTC)
_LOC = ManagementLocations()
_ROLE = ReviewedSignerRole(
    role_name="secp_enrollment_signer",
    credential_source_path=_LOC.enrollment_signer_credential_path(),
)
_WORLD: dict = {}


def _policy() -> ControllerTlsPolicy:
    return ControllerTlsPolicy(
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


def _plan(generation: int = 0) -> ControllerEnrollmentFinalizationPlan:
    return ControllerEnrollmentFinalizationPlan(
        role="controller",
        tls_policy=_policy(),
        canonical_origin=_ORIGIN,
        tls_mode="generated_local_ca",
        signer_role=_ROLE,
        broker_unit=render_broker_reviewed_unit(_LOC),
        controller_installation_id=_INSTALL,
        release_digest=_RELEASE,
        management_identity_digest=_MGMT,
        bootstrap_evidence_digest=_BOOT,
        generation=generation,
    )


class _Result:
    def __init__(self, code: int, stdout: str) -> None:
        self.exit_code = code
        self.stdout = stdout


class _Lease:
    def __init__(self, w: dict) -> None:
        for k, v in w.items():
            setattr(self, k, v)


class _FakeLeaseProvider:
    def __init__(self, engine: object) -> None:
        self._e = engine

    def lease(self):
        class _C:
            def __enter__(self_inner):
                if not _WORLD:
                    raise RuntimeError("no active identity")
                return _Lease(_WORLD)

            def __exit__(self_inner, *a):
                return False

        return _C()


class _FakeRunner:
    def __init__(self, fs: InMemoryFilesystem, *, provision_overrides: dict | None = None) -> None:
        self._fs = fs
        self._prov = provision_overrides or {}
        self.calls: list[tuple[str, ...]] = []

    def run(self, pin, argv, *, timeout_seconds, max_output_bytes):
        self.calls.append(tuple(argv))
        joined = " ".join(argv)
        if "provision_enrollment_signer_role_once" in joined:
            h = self._handoff(argv)
            posture = {
                "operation_id": h["operation_id"],
                "role_name": "secp_enrollment_signer",
                "can_login": True,
                "not_superuser": True,
                "not_createrole": True,
                "not_createdb": True,
                "not_bypassrls": True,
                "not_inherit": True,
                "not_replication": True,
                "select_on_identity": True,
                "no_write_on_identity": True,
                "no_unrelated_read": True,
                "owns_nothing": True,
                "no_memberships": True,
            }
            posture.update(self._prov)  # drift injection (a failed least-privilege bit)
            return _Result(0, canonical_json(posture))
        if "activate_controller_identity_once" in joined:
            h = self._handoff(argv)
            return _Result(
                0,
                canonical_json(
                    {
                        "operation_id": h["operation_id"],
                        "candidate_digest": h["candidate_digest"],
                        "resulting_row_id": _ROW,
                        "activation_token": _TOKEN,
                        "previous_active_row_id": h["expected_predecessor_row_id"],
                        "created": True,
                        "resulting_status": "active",
                        "resulting_public_state_digest": "sha256:" + "a" * 64,
                    }
                ),
            )
        return _Result(0, "")

    def _handoff(self, argv) -> dict:
        spec = argv[argv.index("--volume") + 1]
        return json.loads(self._fs.safe_read(spec.split(":")[0], max_bytes=8192, expected_uid=0))


def _fs(*, socket: bool = True) -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in (
        "/opt",
        "/opt/secp",
        "/opt/secp/controller",
        "/opt/secp/bootstrap",
        "/etc",
        "/etc/secp",
        "/etc/secp/controller",
        "/etc/secp/controller/tls",
        "/etc/secp/controller/credentials",
        "/etc/systemd",
        "/etc/systemd/system",
        "/var",
        "/var/lib",
        "/var/lib/secp",
        "/var/lib/secp/bootstrap",
        "/var/lib/secp/bootstrap/handoff",
        "/var/lib/secp/bootstrap/finalization-staging",
        "/run",
        "/run/secp",
    ):
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    if socket:
        fs.seed_socket(ENROLLMENT_SIGNER_SOCKET_PATH, uid=0, gid=API_RUNTIME_GID, mode=0o660)
    return fs


def _pin() -> PinnedExecutables:
    from secp_operator_deployment.pinned_exec import ExecutablePin

    p = ExecutablePin(path="/usr/bin/docker", digest="sha256:" + "0" * 64)
    return PinnedExecutables(container_runtime=p, compose_runtime=p, service_manager=p)


def _passing_observation(marker) -> ApiSignerRuntimeObservation:
    return ApiSignerRuntimeObservation(*([True] * 12))


def _adapter(fs, runner, *, generation=0, runtime_observer=None):
    ctx = FinalizationContext(
        host=RealAdapterContext(locations=_LOC, fs=fs, runner=runner, executables=_pin()),
        lease_provider_factory=_FakeLeaseProvider,
        db_prober=lambda engine: None,
        socket_prober=lambda path, *, expected_peer: None,
        runtime_observer=runtime_observer or _passing_observation,
        now=lambda tz=UTC: _NOW,
    )
    return RealControllerEnrollmentFinalizationAdapter(ctx, plan=_plan(generation))


def _drive_to_activation(adapter, fs, *, generation=0):
    _WORLD.clear()
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    adapter.record_locator(canonical_origin=_ORIGIN)
    adapter.provision_signer_role(_ROLE)
    key = adapter.prepare_enrollment_key()
    _WORLD.update(
        row_id=_ROW,
        activation_token=_TOKEN,
        controller_installation_id=_INSTALL,
        controller_key_id=key.controller_key_id,
        controller_trust_anchor_hex=key.controller_trust_anchor_hex,
        controller_origin=_ORIGIN,
        release_digest=_RELEASE,
        management_identity_digest=_MGMT,
        bootstrap_evidence_digest=_BOOT,
        enrollment_key_proof_id=key.enrollment_key_proof_id,
    )
    adapter.install_broker_unit(render_broker_reviewed_unit(_LOC))
    adapter.start_broker()
    adapter.verify_signer_operational(key_identity=key)
    activation = ControllerIdentityActivation(
        controller_installation_id=_INSTALL,
        controller_key_id=key.controller_key_id,
        controller_trust_anchor_hex=key.controller_trust_anchor_hex,
        controller_origin=_ORIGIN,
        release_digest=_RELEASE,
        management_identity_digest=_MGMT,
        bootstrap_evidence_digest=_BOOT,
        enrollment_key_proof_id=key.enrollment_key_proof_id,
        operation_id="op-finalize",
        generation=generation,
        previous_active_row_id=None,
    )
    receipt = adapter.activate_controller_identity(activation)
    ca_digest = (
        "sha256:"
        + hashlib.sha256(
            fs.safe_read(_LOC.controller_ca_bundle_path(), max_bytes=1 << 20, expected_uid=0)
        ).hexdigest()
    )
    return key, receipt, ca_digest


def _marker(receipt, ca_digest):
    return ApiSignerMarker(
        marker_path=_LOC.api_signer_marker_path(),
        installation_id=_INSTALL,
        release_digest=_RELEASE,
        active_identity_row_id=receipt.resulting_row_id,
        activation_token=receipt.activation_token,
        controller_key_id=_WORLD["controller_key_id"],
        uds_contract_identity=ENROLLMENT_SIGNER_SOCKET_PATH,
        api_uid=API_RUNTIME_UID,
        api_gid=API_RUNTIME_GID,
        signer_role_name="secp_enrollment_signer",
        locator_ca_digest=ca_digest,
        management_identity_digest=_MGMT,
        bootstrap_evidence_digest=_BOOT,
    )


# ---- full sequence + typed receipts + marker last ----
def test_fresh_install_sequence_records_typed_effects_and_writes_marker_last():
    fs = _fs()
    runner = _FakeRunner(fs)
    adapter = _adapter(fs, runner)
    key, receipt, ca_digest = _drive_to_activation(adapter, fs)
    assert fs.lstat(_LOC.api_signer_marker_path()) is None  # marker not written until enable
    adapter.enable_api_signer(_marker(receipt, ca_digest))
    r = adapter.receipt()
    effects = [e.effect for e in r.effects]
    assert effects[-1] == "marker" and "identity_activation" in effects  # marker LAST
    assert r.transaction_id.startswith("tx-") and r.generation == 0
    # every fresh-install effect is disposition=absent (created)
    assert all(
        e.disposition == EffectDisposition.ABSENT.value
        for e in r.effects
        if e.effect in ("tls", "locator", "signer_role", "signer_credential", "marker")
    )
    assert fs.lstat(_LOC.api_signer_marker_path()) is not None


def test_no_secret_bytes_in_any_receipt_effect():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_to_activation(adapter, fs)
    adapter.enable_api_signer(_marker(receipt, ca_digest))
    blob = json.dumps([e.__dict__ for e in adapter.receipt().effects])
    for forbidden in ("SCRAM-SHA-256", "PRIVATE KEY", "BEGIN EC", "password", "verifier"):
        assert forbidden not in blob


# ---- F2: cryptographic TLS adoption ----
def _install_valid_tls(fs):
    produced = produce_controller_tls(
        policy=_policy(), canonical_origin=_ORIGIN, mode="generated_local_ca", now=_NOW
    )
    fs.seed_file(
        _LOC.controller_ca_bundle_path(), produced.ca_bundle_pem(), uid=0, gid=0, mode=0o644
    )
    fs.seed_file(
        _LOC.controller_server_cert_path(),
        produced.server_certificate_pem(),
        uid=0,
        gid=0,
        mode=0o644,
    )
    fs.seed_file(
        _LOC.controller_server_key_path(),
        produced.server_private_key_pem(),
        uid=0,
        gid=0,
        mode=0o600,
    )


def test_valid_existing_tls_is_cryptographically_adopted_without_rewrite():
    fs = _fs()
    _install_valid_tls(fs)
    before = fs.safe_read(_LOC.controller_server_cert_path(), max_bytes=1 << 20, expected_uid=0)
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    after = fs.safe_read(_LOC.controller_server_cert_path(), max_bytes=1 << 20, expected_uid=0)
    assert before == after  # adopted, not rewritten
    tls = adapter.receipt().of("tls")
    assert tls is not None and tls.disposition == EffectDisposition.EXACT_ADOPTED.value


def test_partial_tls_set_refuses():
    fs = _fs()
    _install_valid_tls(fs)
    fs.remove_file(_LOC.controller_server_key_path())  # 2 of 3 present
    adapter = _adapter(fs, _FakeRunner(fs))
    with pytest.raises(ManagementError) as e:
        adapter.install_tls_material(
            policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
        )
    assert e.value.reason_code == "finalization_tls_partial_set"


def test_existing_tls_with_wrong_origin_refuses():
    fs = _fs()
    _install_valid_tls(fs)
    adapter = _adapter(fs, _FakeRunner(fs))
    with pytest.raises(ManagementError) as e:
        adapter.install_tls_material(
            policy=_policy(),
            canonical_origin="https://attacker.example:8443",
            tls_mode="generated_local_ca",
        )
    assert e.value.reason_code.startswith("finalization_tls_adopt_invalid")


# ---- F3: locator adopt / refuse ----
def test_absent_locator_is_created_then_exact_locator_is_adopted_without_rewrite():
    fs = _fs()
    _install_valid_tls(fs)
    a1 = _adapter(fs, _FakeRunner(fs))
    a1.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    a1.record_locator(canonical_origin=_ORIGIN)
    assert a1.receipt().of("locator").disposition == EffectDisposition.ABSENT.value
    before = fs.safe_read(_LOC.controller_api_locator_path(), max_bytes=1 << 20, expected_uid=0)
    a2 = _adapter(fs, _FakeRunner(fs))
    a2.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    a2.record_locator(canonical_origin=_ORIGIN)
    after = fs.safe_read(_LOC.controller_api_locator_path(), max_bytes=1 << 20, expected_uid=0)
    assert before == after
    assert a2.receipt().of("locator").disposition == EffectDisposition.EXACT_ADOPTED.value


def test_foreign_locator_refuses():
    fs = _fs()
    _install_valid_tls(fs)
    fs.seed_file(_LOC.controller_api_locator_path(), b"{ not a locator }", uid=0, gid=0, mode=0o644)
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    with pytest.raises(ManagementError) as e:
        adapter.record_locator(canonical_origin=_ORIGIN)
    assert e.value.reason_code == "finalization_locator_unsafe_or_foreign"


# ---- F4: signer credential adopt-unchanged (no rotation) but least privilege re-proven ----
def test_existing_credential_is_adopted_without_rotation_but_least_privilege_is_reproven():
    fs = _fs()
    fs.seed_file(
        _LOC.enrollment_signer_credential_path(),
        (("a" * 64) + "\n").encode(),
        uid=0,
        gid=0,
        mode=0o600,
    )
    runner = _FakeRunner(fs)
    adapter = _adapter(fs, runner)
    adapter.provision_signer_role(_ROLE)
    cred = adapter.receipt().of("signer_credential")
    assert cred.disposition == EffectDisposition.EXACT_ADOPTED.value
    # the operator credential bytes are UNCHANGED (no password rotation on an ordinary upgrade)...
    assert (
        fs.safe_read(_LOC.enrollment_signer_credential_path(), max_bytes=128, expected_uid=0)
        == (("a" * 64) + "\n").encode()
    )
    # ...but the least-privilege provisioning/repair one-shot IS re-run to re-prove the adopted role
    assert any("provision_enrollment_signer_role_once" in " ".join(c) for c in runner.calls)


def test_adopt_refuses_a_privilege_drifted_role():
    # F4: an existing role whose least-privilege posture drifted (the exhaustive receipt reports a
    # failed bit) is refused on adoption — never silently adopted.
    fs = _fs()
    fs.seed_file(
        _LOC.enrollment_signer_credential_path(),
        (("a" * 64) + "\n").encode(),
        uid=0,
        gid=0,
        mode=0o600,
    )
    runner = _FakeRunner(fs, provision_overrides={"not_superuser": False})  # drifted → superuser
    adapter = _adapter(fs, runner)
    with pytest.raises(ManagementError) as e:
        adapter.provision_signer_role(_ROLE)
    assert e.value.reason_code == "finalization_provisioning_posture_invalid"


def test_wrong_credential_source_path_refuses():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    bad = ReviewedSignerRole(
        role_name="secp_enrollment_signer", credential_source_path="/etc/secp/other"
    )
    with pytest.raises(ManagementError) as e:
        adapter.provision_signer_role(bad)
    assert e.value.reason_code == "finalization_signer_credential_path_invalid"


# ---- F5/F7: broker unit exact + socket proof ----
def test_arbitrary_self_consistent_broker_unit_refuses():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    from secp_management.adapters import ReviewedUnit

    fake = b"[Unit]\nDescription=evil\n"
    unit = ReviewedUnit(identity=sha256_bytes(fake), content=fake)
    with pytest.raises(ManagementError) as e:
        adapter.install_broker_unit(unit)
    assert e.value.reason_code == "finalization_broker_unit_not_code_rendered"


def test_broker_socket_that_is_a_fifo_refuses():
    fs = _fs(socket=False)
    fs.seed_special(
        ENROLLMENT_SIGNER_SOCKET_PATH, uid=0, gid=API_RUNTIME_GID
    )  # FIFO/device, not a socket
    adapter = _adapter(fs, _FakeRunner(fs))
    _drive_partial_for_socket(adapter, fs)
    key = adapter._key_identity
    with pytest.raises(ManagementError) as e:
        adapter.verify_signer_operational(key_identity=key)
    assert e.value.reason_code == "finalization_broker_socket_posture_invalid"


def _drive_partial_for_socket(adapter, fs):
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    adapter.record_locator(canonical_origin=_ORIGIN)
    adapter.provision_signer_role(_ROLE)
    adapter.prepare_enrollment_key()
    adapter.install_broker_unit(render_broker_reviewed_unit(_LOC))
    adapter.start_broker()


def test_real_socket_passes_the_operational_proof():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    _drive_partial_for_socket(adapter, fs)
    adapter.verify_signer_operational(key_identity=adapter._key_identity)  # no raise


# ---- F6: generation ----
def test_activation_generation_must_equal_plan_generation():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs), generation=0)
    _WORLD.clear()
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    adapter.record_locator(canonical_origin=_ORIGIN)
    adapter.provision_signer_role(_ROLE)
    key = adapter.prepare_enrollment_key()
    adapter.install_broker_unit(render_broker_reviewed_unit(_LOC))
    adapter.start_broker()
    adapter.verify_signer_operational(key_identity=key)
    mismatched = ControllerIdentityActivation(
        controller_installation_id=_INSTALL,
        controller_key_id=key.controller_key_id,
        controller_trust_anchor_hex=key.controller_trust_anchor_hex,
        controller_origin=_ORIGIN,
        release_digest=_RELEASE,
        management_identity_digest=_MGMT,
        bootstrap_evidence_digest=_BOOT,
        enrollment_key_proof_id=key.enrollment_key_proof_id,
        operation_id="op-x",
        generation=5,
        previous_active_row_id=None,  # != plan generation 0
    )
    with pytest.raises(ManagementError) as e:
        adapter.activate_controller_identity(mismatched)
    assert e.value.reason_code == "finalization_activation_generation_mismatch"


# ---- F8: post-marker runtime observation ----
def test_failed_runtime_observation_removes_marker_first_and_seals():
    fs = _fs()

    def _failing(marker):
        return ApiSignerRuntimeObservation(*([True] * 11 + [False]))  # no_mixed_generation False

    adapter = _adapter(fs, _FakeRunner(fs), runtime_observer=_failing)
    key, receipt, ca_digest = _drive_to_activation(adapter, fs)
    with pytest.raises(ManagementError) as e:
        adapter.enable_api_signer(_marker(receipt, ca_digest))
    assert e.value.reason_code == "finalization_post_marker_runtime_unverified"
    assert fs.lstat(_LOC.api_signer_marker_path()) is None  # candidate marker removed FIRST


def test_failed_runtime_on_an_upgrade_restores_the_prior_marker():
    # F5/F8: when a PRIOR marker exists (an upgrade), a failed post-marker runtime must RESTORE the
    # prior marker bytes (not merely remove the candidate) and restart the API back to the prior
    # working generation — the managed_replaced rollback path.
    fs = _fs()
    prior_bytes = b'{"schema":"secp.api_signer.marker.prior","prior":"working-generation"}'
    fs.seed_file(_LOC.api_signer_marker_path(), prior_bytes, uid=0, gid=0, mode=0o644)

    def _failing(marker):
        return ApiSignerRuntimeObservation(*([True] * 11 + [False]))

    adapter = _adapter(fs, _FakeRunner(fs), runtime_observer=_failing)
    key, receipt, ca_digest = _drive_to_activation(adapter, fs)
    with pytest.raises(ManagementError) as e:
        adapter.enable_api_signer(_marker(receipt, ca_digest))
    assert e.value.reason_code == "finalization_post_marker_runtime_unverified"
    restored = fs.safe_read(_LOC.api_signer_marker_path(), max_bytes=1 << 16, expected_uid=0)
    assert (
        restored == prior_bytes
    )  # the PRIOR marker is restored, not removed and not the candidate
    assert adapter.receipt().of("marker").disposition == EffectDisposition.MANAGED_REPLACED.value


# ------------------------------------------- the readiness-origin GATE lifecycle (2b-3c-c, C3)

_GATE_PATH = _LOC.api_signer_readiness_gate_path()
_GATE_RE = re.compile(rb"[0-9a-f]{64}\n")


def test_a_fresh_install_creates_and_PROVES_the_readiness_gate() -> None:
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_readiness_gate()

    st = fs.lstat(_GATE_PATH)
    assert st is not None
    assert st.uid == 0 and st.gid == API_RUNTIME_GID  # root-owned, API-group readable
    assert st.mode & 0o777 == 0o640  # NO world bit on a 256-bit machine secret
    raw = fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0)
    assert _GATE_RE.fullmatch(raw)  # 256 bits of lowercase hex plus exactly one LF


def test_two_fresh_installs_never_produce_the_same_gate() -> None:
    # the value comes from the OS CSPRNG, not from any installation fact the caller controls.
    values = set()
    for _ in range(4):
        fs = _fs()
        _adapter(fs, _FakeRunner(fs)).install_readiness_gate()
        values.add(fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0))
    assert len(values) == 4


def test_the_gate_effect_records_only_a_digest_and_ownership_never_the_value() -> None:
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_readiness_gate()
    raw = fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0)
    secret = raw.decode("ascii").strip()

    effects = [e for e in adapter.receipt().effects if e.effect == "readiness_gate"]
    assert len(effects) == 1
    blob = canonical_json([dataclasses.asdict(e) for e in adapter.receipt().effects])
    assert secret not in blob  # the 256-bit value never enters a receipt
    assert effects[0].candidate_digest.startswith("sha256:")


def test_an_exact_replay_ADOPTS_the_gate_unchanged_and_never_rotates_it() -> None:
    fs = _fs()
    _adapter(fs, _FakeRunner(fs)).install_readiness_gate()
    installed = fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0)

    replay = _adapter(fs, _FakeRunner(fs))
    replay.install_readiness_gate()
    # rotating would revoke a LIVE api's authorization while proving nothing.
    assert fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0) == installed
    effect = [e for e in replay.receipt().effects if e.effect == "readiness_gate"][0]
    assert effect.disposition == EffectDisposition.EXACT_ADOPTED.value
    assert effect.candidate_digest == ""  # nothing was authored, so nothing is claimed


@pytest.mark.parametrize(
    "uid,gid,mode,body",
    [
        (0, API_RUNTIME_GID, 0o644, b"a" * 64 + b"\n"),  # world-readable
        (0, API_RUNTIME_GID, 0o660, b"a" * 64 + b"\n"),  # group-WRITABLE
        (1000, API_RUNTIME_GID, 0o640, b"a" * 64 + b"\n"),  # not root-owned
        (0, 0, 0o640, b"a" * 64 + b"\n"),  # a group the API cannot read
        (0, API_RUNTIME_GID, 0o640, b"A" * 64 + b"\n"),  # not lowercase hex
        (0, API_RUNTIME_GID, 0o640, b"a" * 64),  # no trailing LF
        (0, API_RUNTIME_GID, 0o640, b"a" * 63 + b"\n"),  # short of 256 bits
    ],
)
def test_a_foreign_or_malformed_gate_refuses_and_is_never_overwritten(uid, gid, mode, body) -> None:
    fs = _fs()
    fs.seed_file(_GATE_PATH, body, uid=uid, gid=gid, mode=mode)
    before = fs.lstat(_GATE_PATH)
    with pytest.raises(ControllerFinalizationError) as exc:
        _adapter(fs, _FakeRunner(fs)).install_readiness_gate()
    assert exc.value.reason_code == "finalization_readiness_gate_unsafe_or_foreign"
    # classify-before-mutate: the foreign object is left EXACTLY as found. The install is atomic,
    # so an overwrite would replace the node -- an identical stat proves nothing was written.
    assert fs.lstat(_GATE_PATH) == before


def test_compensation_removes_a_gate_this_transaction_CREATED() -> None:
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_readiness_gate()
    assert fs.lstat(_GATE_PATH) is not None
    result = adapter.compensate(adapter.receipt())
    assert result.proven is True
    assert fs.lstat(_GATE_PATH) is None


def test_compensation_PRESERVES_a_gate_the_installation_already_owned() -> None:
    fs = _fs()
    _adapter(fs, _FakeRunner(fs)).install_readiness_gate()
    prior = fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0)

    replay = _adapter(fs, _FakeRunner(fs))
    replay.install_readiness_gate()  # adopted, not created
    assert replay.compensate(replay.receipt()).proven is True
    # a rollback must never revoke authorization the installation owned before it started.
    assert fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0) == prior


def test_compensation_leaves_a_DRIFTED_gate_in_place_and_reports_a_residual() -> None:
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_readiness_gate()
    drifted = b"b" * 64 + b"\n"
    fs.seed_file(_GATE_PATH, drifted, uid=0, gid=API_RUNTIME_GID, mode=0o640)

    result = adapter.compensate(adapter.receipt())
    assert result.proven is False
    assert "readiness_gate" in result.residual
    assert fs.safe_read(_GATE_PATH, max_bytes=65, expected_uid=0) == drifted


def test_marker_seals_on_reobservation_disagreement():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_to_activation(adapter, fs)
    import dataclasses

    bad = dataclasses.replace(
        _marker(receipt, ca_digest), active_identity_row_id="99999999-9999-9999-9999-999999999999"
    )
    with pytest.raises(ManagementError) as e:
        adapter.enable_api_signer(bad)
    assert e.value.reason_code == "finalization_marker_identity_disagreement"
    assert fs.lstat(_LOC.api_signer_marker_path()) is None


# ---- F1: compensation (restore / recovery_required) ----
def test_pre_activation_fs_compensation_removes_all_created_host_objects():
    # A rollback BEFORE the DB role / identity are created removes every created HOST object cleanly
    # and proves it (the DB role + activated identity are the only recovery_required residuals, and
    # they require an API-plane one-shot to reverse — proved separately below).
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    adapter.record_locator(canonical_origin=_ORIGIN)
    adapter.prepare_enrollment_key()
    adapter.install_broker_unit(render_broker_reviewed_unit(_LOC))
    result = adapter.compensate(adapter.receipt())
    assert result.proven is True and result.residual == ()
    for p in (
        _LOC.controller_ca_bundle_path(),
        _LOC.controller_server_key_path(),
        _LOC.controller_api_locator_path(),
        _LOC.broker_unit_path(),
    ):
        assert fs.lstat(p) is None


def test_activated_identity_forces_recovery_required():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_to_activation(adapter, fs)
    adapter.enable_api_signer(_marker(receipt, ca_digest))
    result = adapter.compensate(adapter.receipt())
    assert fs.lstat(_LOC.api_signer_marker_path()) is None  # marker removed FIRST
    assert result.proven is False
    assert "identity_activation" in result.residual and "signer_role_created" in result.residual


def test_adopted_objects_are_not_removed_on_compensation():
    fs = _fs()
    _install_valid_tls(fs)  # pre-existing valid TLS → adopted, never recorded for removal
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    adapter.compensate(adapter.receipt())
    assert fs.lstat(_LOC.controller_ca_bundle_path()) is not None  # adopted TLS left in place


def test_compensate_refuses_a_foreign_receipt_type():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    result = adapter.compensate("nope")  # type: ignore[arg-type]
    assert result.proven is False and result.residual == ("malformed_receipt",)


def test_empty_receipt_compensates_cleanly():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    assert adapter.compensate(ControllerFinalizationReceipt()).proven is True


_JOURNAL_PATH = f"{_LOC.bootstrap_state}/controller-finalization-journal.json"


def _adapter_default_observer(fs, runner):
    # build the adapter with NO injected runtime_observer so it uses the real fail-closed default.
    ctx = FinalizationContext(
        host=RealAdapterContext(locations=_LOC, fs=fs, runner=runner, executables=_pin()),
        lease_provider_factory=_FakeLeaseProvider,
        db_prober=lambda engine: None,
        socket_prober=lambda path, *, expected_peer: None,
        runtime_observer=None,
        now=lambda tz=UTC: _NOW,
    )
    return RealControllerEnrollmentFinalizationAdapter(ctx, plan=_plan(0))


# ---- F8: the DEFAULT runtime observer fails closed (no rubber stamp) ----
def test_default_runtime_observer_fails_closed_when_not_injected():
    fs = _fs()
    adapter = _adapter_default_observer(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_to_activation(adapter, fs)
    with pytest.raises(ManagementError) as e:
        adapter.enable_api_signer(_marker(receipt, ca_digest))
    assert e.value.reason_code == "finalization_post_marker_runtime_unverified"
    assert fs.lstat(_LOC.api_signer_marker_path()) is None  # marker removed first + API resealed


# ---- single-use transaction: sealed after a terminal outcome ----
def test_transaction_is_single_use_after_compensate():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    adapter.compensate(adapter.receipt())
    with pytest.raises(ManagementError) as e:
        adapter.record_locator(canonical_origin=_ORIGIN)  # sealed → any further mutation refuses
    assert e.value.reason_code == "finalization_transaction_sealed"


# ---- F1: the recovery journal is WRITE-AHEAD (intent durable before the mutation) ----
class _JournalPeekRunner(_FakeRunner):
    def __init__(self, fs):
        super().__init__(fs)
        self.pending_at_activation = None

    def run(self, pin, argv, *, timeout_seconds, max_output_bytes):
        if "activate_controller_identity_once" in " ".join(argv):
            doc = json.loads(self._fs.safe_read(_JOURNAL_PATH, max_bytes=1 << 16, expected_uid=0))
            self.pending_at_activation = doc.get("pending")  # BEFORE the DB one-shot runs
        return super().run(
            pin, argv, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes
        )


def test_identity_activation_intent_is_journaled_before_the_db_mutation():
    fs = _fs()
    runner = _JournalPeekRunner(fs)
    adapter = _adapter(fs, runner)
    _drive_to_activation(adapter, fs)
    assert runner.pending_at_activation is not None
    assert runner.pending_at_activation["effect"] == "identity_activation"


def test_recovery_journal_is_public_and_removed_on_commit():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    raw = fs.safe_read(_JOURNAL_PATH, max_bytes=1 << 16, expected_uid=0)  # journal exists mid-tx
    doc = json.loads(raw)
    assert doc["transaction_id"] == adapter.receipt().transaction_id
    for forbidden in ("PRIVATE KEY", "BEGIN EC", "password", "SCRAM-SHA-256"):
        assert forbidden not in raw.decode()
    assert adapter.commit() is True
    assert fs.lstat(_JOURNAL_PATH) is None  # removed after commit


def test_known_credential_secret_never_appears_in_receipt_or_journal():
    fs = _fs()
    known = "feedface" * 8  # a valid 64-char lowercase-hex credential with a recognizable marker
    fs.seed_file(
        _LOC.enrollment_signer_credential_path(),
        (known + "\n").encode(),
        uid=0,
        gid=0,
        mode=0o600,
    )
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.provision_signer_role(_ROLE)  # adopt path reads the KNOWN plaintext credential
    blob = json.dumps([e.__dict__ for e in adapter.receipt().effects])
    assert known not in blob
    assert known not in fs.safe_read(_JOURNAL_PATH, max_bytes=1 << 16, expected_uid=0).decode()
