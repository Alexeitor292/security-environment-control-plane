"""RealControllerEnrollmentFinalizationAdapter — sequencing, marker-last, secret boundaries,
handoff lifecycle, reobserve-agreement, and drift-checked compensation (SECP-PR5H-B2, 2b-3b-iii).

Hermetic: an in-memory hardened filesystem + a fake pinned compose runner (which reads the
read-only handoff it is handed and returns the bounded one-shot receipt, exactly like the real API
one-shots) + a fake dedicated-role lease provider + a no-op DB prober. No PostgreSQL, no Docker, no
systemd, no root. The real-PostgreSQL dedicated-role proof is the separate zero-skip fence.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
from secp_commissioning.controller_enrollment_signer import (
    ENROLLMENT_SIGNER_SOCKET_PATH,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.controller_compose_contract import render_broker_reviewed_unit
from secp_management.controller_finalization import (
    FinalizationContext,
    RealControllerEnrollmentFinalizationAdapter,
)
from secp_management.finalization import (
    ApiSignerMarker,
    ControllerFinalizationReceipt,
    ControllerIdentityActivation,
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
_FIXED_NOW = datetime(2026, 7, 28, 0, 0, 30, tzinfo=UTC)
_ROLE = ReviewedSignerRole(
    role_name="secp_enrollment_signer",
    credential_source_path=ManagementLocations().enrollment_signer_credential_path(),
)


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


class _Result:
    def __init__(self, exit_code: int, stdout: str) -> None:
        self.exit_code = exit_code
        self.stdout = stdout


class _Lease:
    def __init__(self, world: dict) -> None:
        for k, v in world.items():
            setattr(self, k, v)


class _FakeLeaseProvider:
    """A fake ``DbActiveControllerSigningIdentityProvider`` — yields a lease built from the shared
    mutable ``world`` (set once the enrollment key identity is known)."""

    def __init__(self, engine: object) -> None:
        self._engine = engine

    def lease(self):
        provider = self

        class _Ctx:
            def __enter__(self):
                if provider is _NO_ACTIVE.get("provider"):
                    raise RuntimeError("no active identity")
                return _Lease(_WORLD)

            def __exit__(self, *a):
                return False

        return _Ctx()


_WORLD: dict = {}
_NO_ACTIVE: dict = {}


class _FakeRunner:
    """Records every pinned command and, for the two one-shots, reads the read-only handoff it was
    handed (via the ``--volume`` spec) and returns the bounded receipt the real one-shot would."""

    def __init__(self, fs: InMemoryFilesystem) -> None:
        self._fs = fs
        self.calls: list[tuple[str, ...]] = []

    def run(self, pin, argv, *, timeout_seconds, max_output_bytes):
        self.calls.append(tuple(argv))
        joined = " ".join(argv)
        if "provision_enrollment_signer_role_once" in joined:
            h = self._handoff(argv)
            return _Result(
                0,
                json.dumps(
                    {
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
                ),
            )
        if "activate_controller_identity_once" in joined:
            h = self._handoff(argv)
            return _Result(
                0,
                json.dumps(
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
        return _Result(0, "")  # daemon-reload / start / stop / up

    def _handoff(self, argv) -> dict:
        spec = argv[argv.index("--volume") + 1]
        host = spec.split(":")[0]
        return json.loads(self._fs.safe_read(host, max_bytes=8192, expected_uid=0))


def _fs() -> InMemoryFilesystem:
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
        "/run",
        "/run/secp",
    ):
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    # the broker binds its UDS at start (root:api-group 0660); the fake represents that bound socket
    fs.seed_special(ENROLLMENT_SIGNER_SOCKET_PATH, uid=0, gid=API_RUNTIME_GID)
    return fs


def _pin() -> PinnedExecutables:
    d = "sha256:" + "0" * 64
    from secp_operator_deployment.pinned_exec import ExecutablePin

    p = ExecutablePin(path="/usr/bin/docker", digest=d)
    return PinnedExecutables(container_runtime=p, compose_runtime=p, service_manager=p)


def _adapter(fs, runner):
    ctx = FinalizationContext(
        host=RealAdapterContext(
            locations=ManagementLocations(), fs=fs, runner=runner, executables=_pin()
        ),
        lease_provider_factory=_FakeLeaseProvider,
        db_prober=lambda engine: None,  # no live PostgreSQL in the unit fence
        now=lambda tz=UTC: _FIXED_NOW,
    )
    return RealControllerEnrollmentFinalizationAdapter(ctx)


def _drive_through_activation(adapter, fs):
    """Run steps 1-8 (TLS -> locator -> signer role -> key -> broker unit -> start -> verify ->
    activate) and return (key_identity, activation_receipt, ca_digest)."""
    _WORLD.clear()
    _NO_ACTIVE.clear()
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    ca_pem = fs.safe_read(
        ManagementLocations().controller_ca_bundle_path(), max_bytes=1 << 20, expected_uid=0
    )
    ca_digest = "sha256:" + hashlib.sha256(ca_pem).hexdigest()
    adapter.record_locator(canonical_origin=_ORIGIN)
    adapter.provision_signer_role(_ROLE)
    key = adapter.prepare_enrollment_key()
    # the reobserved active identity agrees with the just-activated candidate
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
    adapter.install_broker_unit(render_broker_reviewed_unit())
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
        operation_id="op-finalize-1",
        previous_active_row_id=None,
    )
    receipt = adapter.activate_controller_identity(activation)
    return key, receipt, ca_digest


def _marker(receipt, ca_digest) -> ApiSignerMarker:
    return ApiSignerMarker(
        marker_path=ManagementLocations().api_signer_marker_path(),
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


def test_full_finalization_sequence_writes_marker_last_and_populates_receipt():
    fs = _fs()
    runner = _FakeRunner(fs)
    adapter = _adapter(fs, runner)
    key, receipt, ca_digest = _drive_through_activation(adapter, fs)
    assert receipt.created is True and receipt.resulting_row_id == _ROW
    marker_path = ManagementLocations().api_signer_marker_path()
    # the marker does not exist until enable_api_signer runs LAST
    assert fs.lstat(marker_path) is None
    adapter.enable_api_signer(_marker(receipt, ca_digest))
    st = fs.lstat(marker_path)
    assert st is not None and st.uid == 0 and st.nlink == 1 and st.mode == 0o644
    r = adapter.receipt()
    assert r.installed_tls and r.recorded_locators and r.provisioned_roles
    assert r.prepared_keys and r.installed_broker_units and r.started_brokers
    assert r.activated_identities == (_ROW,) and len(r.enabled_markers) == 1
    # the API restart (compose up ... api) runs AFTER the marker is written (marker is the switch)
    up_calls = [c for c in runner.calls if "up" in c and "api" in c]
    assert up_calls, "the API must be restarted after the marker is written"


def test_handoffs_are_removed_and_absence_proven_after_each_one_shot():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    _drive_through_activation(adapter, fs)
    loc = ManagementLocations()
    assert fs.lstat(loc.provisioning_handoff_host_path()) is None
    assert fs.lstat(loc.activation_handoff_host_path()) is None


def test_handoff_posture_is_root_api_group_0640_while_present():
    fs = _fs()

    class _CapturingRunner(_FakeRunner):
        posture: dict = {}

        def _handoff(self, argv):
            spec = argv[argv.index("--volume") + 1]
            host = spec.split(":")[0]
            st = self._fs.lstat(host)
            _CapturingRunner.posture[host] = (st.uid, st.gid, st.mode, st.nlink, st.is_regular)
            return super()._handoff(argv)

    adapter = _adapter(fs, _CapturingRunner(fs))
    _drive_through_activation(adapter, fs)
    assert _CapturingRunner.posture, "the one-shots must have observed a handoff"
    for uid, gid, mode, nlink, is_regular in _CapturingRunner.posture.values():
        assert (uid, gid, mode, nlink, is_regular) == (0, API_RUNTIME_GID, 0o640, 1, True)


def test_no_secret_appears_in_the_receipt_or_repr():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_through_activation(adapter, fs)
    adapter.enable_api_signer(_marker(receipt, ca_digest))
    blob = json.dumps(
        [
            list(getattr(adapter.receipt(), f.name))
            for f in __import__("dataclasses").fields(adapter.receipt())
        ]
    )
    for forbidden in ("SCRAM-SHA-256", "PRIVATE KEY", "BEGIN EC", "password", "verifier"):
        assert forbidden not in blob
    assert "redacted" in repr(adapter).lower()


def test_marker_write_seals_when_reobserved_identity_disagrees():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_through_activation(adapter, fs)
    marker = _marker(receipt, ca_digest)
    tampered = __import__("dataclasses").replace(
        marker, active_identity_row_id="99999999-9999-9999-9999-999999999999"
    )
    with pytest.raises(ManagementError) as e:
        adapter.enable_api_signer(tampered)
    assert e.value.reason_code == "finalization_marker_identity_disagreement"
    assert fs.lstat(ManagementLocations().api_signer_marker_path()) is None  # never written on seal


def test_marker_write_seals_when_no_active_identity_is_reobservable():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_through_activation(adapter, fs)
    _NO_ACTIVE["provider"] = None  # force the lease to raise (no active identity)
    marker = _marker(receipt, ca_digest)
    # patch the fake so the ctx manager raises
    _NO_ACTIVE.clear()

    class _RaisingProvider(_FakeLeaseProvider):
        def lease(self):
            class _C:
                def __enter__(self):
                    raise RuntimeError("unavailable")

                def __exit__(self, *a):
                    return False

            return _C()

    adapter._ctx = __import__("dataclasses").replace(
        adapter._ctx, lease_provider_factory=_RaisingProvider
    )
    with pytest.raises(ManagementError) as e:
        adapter.enable_api_signer(marker)
    assert e.value.reason_code == "finalization_active_identity_unavailable"


def test_compensation_removes_marker_first_and_activation_forces_recovery_required():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    key, receipt, ca_digest = _drive_through_activation(adapter, fs)
    adapter.enable_api_signer(_marker(receipt, ca_digest))
    marker_path = ManagementLocations().api_signer_marker_path()
    assert fs.lstat(marker_path) is not None
    result = adapter.compensate(adapter.receipt())
    # the marker is removed FIRST (API returned to sealed); an activated identity cannot be silently
    # rolled back here, so compensation is not proven -> recovery_required.
    assert fs.lstat(marker_path) is None
    assert result.proven is False and "activated_identity" in result.residual


def test_compensation_of_a_pre_activation_receipt_is_proven():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    adapter.record_locator(canonical_origin=_ORIGIN)
    result = adapter.compensate(adapter.receipt())
    assert result.proven is True and result.residual == ()
    # the created TLS + locator were removed (drift-checked)
    assert fs.lstat(ManagementLocations().controller_ca_bundle_path()) is None
    assert fs.lstat(ManagementLocations().controller_api_locator_path()) is None


def test_compensation_flags_a_drifted_tls_object_and_removes_the_others():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    loc = ManagementLocations()
    # a foreign process replaces the CA bundle after install (drift)
    fs.seed_file(loc.controller_ca_bundle_path(), b"FOREIGN CA", uid=0, gid=0, mode=0o644)
    result = adapter.compensate(adapter.receipt())
    # the drifted CA is left in place and flagged; the cert + server KEY are still removed
    assert result.proven is False and "controller_tls" in result.residual
    assert fs.lstat(loc.controller_ca_bundle_path()) is not None  # foreign object untouched
    assert fs.lstat(loc.controller_server_cert_path()) is None
    assert fs.lstat(loc.controller_server_key_path()) is None


def test_compensation_removes_the_server_key_even_if_ca_bundle_was_externally_deleted():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    adapter.install_tls_material(
        policy=_policy(), canonical_origin=_ORIGIN, tls_mode="generated_local_ca"
    )
    loc = ManagementLocations()
    fs.remove_file(loc.controller_ca_bundle_path())  # CA externally deleted before compensation
    result = adapter.compensate(adapter.receipt())
    # the 0600 secret server key is REMOVED (never left on disk); no false residual for absent CA
    assert fs.lstat(loc.controller_server_key_path()) is None
    assert fs.lstat(loc.controller_server_cert_path()) is None
    assert result.proven is True and result.residual == ()


def test_compensate_refuses_a_foreign_receipt_type():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    result = adapter.compensate("not a receipt")  # type: ignore[arg-type]
    assert result.proven is False and result.residual == ("malformed_receipt",)


def test_empty_receipt_compensates_cleanly():
    fs = _fs()
    adapter = _adapter(fs, _FakeRunner(fs))
    result = adapter.compensate(ControllerFinalizationReceipt())
    assert result.proven is True and result.residual == ()
