"""Real controller-enrollment FINALIZATION adapter (SECP-PR5H-B2, 2b-3b-iii).

The production leaf for the closed :class:`~secp_management.finalization.
ControllerEnrollmentFinalizationAdapter` protocol. Like the bootstrap adapters
(``real_adapters.py``),
it COMPOSES already-reviewed primitives (the TLS producer, the CA-pinned locator writer, the SCRAM
role primitives, the 0600 enrollment-key prep, the hardened filesystem, the pinned compose runner,
and the dedicated-role advisory-lock lease) into the exact reviewed finalization order, accumulates
a
:class:`~secp_management.finalization.ControllerFinalizationReceipt` of ONLY the objects it created,
and exposes a closed drift-checked ``compensate`` that removes exactly those in reverse — the MARKER
FIRST (returning the API to sealed) — leaving adopted/foreign objects in place and forcing
``recovery_required`` on any unproven removal.

The management plane NEVER imports ``secp_api``: the two API-plane persistence effects
(dedicated-role
provisioning, controller-identity activation) run ONLY through the two fixed code-owned
``compose run --rm`` one-shots (mirroring ``RealControllerBootstrapAdapter.run_migrations``), and
the
independent ACTIVE-identity reobservation runs as the dedicated least-privilege
``secp_enrollment_signer``
role over raw SQL. Secrets (the TLS key, the SCRAM plaintext, the enrollment private key) are
generated
at write time and NEVER enter the plan, the marker, the receipt, a log, or a repr — the API signer
client is enabled ONLY by the root-owned marker written LAST, after the reobserved active identity
EXACTLY agrees with it.

This module performs host effects only through the injected hardened seams; it is constructed ONLY
by
the root-only install composition (never by a CLI/env/global selection).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn

from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY,
    ENROLLMENT_SIGNER_SOCKET_PATH,
    prepare_controller_enrollment_key,
)
from secp_commissioning.enrollment_attestation import enrollment_key_proof_id_for, key_id_for
from secp_commissioning.runtime import FilesystemError

from secp_management import ManagementError
from secp_management.adapters import CompensationResult, ReviewedUnit
from secp_management.controller_api_locator import (
    ControllerApiLocatorError,
    FileControllerApiLocatorProvider,
    record_fixed_controller_api_locator,
)
from secp_management.controller_tls import ControllerTlsError, produce_controller_tls
from secp_management.enrollment_signer_db import (
    ENROLLMENT_SIGNER_DB_ROLE,
    build_signer_role_engine,
    generate_signer_db_password,
    scram_sha256_verifier,
)
from secp_management.enrollment_signer_identity import DbActiveControllerSigningIdentityProvider
from secp_management.finalization import (
    ActivationReceipt,
    ApiSignerMarker,
    ControllerFinalizationReceipt,
    ControllerIdentityActivation,
    EnrollmentKeyIdentity,
    ReviewedSignerRole,
)
from secp_management.real_adapters import RealAdapterContext
from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID

if TYPE_CHECKING:
    from secp_management.release_bundle import ControllerTlsPolicy

_ENROLLMENT_KEY_PATH = CONTROLLER_ENROLLMENT_KEY_PATH
_ADVISORY_LOCK_KEY = ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY

# --------------------------------------------------------------------------- constants

_ROOT_UID = 0
_ROOT_GID = 0
_CA_BUNDLE_MODE = 0o644  # public CA + leaf cert, world-readable
_SERVER_KEY_MODE = 0o600  # controller-API server private key, root-only
_CREDENTIAL_MODE = 0o600  # the SCRAM plaintext source (systemd LoadCredential copies it out)
_HANDOFF_MODE = 0o640  # root:api-group, exactly what the hardened one-shot reader requires
_LOCATOR_MODE = 0o644  # public locator record
_MARKER_MODE = 0o644  # public enablement marker (non-secret; API reads it)

_MAX_READ = 512 * 1024
_ONESHOT_TIMEOUT = 600
_RESTART_TIMEOUT = 300

_PROVISION_SCHEMA = "secp.enrollment-signer-role-provision/v1"
_ACTIVATION_SCHEMA = "secp.controller-identity-activation/v1"
_MARKER_SCHEMA = "secp.enrollment-signer-enablement/v1"
# The 8 identity fields, in the fixed order the API activation one-shot canonicalizes the candidate.
_IDENTITY_FIELDS = (
    "controller_installation_id",
    "controller_key_id",
    "controller_trust_anchor_hex",
    "controller_origin",
    "release_digest",
    "management_identity_digest",
    "bootstrap_evidence_digest",
    "enrollment_key_proof_id",
)
_PROVISION_ARGV = ("python", "-m", "secp_api.provision_enrollment_signer_role_once")
_ACTIVATION_ARGV = ("python", "-m", "secp_api.activate_controller_identity_once")


class ControllerFinalizationError(ManagementError):
    """A bounded, closed finalization refusal — only a reason code, never a
    secret/path/exception."""


def _reject(reason_code: str) -> NoReturn:
    raise ControllerFinalizationError(reason_code)


def _utc(now: datetime) -> str:
    return now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest71(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- context


@dataclass(frozen=True)
class FinalizationContext:
    """The fixed production composition context for finalization. ``host`` seams are the hardened
    fs +
    pinned compose runner shared with the bootstrap adapters (``RealAdapterContext``); ``api_uid`` /
    ``api_gid`` are the reviewed non-root controller-API peer identity; ``db_base_url`` is a
    TEST-ONLY
    coordinate seam for the dedicated-role Engine (production passes none)."""

    host: RealAdapterContext
    api_uid: int = API_RUNTIME_UID
    api_gid: int = API_RUNTIME_GID
    db_base_url: str | None = None
    lease_provider_factory: Any = DbActiveControllerSigningIdentityProvider
    now: Any = None  # test-only clock seam (callable(tz) -> datetime); production uses datetime.now
    db_prober: Any = None  # test-only DB-proof seam (callable(engine)); production uses live SQL

    def dedicated_role_engine(self, password: str) -> Any:
        return build_signer_role_engine(password, base_url=self.db_base_url)


# --------------------------------------------------------------------------- fs helpers


def _install(ctx: FinalizationContext, path: str, content: bytes, *, gid: int, mode: int) -> None:
    ctx.host.locations.assert_writable(path)
    try:
        ctx.host.fs.atomic_install(path, content, uid=_ROOT_UID, gid=gid, mode=mode)
    except FilesystemError:
        _reject("finalization_file_install_failed")


def _install_unit(ctx: FinalizationContext, path: str, content: bytes) -> None:
    ctx.host.locations.assert_unit_writable(path)
    try:
        ctx.host.fs.atomic_install(path, content, uid=_ROOT_UID, gid=_ROOT_GID, mode=0o644)
    except FilesystemError:
        _reject("finalization_file_install_failed")


def _read_exact(ctx: FinalizationContext, path: str) -> bytes:
    try:
        return ctx.host.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=_ROOT_UID)
    except (FilesystemError, ManagementError):
        _reject("finalization_readback_failed")


def _assert_posture(ctx: FinalizationContext, path: str, *, gid: int, mode: int) -> None:
    st = ctx.host.fs.lstat(path)
    if (
        st is None
        or not st.is_regular
        or st.is_symlink
        or st.uid != _ROOT_UID
        or st.gid != gid
        or st.mode != mode
        or st.nlink != 1
    ):
        _reject("finalization_object_posture_invalid")


def _remove_created(
    ctx: FinalizationContext, path: str, expected_digest: str, *, unit: bool
) -> bool:
    """Remove a transaction-created object ONLY after proving its current bytes are exactly what we
    installed — drifted/foreign content is left in place (not ours). Returns True iff proven
    removed."""
    try:
        if unit:
            ctx.host.locations.assert_unit_writable(path)
        else:
            ctx.host.locations.assert_writable(path)
        st = ctx.host.fs.lstat(path)
        if st is None:
            return True  # already absent
        current = ctx.host.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=_ROOT_UID)
        if sha256_bytes(current) != expected_digest:
            return False  # drifted → not ours; do not touch
        ctx.host.fs.remove_file(path)
        return ctx.host.fs.lstat(path) is None
    except (FilesystemError, ManagementError):
        return False


def _absent(ctx: FinalizationContext, path: str) -> bool:
    try:
        return ctx.host.fs.lstat(path) is None
    except (FilesystemError, ManagementError):
        return False


def _remove_handoff(ctx: FinalizationContext, path: str) -> None:
    """Remove a consumed handoff and PROVE its absence — a handoff is transient and MUST NOT linger
    after the one-shot consumed it (a lingering credential/identity handoff is a residual
    foothold)."""
    try:
        if ctx.host.fs.lstat(path) is not None:
            ctx.host.fs.remove_file(path)
    except (FilesystemError, ManagementError):
        pass
    if not _absent(ctx, path):
        _reject("finalization_handoff_residual")


# --------------------------------------------------------------------------- one-shots


def _run_oneshot(
    ctx: FinalizationContext,
    host_path: str,
    container_path: str,
    argv: tuple[str, ...],
    *,
    reason: str,
) -> dict[str, Any]:
    """Drive a fixed API-plane one-shot as ``compose run --rm --no-deps -v <handoff>:<container>:ro
    api <argv>`` (mirrors ``run_migrations``): the container is removed after completion, no sibling
    is started, and the ONLY extra mount is the READ-ONLY handoff. Returns the parsed bounded public
    receipt (never a secret) or fails closed."""
    out = ctx.host.run(
        ctx.host.executables.compose_runtime,
        (
            "--project-name",
            ctx.host.controller_project,
            "--file",
            ctx.host.locations.controller_compose_path(),
            "run",
            "--rm",
            "--no-deps",
            "--volume",
            f"{host_path}:{container_path}:ro",
            "api",
            *argv,
        ),
        timeout=_ONESHOT_TIMEOUT,
        reason=reason,
    )
    try:
        receipt = json.loads(out.strip().splitlines()[-1]) if out.strip() else None
    except (ValueError, IndexError):
        _reject(reason)
    if not isinstance(receipt, dict):
        _reject(reason)
    return receipt


# --------------------------------------------------------------------------- the adapter


class RealControllerEnrollmentFinalizationAdapter:
    """The exact reviewed controller-enrollment finalization sequence. No generic
    callback/dict-of-ops/shell/SQL/module surface is ever exposed; every op consumes a typed input
    and
    composes reviewed primitives. Marker is written LAST; compensation removes it FIRST."""

    def __init__(self, ctx: FinalizationContext) -> None:
        self._ctx = ctx
        # receipt accumulators (public identities only — never a secret)
        self._installed_tls: list[str] = []
        self._recorded_locators: list[str] = []
        self._provisioned_roles: list[str] = []
        self._written_credentials: list[str] = []
        self._prepared_keys: list[str] = []
        self._installed_broker_units: list[str] = []
        self._started_brokers: list[str] = []
        self._activated_identities: list[str] = []
        self._enabled_markers: list[str] = []
        # forward-flowing state (secrets held ONLY in memory, never recorded)
        self._password: str | None = None
        self._role_name: str | None = None
        self._locator_ca_digest: str | None = None
        self._key_identity: EnrollmentKeyIdentity | None = None
        self._now = ctx.now if ctx.now is not None else datetime.now

    def __repr__(self) -> str:  # never expose held secrets
        return "RealControllerEnrollmentFinalizationAdapter(<redacted>)"

    # ---- 1-2: TLS material (install-or-adopt + verify posture + pairing) ----
    def install_tls_material(
        self, *, policy: ControllerTlsPolicy, canonical_origin: str, tls_mode: str
    ) -> None:
        loc = self._ctx.host.locations
        ca_path = loc.controller_ca_bundle_path()
        cert_path = loc.controller_server_cert_path()
        key_path = loc.controller_server_key_path()
        if not _absent(self._ctx, ca_path):
            # ADOPT existing valid material — do NOT overwrite, do NOT record (compensation leaves
            # it).
            ca_pem = _read_exact(self._ctx, ca_path)
            self._locator_ca_digest = "sha256:" + hashlib.sha256(ca_pem).hexdigest()
            _assert_posture(self._ctx, ca_path, gid=_ROOT_GID, mode=_CA_BUNDLE_MODE)
            _assert_posture(self._ctx, cert_path, gid=_ROOT_GID, mode=_CA_BUNDLE_MODE)
            _assert_posture(self._ctx, key_path, gid=_ROOT_GID, mode=_SERVER_KEY_MODE)
            return
        try:
            produced = produce_controller_tls(
                policy=policy, canonical_origin=canonical_origin, mode=tls_mode
            )
            ca_pem = produced.ca_bundle_pem()
            cert_pem = produced.server_certificate_pem()
            key_pem = produced.server_private_key_pem()
        except ControllerTlsError as exc:
            _reject(getattr(exc, "reason_code", "controller_tls_produce_failed"))
        # install each file and record its content digest IMMEDIATELY (in the fixed _TLS_ARTIFACTS
        # order ca -> cert -> key), so a partial install still records exactly what reached disk and
        # compensation can pair each recorded digest with its OWN path. Then RE-READ + verify
        # byte-equality + fs posture (the crypto pairing was verified by produce_controller_tls).
        for path, pem, mode in (
            (ca_path, ca_pem, _CA_BUNDLE_MODE),
            (cert_path, cert_pem, _CA_BUNDLE_MODE),
            (key_path, key_pem, _SERVER_KEY_MODE),
        ):
            _install(self._ctx, path, pem, gid=_ROOT_GID, mode=mode)
            self._installed_tls.append(sha256_bytes(pem))
        for path, expected in ((ca_path, ca_pem), (cert_path, cert_pem), (key_path, key_pem)):
            if _read_exact(self._ctx, path) != expected:
                _reject("finalization_tls_readback_mismatch")
        _assert_posture(self._ctx, key_path, gid=_ROOT_GID, mode=_SERVER_KEY_MODE)
        self._locator_ca_digest = "sha256:" + hashlib.sha256(ca_pem).hexdigest()

    # ---- 4-5: locator (record + read-back verify) ----
    def record_locator(self, *, canonical_origin: str) -> None:
        loc = self._ctx.host.locations
        existed = not _absent(self._ctx, loc.controller_api_locator_path())
        try:
            record_fixed_controller_api_locator(
                self._ctx.host.fs,
                canonical_origin=canonical_origin,
                write=True,
                confirm=True,
                locations=loc,
            )
            FileControllerApiLocatorProvider(
                self._ctx.host.fs, path=loc.controller_api_locator_path()
            ).locate()  # independent read-back verify
        except ControllerApiLocatorError as exc:
            _reject(getattr(exc, "reason_code", "controller_locator_record_failed"))
        if (
            not existed
        ):  # record ONLY a newly-created locator (an adopted one is left on compensate)
            self._recorded_locators.append(
                sha256_bytes(_read_exact(self._ctx, loc.controller_api_locator_path()))
            )

    # ---- 6-13: signer role (gen creds, broker credential, handoff, one-shot, prove) ----
    def provision_signer_role(self, role: ReviewedSignerRole) -> None:
        if role.role_name != ENROLLMENT_SIGNER_DB_ROLE:
            _reject("finalization_signer_role_name_invalid")
        loc = self._ctx.host.locations
        cred_path = loc.enrollment_signer_credential_path()
        handoff_path = loc.provisioning_handoff_host_path()
        container_path = loc.provisioning_handoff_container_path()
        # 6) generate the high-entropy plaintext + the SCRAM verifier (plaintext NEVER leaves
        # memory)
        password = generate_signer_db_password()
        verifier = scram_sha256_verifier(password)
        # 7) install the root-owned broker DB credential SOURCE (systemd LoadCredential copies it
        # out)
        _install(
            self._ctx,
            cred_path,
            (password + "\n").encode("ascii"),
            gid=_ROOT_GID,
            mode=_CREDENTIAL_MODE,
        )
        self._written_credentials.append(role.credential_source_path or cred_path)
        # 8) install the provisioning handoff (root:api-gid 0640) carrying ONLY the SCRAM verifier
        operation_id = "provision-" + _digest71(verifier)[7:23]
        handoff = {
            "schema": _PROVISION_SCHEMA,
            "operation_id": operation_id,
            "scram_verifier": verifier,
            "created_at": _utc(self._now(UTC)),
        }
        _install(
            self._ctx,
            handoff_path,
            canonical_json(handoff).encode("utf-8"),
            gid=self._ctx.api_gid,
            mode=_HANDOFF_MODE,
        )
        _assert_posture(self._ctx, handoff_path, gid=self._ctx.api_gid, mode=_HANDOFF_MODE)
        try:
            # 9-10) invoke the provisioning one-shot + validate its bounded least-privilege receipt
            receipt = _run_oneshot(
                self._ctx,
                handoff_path,
                container_path,
                _PROVISION_ARGV,
                reason="finalization_provisioning_oneshot_failed",
            )
            self._assert_provision_receipt(receipt, operation_id)
        finally:
            # 11) remove + absence-prove the provisioning handoff (transient, never lingers)
            _remove_handoff(self._ctx, handoff_path)
        # 12-13) independently authenticate as the dedicated role + prove least-privilege posture
        self._prove_dedicated_role(password)
        self._password = password
        self._role_name = role.role_name
        self._provisioned_roles.append(role.role_name)

    def _assert_provision_receipt(self, receipt: dict[str, Any], operation_id: str) -> None:
        if "reason_code" in receipt:  # a refusal payload → fail closed
            _reject("finalization_provisioning_refused")
        required_true = (
            "can_login",
            "not_superuser",
            "not_createrole",
            "not_createdb",
            "not_bypassrls",
            "select_on_identity",
            "no_write_on_identity",
            "owns_nothing",
            "no_memberships",
        )
        if (
            receipt.get("operation_id") != operation_id
            or receipt.get("role_name") != ENROLLMENT_SIGNER_DB_ROLE
            or not all(receipt.get(k) is True for k in required_true)
        ):
            _reject("finalization_provisioning_posture_invalid")

    def _prove_dedicated_role(self, password: str) -> None:
        """Connect as the actual dedicated role and prove it can take the advisory lock (executable
        by
        PUBLIC — the SELECT-only role needs no extra grant). Auth + lock acquisition prove the role
        is
        real, least-privilege, and can participate in the lease; a full ACTIVE-identity lease is
        proven later (there is no active identity yet). Fails closed on any fault."""
        from sqlalchemy import text

        engine = self._ctx.dedicated_role_engine(password)
        try:
            if self._ctx.db_prober is not None:  # test seam (no live PostgreSQL)
                self._ctx.db_prober(engine)
                return
            with engine.begin() as conn:
                who = conn.execute(text("SELECT current_user")).scalar()
                if who != ENROLLMENT_SIGNER_DB_ROLE:
                    _reject("finalization_signer_role_identity_mismatch")
                conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
        except ControllerFinalizationError:
            raise
        except Exception:  # noqa: BLE001 - any DB fault is a bounded fail-closed refusal
            _reject("finalization_dedicated_role_unproven")
        finally:
            engine.dispose()

    # ---- 14-15: enrollment key (prepare-or-adopt + derive public identity) ----
    def prepare_enrollment_key(self) -> EnrollmentKeyIdentity:
        existed = not _absent(self._ctx, _ENROLLMENT_KEY_PATH)
        try:
            public = prepare_controller_enrollment_key(self._ctx.host.fs, write=True, confirm=True)
        except ManagementError as exc:
            _reject(getattr(exc, "reason_code", "finalization_enrollment_key_failed"))
        pub_hex = public["public_key_hex"]
        # re-derive independently and require exact agreement (key-separation invariants)
        if public["key_id"] != key_id_for(pub_hex) or public[
            "enrollment_key_proof_id"
        ] != enrollment_key_proof_id_for(pub_hex):
            _reject("finalization_enrollment_key_identity_mismatch")
        identity = EnrollmentKeyIdentity(
            controller_key_id=public["key_id"],
            controller_trust_anchor_hex=pub_hex,
            enrollment_key_proof_id=public["enrollment_key_proof_id"],
        )
        self._key_identity = identity
        if not existed:  # record ONLY a newly-created key (an adopted key is never removed)
            self._prepared_keys.append(_ENROLLMENT_KEY_PATH)
        return identity

    # ---- 16-18: broker unit (verify + install through the strict unit authority) ----
    def install_broker_unit(self, unit: ReviewedUnit) -> None:
        unit.verify()
        path = self._ctx.host.locations.broker_unit_path()
        _install_unit(self._ctx, path, unit.content)
        if _read_exact(self._ctx, path) != unit.content:
            _reject("finalization_broker_unit_readback_mismatch")
        self._installed_broker_units.append(unit.identity)

    def _broker_unit_name(self) -> str:
        return self._ctx.host.locations.broker_unit_path().rsplit("/", 1)[-1]

    # ---- 19: start the broker (daemon-reload then start the fixed unit) ----
    def start_broker(self) -> None:
        unit = self._broker_unit_name()
        self._ctx.host.run(
            self._ctx.host.executables.service_manager,
            ("daemon-reload",),
            timeout=60,
            reason="finalization_broker_daemon_reload_failed",
        )
        self._ctx.host.run(
            self._ctx.host.executables.service_manager,
            ("start", unit),
            timeout=120,
            reason="finalization_broker_start_failed",
        )
        self._started_brokers.append(unit)

    # ---- 20: prove the broker signer path operational ----
    def verify_signer_operational(self, *, key_identity: EnrollmentKeyIdentity) -> None:
        if self._key_identity is None or key_identity != self._key_identity:
            _reject("finalization_key_identity_disagreement")
        # the on-disk enrollment key must still derive EXACTLY the prepared identity (key/identity)
        raw = _read_exact(self._ctx, _ENROLLMENT_KEY_PATH)
        try:
            pub_hex = _ed25519_public_hex(raw)
        except Exception:  # noqa: BLE001
            _reject("finalization_enrollment_key_unreadable")
        if (
            key_id_for(pub_hex) != key_identity.controller_key_id
            or pub_hex != key_identity.controller_trust_anchor_hex
            or enrollment_key_proof_id_for(pub_hex) != key_identity.enrollment_key_proof_id
        ):
            _reject("finalization_key_identity_disagreement")
        # fixed UDS posture: the broker socket must be a root:api-group 0660 socket at the fixed
        # path
        st = self._ctx.host.fs.lstat(self._ctx.host.locations.broker_socket_path())
        if (
            st is None
            or not st.is_special  # a socket is non-regular non-dir → is_special
            or st.is_symlink
            or st.uid != _ROOT_UID
            or st.gid != self._ctx.api_gid
            or st.mode != 0o660
        ):
            _reject("finalization_broker_socket_posture_invalid")
        # dedicated-role auth + advisory-lock acquisition prove the DB signer path (no TCP anywhere)
        if self._password is None:
            _reject("finalization_signer_credential_missing")
        self._prove_dedicated_role(self._password)

    # ---- 21-25: activate the verified controller identity (PENULTIMATE) ----
    def activate_controller_identity(
        self, activation: ControllerIdentityActivation
    ) -> ActivationReceipt:
        loc = self._ctx.host.locations
        handoff_path = loc.activation_handoff_host_path()
        container_path = loc.activation_handoff_container_path()
        fields = {f: getattr(activation, f) for f in _IDENTITY_FIELDS}
        candidate_digest = sha256_bytes(canonical_json(fields).encode("utf-8"))
        pred_row = activation.previous_active_row_id
        pred_token = self._predecessor_token(pred_row)
        handoff = {
            "schema": _ACTIVATION_SCHEMA,
            "operation_id": activation.operation_id,
            "candidate_digest": candidate_digest,
            "expected_predecessor_row_id": pred_row,
            "expected_predecessor_activation_token": pred_token,
            "generation": 0,  # operation-envelope field; predecessor CAS is the ordering control
            "handoff_created_at": _utc(self._now(UTC)),
            **fields,
        }
        _install(
            self._ctx,
            handoff_path,
            canonical_json(handoff).encode("utf-8"),
            gid=self._ctx.api_gid,
            mode=_HANDOFF_MODE,
        )
        _assert_posture(self._ctx, handoff_path, gid=self._ctx.api_gid, mode=_HANDOFF_MODE)
        try:
            receipt = _run_oneshot(
                self._ctx,
                handoff_path,
                container_path,
                _ACTIVATION_ARGV,
                reason="finalization_activation_oneshot_failed",
            )
            parsed = self._parse_activation_receipt(receipt, activation, candidate_digest)
        finally:
            _remove_handoff(self._ctx, handoff_path)
        self._activated_identities.append(parsed.resulting_row_id)
        return parsed

    def _predecessor_token(self, pred_row: str | None) -> str | None:
        if pred_row is None:
            return None
        # a rotation must present the CURRENT active row + its exact token — reobserve it as the
        # role.
        lease = self._reobserve_active()
        if lease is None or str(lease.row_id) != pred_row:
            _reject("finalization_predecessor_conflict")
        return lease.activation_token

    def _parse_activation_receipt(
        self,
        receipt: dict[str, Any],
        activation: ControllerIdentityActivation,
        candidate_digest: str,
    ) -> ActivationReceipt:
        if "reason_code" in receipt:
            _reject("finalization_activation_refused")
        try:
            parsed = ActivationReceipt(
                operation_id=receipt["operation_id"],
                candidate_digest=receipt["candidate_digest"],
                resulting_row_id=receipt["resulting_row_id"],
                activation_token=receipt["activation_token"],
                previous_active_row_id=receipt.get("previous_active_row_id"),
                created=bool(receipt["created"]),
                resulting_status=receipt["resulting_status"],
                resulting_public_state_digest=receipt["resulting_public_state_digest"],
            )
        except (KeyError, TypeError):
            _reject("finalization_activation_receipt_invalid")
        if (
            parsed.operation_id != activation.operation_id
            or parsed.candidate_digest != candidate_digest
            or parsed.resulting_status != "active"
        ):
            _reject("finalization_activation_receipt_mismatch")
        return parsed

    # ---- 26-31: reobserve, build/verify marker, write LAST, restart API ----
    def enable_api_signer(self, marker: ApiSignerMarker) -> None:
        # 26) INDEPENDENTLY reobserve the current authoritative ACTIVE identity (the historical
        # activation receipt alone is NOT sufficient) and require EXACT agreement with the marker.
        lease = self._reobserve_active()
        if lease is None:
            _reject("finalization_active_identity_unavailable")
        self._require_marker_agrees(marker, lease)
        # 28) write the marker LAST — the SOLE positive runtime enablement switch — then verify
        # posture
        path = self._ctx.host.locations.api_signer_marker_path()
        if path != marker.marker_path:
            _reject("finalization_marker_path_mismatch")
        content = self._render_marker(marker)
        _install(self._ctx, path, content, gid=_ROOT_GID, mode=_MARKER_MODE)
        if _read_exact(self._ctx, path) != content:
            _reject("finalization_marker_readback_mismatch")
        _assert_posture(self._ctx, path, gid=_ROOT_GID, mode=_MARKER_MODE)
        self._enabled_markers.append(sha256_bytes(content))
        # 29) restart the ordinary (non-root) API so it reads the marker and uses the fixed UDS
        # client
        self._ctx.host.run(
            self._ctx.host.executables.compose_runtime,
            (
                "--project-name",
                self._ctx.host.controller_project,
                "--file",
                self._ctx.host.locations.controller_compose_path(),
                "up",
                "--detach",
                "--no-deps",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                "api",
            ),
            timeout=_RESTART_TIMEOUT,
            reason="finalization_api_restart_failed",
        )

    def _require_marker_agrees(self, marker: ApiSignerMarker, lease: Any) -> None:
        # every DB-sourced identity fact must EXACTLY equal the independently reobserved active row
        db_expected = {
            "installation_id": lease.controller_installation_id,
            "release_digest": lease.release_digest,
            "active_identity_row_id": str(lease.row_id),
            "activation_token": lease.activation_token,
            "controller_key_id": lease.controller_key_id,
            "management_identity_digest": lease.management_identity_digest,
            "bootstrap_evidence_digest": lease.bootstrap_evidence_digest,
        }
        for field, expected in db_expected.items():
            if getattr(marker, field) != expected:
                _reject("finalization_marker_identity_disagreement")
        # every installer-known non-DB fact must equal the reviewed constants
        if (
            marker.api_uid != self._ctx.api_uid
            or marker.api_gid != self._ctx.api_gid
            or marker.signer_role_name != ENROLLMENT_SIGNER_DB_ROLE
            or marker.uds_contract_identity != ENROLLMENT_SIGNER_SOCKET_PATH
            or marker.locator_ca_digest != self._locator_ca_digest
        ):
            _reject("finalization_marker_binding_disagreement")

    def _render_marker(self, marker: ApiSignerMarker) -> bytes:
        obj = {
            "schema": _MARKER_SCHEMA,
            "installation_id": marker.installation_id,
            "release_digest": marker.release_digest,
            "active_identity_row_id": marker.active_identity_row_id,
            "activation_token": marker.activation_token,
            "controller_key_id": marker.controller_key_id,
            "uds_contract_identity": marker.uds_contract_identity,
            "api_uid": marker.api_uid,
            "api_gid": marker.api_gid,
            "signer_role_name": marker.signer_role_name,
            "locator_ca_digest": marker.locator_ca_digest,
            "management_identity_digest": marker.management_identity_digest,
            "bootstrap_evidence_digest": marker.bootstrap_evidence_digest,
            "recorded_at": _utc(self._now(UTC)),
        }
        return canonical_json(obj).encode("utf-8")

    def _reobserve_active(self) -> Any:
        if self._password is None:
            _reject("finalization_signer_credential_missing")
        engine = self._ctx.dedicated_role_engine(self._password)
        try:
            with self._ctx.lease_provider_factory(engine).lease() as lease:
                return lease
        except Exception:  # noqa: BLE001 - absent/ambiguous/unverified/unreachable -> none
            return None
        finally:
            engine.dispose()

    # ---- receipt + compensation ----
    def receipt(self) -> ControllerFinalizationReceipt:
        return ControllerFinalizationReceipt(
            installed_tls=tuple(self._installed_tls),
            recorded_locators=tuple(self._recorded_locators),
            provisioned_roles=tuple(self._provisioned_roles),
            written_credentials=tuple(self._written_credentials),
            prepared_keys=tuple(self._prepared_keys),
            installed_broker_units=tuple(self._installed_broker_units),
            started_brokers=tuple(self._started_brokers),
            activated_identities=tuple(self._activated_identities),
            enabled_markers=tuple(self._enabled_markers),
        )

    def compensate(self, receipt: ControllerFinalizationReceipt) -> CompensationResult:
        if type(receipt) is not ControllerFinalizationReceipt:
            return CompensationResult(proven=False, residual=("malformed_receipt",))
        ctx = self._ctx
        loc = ctx.host.locations
        residual: list[str] = []
        # REVERSE reviewed order — the MARKER FIRST (return the API to sealed), then the broker,
        # then the created artifacts. Adopted/pre-existing objects were never recorded, so they are
        # left in place. A drifted/foreign object is left in place and forces recovery_required.
        for identity in receipt.enabled_markers:
            if not _remove_created(ctx, loc.api_signer_marker_path(), identity, unit=False):
                residual.append("api_signer_marker")
        if receipt.enabled_markers:  # after removing the marker, seal + restart the API
            if not self._reseal_api():
                residual.append("api_reseal")
        for _ in receipt.started_brokers:
            if not self._stop_broker():
                residual.append("broker_service")
        for identity in receipt.installed_broker_units:
            if not _remove_created(ctx, loc.broker_unit_path(), identity, unit=True):
                residual.append("broker_unit")
        # activated identities + prepared keys: an activated identity is NOT auto-removed (rolling
        # it
        # back is the engine's prior-state receipt job in 2b-3c); a created enrollment key is
        # removed
        # only when ownership is proven.
        if receipt.activated_identities:
            residual.append("activated_identity")  # forces recovery_required — never silently kept
        for path in receipt.prepared_keys:
            if not _remove_created_key(ctx, path):
                residual.append("enrollment_key")
        for _identity in receipt.written_credentials:
            # the SCRAM plaintext credential is always OURS (generated at write time, not adopted);
            # remove it if present — a residual (removal failure) forces recovery_required.
            if not _remove_if_present(ctx, loc.enrollment_signer_credential_path()):
                residual.append("signer_credential")
        for identity in receipt.recorded_locators:
            if not _remove_created(ctx, loc.controller_api_locator_path(), identity, unit=False):
                residual.append("controller_locator")
        # pair each recorded TLS digest with its OWN fixed path (installed_tls is recorded in the
        # exact ca -> cert -> key install order) — never an or-chain over shared paths, which could
        # mask a drifted CA or leave the 0600 server key while falsely reporting proven.
        for path, identity in zip(_tls_paths(loc), receipt.installed_tls, strict=False):
            if not _remove_created(ctx, path, identity, unit=False):
                residual.append("controller_tls")
        # any remaining transient handoff is a residual
        for path in (loc.provisioning_handoff_host_path(), loc.activation_handoff_host_path()):
            if not _absent(ctx, path):
                residual.append("residual_handoff")
        return CompensationResult(proven=not residual, residual=tuple(residual))

    def _reseal_api(self) -> bool:
        try:
            self._ctx.host.run(
                self._ctx.host.executables.compose_runtime,
                (
                    "--project-name",
                    self._ctx.host.controller_project,
                    "--file",
                    self._ctx.host.locations.controller_compose_path(),
                    "up",
                    "--detach",
                    "--no-deps",
                    "--no-build",
                    "--pull",
                    "never",
                    "--force-recreate",
                    "api",
                ),
                timeout=_RESTART_TIMEOUT,
                reason="finalization_api_reseal_failed",
            )
            return True
        except ManagementError:
            return False

    def _stop_broker(self) -> bool:
        try:
            self._ctx.host.run(
                self._ctx.host.executables.service_manager,
                ("stop", self._broker_unit_name()),
                timeout=120,
                reason="finalization_broker_stop_failed",
            )
            return True
        except ManagementError:
            return False


# --------------------------------------------------------------------------- module helpers


def _remove_created_key(ctx: FinalizationContext, path: str) -> bool:
    """Remove a newly-created 0600 root enrollment key ONLY after proving root ownership + posture —
    never touch a drifted/foreign key. Returns True iff proven removed (or already absent). The path
    is the fixed commissioning-plane key constant, not a caller path."""
    if path != _ENROLLMENT_KEY_PATH:
        return False
    try:
        st = ctx.host.fs.lstat(path)
        if st is None:
            return True
        if st.is_symlink or not st.is_regular or st.uid != _ROOT_UID or st.mode != 0o600:
            return False  # not our clean root key → leave it
        ctx.host.fs.remove_file(path)
        return ctx.host.fs.lstat(path) is None
    except (FilesystemError, ManagementError):
        return False


def _remove_if_present(ctx: FinalizationContext, path: str) -> bool:
    try:
        ctx.host.locations.assert_writable(path)
        if ctx.host.fs.lstat(path) is None:
            return True
        ctx.host.fs.remove_file(path)
        return ctx.host.fs.lstat(path) is None
    except (FilesystemError, ManagementError):
        return False


def _tls_paths(loc) -> tuple[str, str, str]:
    """The three controller-API TLS artifact paths in the FIXED order install_tls_material records
    their digests (ca bundle -> server cert -> server key), so compensation pairs each recorded
    digest with its own path (never an or-chain over shared paths)."""
    return (
        loc.controller_ca_bundle_path(),
        loc.controller_server_cert_path(),
        loc.controller_server_key_path(),
    )


def _ed25519_public_hex(raw: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if len(raw) != 32:
        raise ValueError("enrollment key must be 32 raw bytes")
    key = Ed25519PrivateKey.from_private_bytes(raw)
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


__all__ = [
    "ControllerFinalizationError",
    "FinalizationContext",
    "RealControllerEnrollmentFinalizationAdapter",
]
