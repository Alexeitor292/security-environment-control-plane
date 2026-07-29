"""Real controller-enrollment FINALIZATION adapter (SECP-PR5H-B2, 2b-3b-iv — upgrade-safe).

The production leaf for the closed :class:`~secp_management.finalization.
ControllerEnrollmentFinalizationAdapter`. It composes the already-reviewed 2b-2 primitives (TLS
producer + strict validator, CA-pinned locator, SCRAM role primitives, 0600 enrollment-key prep,
hardened filesystem, pinned compose runner, dedicated-role advisory-lock lease) into the exact
reviewed finalization order and — unlike the 2b-3b-iii checkpoint — is UPGRADE-SAFE:

* every fixed object is CLASSIFIED before mutation as absent / exact_adopted / managed_replaced /
  managed_unchanged / unsafe_or_foreign; unsafe/foreign state REFUSES before any mutation;
* existing TLS material is CRYPTOGRAPHICALLY adopted (chain, pairing, SAN==origin, EKU, validity,
  signed policy) via the public ``validate_controller_tls_material`` — never posture-only;
* a managed object that must be replaced has its exact prior PUBLIC bytes captured (and prior SECRET
  bytes staged root-only 0600 under a bounded transaction id) so compensation RESTORES the prior
  working generation, drift-checked, or returns recovery_required;
* the marker is written LAST, only after the independently reobserved ACTIVE identity agrees, and is
  followed by an authoritative post-restart runtime observation (non-root, marker-bound, fixed UDS
  signer, secrets inaccessible, healthy) — a failed proof removes the marker FIRST, reseals the API,
  and compensates the identity/prior state;
* the broker socket is proven to be EXACTLY an AF_UNIX socket (``is_socket``) with a bounded
  no-sign transport probe and no TCP listener;
* activation carries an authenticated nonnegative GENERATION (fresh=0, upgrade=prev+1) the API
  one-shot independently validates under the advisory lock.

Every per-effect receipt is a typed :class:`FinalizationEffectReceipt` binding public facts + opaque
restoration handles only — never a secret byte, path content, DSN, or raw exception. The adapter is
bound to ONE transaction id + plan; a durable finalization journal (public + handles only) is
written
before the first mutation and removed after commit/rollback so the management transaction can
resume.

The management plane NEVER imports ``secp_api``: the two API persistence effects run only through
the
fixed ``compose run --rm`` one-shots; the ACTIVE-identity reobservation is raw SQL as the dedicated
role. Constructed ONLY by the root-only install composition.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn

from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY,
    ENROLLMENT_SIGNER_SOCKET_PATH,
    enrollment_key_proof_id_for,
    key_id_for,
    prepare_controller_enrollment_key,
)
from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES,
    ENROLLMENT_SIGNER_READINESS_GATE_HEX_BYTES,
)
from secp_commissioning.enrollment_signer_marker import render_marker_bytes
from secp_commissioning.runtime import FilesystemError

from secp_management import ManagementError
from secp_management.adapters import CompensationResult, ReviewedUnit
from secp_management.controller_api_locator import (
    ControllerApiLocatorError,
    FileControllerApiLocatorProvider,
    record_fixed_controller_api_locator,
)
from secp_management.controller_compose_contract import render_broker_reviewed_unit
from secp_management.controller_tls import (
    ControllerTlsError,
    produce_controller_tls,
    validate_controller_tls_material,
)
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
    EffectDisposition,
    EnrollmentKeyIdentity,
    FinalizationEffectReceipt,
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
_CA_BUNDLE_MODE = 0o644
_SERVER_KEY_MODE = 0o600
_CREDENTIAL_MODE = 0o600
_HANDOFF_MODE = 0o640
_MARKER_MODE = 0o644
_LOCATOR_MODE = 0o644
_STAGING_DIR_MODE = 0o700
_STAGING_FILE_MODE = 0o600

_MAX_READ = 512 * 1024
_ONESHOT_TIMEOUT = 600
_RESTART_TIMEOUT = 300

_PROVISION_SCHEMA = "secp.enrollment-signer-role-provision/v1"
_ACTIVATION_SCHEMA = "secp.controller-identity-activation/v1"
_JOURNAL_SCHEMA = "secp.controller-finalization-journal/v1"

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

_UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"


class ControllerFinalizationError(ManagementError):
    """A bounded, closed finalization refusal — only a reason code, never a
    secret/path/exception."""


def _reject(reason_code: str) -> NoReturn:
    raise ControllerFinalizationError(reason_code)


def _utc(now: datetime) -> str:
    return now.astimezone(UTC).strftime(_UTC_FMT)


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- context


@dataclass(frozen=True)
class FinalizationContext:
    """The fixed production composition context. ``host`` is the hardened fs + pinned compose runner
    shared with the bootstrap adapters; ``api_uid``/``api_gid`` are the reviewed non-root API peer
    identity. The remaining fields are TEST-ONLY seams (production passes none): ``db_base_url``
    (the
    dedicated-role Engine coordinate), ``lease_provider_factory`` (the reobservation provider),
    ``db_prober``/``socket_prober``/``runtime_observer`` (the live DB/socket/runtime proofs), and
    ``now`` (the clock)."""

    host: RealAdapterContext
    api_uid: int = API_RUNTIME_UID
    api_gid: int = API_RUNTIME_GID
    db_base_url: str | None = None
    lease_provider_factory: Any = DbActiveControllerSigningIdentityProvider
    now: Any = None
    db_prober: Any = None
    socket_prober: Any = None
    runtime_observer: Any = None

    def dedicated_role_engine(self, password: str) -> Any:
        return build_signer_role_engine(password, base_url=self.db_base_url)


@dataclass(frozen=True)
class ApiSignerRuntimeObservation:
    """One authoritative post-marker runtime observation of the ordinary API (F8). Public facts
    only;
    ``ok`` is True only when EVERY invariant holds."""

    api_present: bool
    api_non_root: bool
    api_healthy: bool
    marker_mounted_readonly: bool
    handoffs_absent: bool
    enrollment_key_not_mounted: bool
    signer_credential_not_mounted: bool
    effective_signer_is_fixed_uds: bool
    binding_equals_marker: bool
    no_env_enablement: bool
    broker_reachable: bool
    no_mixed_generation: bool

    @property
    def ok(self) -> bool:
        return all(
            (
                self.api_present,
                self.api_non_root,
                self.api_healthy,
                self.marker_mounted_readonly,
                self.handoffs_absent,
                self.enrollment_key_not_mounted,
                self.signer_credential_not_mounted,
                self.effective_signer_is_fixed_uds,
                self.binding_equals_marker,
                self.no_env_enablement,
                self.broker_reachable,
                self.no_mixed_generation,
            )
        )


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


def _read_exact(ctx: FinalizationContext, path: str, *, uid: int = _ROOT_UID) -> bytes:
    try:
        return ctx.host.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=uid)
    except (FilesystemError, ManagementError):
        _reject("finalization_readback_failed")


def _absent(ctx: FinalizationContext, path: str) -> bool:
    try:
        return ctx.host.fs.lstat(path) is None
    except (FilesystemError, ManagementError):
        return False


def _root_regular_posture(ctx: FinalizationContext, path: str, *, gid: int, mode: int) -> bool:
    st = ctx.host.fs.lstat(path)
    return bool(
        st is not None
        and st.is_regular
        and not st.is_symlink
        and st.uid == _ROOT_UID
        and st.gid == gid
        and st.mode == mode
        and st.nlink == 1
    )


def _ownership_evidence(ctx: FinalizationContext, path: str) -> str:
    st = ctx.host.fs.lstat(path)
    if st is None:
        return "absent"
    return f"uid={st.uid};gid={st.gid};mode={st.mode:o};nlink={st.nlink};regular={st.is_regular}"


def _remove_created(ctx: FinalizationContext, path: str, expected_digest: str) -> bool:
    """Remove a transaction-created object ONLY after proving its current bytes are exactly what we
    installed. A drifted/foreign object is left in place. Returns True iff proven removed/absent."""
    try:
        st = ctx.host.fs.lstat(path)
        if st is None:
            return True
        current = ctx.host.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=_ROOT_UID)
        if _digest_bytes(current) != expected_digest:
            return False
        ctx.host.fs.remove_file(path)
        return ctx.host.fs.lstat(path) is None
    except (FilesystemError, ManagementError):
        return False


def _remove_handoff(ctx: FinalizationContext, path: str) -> None:
    try:
        if ctx.host.fs.lstat(path) is not None:
            ctx.host.fs.remove_file(path)
    except (FilesystemError, ManagementError):
        pass
    if not _absent(ctx, path):
        _reject("finalization_handoff_residual")


# --------------------------------------------------------------------------- staging + journal


class _Staging:
    """The fixed root-owned 0700 transaction staging area for prior rollback copies. Valid existing
    TLS is ADOPTED unchanged (never replaced) and the signer credential is ADOPTED unchanged (never
    rotated), so no private key or credential secret is ever staged; the only replaceable objects
    are the PUBLIC locator, broker unit, and marker. Backups are 0600 root-owned single-link files
    with fixed code-owned names under a bounded transaction id; a receipt keeps only an OPAQUE
    handle (the fixed name) + a public digest — never the bytes. All removed + absence-proven on
    commit. (The 0600 posture is retained defensively even though the staged objects are public.)"""

    #: the fixed, code-owned staging handles (never a caller-selected name). Valid existing TLS is
    #: ADOPTED unchanged (never replaced), so no prior TLS/credential secret is staged; the managed
    #: replaceable objects are the (public) locator, broker unit, and marker.
    _HANDLES = ("broker-unit.prior", "marker.prior", "locator.prior")

    def __init__(self, ctx: FinalizationContext, transaction_id: str) -> None:
        self._ctx = ctx
        self._dir = f"{ctx.host.locations.bootstrap_state}/finalization-staging/{transaction_id}"

    def _path(self, handle: str) -> str:
        if handle not in self._HANDLES:
            _reject("finalization_staging_handle_invalid")
        return f"{self._dir}/{handle}"

    def _ensure_dir(self) -> None:
        self._ctx.host.locations.assert_writable(self._dir)
        if self._ctx.host.fs.lstat(self._dir) is None:
            try:
                self._ctx.host.fs.makedir(
                    self._dir, uid=_ROOT_UID, gid=_ROOT_GID, mode=_STAGING_DIR_MODE
                )
            except (FilesystemError, ManagementError):
                _reject("finalization_staging_dir_failed")

    def stage_secret(self, handle: str, secret: bytes) -> str:
        """Stage a prior secret under a fixed ``handle`` (root:root 0600), read it back, and return
        its public digest. The bytes never leave the staging file."""
        path = self._path(handle)
        self._ensure_dir()
        try:
            self._ctx.host.fs.atomic_install(
                path, secret, uid=_ROOT_UID, gid=_ROOT_GID, mode=_STAGING_FILE_MODE
            )
        except FilesystemError:
            _reject("finalization_staging_write_failed")
        if not _root_regular_posture(self._ctx, path, gid=_ROOT_GID, mode=_STAGING_FILE_MODE):
            _reject("finalization_staging_posture_invalid")
        if _read_exact(self._ctx, path) != secret:
            _reject("finalization_staging_readback_mismatch")
        return _digest_bytes(secret)

    def read_secret(self, handle: str, expected_digest: str) -> bytes:
        data = _read_exact(self._ctx, self._path(handle))
        if _digest_bytes(data) != expected_digest:
            _reject("finalization_staging_restore_digest_mismatch")
        return data

    def remove_all(self) -> bool:
        """Remove + absence-prove every fixed staged secret (a deterministic, backend-neutral sweep
        —
        never an enumeration). An emptied 0700 dir is not a secret residual. True iff proven
        clean."""
        ok = True
        for handle in self._HANDLES:
            path = f"{self._dir}/{handle}"
            try:
                if self._ctx.host.fs.lstat(path) is not None:
                    self._ctx.host.fs.remove_file(path)
                if self._ctx.host.fs.lstat(path) is not None:
                    ok = False  # could not prove absence of a staged secret
            except (FilesystemError, ManagementError):
                ok = False
        return ok


class _Journal:
    """The durable finalization recovery journal (fixed path, canonical, PUBLIC + opaque handles
    only). It is WRITE-AHEAD: the INTENT of each effect (a ``pending`` entry) is journaled BEFORE
    the mutation that produces it, so a crash between a durable host/DB effect and its completion
    entry still leaves a recoverable record of what was in flight. The completed effect replaces the
    pending entry after the mutation, and the whole journal is removed after commit or proven
    rollback so the management transaction can resume deterministically."""

    def __init__(self, ctx: FinalizationContext, transaction_id: str, generation: int) -> None:
        self._ctx = ctx
        self._path = f"{ctx.host.locations.bootstrap_state}/controller-finalization-journal.json"
        self._tx = transaction_id
        self._gen = generation

    def write(
        self,
        state: str,
        effects: tuple[FinalizationEffectReceipt, ...],
        *,
        pending: dict[str, str] | None = None,
    ) -> None:
        doc = {
            "schema": _JOURNAL_SCHEMA,
            "transaction_id": self._tx,
            "generation": self._gen,
            "state": state,
            "pending": pending,  # the about-to-mutate effect (public), or null once completed
            "effects": [
                {
                    "effect": e.effect,
                    "object_identity": e.object_identity,
                    "disposition": e.disposition,
                    "candidate_digest": e.candidate_digest,
                    "prior_digest": e.prior_digest,
                    "restoration_handle": e.restoration_handle,
                    "restoration_digest": e.restoration_digest,
                    "prior_active": e.prior_active,
                }
                for e in effects
            ],
        }
        _install(
            self._ctx, self._path, canonical_json(doc).encode("utf-8"), gid=_ROOT_GID, mode=0o600
        )

    def remove(self) -> bool:
        try:
            if self._ctx.host.fs.lstat(self._path) is not None:
                self._ctx.host.fs.remove_file(self._path)
            return self._ctx.host.fs.lstat(self._path) is None
        except (FilesystemError, ManagementError):
            return False


# --------------------------------------------------------------------------- one-shots


def _run_oneshot(
    ctx: FinalizationContext,
    host_path: str,
    container_path: str,
    argv: tuple[str, ...],
    *,
    reason: str,
) -> dict[str, Any]:
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
    body = out.strip()
    if not body:
        _reject(reason)
    try:
        parsed = json.loads(body.splitlines()[-1])
    except (ValueError, IndexError):
        _reject(reason)
    if not isinstance(parsed, dict):
        _reject(reason)
    # canonical one-shot output: the receipt must round-trip canonical_json (no drift / extra prose)
    if canonical_json(parsed).encode("utf-8") != body.splitlines()[-1].encode("utf-8"):
        _reject("finalization_oneshot_output_noncanonical")
    return parsed


# --------------------------------------------------------------------------- the adapter


#: The readiness-origin GATE's reviewed on-disk posture: root-owned, API-group readable, NO world
#: bit. It is the one authorization-only secret the ordinary API may hold, so its mode is stricter
#: than the marker's (0644 public installation facts) and looser than the signer credential's
#: (0600 root-only) by exactly the group read the API process needs.
_READINESS_GATE_MODE = 0o640
#: the ONE accepted on-disk gate representation: 256-bit lowercase hex plus a single LF.
_READINESS_GATE_ON_DISK = re.compile(rb"[0-9a-f]{64}\n")


def generate_readiness_gate_secret() -> bytes:
    """256 bits from the operating system's cryptographically secure source, rendered in the ONE
    accepted on-disk form: 64 lowercase hex characters plus exactly one LF.

    The caller may not choose the length, the alphabet, the encoding or the source."""
    return (
        secrets.token_hex(ENROLLMENT_SIGNER_READINESS_GATE_HEX_BYTES // 2).encode("ascii") + b"\n"
    )


def _readiness_gate_content_ok(raw: bytes) -> bool:
    """True only for the ONE accepted on-disk gate representation. Never echoes the bytes."""
    return bool(
        isinstance(raw, bytes)
        and len(raw) == ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES
        and _READINESS_GATE_ON_DISK.fullmatch(raw)
    )


class RealControllerEnrollmentFinalizationAdapter:
    """The exact reviewed, UPGRADE-SAFE controller-enrollment finalization sequence. Bound to ONE
    plan + transaction id (reuse across unrelated transactions is refused). Every op classifies its
    fixed object before mutation, records a typed :class:`FinalizationEffectReceipt`, and stages a
    restorable prior when a managed object is replaced. Marker is written LAST + runtime-verified;
    compensation restores the prior working generation in reverse (marker FIRST) or
    recovery_required."""

    def __init__(self, ctx: FinalizationContext, *, plan: Any | None = None) -> None:
        self._ctx = ctx
        self._plan = plan
        self._now = ctx.now if ctx.now is not None else datetime.now
        self._generation = int(getattr(plan, "generation", 0)) if plan is not None else 0
        self._transaction_id = _transaction_id(plan) if plan is not None else "tx-unbound"
        self._effects: list[FinalizationEffectReceipt] = []
        self._staging = _Staging(ctx, self._transaction_id)
        self._journal = _Journal(ctx, self._transaction_id, self._generation)
        self._password: str | None = None
        self._locator_ca_digest: str | None = None
        self._key_identity: EnrollmentKeyIdentity | None = None
        self._started = False
        self._sealed = False

    def __repr__(self) -> str:
        return "RealControllerEnrollmentFinalizationAdapter(<redacted>)"

    # ---- transaction binding + journal ----
    def _journal_ahead(
        self, effect: str, object_identity: str, disposition: EffectDisposition
    ) -> None:
        """WRITE-AHEAD: journal the INTENT of the about-to-happen mutation BEFORE performing it (the
        first call satisfies write-before-first-mutation), and refuse a sealed transaction so this
        adapter is single-use — bound to exactly the one transaction id + plan it was built for."""
        if self._sealed:
            _reject("finalization_transaction_sealed")
        self._journal.write(
            "in_progress",
            tuple(self._effects),
            pending={
                "effect": effect,
                "object_identity": object_identity,
                "disposition": disposition.value,
            },
        )

    def _record(self, receipt: FinalizationEffectReceipt) -> None:
        self._effects.append(receipt)
        self._journal.write("in_progress", tuple(self._effects))  # completed → clears pending

    def _effect(
        self,
        effect: str,
        object_identity: str,
        disposition: EffectDisposition,
        *,
        candidate_digest: str = "",
        prior_digest: str = "",
        ownership_evidence: str = "",
        restoration_handle: str = "",
        restoration_digest: str = "",
        prior_active: bool = False,
    ) -> None:
        self._record(
            FinalizationEffectReceipt(
                effect=effect,
                transaction_id=self._transaction_id,
                generation=self._generation,
                object_identity=object_identity,
                disposition=disposition.value,
                candidate_digest=candidate_digest,
                prior_digest=prior_digest,
                ownership_evidence=ownership_evidence,
                restoration_handle=restoration_handle,
                restoration_digest=restoration_digest,
                prior_active=prior_active,
            )
        )

    # ---- 1-3: TLS material (classify → cryptographically adopt / stage+replace / create) ----
    def install_tls_material(
        self, *, policy: ControllerTlsPolicy, canonical_origin: str, tls_mode: str
    ) -> None:
        loc = self._ctx.host.locations
        ca_p, cert_p, key_p = _tls_paths(loc)
        present = [p for p in (ca_p, cert_p, key_p) if not _absent(self._ctx, p)]
        if present and len(present) != 3:
            _reject("finalization_tls_partial_set")  # any partial three-file set refuses
        if len(present) == 3:
            self._adopt_or_replace_tls(policy, canonical_origin, ca_p, cert_p, key_p)
            return
        self._create_tls(policy, canonical_origin, tls_mode, ca_p, cert_p, key_p)

    def _validate_existing_tls(
        self, policy: Any, canonical_origin: str, ca_p, cert_p, key_p
    ) -> bytes:
        for p, gid, mode in (
            (ca_p, _ROOT_GID, _CA_BUNDLE_MODE),
            (cert_p, _ROOT_GID, _CA_BUNDLE_MODE),
            (key_p, _ROOT_GID, _SERVER_KEY_MODE),
        ):
            if not _root_regular_posture(self._ctx, p, gid=gid, mode=mode):
                _reject("finalization_tls_posture_invalid")
        ca_pem = _read_exact(self._ctx, ca_p)
        cert_pem = _read_exact(self._ctx, cert_p)
        key_pem = _read_exact(self._ctx, key_p)
        try:
            validate_controller_tls_material(
                ca_pem=ca_pem,
                server_pem=cert_pem,
                key_pem=key_pem,
                policy=policy,
                canonical_origin=canonical_origin,
                now=self._now(UTC),
            )
        except ControllerTlsError as exc:
            _reject(f"finalization_tls_adopt_invalid:{getattr(exc, 'reason_code', 'invalid')}"[:60])
        return ca_pem

    def _adopt_or_replace_tls(self, policy, canonical_origin, ca_p, cert_p, key_p) -> None:
        # a complete existing set must be cryptographically valid; adopt it unchanged.
        ca_pem = self._validate_existing_tls(policy, canonical_origin, ca_p, cert_p, key_p)
        self._locator_ca_digest = _digest_bytes(ca_pem)
        self._effect(
            "tls",
            ca_p,
            EffectDisposition.EXACT_ADOPTED,
            candidate_digest=_digest_bytes(ca_pem),
            ownership_evidence=_ownership_evidence(self._ctx, ca_p),
        )

    def _create_tls(self, policy, canonical_origin, tls_mode, ca_p, cert_p, key_p) -> None:
        try:
            produced = produce_controller_tls(
                policy=policy, canonical_origin=canonical_origin, mode=tls_mode
            )
            ca_pem = produced.ca_bundle_pem()
            cert_pem = produced.server_certificate_pem()
            key_pem = produced.server_private_key_pem()
        except ControllerTlsError as exc:
            _reject(getattr(exc, "reason_code", "controller_tls_produce_failed"))
        self._journal_ahead("tls", ca_p, EffectDisposition.ABSENT)  # write-ahead before first write
        for path, pem, mode in (
            (ca_p, ca_pem, _CA_BUNDLE_MODE),
            (cert_p, cert_pem, _CA_BUNDLE_MODE),
            (key_p, key_pem, _SERVER_KEY_MODE),
        ):
            _install(self._ctx, path, pem, gid=_ROOT_GID, mode=mode)
            if _read_exact(self._ctx, path) != pem:
                _reject("finalization_tls_readback_mismatch")
            self._effect("tls", path, EffectDisposition.ABSENT, candidate_digest=_digest_bytes(pem))
        if not _root_regular_posture(self._ctx, key_p, gid=_ROOT_GID, mode=_SERVER_KEY_MODE):
            _reject("finalization_tls_posture_invalid")
        self._locator_ca_digest = _digest_bytes(ca_pem)

    # ---- 4-5: locator (classify → adopt / stage+replace / create) ----
    def record_locator(self, *, canonical_origin: str) -> None:
        loc = self._ctx.host.locations
        path = loc.controller_api_locator_path()
        disposition, prior_bytes = self._classify_locator(path, canonical_origin)
        if disposition is EffectDisposition.UNSAFE_OR_FOREIGN:
            _reject("finalization_locator_unsafe_or_foreign")
        if disposition in (EffectDisposition.EXACT_ADOPTED, EffectDisposition.MANAGED_UNCHANGED):
            self._effect(
                "locator",
                path,
                disposition,
                candidate_digest=_digest_bytes(_read_exact(self._ctx, path)),
                prior_digest=self._locator_ca_digest or "",
                ownership_evidence=_ownership_evidence(self._ctx, path),
            )
            return
        handle = "locator.prior"
        restoration_handle = ""
        restoration_digest = ""
        prior_digest = ""
        if disposition is EffectDisposition.MANAGED_REPLACED and prior_bytes is not None:
            prior_digest = _digest_bytes(prior_bytes)
            restoration_handle = handle
            restoration_digest = self._staging.stage_secret(
                handle, prior_bytes
            )  # public locator, staged uniformly
        self._journal_ahead("locator", path, disposition)  # write-ahead before the locator write
        self._write_locator(canonical_origin, path)
        self._effect(
            "locator",
            path,
            disposition,
            candidate_digest=_digest_bytes(_read_exact(self._ctx, path)),
            prior_digest=prior_digest,
            ownership_evidence=_ownership_evidence(self._ctx, path),
            restoration_handle=restoration_handle,
            restoration_digest=restoration_digest,
        )

    def _classify_locator(
        self, path: str, canonical_origin: str
    ) -> tuple[EffectDisposition, bytes | None]:
        loc = self._ctx.host.locations
        if _absent(self._ctx, path):
            return EffectDisposition.ABSENT, None
        if not _root_regular_posture(self._ctx, path, gid=_ROOT_GID, mode=_LOCATOR_MODE):
            return EffectDisposition.UNSAFE_OR_FOREIGN, None
        try:
            prior = _read_exact(self._ctx, path)
            record = FileControllerApiLocatorProvider(self._ctx.host.fs, path=path).locate()
        except (ControllerApiLocatorError, ManagementError):
            return EffectDisposition.UNSAFE_OR_FOREIGN, None
        # the CA digest must match the CA we installed/adopted, and the origin must match exactly
        actual_ca = None
        if not _absent(self._ctx, loc.controller_ca_bundle_path()):
            actual_ca = _digest_bytes(_read_exact(self._ctx, loc.controller_ca_bundle_path()))
        if (
            record.canonical_origin == canonical_origin
            and record.ca_bundle_path == loc.controller_ca_bundle_path()
            and (actual_ca is None or actual_ca == self._locator_ca_digest)
        ):
            return EffectDisposition.EXACT_ADOPTED, prior
        return EffectDisposition.MANAGED_REPLACED, prior

    def _write_locator(self, canonical_origin: str, path: str) -> None:
        loc = self._ctx.host.locations
        try:
            record_fixed_controller_api_locator(
                self._ctx.host.fs,
                canonical_origin=canonical_origin,
                write=True,
                confirm=True,
                locations=loc,
            )
            FileControllerApiLocatorProvider(self._ctx.host.fs, path=path).locate()
        except ControllerApiLocatorError as exc:
            _reject(getattr(exc, "reason_code", "controller_locator_record_failed"))

    # ---- 6-13: signer role + credential (classify → adopt-unchanged / create; foreign refuses)
    # ----
    def provision_signer_role(self, role: ReviewedSignerRole) -> None:
        loc = self._ctx.host.locations
        if role.role_name != ENROLLMENT_SIGNER_DB_ROLE:
            _reject("finalization_signer_role_name_invalid")
        if role.credential_source_path != loc.enrollment_signer_credential_path():
            _reject("finalization_signer_credential_path_invalid")
        cred_path = loc.enrollment_signer_credential_path()
        if not _absent(self._ctx, cred_path):
            self._adopt_signer(cred_path)
            return
        self._create_signer(role, cred_path)

    def _adopt_signer(self, cred_path: str) -> None:
        # authenticate the existing root-owned credential, then RE-PROVE the role is exactly
        # least-privilege by re-running the fixed provisioning/repair one-shot with the SAME
        # plaintext: a privilege-drifted or object-owning role refuses (the exhaustive receipt),
        # while an already-least-privilege role is a no-op. The operator credential file is adopted
        # UNCHANGED — an ordinary upgrade never rotates the password (only the transparent SCRAM
        # salt behind the same plaintext moves), so the adopt disposition stays EXACT_ADOPTED.
        if not _root_regular_posture(self._ctx, cred_path, gid=_ROOT_GID, mode=_CREDENTIAL_MODE):
            _reject("finalization_signer_credential_unsafe")
        password = _read_exact(self._ctx, cred_path).decode("ascii", "ignore").strip()
        self._journal_ahead(
            "signer_role", ENROLLMENT_SIGNER_DB_ROLE, EffectDisposition.EXACT_ADOPTED
        )
        self._provision_and_prove(password)
        self._effect(
            "signer_credential",
            cred_path,
            EffectDisposition.EXACT_ADOPTED,
            ownership_evidence=_ownership_evidence(self._ctx, cred_path),
        )
        self._effect("signer_role", ENROLLMENT_SIGNER_DB_ROLE, EffectDisposition.EXACT_ADOPTED)

    def _create_signer(self, role: ReviewedSignerRole, cred_path: str) -> None:
        password = generate_signer_db_password()
        self._journal_ahead("signer_role", ENROLLMENT_SIGNER_DB_ROLE, EffectDisposition.ABSENT)
        _install(
            self._ctx,
            cred_path,
            (password + "\n").encode("ascii"),
            gid=_ROOT_GID,
            mode=_CREDENTIAL_MODE,
        )
        cred_digest = _digest_bytes((password + "\n").encode("ascii"))
        self._provision_and_prove(password)
        self._effect("signer_role", ENROLLMENT_SIGNER_DB_ROLE, EffectDisposition.ABSENT)
        self._effect(
            "signer_credential",
            cred_path,
            EffectDisposition.ABSENT,
            candidate_digest=cred_digest,
            ownership_evidence=_ownership_evidence(self._ctx, cred_path),
        )

    def _provision_and_prove(self, password: str) -> None:
        """Drive the fixed least-privilege provisioning/repair one-shot for ``password`` (fresh or
        adopted), assert the exhaustive least-privilege receipt, remove the handoff, then prove the
        dedicated role authenticates + takes the advisory lock. Sets ``self._password``. Running it
        on BOTH the create and adopt paths guarantees an adopted role is re-proven least-privilege
        (a drifted or object-owning role refuses) without ever rotating the operator credential."""
        verifier = scram_sha256_verifier(password)
        handoff_path = self._ctx.host.locations.provisioning_handoff_host_path()
        container_path = self._ctx.host.locations.provisioning_handoff_container_path()
        operation_id = f"provision-{self._transaction_id[:24]}"
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
        if not _root_regular_posture(
            self._ctx, handoff_path, gid=self._ctx.api_gid, mode=_HANDOFF_MODE
        ):
            _reject("finalization_handoff_posture_invalid")
        try:
            receipt = _run_oneshot(
                self._ctx,
                handoff_path,
                container_path,
                _PROVISION_ARGV,
                reason="finalization_provisioning_oneshot_failed",
            )
            self._assert_provision_receipt(receipt, operation_id)
        finally:
            _remove_handoff(self._ctx, handoff_path)
        self._prove_dedicated_role(password)
        self._password = password

    def _assert_provision_receipt(self, receipt: dict[str, Any], operation_id: str) -> None:
        if "reason_code" in receipt:
            _reject("finalization_provisioning_refused")
        required = (
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
            or not all(receipt.get(k) is True for k in required)
        ):
            _reject("finalization_provisioning_posture_invalid")

    def _prove_dedicated_role(self, password: str) -> None:
        from sqlalchemy import text

        engine = self._ctx.dedicated_role_engine(password)
        try:
            if self._ctx.db_prober is not None:
                self._ctx.db_prober(engine)
                return
            with engine.begin() as conn:
                if conn.execute(text("SELECT current_user")).scalar() != ENROLLMENT_SIGNER_DB_ROLE:
                    _reject("finalization_signer_role_identity_mismatch")
                conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
        except ControllerFinalizationError:
            raise
        except Exception:  # noqa: BLE001 - any DB fault (auth / connect / SQL) is a closed refusal
            _reject("finalization_dedicated_role_unproven")
        finally:
            engine.dispose()

    # ---- 15b: the readiness-origin GATE (classify -> adopt UNCHANGED / create+prove) ----
    def install_readiness_gate(self) -> None:
        """Install or ADOPT the fixed readiness-origin gate, before anything can recreate the API.

        Classify first, mutate second. An existing gate with the exact reviewed posture is adopted
        UNCHANGED -- an exact replay or a managed upgrade never rotates it, because rotation would
        revoke a live API's authorization while proving nothing (the value is already root-owned and
        readable only by the API group). Any other on-disk state is FOREIGN and refuses rather than
        being overwritten. A freshly created gate is RE-READ and proven, both posture and content
        identity, before its effect is recorded."""
        path = self._ctx.host.locations.api_signer_readiness_gate_path()
        if not _absent(self._ctx, path):
            if not _root_regular_posture(
                self._ctx, path, gid=API_RUNTIME_GID, mode=_READINESS_GATE_MODE
            ) or not _readiness_gate_content_ok(_read_exact(self._ctx, path)):
                _reject("finalization_readiness_gate_unsafe_or_foreign")
            self._effect(
                "readiness_gate",
                path,
                EffectDisposition.EXACT_ADOPTED,
                ownership_evidence=_ownership_evidence(self._ctx, path),
            )
            return
        content = generate_readiness_gate_secret()
        self._journal_ahead("readiness_gate", path, EffectDisposition.ABSENT)
        _install(self._ctx, path, content, gid=API_RUNTIME_GID, mode=_READINESS_GATE_MODE)
        if _read_exact(self._ctx, path) != content or not _root_regular_posture(
            self._ctx, path, gid=API_RUNTIME_GID, mode=_READINESS_GATE_MODE
        ):
            _reject("finalization_readiness_gate_readback_mismatch")
        self._effect(
            "readiness_gate",
            path,
            EffectDisposition.ABSENT,
            # the DIGEST and the ownership facts -- never the 256-bit value.
            candidate_digest=_digest_bytes(content),
            ownership_evidence=_ownership_evidence(self._ctx, path),
        )

    # ---- 14-15: enrollment key ----
    def prepare_enrollment_key(self) -> EnrollmentKeyIdentity:
        existed = not _absent(self._ctx, _ENROLLMENT_KEY_PATH)
        self._journal_ahead(
            "enrollment_key",
            _ENROLLMENT_KEY_PATH,
            EffectDisposition.EXACT_ADOPTED if existed else EffectDisposition.ABSENT,
        )
        try:
            public = prepare_controller_enrollment_key(self._ctx.host.fs, write=True, confirm=True)
        except ManagementError as exc:
            _reject(getattr(exc, "reason_code", "finalization_enrollment_key_failed"))
        pub_hex = public["public_key_hex"]
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
        # bind the exact derived public key id + content identity (not mode/path) for compensation
        self._effect(
            "enrollment_key",
            _ENROLLMENT_KEY_PATH,
            EffectDisposition.EXACT_ADOPTED if existed else EffectDisposition.ABSENT,
            candidate_digest=identity.controller_key_id,
            ownership_evidence=_ownership_evidence(self._ctx, _ENROLLMENT_KEY_PATH),
        )
        return identity

    # ---- 16-18: broker unit (exact code-rendered equality → adopt / stage+replace / install) ----
    def install_broker_unit(self, unit: ReviewedUnit) -> None:
        unit.verify()
        expected = render_broker_reviewed_unit(self._ctx.host.locations)
        if unit.identity != expected.identity or unit.content != expected.content:
            _reject(
                "finalization_broker_unit_not_code_rendered"
            )  # self-consistent bytes insufficient
        path = self._ctx.host.locations.broker_unit_path()
        if not _absent(self._ctx, path):
            current = _read_exact(self._ctx, path)
            if _digest_bytes(current) == _digest_bytes(unit.content):
                self._effect(
                    "broker_unit",
                    path,
                    EffectDisposition.EXACT_ADOPTED,
                    candidate_digest=unit.identity,
                )
                return
            prior_digest = _digest_bytes(current)
            handle = "broker-unit.prior"
            rdigest = self._staging.stage_secret(handle, current)
            self._journal_ahead("broker_unit", path, EffectDisposition.MANAGED_REPLACED)
            _install_unit(self._ctx, path, unit.content)
            self._effect(
                "broker_unit",
                path,
                EffectDisposition.MANAGED_REPLACED,
                candidate_digest=unit.identity,
                prior_digest=prior_digest,
                restoration_handle=handle,
                restoration_digest=rdigest,
            )
            return
        self._journal_ahead("broker_unit", path, EffectDisposition.ABSENT)
        _install_unit(self._ctx, path, unit.content)
        if _read_exact(self._ctx, path) != unit.content:
            _reject("finalization_broker_unit_readback_mismatch")
        self._effect("broker_unit", path, EffectDisposition.ABSENT, candidate_digest=unit.identity)

    # ---- 19: start the broker (record prior running state) ----
    def start_broker(self) -> None:
        unit = self._ctx.host.locations.broker_unit_path().rsplit("/", 1)[-1]
        prior_active = self._broker_is_active(unit)
        self._journal_ahead("broker_service", unit, EffectDisposition.ABSENT)
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
        self._started = True
        self._effect("broker_service", unit, EffectDisposition.ABSENT, prior_active=prior_active)

    def _broker_is_active(self, unit: str) -> bool:
        try:
            out = self._ctx.host.run(
                self._ctx.host.executables.service_manager,
                ("is-active", unit),
                timeout=30,
                reason="finalization_broker_state_query_failed",
            )
            return out.strip() == "active"
        except ManagementError:
            return False

    # ---- 20: prove the broker signer path operational (AF_UNIX socket + reachability + key/
    # identity). The "no TCP" guarantee is structural — it comes from install_broker_unit requiring
    # the byte-exact code-rendered unit, which binds ONLY the fixed AF_UNIX socket (no ListenStream
    # /port), NOT from a runtime port scan (that is the systemd/root fence's job). ----
    def verify_signer_operational(self, *, key_identity: EnrollmentKeyIdentity) -> None:
        if self._key_identity is None or key_identity != self._key_identity:
            _reject("finalization_key_identity_disagreement")
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
        # EXACTLY an AF_UNIX socket (not FIFO/device/regular) at root:api-group 0660, single-link
        sp = self._ctx.host.locations.broker_socket_path()
        st = self._ctx.host.fs.lstat(sp)
        if (
            st is None
            or not st.is_socket
            or st.is_symlink
            or st.uid != _ROOT_UID
            or st.gid != self._ctx.api_gid
            or st.mode != 0o660
            or st.nlink != 1
        ):
            _reject("finalization_broker_socket_posture_invalid")
        self._probe_broker_transport(sp)
        if self._password is None:
            _reject("finalization_signer_credential_missing")
        self._prove_dedicated_role(self._password)

    def _probe_broker_transport(self, socket_path: str) -> None:
        """A bounded no-sign transport probe: prove the accept loop is REACHABLE on the fixed UDS
        (connect/close only — never a signing request). Absence of any TCP listener is guaranteed
        structurally by the byte-exact code-rendered broker unit (AF_UNIX-only), not by a scan."""
        if self._ctx.socket_prober is not None:
            self._ctx.socket_prober(
                socket_path, expected_peer=(self._ctx.api_uid, self._ctx.api_gid)
            )
            return
        import socket as _socket  # pragma: no cover - production probe (root fence exercises it)

        af_unix = getattr(_socket, "AF_UNIX", None)
        if af_unix is None:
            _reject("finalization_broker_probe_unsupported")
        s = _socket.socket(af_unix, _socket.SOCK_STREAM)
        try:
            s.settimeout(5.0)
            s.connect(socket_path)  # connect/close only — no sign_offer request
        except OSError:
            _reject("finalization_broker_unreachable")
        finally:
            s.close()

    # ---- 21-25: activate (generation-bound; strict receipt) ----
    def activate_controller_identity(
        self, activation: ControllerIdentityActivation
    ) -> ActivationReceipt:
        loc = self._ctx.host.locations
        handoff_path = loc.activation_handoff_host_path()
        container_path = loc.activation_handoff_container_path()
        if activation.generation != self._generation:
            _reject("finalization_activation_generation_mismatch")
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
            "generation": activation.generation,
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
        if not _root_regular_posture(
            self._ctx, handoff_path, gid=self._ctx.api_gid, mode=_HANDOFF_MODE
        ):
            _reject("finalization_handoff_posture_invalid")
        # write-ahead the identity-activation INTENT before the durable DB one-shot: this is the
        # crown-jewel mutation, so a crash between the commit and its receipt must be recoverable.
        self._journal_ahead(
            "identity_activation",
            pred_row or candidate_digest,
            EffectDisposition.MANAGED_REPLACED if pred_row else EffectDisposition.ABSENT,
        )
        try:
            raw = _run_oneshot(
                self._ctx,
                handoff_path,
                container_path,
                _ACTIVATION_ARGV,
                reason="finalization_activation_oneshot_failed",
            )
            parsed = _parse_activation_receipt(raw, activation, candidate_digest)
        finally:
            _remove_handoff(self._ctx, handoff_path)
        self._effect(
            "identity_activation",
            parsed.resulting_row_id,
            EffectDisposition.MANAGED_REPLACED if pred_row else EffectDisposition.ABSENT,
            candidate_digest=parsed.activation_token,
            prior_digest=pred_row or "",
            prior_active=bool(pred_row),
        )
        return parsed

    def _predecessor_token(self, pred_row: str | None) -> str | None:
        if pred_row is None:
            return None
        lease = self._reobserve_active()
        if lease is None or str(lease.row_id) != pred_row:
            _reject("finalization_predecessor_conflict")
        return lease.activation_token

    # ---- 26-31: reobserve, marker LAST, post-restart runtime observation ----
    def enable_api_signer(self, marker: ApiSignerMarker) -> None:
        lease = self._reobserve_active()
        if lease is None:
            _reject("finalization_active_identity_unavailable")
        self._require_marker_agrees(marker, lease)
        path = self._ctx.host.locations.api_signer_marker_path()
        if path != marker.marker_path:
            _reject("finalization_marker_path_mismatch")
        prior = None
        disposition = EffectDisposition.ABSENT
        if not _absent(self._ctx, path):
            if not _root_regular_posture(self._ctx, path, gid=_ROOT_GID, mode=_MARKER_MODE):
                _reject("finalization_marker_unsafe_or_foreign")
            prior = _read_exact(self._ctx, path)
            disposition = EffectDisposition.MANAGED_REPLACED
        content = self._render_marker(marker)
        restoration_handle = ""
        restoration_digest = ""
        prior_digest = ""
        if disposition is EffectDisposition.MANAGED_REPLACED and prior is not None:
            prior_digest = _digest_bytes(prior)
            restoration_handle = "marker.prior"
            restoration_digest = self._staging.stage_secret(restoration_handle, prior)
        self._journal_ahead("marker", path, disposition)  # write-ahead before the enablement marker
        _install(self._ctx, path, content, gid=_ROOT_GID, mode=_MARKER_MODE)
        if _read_exact(self._ctx, path) != content or not _root_regular_posture(
            self._ctx, path, gid=_ROOT_GID, mode=_MARKER_MODE
        ):
            _reject("finalization_marker_readback_mismatch")
        self._effect(
            "marker",
            path,
            disposition,
            candidate_digest=_digest_bytes(content),
            prior_digest=prior_digest,
            restoration_handle=restoration_handle,
            restoration_digest=restoration_digest,
        )
        self._restart_api()
        obs = self._observe_runtime(marker)
        if not obs.ok:
            self._rollback_after_failed_runtime()
            _reject("finalization_post_marker_runtime_unverified")

    def _restart_api(self) -> None:
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

    def _observe_runtime(self, marker: ApiSignerMarker) -> ApiSignerRuntimeObservation:
        if self._ctx.runtime_observer is not None:
            return self._ctx.runtime_observer(marker)
        return self._default_runtime_observation(marker)

    def _default_runtime_observation(self, marker: ApiSignerMarker) -> ApiSignerRuntimeObservation:
        # FAIL-CLOSED default. Management can authoritatively verify only the HOST-side facts below
        # (marker posture, handoffs absent, secret paths not API/world-readable, broker reachable).
        # The LIVE-runtime invariants — the API is actually running, actually non-root, healthy,
        # signing only over the fixed UDS with a binding equal to the marker, with no env-based
        # enablement and no mixed generation — cannot be observed from the host, so they are left
        # FALSE here. That makes `.ok` False, so an adapter with NO injected observer refuses
        # (recovery_required) instead of rubber-stamping success; the real observer is supplied by
        # the root/systemd runtime fence and by the 2b-3c combined transaction.
        loc = self._ctx.host.locations
        marker_ok = _root_regular_posture(
            self._ctx, loc.api_signer_marker_path(), gid=_ROOT_GID, mode=_MARKER_MODE
        )
        handoffs_absent = _absent(self._ctx, loc.provisioning_handoff_host_path()) and _absent(
            self._ctx, loc.activation_handoff_host_path()
        )
        key_st = self._ctx.host.fs.lstat(_ENROLLMENT_KEY_PATH)
        key_not_api = (
            key_st is None or (key_st.mode & 0o007) == 0
        )  # not world-readable → API cannot read
        cred_st = self._ctx.host.fs.lstat(loc.enrollment_signer_credential_path())
        cred_not_api = cred_st is None or (cred_st.mode & 0o077) == 0
        broker_ok = True
        try:
            self._probe_broker_transport(loc.broker_socket_path())
        except ControllerFinalizationError:
            broker_ok = False
        return ApiSignerRuntimeObservation(
            api_present=False,  # live-runtime facts: not observable host-side → fail closed
            api_non_root=False,
            api_healthy=False,
            marker_mounted_readonly=marker_ok,
            handoffs_absent=handoffs_absent,
            enrollment_key_not_mounted=key_not_api,
            signer_credential_not_mounted=cred_not_api,
            effective_signer_is_fixed_uds=False,
            binding_equals_marker=False,
            no_env_enablement=False,
            broker_reachable=broker_ok,
            no_mixed_generation=False,
        )

    def _rollback_after_failed_runtime(self) -> None:
        # the marker effect is the last one recorded; compensate it — remove (fresh install) or
        # RESTORE the prior (upgrade) FIRST, then restart the API back to sealed. Any residual is
        # surfaced through the receipt-level compensation that the transaction then runs.
        self._compensate_marker(self._effects[-1], [])

    def _require_marker_agrees(self, marker: ApiSignerMarker, lease: Any) -> None:
        db_expected = {
            "installation_id": lease.controller_installation_id,
            "release_digest": lease.release_digest,
            "active_identity_row_id": str(lease.row_id),
            "activation_token": lease.activation_token,
            "controller_key_id": lease.controller_key_id,
            "management_identity_digest": lease.management_identity_digest,
            "bootstrap_evidence_digest": lease.bootstrap_evidence_digest,
        }
        for f, expected in db_expected.items():
            if getattr(marker, f) != expected:
                _reject("finalization_marker_identity_disagreement")
        if (
            marker.api_uid != self._ctx.api_uid
            or marker.api_gid != self._ctx.api_gid
            or marker.signer_role_name != ENROLLMENT_SIGNER_DB_ROLE
            or marker.uds_contract_identity != ENROLLMENT_SIGNER_SOCKET_PATH
            or marker.locator_ca_digest != self._locator_ca_digest
        ):
            _reject("finalization_marker_binding_disagreement")

    def _render_marker(self, marker: ApiSignerMarker) -> bytes:
        """Render the enablement marker through the ONE plane-neutral strict contract (R7), so the
        writer can never drift from the parser every consumer (API + management) validates with."""
        return render_marker_bytes(
            installation_id=marker.installation_id,
            release_digest=marker.release_digest,
            active_identity_row_id=marker.active_identity_row_id,
            activation_token=marker.activation_token,
            controller_key_id=marker.controller_key_id,
            uds_contract_identity=marker.uds_contract_identity,
            api_uid=marker.api_uid,
            api_gid=marker.api_gid,
            signer_role_name=marker.signer_role_name,
            locator_ca_digest=marker.locator_ca_digest,
            management_identity_digest=marker.management_identity_digest,
            bootstrap_evidence_digest=marker.bootstrap_evidence_digest,
            recorded_at=_utc(self._now(UTC)),
        )

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

    # ---- receipt + commit + compensation ----
    def receipt(self) -> ControllerFinalizationReceipt:
        return ControllerFinalizationReceipt(
            effects=tuple(self._effects),
            transaction_id=self._transaction_id,
            generation=self._generation,
        )

    def commit(self) -> bool:
        """Called by the transaction on success: seal the adapter (single-use), then remove +
        absence-prove every staged backup + the recovery journal. Returns True iff proven clean."""
        self._sealed = True
        clean = self._staging.remove_all()
        return self._journal.remove() and clean

    def compensate(self, receipt: ControllerFinalizationReceipt) -> CompensationResult:
        if type(receipt) is not ControllerFinalizationReceipt:
            return CompensationResult(proven=False, residual=("malformed_receipt",))
        self._sealed = True  # single-use: no further mutation after a rollback begins
        residual: list[str] = []
        # REVERSE reviewed order → the MARKER effect FIRST (return the API to sealed).
        for e in reversed(receipt.effects):
            self._compensate_effect(e, residual)
        if not self._staging.remove_all():
            residual.append("secret_staging_residual")
        if not self._journal.remove():
            residual.append("journal_residual")
        return CompensationResult(proven=not residual, residual=tuple(residual))

    def _compensate_effect(self, e: FinalizationEffectReceipt, residual: list[str]) -> None:
        d = e.disposition
        if d in (EffectDisposition.EXACT_ADOPTED.value, EffectDisposition.MANAGED_UNCHANGED.value):
            return  # adopted/unchanged → leave in place
        if e.effect == "identity_activation":
            self._compensate_identity(e, residual)
            return
        if e.effect == "broker_service":
            self._compensate_broker_service(e, residual)
            return
        if e.effect == "signer_role":
            self._compensate_signer_role(e, residual)
            return
        if e.effect == "marker":
            self._compensate_marker(e, residual)
            return
        obj = e.object_identity
        unit = e.effect == "broker_unit"
        if d == EffectDisposition.ABSENT.value:
            ok = self._remove_obj(obj, e.candidate_digest, unit=unit, effect=e.effect)
            if not ok:
                residual.append(e.effect)
        elif d == EffectDisposition.MANAGED_REPLACED.value:
            if not self._restore_obj(e, unit=unit):
                residual.append(e.effect)

    def _remove_obj(self, path: str, digest: str, *, unit: bool, effect: str) -> bool:
        if effect == "enrollment_key":
            return _remove_created_key(self._ctx, path, digest)
        if effect == "signer_credential":
            return _remove_if_present(self._ctx, path)
        return _remove_created(self._ctx, path, digest)

    def _restore_obj(self, e: FinalizationEffectReceipt, *, unit: bool) -> bool:
        try:
            prior = self._staging.read_secret(e.restoration_handle, e.restoration_digest)
        except ControllerFinalizationError:
            return False
        try:
            self._ctx.host.fs.atomic_install(
                e.object_identity,
                prior,
                uid=_ROOT_UID,
                gid=_ROOT_GID,
                mode=(0o644 if unit else _LOCATOR_MODE if e.effect == "locator" else _MARKER_MODE),
            )
            return _read_exact(self._ctx, e.object_identity) == prior
        except (FilesystemError, ManagementError):
            return False

    def _compensate_marker(self, e: FinalizationEffectReceipt, residual: list[str]) -> None:
        # revert the enablement marker FIRST (remove on a fresh install → SEALED, RESTORE the prior
        # on an upgrade → the prior working generation), THEN restart the API so a still-running
        # enabled API re-reads the reverted marker — removing/replacing the file alone does not
        # reseal/revert a process that already loaded the marker at boot.
        if e.disposition == EffectDisposition.ABSENT.value:
            reverted = self._remove_obj(
                e.object_identity, e.candidate_digest, unit=False, effect="marker"
            )
        else:  # MANAGED_REPLACED → restore the prior marker
            reverted = self._restore_obj(e, unit=False)
        if not reverted:
            residual.append("marker")
        try:
            self._restart_api()
        except ManagementError:
            residual.append("api_reseal")

    def _compensate_broker_service(self, e: FinalizationEffectReceipt, residual: list[str]) -> None:
        unit = e.object_identity
        try:
            if not e.prior_active:  # we started it fresh → stop it
                self._ctx.host.run(
                    self._ctx.host.executables.service_manager,
                    ("stop", unit),
                    timeout=120,
                    reason="finalization_broker_stop_failed",
                )
            # a previously-active broker is left running (prior working generation preserved)
        except ManagementError:
            residual.append("broker_service")

    def _compensate_signer_role(self, e: FinalizationEffectReceipt, residual: list[str]) -> None:
        if e.disposition == EffectDisposition.ABSENT.value:
            # a freshly-created role: dropping it requires a fixed rollback one-shot (not generic
            # SQL). Not driven in this composed-but-not-orchestrated commit → a bounded residual so
            # the transaction reports recovery_required rather than a false success.
            residual.append("signer_role_created")

    def _compensate_identity(self, e: FinalizationEffectReceipt, residual: list[str]) -> None:
        # an activated identity cannot be silently un-activated. On an UPGRADE (a prior generation
        # existed) the reviewed recovery is a rollback reactivation of the prior verified identity
        # through the activation one-shot (distinct rollback op id, next truthful generation). That
        # is driven by the engine's combined transaction in 2b-3c; here it is a bounded residual so
        # the transaction reports recovery_required. A fresh install has no prior to restore.
        residual.append("identity_activation")


# --------------------------------------------------------------------------- strict receipt parse


def _parse_activation_receipt(
    raw: dict[str, Any], activation: ControllerIdentityActivation, candidate_digest: str
) -> ActivationReceipt:
    if "reason_code" in raw:
        _reject("finalization_activation_refused")
    allowed = {
        "operation_id",
        "candidate_digest",
        "resulting_row_id",
        "activation_token",
        "previous_active_row_id",
        "created",
        "resulting_status",
        "resulting_public_state_digest",
    }
    if set(raw) != allowed:  # reject missing AND extra fields
        _reject("finalization_activation_receipt_fields_invalid")
    if not isinstance(raw["created"], bool):  # strict bool — no bool() coercion of ints/strings
        _reject("finalization_activation_receipt_created_not_bool")
    for k in (
        "operation_id",
        "candidate_digest",
        "resulting_row_id",
        "activation_token",
        "resulting_status",
        "resulting_public_state_digest",
    ):
        if not isinstance(raw[k], str):
            _reject("finalization_activation_receipt_type_invalid")
    if not (
        raw["previous_active_row_id"] is None or isinstance(raw["previous_active_row_id"], str)
    ):
        _reject("finalization_activation_receipt_type_invalid")
    parsed = ActivationReceipt(
        operation_id=raw["operation_id"],
        candidate_digest=raw["candidate_digest"],
        resulting_row_id=raw["resulting_row_id"],
        activation_token=raw["activation_token"],
        previous_active_row_id=raw["previous_active_row_id"],
        created=raw["created"],
        resulting_status=raw["resulting_status"],
        resulting_public_state_digest=raw["resulting_public_state_digest"],
    )
    if (
        parsed.operation_id != activation.operation_id
        or parsed.candidate_digest != candidate_digest
        or parsed.resulting_status != "active"
        or parsed.previous_active_row_id != activation.previous_active_row_id
    ):
        _reject("finalization_activation_receipt_mismatch")
    return parsed


# --------------------------------------------------------------------------- module helpers


def _transaction_id(plan: Any) -> str:
    return (
        "tx-"
        + hashlib.sha256(
            canonical_json(
                {
                    "installation_id": plan.controller_installation_id,
                    "release_digest": plan.release_digest,
                    "generation": int(plan.generation),
                }
            ).encode("utf-8")
        ).hexdigest()[:32]
    )


def _tls_paths(loc: Any) -> tuple[str, str, str]:
    return (
        loc.controller_ca_bundle_path(),
        loc.controller_server_cert_path(),
        loc.controller_server_key_path(),
    )


def _remove_created_key(ctx: FinalizationContext, path: str, expected_key_id: str) -> bool:
    """Remove a freshly-created 0600 root enrollment key ONLY after proving root posture AND that
    its
    derived public key id matches what we recorded — never touch a drifted/foreign key."""
    if path != _ENROLLMENT_KEY_PATH:
        return False
    try:
        st = ctx.host.fs.lstat(path)
        if st is None:
            return True
        if (
            st.is_symlink
            or not st.is_regular
            or st.uid != _ROOT_UID
            or st.mode != 0o600
            or st.nlink != 1
        ):
            return False
        raw = ctx.host.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=_ROOT_UID)
        if key_id_for(_ed25519_public_hex(raw)) != expected_key_id:
            return False  # a different key → not ours; leave it
        ctx.host.fs.remove_file(path)
        return ctx.host.fs.lstat(path) is None
    except Exception:  # noqa: BLE001 - a malformed/unreadable key is left untouched, not removed
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
    "ApiSignerRuntimeObservation",
    "ControllerFinalizationError",
    "FinalizationContext",
    "RealControllerEnrollmentFinalizationAdapter",
]
