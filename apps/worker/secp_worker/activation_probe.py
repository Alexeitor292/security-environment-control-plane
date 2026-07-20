"""Closed, worker-local production activation probe for SECP-B8.

The probe is deliberately narrower than a general diagnostics command.  Importing this module does
nothing.  Explicit execution accepts no arguments, reads no caller-selected path, submits no work,
and performs only bounded, read-only projections rooted at the configured worker discovery node.
Its JSON contract contains configuration posture, fixed-path facts, the process-local health marker,
the four reviewed safety seals, validated PUBLIC-key fingerprints, and closed later-lifecycle
facts bound to that exact node/key/organization.  It never emits an endpoint, raw environment,
certificate, database setting, private key, credential, or exception text.

This is intended to be executed *inside the ordinary worker* after container recreation.  It is not
an enrollment path and does not import or construct the operator worker.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import secp_api

import secp_worker

CONTRACT_VERSION = "secp.worker.activation-probe/v1"
ORDINARY_TASK_QUEUE = "secp-orchestration"

# Code-owned container paths rendered by the PR5F deployment package.  There is intentionally no
# path builder and none of these values can be supplied on the command line.
WORKER_STATE_PATH = "/var/run/secp"
WORKER_KEY_DIR = "/var/run/secp/worker-keys"
DISCOVERY_BUNDLE_PATH = "/var/run/secp/discovery-bundle"
WORKER_IDENTITY_KEY_PATH = "/var/run/secp/worker-keys/admission_key"
WORKER_IDENTITY_ANCHOR_PATH = "/var/run/secp/worker-keys/admission_anchor"
ADMISSION_CA_PATH = "/etc/secp/admission-ca.pem"
RUNTIME_OVERLAY_PATH = "/opt/secp/secp-pr5f-runtime-overlay.zip"
RUNTIME_OVERLAY_DIGEST_ENV = "SECP_DISCOVERY_RUNTIME_OVERLAY_SHA256"
HEALTH_MARKER_PATH = "/tmp/secp-worker.ready"  # noqa: S108 - existing worker tmpfs marker
BUNDLE_PREP_LOOP_MARKER_PATH = "/tmp/secp-discovery-bundle-prep.ready"  # noqa: S108

_NODE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_ANCHOR = re.compile(r"^[0-9a-f]{64}$")
_ANCHOR_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_REVISION = 2**31 - 1
_MAX_RUNTIME_OVERLAY_BYTES = 4 * 1024 * 1024
_RUNTIME_OVERLAY_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BOOTSTRAP_STATUSES = frozenset({"pending", "completed", "bound", "superseded", "refused"})


@dataclass(frozen=True, repr=False)
class PublicNodeRecord:
    """The exact, public-only projection selected from ``WorkerDiscoveryNode``."""

    id: object
    organization_id: object
    node_label: object
    ssh_public_key: object
    ssh_public_key_fingerprint: object
    admission_anchor_hex: object
    admission_anchor_fingerprint: object
    revision: object
    worker_identity_registration_id: object

    def __repr__(self) -> str:
        return "PublicNodeRecord(<public-only projection>)"


@dataclass(frozen=True, repr=False)
class LifecycleRecord:
    """Closed, secret-free lifecycle facts derived from the exact published node binding."""

    bootstrap_status: object
    worker_identity_approved: object
    worker_identity_current: object
    live_read_authorization_approved: object
    live_read_authorization_current: object
    bundle_available: object
    discovery_contacted: object
    candidate_executable: object

    def __repr__(self) -> str:
        return "LifecycleRecord(<closed public-only projection>)"


@dataclass(frozen=True, repr=False)
class LocalKeyRecord:
    """Fingerprint-only projection of the exact persisted worker keypairs."""

    ssh_public_key_fingerprint: object
    admission_anchor_fingerprint: object

    def __repr__(self) -> str:
        return "LocalKeyRecord(<fingerprints-only projection>)"


ReadinessReader = Callable[[], tuple[bool, str]]
SealReader = Callable[[], dict[str, bool]]
NodeReader = Callable[[uuid.UUID, str], PublicNodeRecord | None]
LifecycleReader = Callable[[uuid.UUID, PublicNodeRecord], LifecycleRecord]
KeyReader = Callable[[], LocalKeyRecord]
LoopStartedReader = Callable[[], bool]
RuntimeOverlayReader = Callable[[], str]


def _empty_lifecycle_payload() -> dict[str, object]:
    return {
        "bootstrap_status": None,
        "worker_identity_approved": False,
        "worker_identity_current": False,
        "live_read_authorization_approved": False,
        "live_read_authorization_current": False,
        "bundle_available": False,
        "discovery_contacted": False,
        "candidate_executable": None,
    }


def _base_payload() -> dict[str, Any]:
    """Return the complete, bounded response shape with closed defaults."""

    return {
        "contract_version": CONTRACT_VERSION,
        "ok": False,
        "reason_code": "probe_failed",
        "ordinary_task_queue": ORDINARY_TASK_QUEUE,
        "configuration": {
            "controlled_integration_enabled": False,
            "worker_managed_bundle": False,
            "fixed_paths_valid": False,
            "admission_configured": False,
            "runtime_overlay_loaded": False,
        },
        "fixed_paths": {
            "worker_state": WORKER_STATE_PATH,
            "worker_keys": WORKER_KEY_DIR,
            "discovery_bundle": DISCOVERY_BUNDLE_PATH,
            "worker_identity_key": WORKER_IDENTITY_KEY_PATH,
            "worker_identity_anchor": WORKER_IDENTITY_ANCHOR_PATH,
            "admission_ca": ADMISSION_CA_PATH,
            "runtime_overlay": RUNTIME_OVERLAY_PATH,
            "health_marker": HEALTH_MARKER_PATH,
        },
        "health": {
            "ready": False,
            "ordinary_queue": False,
            "bundle_prep_loop_started": False,
        },
        "worker_keys": {
            "metadata_safe": False,
            "public_node_matches_local_keys": False,
        },
        "safety_seals": {
            "generic_activation_subprocess_sealed": False,
            "generic_executor_subprocess_sealed": False,
            "plan_only_process_sealed": True,
            "real_provisioning_disabled": False,
        },
        "worker_node": None,
        "lifecycle": _empty_lifecycle_payload(),
        "runtime_overlay_sha256": None,
        # These are effects/registrations of this probe, not guesses about an external service.
        # They are immutable facts about this module's closed implementation.
        "probe_effects": {
            "operator_registered": False,
            "operator_queue_polled": False,
            "workflow_submitted": False,
            "run_plan_generation_called": False,
            "opentofu_executed": False,
            "proxmox_contacted": False,
        },
    }


def _closed(payload: dict[str, Any], reason_code: str) -> dict[str, Any]:
    """Set one allowlisted closed reason without ever carrying exception/configuration text."""

    payload["ok"] = False
    payload["reason_code"] = reason_code
    payload["worker_node"] = None
    payload["lifecycle"] = _empty_lifecycle_payload()
    payload["worker_keys"] = {
        "metadata_safe": False,
        "public_node_matches_local_keys": False,
    }
    payload["health"]["bundle_prep_loop_started"] = False
    return payload


def _default_readiness() -> tuple[bool, str]:
    """Read only the existing fixed worker marker; an env-redirected marker is refused."""

    from secp_worker import health

    # ``health`` supports a test/dev override.  A production activation observation must not follow
    # an arbitrary env path, so refuse it before ``readiness_status`` opens anything.
    if health.READY_FILE != HEALTH_MARKER_PATH or health._ready_path() != HEALTH_MARKER_PATH:
        return False, ""
    return health.readiness_status()


def _default_loop_started() -> bool:
    """Prove the bundle loop marker belongs to the exact live ordinary worker process instance."""

    from secp_worker import bundle_loop_marker, health

    if (
        health.READY_FILE != HEALTH_MARKER_PATH
        or health._ready_path() != HEALTH_MARKER_PATH
        or bundle_loop_marker.BUNDLE_PREP_LOOP_MARKER_PATH != BUNDLE_PREP_LOOP_MARKER_PATH
    ):
        return False
    worker_pid = health.readiness_process_id()
    if worker_pid is None:
        return False
    return bundle_loop_marker.is_current(expected_worker_pid=worker_pid)


def _default_seals() -> dict[str, bool]:
    """Read the four reviewed code constants without constructing an executor or operator."""

    from secp_api.routers import providers

    from secp_worker.plan_gen import process_boundary
    from secp_worker.provisioning import activation, process_executor

    return {
        "generic_activation_subprocess_sealed": activation._B1A_SUBPROCESS_SEALED,
        "generic_executor_subprocess_sealed": process_executor._B1A_SUBPROCESS_SEALED,
        "plan_only_process_sealed": process_boundary._PLAN_ONLY_PROCESS_SEALED,
        "real_provisioning_disabled": not providers.PROVISIONING_ENABLED,
    }


def _module_loaded_from_overlay(module: object, relative_path: str) -> bool:
    expected_origin = f"{RUNTIME_OVERLAY_PATH}/{relative_path}"
    loader = getattr(module, "__loader__", None)
    spec = getattr(module, "__spec__", None)
    return bool(
        getattr(module, "__file__", None) == expected_origin
        and getattr(spec, "origin", None) == expected_origin
        and type(loader).__name__ == "zipimporter"
        and getattr(loader, "archive", None) == RUNTIME_OVERLAY_PATH
    )


def _default_runtime_overlay_reader() -> str:
    """Bind the running packages to the exact read-only archive and its reviewed digest."""

    expected = os.environ.get(RUNTIME_OVERLAY_DIGEST_ENV)
    if (
        not isinstance(expected, str)
        or not _RUNTIME_OVERLAY_DIGEST.fullmatch(expected)
        or os.environ.get("PYTHONPATH") != RUNTIME_OVERLAY_PATH
    ):
        raise RuntimeError("runtime_overlay_configuration_invalid")
    fd = -1
    try:
        before = os.lstat(RUNTIME_OVERLAY_PATH)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) != 0o644
            or not 22 <= before.st_size <= _MAX_RUNTIME_OVERLAY_BYTES
        ):
            raise RuntimeError("runtime_overlay_metadata_invalid")
        fd = os.open(RUNTIME_OVERLAY_PATH, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("runtime_overlay_changed")
        chunks = bytearray()
        while len(chunks) <= _MAX_RUNTIME_OVERLAY_BYTES:
            chunk = os.read(fd, min(64 * 1024, _MAX_RUNTIME_OVERLAY_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(fd)
        if len(chunks) != before.st_size or (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise RuntimeError("runtime_overlay_changed")
    except OSError:
        raise RuntimeError("runtime_overlay_unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)
    actual = "sha256:" + hashlib.sha256(chunks).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise RuntimeError("runtime_overlay_digest_mismatch")

    this_module = sys.modules.get(__name__)
    if not (
        _module_loaded_from_overlay(secp_api, "secp_api/__init__.py")
        and _module_loaded_from_overlay(secp_worker, "secp_worker/__init__.py")
        and _module_loaded_from_overlay(this_module, "secp_worker/activation_probe.py")
        and tuple(str(path) for path in getattr(secp_api, "__path__", ()))
        == (f"{RUNTIME_OVERLAY_PATH}/secp_api",)
        and tuple(str(path) for path in getattr(secp_worker, "__path__", ()))
        == (f"{RUNTIME_OVERLAY_PATH}/secp_worker",)
    ):
        raise RuntimeError("runtime_overlay_origin_invalid")
    return actual


def _default_key_reader() -> LocalKeyRecord:
    """Validate both persisted keypairs and retain only their public fingerprints."""

    from secp_api.discovery_bootstrap_contract import validate_public_ssh_key

    from secp_worker.bundle_manager import inspect_worker_keys

    material = inspect_worker_keys(WORKER_KEY_DIR)
    _normalized, ssh_fingerprint = validate_public_ssh_key(material.ssh_public_key)
    return LocalKeyRecord(
        ssh_public_key_fingerprint=ssh_fingerprint,
        admission_anchor_fingerprint=material.admission_anchor_fingerprint,
    )


def _default_node_reader(organization_id: uuid.UUID, node_label: str) -> PublicNodeRecord | None:
    """Select only the exact public columns for the configured organization and label.

    No ORM object or unrelated database column is loaded.  The session is never committed; close
    rolls back the read transaction on both SQLite and PostgreSQL.
    """

    from secp_api.db import get_sessionmaker
    from secp_api.models import WorkerDiscoveryNode
    from sqlalchemy import select

    statement = (
        select(
            WorkerDiscoveryNode.id,
            WorkerDiscoveryNode.organization_id,
            WorkerDiscoveryNode.node_label,
            WorkerDiscoveryNode.ssh_public_key,
            WorkerDiscoveryNode.ssh_public_key_fingerprint,
            WorkerDiscoveryNode.admission_anchor_hex,
            WorkerDiscoveryNode.admission_anchor_fingerprint,
            WorkerDiscoveryNode.revision,
            WorkerDiscoveryNode.worker_identity_registration_id,
        )
        .where(
            WorkerDiscoveryNode.organization_id == organization_id,
            WorkerDiscoveryNode.node_label == node_label,
        )
        .limit(2)
    )
    factory = get_sessionmaker()
    with factory() as session:
        rows = list(session.execute(statement).all())
        session.rollback()
    if not rows:
        return None
    if len(rows) != 1:
        raise RuntimeError("worker_node_cardinality_invalid")
    return PublicNodeRecord(*rows[0])


def _future_datetime(value: object, *, now: datetime) -> bool:
    if not isinstance(value, datetime):
        return False
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware > now


def _default_lifecycle_reader(
    organization_id: uuid.UUID, node: PublicNodeRecord
) -> LifecycleRecord:
    """Read the closed later-lifecycle projection for one exact published node.

    Every query is organization-scoped, column-only, and bounded.  The bootstrap lookup matches
    both PUBLIC worker keys; all later records must bind that bootstrap's target/onboarding and the
    node's exact linked identity.  No ORM entity, target configuration, endpoint, certificate,
    credential, evidence JSON, or raw plan document is loaded or returned.
    """

    from secp_api.db import get_sessionmaker
    from secp_api.enums import (
        DiscoveryContactState,
        LiveReadAuthorizationStatus,
        ProxmoxBootstrapStatus,
        WorkerDiscoveryAdmissionStatus,
        WorkerIdentityMechanism,
        WorkerIdentityStatus,
    )
    from secp_api.models import (
        DiscoveryCandidatePlan,
        DiscoverySnapshot,
        LiveReadAuthorization,
        ProxmoxReadOnlyBootstrapSession,
        TargetDiscoveryEnrollment,
        WorkerDiscoveryAdmission,
        WorkerDiscoveryNode,
        WorkerIdentityRegistration,
    )
    from secp_api.worker_admission_contract import WORKER_ADMISSION_PURPOSE
    from sqlalchemy import select

    try:
        node_id = uuid.UUID(str(node.id))
    except (ValueError, AttributeError):
        raise RuntimeError("worker_node_binding_invalid") from None
    linked_registration_id: uuid.UUID | None = None
    if node.worker_identity_registration_id is not None:
        try:
            linked_registration_id = uuid.UUID(str(node.worker_identity_registration_id))
        except (ValueError, AttributeError):
            raise RuntimeError("worker_identity_binding_invalid") from None

    bootstrap_status: object = None
    identity_approved = False
    identity_current = False
    authorization_approved = False
    authorization_current = False
    bundle_available = False
    discovery_contacted = False
    candidate_executable: object = None
    identity_version: int | None = None
    now = datetime.now(UTC)

    factory = get_sessionmaker()
    with factory() as session:
        # Re-pin the public node before following any lifecycle relation.  A rotated key clears the
        # identity link in the publication service, so an old registration/snapshot cannot be
        # attributed to a newly published key.
        exact_node_rows = list(
            session.execute(
                select(WorkerDiscoveryNode.id)
                .where(
                    WorkerDiscoveryNode.id == node_id,
                    WorkerDiscoveryNode.organization_id == organization_id,
                    WorkerDiscoveryNode.node_label == node.node_label,
                    WorkerDiscoveryNode.ssh_public_key == node.ssh_public_key,
                    WorkerDiscoveryNode.ssh_public_key_fingerprint
                    == node.ssh_public_key_fingerprint,
                    WorkerDiscoveryNode.admission_anchor_hex == node.admission_anchor_hex,
                    WorkerDiscoveryNode.admission_anchor_fingerprint
                    == node.admission_anchor_fingerprint,
                    WorkerDiscoveryNode.revision == node.revision,
                    WorkerDiscoveryNode.worker_identity_registration_id == linked_registration_id,
                )
                .limit(2)
            ).all()
        )
        if len(exact_node_rows) != 1:
            raise RuntimeError("worker_node_changed")

        identity_exact = False
        if linked_registration_id is not None:
            identity_rows = list(
                session.execute(
                    select(
                        WorkerIdentityRegistration.mechanism,
                        WorkerIdentityRegistration.verification_anchor_fingerprint,
                        WorkerIdentityRegistration.identity_version,
                        WorkerIdentityRegistration.expiry,
                        WorkerIdentityRegistration.status,
                    )
                    .where(
                        WorkerIdentityRegistration.id == linked_registration_id,
                        WorkerIdentityRegistration.organization_id == organization_id,
                    )
                    .limit(2)
                ).all()
            )
            if len(identity_rows) == 1:
                mechanism, anchor_fingerprint, raw_version, expiry, identity_status = identity_rows[
                    0
                ]
                identity_exact = bool(
                    mechanism == WorkerIdentityMechanism.ed25519_signed_nonce
                    and anchor_fingerprint == node.admission_anchor_fingerprint
                    and type(raw_version) is int
                    and 1 <= raw_version <= _MAX_REVISION
                )
                if identity_exact:
                    identity_version = raw_version
                    identity_approved = identity_status == WorkerIdentityStatus.approved
                    approved_ids = list(
                        session.execute(
                            select(WorkerIdentityRegistration.id)
                            .where(
                                WorkerIdentityRegistration.organization_id == organization_id,
                                WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
                                WorkerIdentityRegistration.mechanism
                                == WorkerIdentityMechanism.ed25519_signed_nonce,
                            )
                            .order_by(WorkerIdentityRegistration.id)
                            .limit(2)
                        ).scalars()
                    )
                    identity_current = bool(
                        identity_approved
                        and _future_datetime(expiry, now=now)
                        and approved_ids == [linked_registration_id]
                    )

        bootstrap_row = session.execute(
            select(
                ProxmoxReadOnlyBootstrapSession.status,
                ProxmoxReadOnlyBootstrapSession.execution_target_id,
                ProxmoxReadOnlyBootstrapSession.onboarding_id,
                ProxmoxReadOnlyBootstrapSession.endpoint_binding_hash,
                ProxmoxReadOnlyBootstrapSession.live_read_authorization_id,
                ProxmoxReadOnlyBootstrapSession.authorization_version,
            )
            .where(
                ProxmoxReadOnlyBootstrapSession.organization_id == organization_id,
                ProxmoxReadOnlyBootstrapSession.worker_ssh_public_key == node.ssh_public_key,
                ProxmoxReadOnlyBootstrapSession.worker_ssh_public_key_fingerprint
                == node.ssh_public_key_fingerprint,
            )
            .order_by(
                ProxmoxReadOnlyBootstrapSession.created_at.desc(),
                ProxmoxReadOnlyBootstrapSession.id.desc(),
            )
            .limit(1)
        ).first()

        if bootstrap_row is not None:
            (
                raw_bootstrap_status,
                execution_target_id,
                onboarding_id,
                endpoint_binding_hash,
                raw_authorization_id,
                raw_authorization_version,
            ) = bootstrap_row
            bootstrap_status = (
                raw_bootstrap_status.value
                if isinstance(raw_bootstrap_status, ProxmoxBootstrapStatus)
                else raw_bootstrap_status
            )

            authorization_id: uuid.UUID | None = None
            if raw_authorization_id is not None:
                try:
                    authorization_id = uuid.UUID(str(raw_authorization_id))
                except (ValueError, AttributeError):
                    authorization_id = None
            try:
                target_id = uuid.UUID(str(execution_target_id))
                onboarding_uuid = uuid.UUID(str(onboarding_id))
            except (ValueError, AttributeError):
                target_id = None
                onboarding_uuid = None

            binding_complete = bool(
                bootstrap_status == "bound"
                and target_id is not None
                and onboarding_uuid is not None
                and authorization_id is not None
                and type(raw_authorization_version) is int
                and 1 <= raw_authorization_version <= _MAX_REVISION
                and isinstance(endpoint_binding_hash, str)
                and _ANCHOR_FINGERPRINT.fullmatch(endpoint_binding_hash)
            )
            authorization_exact = False
            if binding_complete:
                authorization_rows = list(
                    session.execute(
                        select(
                            LiveReadAuthorization.status,
                            LiveReadAuthorization.authorization_expiry,
                        )
                        .where(
                            LiveReadAuthorization.id == authorization_id,
                            LiveReadAuthorization.organization_id == organization_id,
                            LiveReadAuthorization.execution_target_id == target_id,
                            LiveReadAuthorization.onboarding_id == onboarding_uuid,
                            LiveReadAuthorization.authorization_version
                            == raw_authorization_version,
                            LiveReadAuthorization.endpoint_binding_hash == endpoint_binding_hash,
                        )
                        .limit(2)
                    ).all()
                )
                if len(authorization_rows) == 1:
                    authorization_status, authorization_expiry = authorization_rows[0]
                    authorization_exact = True
                    authorization_approved = (
                        authorization_status == LiveReadAuthorizationStatus.approved
                    )
                    authorization_current = bool(
                        authorization_approved and _future_datetime(authorization_expiry, now=now)
                    )

            if (
                binding_complete
                and authorization_exact
                and identity_exact
                and linked_registration_id is not None
                and identity_version is not None
                and target_id is not None
                and onboarding_uuid is not None
                and authorization_id is not None
                and type(raw_authorization_version) is int
                and isinstance(endpoint_binding_hash, str)
            ):
                enrollment_row = session.execute(
                    select(
                        TargetDiscoveryEnrollment.id,
                        TargetDiscoveryEnrollment.enrollment_version,
                    )
                    .where(
                        TargetDiscoveryEnrollment.organization_id == organization_id,
                        TargetDiscoveryEnrollment.execution_target_id == target_id,
                        TargetDiscoveryEnrollment.onboarding_id == onboarding_uuid,
                    )
                    .order_by(
                        TargetDiscoveryEnrollment.created_at.desc(),
                        TargetDiscoveryEnrollment.id.desc(),
                    )
                    .limit(1)
                ).first()
                if enrollment_row is not None:
                    enrollment_id, enrollment_version = enrollment_row
                    snapshot_row = session.execute(
                        select(
                            DiscoverySnapshot.id,
                            DiscoverySnapshot.job_id,
                            DiscoverySnapshot.enrollment_version,
                            DiscoverySnapshot.evidence_hash,
                            DiscoverySnapshot.capacity_snapshot_hash,
                            DiscoverySnapshot.worker_identity_version,
                            DiscoverySnapshot.bundle_available,
                            DiscoverySnapshot.contact_state,
                        )
                        .where(
                            DiscoverySnapshot.organization_id == organization_id,
                            DiscoverySnapshot.enrollment_id == enrollment_id,
                        )
                        .order_by(
                            DiscoverySnapshot.created_at.desc(),
                            DiscoverySnapshot.id.desc(),
                        )
                        .limit(1)
                    ).first()
                    if snapshot_row is not None:
                        (
                            snapshot_id,
                            discovery_job_id,
                            snapshot_enrollment_version,
                            evidence_hash,
                            capacity_snapshot_hash,
                            snapshot_identity_version,
                            raw_bundle_available,
                            raw_contact_state,
                        ) = snapshot_row
                        snapshot_current = bool(
                            type(enrollment_version) is int
                            and type(snapshot_enrollment_version) is int
                            and enrollment_version == snapshot_enrollment_version
                            and type(snapshot_identity_version) is int
                            and snapshot_identity_version == identity_version
                            and type(raw_bundle_available) is bool
                        )
                        admission_bound = False
                        if snapshot_current:
                            admission_rows = list(
                                session.execute(
                                    select(WorkerDiscoveryAdmission.status)
                                    .where(
                                        WorkerDiscoveryAdmission.organization_id == organization_id,
                                        WorkerDiscoveryAdmission.worker_registration_id
                                        == linked_registration_id,
                                        WorkerDiscoveryAdmission.identity_version
                                        == identity_version,
                                        WorkerDiscoveryAdmission.discovery_job_id
                                        == discovery_job_id,
                                        WorkerDiscoveryAdmission.enrollment_id == enrollment_id,
                                        WorkerDiscoveryAdmission.execution_target_id == target_id,
                                        WorkerDiscoveryAdmission.onboarding_id == onboarding_uuid,
                                        WorkerDiscoveryAdmission.live_read_authorization_id
                                        == authorization_id,
                                        WorkerDiscoveryAdmission.authorization_version
                                        == raw_authorization_version,
                                        WorkerDiscoveryAdmission.endpoint_binding_hash
                                        == endpoint_binding_hash,
                                        WorkerDiscoveryAdmission.purpose
                                        == WORKER_ADMISSION_PURPOSE,
                                        WorkerDiscoveryAdmission.status.in_(
                                            (
                                                WorkerDiscoveryAdmissionStatus.admitted,
                                                WorkerDiscoveryAdmissionStatus.consumed,
                                            )
                                        ),
                                    )
                                    .limit(2)
                                ).all()
                            )
                            admission_bound = len(admission_rows) == 1
                        if snapshot_current and admission_bound:
                            contact_state = (
                                raw_contact_state.value
                                if isinstance(raw_contact_state, DiscoveryContactState)
                                else raw_contact_state
                            )
                            if not isinstance(contact_state, str):
                                raise RuntimeError("snapshot_contact_state_invalid")
                            bundle_available = raw_bundle_available
                            discovery_contacted = bool(
                                bundle_available and contact_state == "contacted"
                            )

                            document = DiscoveryCandidatePlan.plan_document
                            candidate_rows = list(
                                session.execute(
                                    select(
                                        DiscoveryCandidatePlan.worker_identity_version,
                                        DiscoveryCandidatePlan.enrollment_version,
                                        DiscoveryCandidatePlan.evidence_hash,
                                        DiscoveryCandidatePlan.capacity_snapshot_hash,
                                        document["organization_id"].as_string(),
                                        document["enrollment_id"].as_string(),
                                        document["worker_registration_id"].as_string(),
                                        document["worker_identity_version"].as_integer(),
                                        document["executable"].as_boolean(),
                                    )
                                    .where(
                                        DiscoveryCandidatePlan.organization_id == organization_id,
                                        DiscoveryCandidatePlan.enrollment_id == enrollment_id,
                                        DiscoveryCandidatePlan.snapshot_id == snapshot_id,
                                    )
                                    .limit(2)
                                ).all()
                            )
                            if len(candidate_rows) > 1:
                                raise RuntimeError("candidate_cardinality_invalid")
                            if candidate_rows:
                                (
                                    plan_identity_version,
                                    plan_enrollment_version,
                                    plan_evidence_hash,
                                    plan_capacity_hash,
                                    plan_organization_id,
                                    plan_enrollment_id,
                                    plan_registration_id,
                                    document_identity_version,
                                    raw_executable,
                                ) = candidate_rows[0]
                                if not (
                                    type(plan_identity_version) is int
                                    and plan_identity_version == identity_version
                                    and type(plan_enrollment_version) is int
                                    and plan_enrollment_version == snapshot_enrollment_version
                                    and plan_evidence_hash == evidence_hash
                                    and plan_capacity_hash == capacity_snapshot_hash
                                    and plan_organization_id == str(organization_id)
                                    and plan_enrollment_id == str(enrollment_id)
                                    and plan_registration_id == str(linked_registration_id)
                                    and type(document_identity_version) is int
                                    and document_identity_version == identity_version
                                    and type(raw_executable) is bool
                                ):
                                    raise RuntimeError("candidate_binding_invalid")
                                candidate_executable = raw_executable
        session.rollback()

    return LifecycleRecord(
        bootstrap_status=bootstrap_status,
        worker_identity_approved=identity_approved,
        worker_identity_current=identity_current,
        live_read_authorization_approved=authorization_approved,
        live_read_authorization_current=authorization_current,
        bundle_available=bundle_available,
        discovery_contacted=discovery_contacted,
        candidate_executable=candidate_executable,
    )


def _configuration(settings: object, payload: dict[str, Any]) -> tuple[uuid.UUID, str] | None:
    """Validate production activation settings while emitting only booleans and fixed paths."""

    controlled = getattr(settings, "discovery_controlled_integration_enabled", None) is True
    managed = getattr(settings, "discovery_worker_managed_bundle", None) is True
    configuration = payload["configuration"]
    configuration["controlled_integration_enabled"] = controlled
    configuration["worker_managed_bundle"] = managed
    if not controlled or not managed:
        _closed(payload, "activation_disabled")
        return None

    expected_paths = (
        ("discovery_worker_key_dir", WORKER_KEY_DIR),
        ("discovery_bootstrap_mount", DISCOVERY_BUNDLE_PATH),
        ("discovery_worker_identity_key", WORKER_IDENTITY_KEY_PATH),
        ("discovery_worker_identity_anchor", WORKER_IDENTITY_ANCHOR_PATH),
        ("discovery_admission_ca", ADMISSION_CA_PATH),
    )
    fixed_paths_valid = all(
        getattr(settings, name, None) == expected for name, expected in expected_paths
    )
    configuration["fixed_paths_valid"] = fixed_paths_valid
    if not fixed_paths_valid:
        _closed(payload, "fixed_path_configuration_invalid")
        return None

    if getattr(settings, "temporal_task_queue", None) != ORDINARY_TASK_QUEUE:
        _closed(payload, "ordinary_queue_configuration_invalid")
        return None

    # Reuse the hardened client's pure parser.  It validates HTTPS, authority, port, path, query,
    # fragment, and userinfo without resolving or contacting the endpoint.  Never emit its value.
    endpoint = getattr(settings, "discovery_admission_endpoint", None)
    if not isinstance(endpoint, str):
        _closed(payload, "admission_configuration_invalid")
        return None
    try:
        from secp_worker.admission_http_transport import _validate_admission_endpoint

        _validate_admission_endpoint(endpoint)
    except Exception:
        _closed(payload, "admission_configuration_invalid")
        return None
    configuration["admission_configured"] = True

    raw_org = getattr(settings, "discovery_worker_node_organization", None)
    label = getattr(settings, "discovery_worker_node_label", None)
    try:
        organization_id = uuid.UUID(raw_org) if isinstance(raw_org, str) else None
    except (ValueError, AttributeError):
        organization_id = None
    if (
        organization_id is None
        or raw_org != str(organization_id)
        or not isinstance(label, str)
        or not _NODE_LABEL.fullmatch(label)
    ):
        _closed(payload, "worker_node_binding_invalid")
        return None
    return organization_id, label


def _validated_seals(raw: object) -> dict[str, bool] | None:
    expected = {
        "generic_activation_subprocess_sealed": True,
        "generic_executor_subprocess_sealed": True,
        "plan_only_process_sealed": False,
        "real_provisioning_disabled": True,
    }
    if not isinstance(raw, dict) or set(raw) != set(expected):
        return None
    if any(type(raw[key]) is not bool for key in expected):
        return None
    return raw if raw == expected else None


def _public_node_payload(
    row: PublicNodeRecord, *, organization_id: uuid.UUID, node_label: str
) -> dict[str, object] | None:
    """Validate exact public material and return fingerprints only."""

    from secp_api.discovery_bootstrap_contract import validate_public_ssh_key
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

    try:
        node_id = uuid.UUID(str(row.id))
        row_org = uuid.UUID(str(row.organization_id))
    except (ValueError, AttributeError):
        return None
    if row_org != organization_id or row.node_label != node_label:
        return None
    if type(row.revision) is not int or not (1 <= row.revision <= _MAX_REVISION):
        return None
    if not isinstance(row.ssh_public_key, str) or not isinstance(row.admission_anchor_hex, str):
        return None
    try:
        normalized, computed_ssh = validate_public_ssh_key(row.ssh_public_key)
    except Exception:
        return None
    # The B8 manager emits one exact Ed25519 public line with a fixed non-sensitive comment.  Do
    # not accept a free-form comment as "public material": an otherwise-valid key comment could be
    # abused to place credentials or endpoint text in this row.
    ssh_parts = normalized.split(" ")
    if len(ssh_parts) != 3 or ssh_parts[0] != "ssh-ed25519" or ssh_parts[2] != "secp-worker":
        return None
    anchor = row.admission_anchor_hex
    if not _ANCHOR.fullmatch(anchor):
        return None
    computed_anchor = compute_verification_anchor_fingerprint(anchor)
    if (
        not isinstance(row.ssh_public_key_fingerprint, str)
        or not _SSH_FINGERPRINT.fullmatch(row.ssh_public_key_fingerprint)
        or row.ssh_public_key_fingerprint != computed_ssh
        or not isinstance(row.admission_anchor_fingerprint, str)
        or not _ANCHOR_FINGERPRINT.fullmatch(row.admission_anchor_fingerprint)
        or row.admission_anchor_fingerprint != computed_anchor
    ):
        return None
    return {
        "id": str(node_id),
        "revision": row.revision,
        "ssh_public_key_fingerprint": computed_ssh,
        "admission_anchor_fingerprint": computed_anchor,
        "public_material_only": True,
    }


def _lifecycle_payload(row: object) -> dict[str, object] | None:
    """Validate the exact closed lifecycle schema and its monotonic implications."""

    if not isinstance(row, LifecycleRecord):
        return None
    status = row.bootstrap_status
    if status is not None and (not isinstance(status, str) or status not in _BOOTSTRAP_STATUSES):
        return None
    boolean_fields = (
        row.worker_identity_approved,
        row.worker_identity_current,
        row.live_read_authorization_approved,
        row.live_read_authorization_current,
        row.bundle_available,
        row.discovery_contacted,
    )
    if any(type(value) is not bool for value in boolean_fields):
        return None
    if row.candidate_executable is not None and type(row.candidate_executable) is not bool:
        return None
    if row.worker_identity_current and not row.worker_identity_approved:
        return None
    if row.live_read_authorization_current and not row.live_read_authorization_approved:
        return None
    if status != "bound" and (
        row.live_read_authorization_approved
        or row.live_read_authorization_current
        or row.bundle_available
        or row.discovery_contacted
        or row.candidate_executable is not None
    ):
        return None
    if row.discovery_contacted and not row.bundle_available:
        return None
    if row.candidate_executable is not None and not row.discovery_contacted:
        return None
    return {
        "bootstrap_status": status,
        "worker_identity_approved": row.worker_identity_approved,
        "worker_identity_current": row.worker_identity_current,
        "live_read_authorization_approved": row.live_read_authorization_approved,
        "live_read_authorization_current": row.live_read_authorization_current,
        "bundle_available": row.bundle_available,
        "discovery_contacted": row.discovery_contacted,
        "candidate_executable": row.candidate_executable,
    }


def run_probe(
    *,
    settings: object | None = None,
    readiness_reader: ReadinessReader | None = None,
    seal_reader: SealReader | None = None,
    node_reader: NodeReader | None = None,
    lifecycle_reader: LifecycleReader | None = None,
    key_reader: KeyReader | None = None,
    loop_started_reader: LoopStartedReader | None = None,
    runtime_overlay_reader: RuntimeOverlayReader | None = None,
) -> dict[str, Any]:
    """Execute the closed worker-local probe.

    The injectable readers are typed test seams, not deployment configuration.  None accepts a
    path, command, endpoint, or arbitrary query.
    """

    payload = _base_payload()
    try:
        if settings is None:
            from secp_api.config import get_settings

            settings = get_settings()
        binding = _configuration(settings, payload)
        if binding is None:
            # A pre-activation host inspection still has to prove which queue the existing
            # ordinary worker is actually serving before any recreation is permitted.  Reading
            # the process-local readiness marker is side-effect free and does not construct a
            # Temporal client.  Keep every other probe (seals/database/key material) inert while
            # activation is disabled.
            if payload["reason_code"] == "activation_disabled":
                readiness = (readiness_reader or _default_readiness)()
                if (
                    isinstance(readiness, tuple)
                    and len(readiness) == 2
                    and type(readiness[0]) is bool
                    and isinstance(readiness[1], str)
                ):
                    payload["health"] = {
                        "ready": readiness[0],
                        "ordinary_queue": readiness[1] == ORDINARY_TASK_QUEUE,
                        "bundle_prep_loop_started": False,
                    }
                # These are immutable process-local code seals.  They neither construct the
                # operator/executor nor contact a service, and preflight must prove them before it
                # is allowed to enable B8.
                seals = _validated_seals((seal_reader or _default_seals)())
                if seals is not None:
                    payload["safety_seals"] = seals
            return payload

        readiness = (readiness_reader or _default_readiness)()
        if (
            not isinstance(readiness, tuple)
            or len(readiness) != 2
            or type(readiness[0]) is not bool
            or not isinstance(readiness[1], str)
        ):
            return _closed(payload, "health_observation_invalid")
        ready, health_queue = readiness
        payload["health"] = {
            "ready": ready,
            "ordinary_queue": health_queue == ORDINARY_TASK_QUEUE,
            "bundle_prep_loop_started": False,
        }
        if not ready or health_queue != ORDINARY_TASK_QUEUE:
            return _closed(payload, "ordinary_worker_not_ready")

        seals = _validated_seals((seal_reader or _default_seals)())
        if seals is None:
            return _closed(payload, "safety_seal_drift")
        payload["safety_seals"] = seals

        try:
            overlay_digest = (runtime_overlay_reader or _default_runtime_overlay_reader)()
        except Exception:
            return _closed(payload, "runtime_overlay_unverified")
        if not isinstance(overlay_digest, str) or not _RUNTIME_OVERLAY_DIGEST.fullmatch(
            overlay_digest
        ):
            return _closed(payload, "runtime_overlay_unverified")
        payload["configuration"]["runtime_overlay_loaded"] = True
        payload["runtime_overlay_sha256"] = overlay_digest

        loop_started = (loop_started_reader or _default_loop_started)()
        if type(loop_started) is not bool:
            return _closed(payload, "bundle_prep_loop_observation_invalid")
        if not loop_started:
            return _closed(payload, "bundle_prep_loop_not_started")
        payload["health"]["bundle_prep_loop_started"] = True

        organization_id, label = binding
        try:
            row = (node_reader or _default_node_reader)(organization_id, label)
        except Exception:
            return _closed(payload, "worker_node_query_failed")
        if row is None:
            return _closed(payload, "worker_node_missing")
        node = _public_node_payload(row, organization_id=organization_id, node_label=label)
        if node is None:
            return _closed(payload, "worker_node_public_material_invalid")
        payload["worker_node"] = node
        try:
            local_keys = (key_reader or _default_key_reader)()
        except Exception:
            return _closed(payload, "worker_key_observation_failed")
        if (
            type(local_keys) is not LocalKeyRecord
            or not isinstance(local_keys.ssh_public_key_fingerprint, str)
            or not _SSH_FINGERPRINT.fullmatch(local_keys.ssh_public_key_fingerprint)
            or not isinstance(local_keys.admission_anchor_fingerprint, str)
            or not _ANCHOR_FINGERPRINT.fullmatch(local_keys.admission_anchor_fingerprint)
        ):
            return _closed(payload, "worker_key_observation_invalid")
        if (
            local_keys.ssh_public_key_fingerprint != node["ssh_public_key_fingerprint"]
            or local_keys.admission_anchor_fingerprint != node["admission_anchor_fingerprint"]
        ):
            return _closed(payload, "worker_publication_key_mismatch")
        payload["worker_keys"] = {
            "metadata_safe": True,
            "public_node_matches_local_keys": True,
        }
        try:
            lifecycle_row = (lifecycle_reader or _default_lifecycle_reader)(organization_id, row)
        except Exception:
            return _closed(payload, "worker_lifecycle_query_failed")
        lifecycle = _lifecycle_payload(lifecycle_row)
        if lifecycle is None:
            return _closed(payload, "worker_lifecycle_observation_invalid")
        payload["lifecycle"] = lifecycle
        payload["ok"] = True
        payload["reason_code"] = "ok"
        return payload
    except Exception:
        # Settings/import/validation failures can contain credentials, endpoints, or paths in their
        # messages.  Collapse all unexpected failures to one fixed code and suppress the chain.
        return _closed(payload, "probe_failed")


def _json_bytes(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    # The response shape is fixed and contains no unbounded values.  Keep a final structural guard
    # so future changes cannot silently turn the exec probe into a bulk-output surface.
    if len(encoded) > 4096:  # pragma: no cover - unreachable with the closed schema
        return (
            b'{"contract_version":"secp.worker.activation-probe/v1","ok":false,'
            b'"reason_code":"probe_output_invalid"}'
        )
    return encoded


def _main(argv: list[str]) -> int:
    payload = _closed(_base_payload(), "arguments_forbidden") if argv else run_probe()
    import sys

    sys.stdout.buffer.write(_json_bytes(payload) + b"\n")
    return 0 if payload["ok"] is True else 1


if __name__ == "__main__":  # pragma: no cover - exercised through focused subprocess tests
    import sys

    raise SystemExit(_main(sys.argv[1:]))


__all__ = [
    "ADMISSION_CA_PATH",
    "CONTRACT_VERSION",
    "DISCOVERY_BUNDLE_PATH",
    "HEALTH_MARKER_PATH",
    "LifecycleRecord",
    "ORDINARY_TASK_QUEUE",
    "PublicNodeRecord",
    "RUNTIME_OVERLAY_DIGEST_ENV",
    "RUNTIME_OVERLAY_PATH",
    "WORKER_IDENTITY_ANCHOR_PATH",
    "WORKER_IDENTITY_KEY_PATH",
    "WORKER_KEY_DIR",
    "WORKER_STATE_PATH",
    "run_probe",
]
