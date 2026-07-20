"""SECP-B8 — worker-owned discovery bundle preparation runtime.

Worker process ONLY. When the deployment-local ``discovery_worker_managed_bundle`` profile is
enabled, this closes the first-time product flow so the ONLY host-side manual action is running the
app-generated Proxmox bootstrap script. Each tick it:

  1. ensures the worker OWNS its SSH + Ed25519 admission keypairs under ``discovery_worker_key_dir``
     (generate-if-missing; the private halves NEVER leave the worker filesystem);
  2. publishes ONLY the PUBLIC material (SSH public key + Ed25519 anchor) to the control plane so
     the bootstrap wizard can auto-populate the "Worker SSH public key" field — the operator never
     runs ``ssh-keygen``;
  3. for every enrollment whose bootstrap is completed + bound AND whose host public key was
     captured at completion, assembles the mounted bundle at ``discovery_bootstrap_mount`` from the
     control plane's SECRET-FREE bundle descriptor (``bundle_manager.write_bundle``).

It contacts NO Proxmox host and runs NO probe — it composes local files from non-secret control
plane state (read from the shared control-plane store). It uploads/transmits NO private key. It
fails closed (logs a closed reason code) on any problem and never blocks worker startup. The mounted
bundle it writes is still independently re-validated by the strict :class:`MountedWorkerBootstrap
BundleSource` and gated by control-plane admission + endpoint binding before any ssh — a bundle
written here grants nothing on its own.
"""

from __future__ import annotations

import logging
import threading
from inspect import signature

logger = logging.getLogger("secp.worker.discovery.bundle")


class BundlePreparationRefused(Exception):
    """Closed worker-preparation refusal. It never carries a configured value or key material."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _configured_org(settings):
    import uuid

    raw = (getattr(settings, "discovery_worker_node_organization", "") or "").strip()
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        # A malformed explicit tenant binding must never degrade to single-organization
        # auto-detection. That would publish the node into an organization the deployment did not
        # actually configure.
        raise BundlePreparationRefused("worker_node_organization_invalid") from None


def _ensure_and_publish_keys(settings, session_scope) -> str:
    """Ensure/publish worker-owned keys and return the freshly validated PUBLIC SSH fingerprint."""
    from secp_worker import bundle_manager

    configured_org = _configured_org(settings)
    key_dir = getattr(settings, "discovery_worker_key_dir", "")
    material = bundle_manager.ensure_worker_keys(
        key_dir
    )  # generate-if-missing; returns PUBLIC only
    from secp_api.discovery_bootstrap_contract import (
        BootstrapContractError,
        validate_public_ssh_key,
    )

    try:
        _normalized_ssh_key, ssh_public_key_fingerprint = validate_public_ssh_key(
            material.ssh_public_key
        )
    except BootstrapContractError:
        raise BundlePreparationRefused("worker_ssh_public_key_invalid") from None

    from secp_api.services import worker_nodes

    node_label = getattr(settings, "discovery_worker_node_label", "default-worker")
    with session_scope() as session:
        org_ids = worker_nodes.resolve_publication_organizations(session, configured_org)
        if not org_ids:
            logger.info(
                "worker public key generated but not published: set "
                "discovery_worker_node_organization (multiple/zero organizations present)"
            )
            return ssh_public_key_fingerprint
        for org_id in org_ids:
            worker_nodes.publish_worker_node(
                session,
                organization_id=org_id,
                node_label=node_label,
                ssh_public_key=material.ssh_public_key,
                admission_anchor_hex=material.admission_anchor_hex,
            )
    logger.info(
        "published worker discovery node public key (fingerprint pinned) to %d organization(s)",
        len(org_ids),
    )
    return ssh_public_key_fingerprint


def _write_ready_bundles(
    settings,
    session_scope,
    *,
    worker_ssh_public_key_fingerprint: str,
) -> int:
    """Assemble the mounted bundle for every ready enrollment from the secret-free descriptor.

    Returns the number of bundles written. In the common single-target deployment there is exactly
    one ready descriptor -> one bundle at the fixed mount path."""
    from secp_worker import bundle_manager

    key_dir = getattr(settings, "discovery_worker_key_dir", "")
    mount_path = getattr(settings, "discovery_bootstrap_mount", "")
    ssh_key_path = bundle_manager.worker_ssh_private_key_path(key_dir)

    from secp_api.services import bootstrap_discovery, worker_nodes

    with session_scope() as session:
        organization_ids = worker_nodes.resolve_publication_organizations(
            session, _configured_org(settings)
        )
        if len(organization_ids) != 1:
            logger.error("worker bundle assembly refused (closed): worker_organization_ambiguous")
            return 0
        descriptors = _resolve_ready_bundle_descriptors(
            bootstrap_discovery.resolve_ready_bundle_descriptors,
            session,
            organization_ids[0],
        )

    if not descriptors:
        return 0
    if any(
        descriptor.get("worker_ssh_public_key_fingerprint") != worker_ssh_public_key_fingerprint
        for descriptor in descriptors
    ):
        # A bound session for a prior worker key is not authority for this worker's private key.
        # Keep the fixed mount untouched until the operator runs the existing bootstrap script
        # with the freshly published public key and binds that new session.
        logger.error("worker bundle assembly refused (closed): worker_ssh_binding_mismatch")
        return 0
    if len(descriptors) > 1:
        # A single fixed mount can represent exactly one enrollment. Query order is not authority:
        # choosing "the first" could retain or install a stale target binding. Refuse without
        # touching the current bundle until the control-plane state is unambiguous.
        logger.error("worker bundle assembly refused (closed): bundle_descriptor_ambiguous")
        return 0
    descriptor = descriptors[0]
    try:
        bundle_manager.write_bundle(
            descriptor, bundle_dir=mount_path, ssh_private_key_path=ssh_key_path
        )
    except bundle_manager.BundleManagerError as exc:
        logger.error("worker bundle assembly failed (closed): %s", exc.reason_code)
        return 0
    logger.info(
        "assembled worker-owned discovery bundle for enrollment=%s at the fixed mount",
        descriptor.get("enrollment_id"),
    )
    return 1


def _resolve_ready_bundle_descriptors(resolver, session, organization_id) -> list[dict]:
    """Call either the current tenant-scoped resolver or the reviewed legacy image resolver.

    The pinned pre-PR5F worker image exposes ``resolver(session)`` while the current API service
    exposes ``resolver(session, organization_id)``. Signature binding selects the compatible call
    without treating an internal ``TypeError`` as an API-version signal. The worker then applies
    its own exact tenant filter in both cases, so the compatibility path cannot restore the legacy
    cross-tenant behavior.
    """
    try:
        signature(resolver).bind(session, organization_id)
    except TypeError:
        descriptors = resolver(session)
    except ValueError as exc:
        raise BundlePreparationRefused("bundle_descriptor_resolver_incompatible") from exc
    else:
        descriptors = resolver(session, organization_id)

    expected_organization = str(organization_id)
    if not isinstance(descriptors, list):
        raise BundlePreparationRefused("bundle_descriptor_result_invalid")
    return [
        descriptor
        for descriptor in descriptors
        if isinstance(descriptor, dict)
        and descriptor.get("organization_id") == expected_organization
    ]


def prepare_once(settings=None, session_scope=None) -> None:
    """One bundle-preparation tick: ensure+publish keys, then write any ready bundle. Each step is
    independently guarded so a failure in one never aborts the others or the worker."""
    if settings is None:
        from secp_api.config import get_settings

        settings = get_settings()
    if not getattr(settings, "discovery_worker_managed_bundle", False):
        return
    try:
        _configured_org(settings)
    except BundlePreparationRefused as exc:
        logger.error("worker bundle preparation refused (closed): %s", exc.reason_code)
        return
    if session_scope is None:
        from secp_api.db import session_scope as default_scope

        session_scope = default_scope

    worker_ssh_public_key_fingerprint: str | None = None
    try:
        worker_ssh_public_key_fingerprint = _ensure_and_publish_keys(settings, session_scope)
    except Exception as exc:  # pragma: no cover - must survive a bad tick
        logger.error("worker key ensure/publish tick failed: %s", type(exc).__name__)
    if worker_ssh_public_key_fingerprint is None:
        return
    try:
        _write_ready_bundles(
            settings,
            session_scope,
            worker_ssh_public_key_fingerprint=worker_ssh_public_key_fingerprint,
        )
    except Exception as exc:  # pragma: no cover - must survive a bad tick
        logger.error("worker bundle write tick failed: %s", type(exc).__name__)


def run_forever(stop_event: threading.Event | None = None) -> None:  # pragma: no cover - runtime
    from secp_api.config import get_settings

    from secp_worker import bundle_loop_marker

    settings = get_settings()
    stop_event = stop_event or threading.Event()
    if not getattr(settings, "discovery_worker_managed_bundle", False):
        bundle_loop_marker.clear_started()
        logger.info("worker-managed discovery bundle profile disabled; bundle-prep loop inert")
        return
    interval = float(getattr(settings, "discovery_worker_bundle_poll_seconds", 15.0))
    try:
        bundle_loop_marker.mark_started()
    except bundle_loop_marker.BundleLoopMarkerError as exc:
        # Continue the harmless preparation loop, but activation will fail closed because it cannot
        # prove that this exact process instance started it.
        logger.error("worker bundle-prep marker failed (closed): %s", exc.reason_code)
    logger.info("worker-owned discovery bundle-prep loop started (interval=%ss)", interval)
    try:
        while not stop_event.is_set():
            prepare_once(settings=settings)
            stop_event.wait(interval)
    finally:
        bundle_loop_marker.clear_started()
        logger.info("worker-owned discovery bundle-prep loop stopped")
