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

logger = logging.getLogger("secp.worker.discovery.bundle")


def _configured_org(settings):
    import uuid

    raw = (getattr(settings, "discovery_worker_node_organization", "") or "").strip()
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        logger.warning("discovery_worker_node_organization is not a valid uuid; ignoring")
        return None


def _ensure_and_publish_keys(settings, session_scope) -> None:
    """Ensure worker-owned keypairs exist and publish the PUBLIC material to the control plane."""
    from secp_worker import bundle_manager

    key_dir = getattr(settings, "discovery_worker_key_dir", "")
    material = bundle_manager.ensure_worker_keys(
        key_dir
    )  # generate-if-missing; returns PUBLIC only

    from secp_api.services import worker_nodes

    node_label = getattr(settings, "discovery_worker_node_label", "default-worker")
    configured_org = _configured_org(settings)
    with session_scope() as session:
        org_ids = worker_nodes.resolve_publication_organizations(session, configured_org)
        if not org_ids:
            logger.info(
                "worker public key generated but not published: set "
                "discovery_worker_node_organization (multiple/zero organizations present)"
            )
            return
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


def _write_ready_bundles(settings, session_scope) -> int:
    """Assemble the mounted bundle for every ready enrollment from the secret-free descriptor.

    Returns the number of bundles written. In the common single-target deployment there is exactly
    one ready descriptor -> one bundle at the fixed mount path."""
    from secp_worker import bundle_manager

    key_dir = getattr(settings, "discovery_worker_key_dir", "")
    mount_path = getattr(settings, "discovery_bootstrap_mount", "")
    ssh_key_path = bundle_manager.worker_ssh_private_key_path(key_dir)

    from secp_api.services import bootstrap_discovery

    with session_scope() as session:
        descriptors = bootstrap_discovery.resolve_ready_bundle_descriptors(session)

    if not descriptors:
        return 0
    if len(descriptors) > 1:
        # A single fixed mount path can host ONE bundle. Surface the truncation rather than silently
        # dropping targets; the runtime endpoint-binding gate rejects a mismatched bundle anyway.
        logger.warning(
            "%d targets are discovery-ready but the fixed mount hosts one bundle; writing the "
            "first (enrollment=%s). Configure a per-target mount for additional targets.",
            len(descriptors),
            descriptors[0].get("enrollment_id"),
        )
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


def prepare_once(settings=None, session_scope=None) -> None:
    """One bundle-preparation tick: ensure+publish keys, then write any ready bundle. Each step is
    independently guarded so a failure in one never aborts the others or the worker."""
    if settings is None:
        from secp_api.config import get_settings

        settings = get_settings()
    if not getattr(settings, "discovery_worker_managed_bundle", False):
        return
    if session_scope is None:
        from secp_api.db import session_scope as default_scope

        session_scope = default_scope

    try:
        _ensure_and_publish_keys(settings, session_scope)
    except Exception as exc:  # pragma: no cover - must survive a bad tick
        logger.error("worker key ensure/publish tick failed: %s", type(exc).__name__)
    try:
        _write_ready_bundles(settings, session_scope)
    except Exception as exc:  # pragma: no cover - must survive a bad tick
        logger.error("worker bundle write tick failed: %s", type(exc).__name__)


def run_forever(stop_event: threading.Event | None = None) -> None:  # pragma: no cover - runtime
    from secp_api.config import get_settings

    settings = get_settings()
    stop_event = stop_event or threading.Event()
    if not getattr(settings, "discovery_worker_managed_bundle", False):
        logger.info("worker-managed discovery bundle profile disabled; bundle-prep loop inert")
        return
    interval = float(getattr(settings, "discovery_worker_bundle_poll_seconds", 15.0))
    logger.info("worker-owned discovery bundle-prep loop started (interval=%ss)", interval)
    while not stop_event.is_set():
        prepare_once(settings=settings)
        stop_event.wait(interval)
    logger.info("worker-owned discovery bundle-prep loop stopped")
