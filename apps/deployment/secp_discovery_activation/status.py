"""Truthful staged status for production B8 read-only discovery activation (SECP-PR5F).

Status is derived from one coherent observation. Flags alone never produce a ready state: the
worker generation, health, queue, isolated mount, key metadata, public node, bootstrap/identity/
authorization lifecycle, bundle, immutable snapshot contact fact, and non-executable candidate
plan are independent gates.
"""

from __future__ import annotations

from dataclasses import dataclass

DISABLED = "disabled"
PREPARED = "prepared"
TLS_READY = "TLS-ready"
WORKER_RECREATION_REQUIRED = "worker-recreation-required"
WORKER_STARTING = "worker-starting"
KEYS_GENERATED = "keys-generated"
PUBLIC_NODE_PUBLISHED = "public-node-published"
AWAITING_FINALIZATION = "awaiting-finalization"
AWAITING_BOOTSTRAP_SESSION = "awaiting-bootstrap-session"
AWAITING_PROOF = "awaiting-proof"
AWAITING_AUTHORIZATION = "awaiting-authorization"
AWAITING_BUNDLE = "awaiting-bundle"
BUNDLE_READY = "bundle-ready"
DISCOVERY_CONTACTED = "discovery-contacted"
RECOVERY_REQUIRED = "recovery-required"

ALL_STATES: tuple[str, ...] = (
    DISABLED,
    PREPARED,
    TLS_READY,
    WORKER_RECREATION_REQUIRED,
    WORKER_STARTING,
    KEYS_GENERATED,
    PUBLIC_NODE_PUBLISHED,
    AWAITING_FINALIZATION,
    AWAITING_BOOTSTRAP_SESSION,
    AWAITING_PROOF,
    AWAITING_AUTHORIZATION,
    AWAITING_BUNDLE,
    BUNDLE_READY,
    DISCOVERY_CONTACTED,
    RECOVERY_REQUIRED,
)


@dataclass(frozen=True)
class ActivationObservation:
    """One bounded, nonsecret activation observation.

    The host adapter constructs this from closed local/TLS/control-plane probes. No raw Docker
    inspect, environment file, certificate, endpoint, or key bytes are carried here.
    """

    coherent: bool = False
    activation_enabled: bool = False
    artifacts_prepared: bool = False
    tls_ready: bool = False
    worker_config_installed: bool = False
    worker_recreation_required: bool = False
    worker_generation_changed: bool = False
    worker_running: bool = False
    worker_healthy: bool = False
    ordinary_queue_exact: bool = False
    b8_flags_enabled: bool = False
    required_paths_present: bool = False
    state_mount_isolated: bool = False
    bundle_loop_started: bool = False
    operator_absent: bool = False
    safety_seals_valid: bool = False
    keys_generated: bool = False
    key_metadata_safe: bool = False
    public_node_id: str | None = None
    public_node_revision: int | None = None
    public_node_public_only: bool = False
    publication_recorded: bool = False
    bootstrap_status: str | None = None
    worker_identity_approved: bool = False
    live_read_authorization_approved: bool = False
    bundle_ready: bool = False
    discovery_contacted: bool = False
    candidate_executable: bool | None = None
    recovery_required: bool = False

    def runtime_ready(self) -> bool:
        return bool(
            self.coherent
            and self.worker_generation_changed
            and self.worker_running
            and self.worker_healthy
            and self.ordinary_queue_exact
            and self.b8_flags_enabled
            and self.required_paths_present
            and self.state_mount_isolated
            and self.bundle_loop_started
            and self.operator_absent
            and self.safety_seals_valid
        )


@dataclass(frozen=True)
class StatusReport:
    state: str
    findings: tuple[str, ...]
    node_id: str | None = None
    node_revision: int | None = None

    def canonical(self) -> dict[str, object]:
        return {
            "state": self.state,
            "findings": list(self.findings),
            "worker_discovery_node_id": self.node_id,
            "worker_discovery_node_revision": self.node_revision,
        }


def derive_status(observation: ActivationObservation) -> StatusReport:
    """Return the first truthful incomplete stage, or the contacted terminal stage.

    A malformed/incoherent observation after any activation artifact exists is recovery-required;
    a missing observation is never interpreted as proof of no effects.
    """

    o = observation
    node = (o.public_node_id, o.public_node_revision)
    if o.recovery_required:
        return StatusReport(RECOVERY_REQUIRED, ("recovery_not_proven",), *node)
    if not o.coherent:
        return StatusReport(RECOVERY_REQUIRED, ("observation_incoherent",), *node)
    observed_effects = bool(
        o.artifacts_prepared
        or o.tls_ready
        or o.worker_config_installed
        or o.worker_recreation_required
        or o.worker_generation_changed
        or o.b8_flags_enabled
        or o.required_paths_present
        or o.state_mount_isolated
        or o.keys_generated
        or o.public_node_id
        or o.bootstrap_status is not None
        or o.bundle_ready
        or o.discovery_contacted
    )
    if not o.activation_enabled and not observed_effects:
        return StatusReport(DISABLED, ("activation_false",), *node)
    if not o.activation_enabled:
        return StatusReport(RECOVERY_REQUIRED, ("activation_false_with_effects",), *node)
    if not o.artifacts_prepared:
        return StatusReport(PREPARED, ("activation_artifacts_not_installed",), *node)
    if not o.tls_ready:
        return StatusReport(PREPARED, ("admission_tls_not_ready",), *node)
    if not o.worker_config_installed:
        return StatusReport(TLS_READY, ("worker_activation_artifact_not_installed",), *node)
    if o.worker_recreation_required or not o.worker_generation_changed:
        return StatusReport(
            WORKER_RECREATION_REQUIRED, ("ordinary_worker_generation_not_activated",), *node
        )
    if not o.runtime_ready():
        return StatusReport(WORKER_STARTING, ("worker_postconditions_incomplete",), *node)
    if not (o.keys_generated and o.key_metadata_safe):
        return StatusReport(WORKER_STARTING, ("worker_keys_not_safely_generated",), *node)
    if not (o.public_node_id and o.public_node_revision and o.public_node_public_only):
        return StatusReport(KEYS_GENERATED, ("public_worker_node_absent",), *node)
    if not o.publication_recorded:
        return StatusReport(PUBLIC_NODE_PUBLISHED, ("public_node_observed",), *node)
    if o.bootstrap_status is None:
        return StatusReport(AWAITING_BOOTSTRAP_SESSION, ("bootstrap_session_absent",), *node)
    if o.bootstrap_status == "pending":
        return StatusReport(AWAITING_PROOF, ("bootstrap_proof_pending",), *node)
    if o.bootstrap_status in ("superseded", "refused"):
        return StatusReport(AWAITING_BOOTSTRAP_SESSION, ("bootstrap_session_terminal",), *node)
    if o.bootstrap_status == "completed":
        return StatusReport(AWAITING_AUTHORIZATION, ("authorization_not_bound",), *node)
    if o.bootstrap_status != "bound":
        return StatusReport(RECOVERY_REQUIRED, ("bootstrap_status_invalid",), *node)
    if not (o.worker_identity_approved and o.live_read_authorization_approved):
        return StatusReport(AWAITING_AUTHORIZATION, ("authorization_incomplete",), *node)
    if not o.bundle_ready:
        return StatusReport(AWAITING_BUNDLE, ("bundle_not_available",), *node)
    if not o.discovery_contacted:
        return StatusReport(BUNDLE_READY, ("target_not_contacted",), *node)
    if o.candidate_executable is not False:
        return StatusReport(RECOVERY_REQUIRED, ("candidate_plan_execution_posture_invalid",), *node)
    return StatusReport(DISCOVERY_CONTACTED, ("read_only_contact_proven",), *node)
