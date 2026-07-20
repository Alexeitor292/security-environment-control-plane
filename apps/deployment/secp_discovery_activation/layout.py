"""Code-owned production layout for B8 discovery activation.

There is deliberately no path builder and no caller-selected production path.  Test and runtime
adapters can inject filesystem implementations around these exact locations, but deployment input
cannot redirect a privileged write or mount.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProductionLayout:
    """The complete fixed path/topology inventory used by rendered activation artifacts."""

    profile_path: str
    host_role_path: str
    worker_compose_override_path: str
    worker_runtime_overlay_import_path: str
    worker_runtime_overlay_path: str
    proxy_contract_path: str
    controller_compose_override_path: str
    ca_certificate_path: str
    server_certificate_path: str
    server_private_key_path: str
    admission_proxy_gate_path: str
    worker_state_host_path: str
    worker_state_container_path: str
    worker_keys_container_path: str
    discovery_bundle_container_path: str
    worker_ca_container_path: str
    worker_runtime_overlay_container_path: str
    proxy_contract_container_path: str
    proxy_ca_certificate_container_path: str
    proxy_server_certificate_container_path: str
    proxy_server_private_key_container_path: str
    admission_proxy_gate_container_path: str
    journal_path: str
    controller_journal_path: str
    worker_journal_path: str
    evidence_path: str
    evidence_attestation_path: str
    evidence_signing_key_path: str
    evidence_trust_anchor_path: str
    tls_import_ca_certificate_path: str
    tls_import_server_certificate_path: str
    tls_import_server_private_key_path: str
    controller_offer_outbox_path: str
    controller_offer_outbox_attestation_path: str
    worker_controller_offer_inbox_path: str
    worker_controller_offer_inbox_attestation_path: str
    worker_result_outbox_path: str
    worker_result_outbox_attestation_path: str
    controller_worker_result_inbox_path: str
    controller_worker_result_inbox_attestation_path: str


PRODUCTION_LAYOUT = ProductionLayout(
    profile_path="/etc/secp/discovery-activation/profile.json",
    host_role_path="/etc/secp/discovery-activation/host-role",
    worker_compose_override_path=("/etc/secp/discovery-activation/worker-compose.override.yaml"),
    worker_runtime_overlay_import_path=(
        "/etc/secp/discovery-activation/import/secp-pr5f-runtime-overlay.zip"
    ),
    worker_runtime_overlay_path=(
        "/var/lib/secp/discovery-activation/runtime/secp-pr5f-runtime-overlay.zip"
    ),
    proxy_contract_path="/etc/secp/discovery-activation/admission-proxy.json",
    controller_compose_override_path=(
        "/etc/secp/discovery-activation/controller-compose.override.yaml"
    ),
    ca_certificate_path="/etc/secp/discovery-activation/tls/admission-ca.pem",
    server_certificate_path="/etc/secp/discovery-activation/tls/admission-server.pem",
    server_private_key_path="/etc/secp/discovery-activation/tls/admission-server.key",
    admission_proxy_gate_path=(
        "/etc/secp/discovery-activation/secrets/admission-proxy-gate.secret"
    ),
    worker_state_host_path="/var/lib/secp/discovery-worker",
    worker_state_container_path="/var/run/secp",
    worker_keys_container_path="/var/run/secp/worker-keys",
    discovery_bundle_container_path="/var/run/secp/discovery-bundle",
    worker_ca_container_path="/etc/secp/admission-ca.pem",
    worker_runtime_overlay_container_path="/opt/secp/secp-pr5f-runtime-overlay.zip",
    proxy_contract_container_path="/etc/secp/admission-proxy.json",
    proxy_ca_certificate_container_path="/run/secp/tls/admission-ca.pem",
    proxy_server_certificate_container_path="/run/secp/tls/admission-server.pem",
    proxy_server_private_key_container_path="/run/secp/tls/admission-server.key",
    admission_proxy_gate_container_path="/run/secp/admission-proxy-gate.secret",
    journal_path="/var/lib/secp/discovery-activation/transaction.json",
    controller_journal_path=("/var/lib/secp/discovery-activation/controller-transaction.json"),
    worker_journal_path="/var/lib/secp/discovery-activation/worker-transaction.json",
    evidence_path="/var/lib/secp/discovery-activation/evidence.json",
    evidence_attestation_path=("/var/lib/secp/discovery-activation/evidence.attestation.json"),
    evidence_signing_key_path=("/var/lib/secp/discovery-activation/evidence-signing.key"),
    evidence_trust_anchor_path=("/var/lib/secp/discovery-activation/evidence-signing.pub"),
    tls_import_ca_certificate_path=("/etc/secp/discovery-activation/import/admission-ca.pem"),
    tls_import_server_certificate_path=(
        "/etc/secp/discovery-activation/import/admission-server.pem"
    ),
    tls_import_server_private_key_path=(
        "/etc/secp/discovery-activation/import/admission-server.key"
    ),
    controller_offer_outbox_path=(
        "/var/lib/secp/discovery-activation/outbox/controller-offer.json"
    ),
    controller_offer_outbox_attestation_path=(
        "/var/lib/secp/discovery-activation/outbox/controller-offer.attestation.json"
    ),
    worker_controller_offer_inbox_path=(
        "/etc/secp/discovery-activation/inbox/controller-offer.json"
    ),
    worker_controller_offer_inbox_attestation_path=(
        "/etc/secp/discovery-activation/inbox/controller-offer.attestation.json"
    ),
    worker_result_outbox_path=("/var/lib/secp/discovery-activation/outbox/worker-result.json"),
    worker_result_outbox_attestation_path=(
        "/var/lib/secp/discovery-activation/outbox/worker-result.attestation.json"
    ),
    controller_worker_result_inbox_path=("/etc/secp/discovery-activation/inbox/worker-result.json"),
    controller_worker_result_inbox_attestation_path=(
        "/etc/secp/discovery-activation/inbox/worker-result.attestation.json"
    ),
)

# Fixed product topology.  These are not deployment-local hostnames or identities.
ORDINARY_WORKER_SERVICE = "worker"
ORDINARY_WORKER_CONTAINER = "secp-ordinary-worker"
ORDINARY_TASK_QUEUE = "secp-orchestration"
CONTROLLER_API_SERVICE = "api"
CONTROLLER_API_CONTAINER_PORT = 8080
ADMISSION_PROXY_SERVICE = "discovery-admission-proxy"
ADMISSION_PROXY_CONTAINER = "secp-discovery-admission-proxy"
ADMISSION_PROXY_CONTAINER_PORT = 8443
ADMISSION_PROXY_EXECUTABLE = "/usr/local/bin/secp-admission-proxy"

WORKER_SSH_PRIVATE_KEY = PRODUCTION_LAYOUT.worker_keys_container_path + "/ssh_id_ed25519"
WORKER_ADMISSION_PRIVATE_KEY = PRODUCTION_LAYOUT.worker_keys_container_path + "/admission_key"
WORKER_ADMISSION_PUBLIC_ANCHOR = PRODUCTION_LAYOUT.worker_keys_container_path + "/admission_anchor"
PROXY_CA_CERTIFICATE_CONTAINER_PATH = PRODUCTION_LAYOUT.proxy_ca_certificate_container_path

ADMISSION_ROUTES = (
    "/internal/worker-discovery-admission/begin",
    "/internal/worker-discovery-admission/complete",
    "/internal/worker-discovery-admission/assert",
    "/internal/worker-discovery-admission/consume",
)

# Code-owned limits are intentionally not deployment knobs.
MAX_ADMISSION_REQUEST_BYTES = 64 * 1024
MAX_ADMISSION_RESPONSE_BYTES = 64 * 1024
ADMISSION_CONNECT_TIMEOUT_SECONDS = 5
ADMISSION_REQUEST_TIMEOUT_SECONDS = 10

__all__ = [
    "PRODUCTION_LAYOUT",
    "ProductionLayout",
    "ORDINARY_WORKER_SERVICE",
    "ORDINARY_WORKER_CONTAINER",
    "ORDINARY_TASK_QUEUE",
    "CONTROLLER_API_SERVICE",
    "CONTROLLER_API_CONTAINER_PORT",
    "ADMISSION_PROXY_SERVICE",
    "ADMISSION_PROXY_CONTAINER",
    "ADMISSION_PROXY_CONTAINER_PORT",
    "ADMISSION_PROXY_EXECUTABLE",
    "WORKER_SSH_PRIVATE_KEY",
    "WORKER_ADMISSION_PRIVATE_KEY",
    "WORKER_ADMISSION_PUBLIC_ANCHOR",
    "PROXY_CA_CERTIFICATE_CONTAINER_PATH",
    "ADMISSION_ROUTES",
    "MAX_ADMISSION_REQUEST_BYTES",
    "MAX_ADMISSION_RESPONSE_BYTES",
    "ADMISSION_CONNECT_TIMEOUT_SECONDS",
    "ADMISSION_REQUEST_TIMEOUT_SECONDS",
]
