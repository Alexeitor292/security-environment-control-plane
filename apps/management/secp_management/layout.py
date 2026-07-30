"""Code-owned fixed filesystem layout for the management-plane bootstrap (SECP-PR5E).

Every path is a reviewed CODE constant — never descriptor-selected and never a CLI argument. The
paths
harmonize with the existing repository conventions: ``/opt/secp/operator`` (PR5C commissioning) and
``/etc/secp/operator-deployment`` (PR5D) are reused as-is; the new management roots are siblings
under
the same ``/opt/secp`` / ``/etc/secp`` / ``/var/lib/secp`` trees. All writes go through the hardened
:class:`~secp_commissioning.runtime.RealFilesystem` (directory-fd-relative, trusted-ancestor walk,
atomic install), so this module only NAMES the fixed clean absolute paths and rejects any unclean or
alternate-root value.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secp_management import ManagementError

# Directories the bootstrap installer must NEVER write into (SSH, boot, system binaries, Docker
# internals, database storage, the ordinary worker's own runtime). The operator installer
# additionally never touches these; the management installer's own writes are confined to its role
# roots below.
_FORBIDDEN_ROOTS: tuple[str, ...] = (
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib/systemd",
    "/root/.ssh",
    "/home",
    "/var/lib/docker",
    "/var/lib/postgresql",
    "/run/systemd",
    "/var/run/docker.sock",
)


# Exact, code-owned, closed unit/config file names (never descriptor-selected, never a wildcard).
# The controller runs under a management wrapper unit; the worker's operator unit name matches the
# reviewed topology (secp-operator-worker.service) and is installed DISABLED + STOPPED.
_CONTROLLER_UNIT_NAME = "secp-controller-stack.service"
_OPERATOR_UNIT_NAME = "secp-operator-worker.service"
_BROKER_UNIT_NAME = "secp-enrollment-signer-broker.service"
_CONTROLLER_COMPOSE_NAME = "docker-compose.yml"
_WORKER_COMPOSE_NAME = "docker-compose.yml"
_WORKER_DEPLOYMENT_PACKAGE_NAME = "secp-operator-deployment-package.zip"

# Closed, code-owned finalization file names (SECP-PR5H-B2, 2b-3b-iii). The signer-enablement
# MARKER and the controller-API LOCATOR are host==container paths under /etc/secp/controller (the
# marker bind-mounted read-only into the non-root API at the same path; the locator read by secpctl
# through the hardened seam). The two HANDOFFS are written by the root installer under an owned
# bootstrap-state root and bind-mounted READ-ONLY into the fixed API one-shots at their fixed
# /run/secp/handoff container paths.
_ENROLLMENT_SIGNER_MARKER_NAME = "enrollment-signer.enabled"
_CONTROLLER_API_LOCATOR_NAME = "api-locator.json"
_PROVISIONING_HANDOFF_NAME = "enrollment-signer-role-provision.json"
_ACTIVATION_HANDOFF_NAME = "controller-identity-activation.json"
# /run container-side, name-only paths. These are NOT under an owned root (assert_writable rejects
# them by design — the installer never atomic_installs a /run path; systemd RuntimeDirectory creates
# the socket dir and the handoffs are bind-mounted). They are FIXED literals that byte-match the
# commissioning-plane socket constants and the API-plane one-shot handoff constants; a boundary
# guard
# test proves the byte-match so the two planes cannot drift (management may not import secp_api).
_BROKER_RUNTIME_DIR = "/run/secp"
_BROKER_SOCKET_PATH = "/run/secp/enrollment-signer.sock"
_HANDOFF_CONTAINER_DIR = "/run/secp/handoff"


def _is_clean_absolute(path: str) -> bool:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 512:
        return False
    if "\\" in path or "\x00" in path or "//" in path:
        return False
    parts = path.split("/")[1:]
    return all(p not in ("", ".", "..") for p in parts)


def _under(path: str, root: str) -> bool:
    if path == root:
        return True
    prefix = root.rstrip("/") + "/"
    return path.startswith(prefix)


@dataclass(frozen=True)
class ManagementLocations:
    """The fixed, code-owned management-plane locations. Defaults ARE the production paths; tests
    inject an in-memory filesystem, not alternate paths."""

    controller_root: str = "/opt/secp/controller"
    worker_root: str = "/opt/secp/worker"
    operator_root: str = "/opt/secp/operator"  # reused from PR5C commissioning
    bootstrap_root: str = "/opt/secp/bootstrap"
    controller_config: str = "/etc/secp/controller"
    worker_config: str = "/etc/secp/worker"
    operator_deployment_config: str = "/etc/secp/operator-deployment"  # reused from PR5D
    # The single, fixed systemd unit directory.  /usr/lib/systemd and /run/systemd are forbidden
    # ancestors; /etc/secp/... roots are not systemd-managed, so the reviewed system unit dir is the
    # one binding.  Only the two EXACT unit paths below are ever writable (assert_unit_writable).
    systemd_dir: str = "/etc/systemd/system"
    bootstrap_state: str = "/var/lib/secp/bootstrap"
    commissioning_state: str = "/var/lib/secp/commissioning"  # reused from PR5C
    forbidden_roots: tuple[str, ...] = field(default=_FORBIDDEN_ROOTS)

    def __post_init__(self) -> None:
        for name in (
            "controller_root",
            "worker_root",
            "operator_root",
            "bootstrap_root",
            "controller_config",
            "worker_config",
            "operator_deployment_config",
            "systemd_dir",
            "bootstrap_state",
            "commissioning_state",
        ):
            value = getattr(self, name)
            if not _is_clean_absolute(value):
                raise ManagementError("layout_path_unclean")
            for forbidden in self.forbidden_roots:
                if _under(value, forbidden):
                    raise ManagementError("layout_path_forbidden_root")

    def role_root(self, role_value: str) -> str:
        if role_value == "controller":
            return self.controller_root
        if role_value == "worker":
            return self.worker_root
        raise ManagementError("role_invalid")

    def evidence_path(self, role_value: str) -> str:
        if role_value == "controller":
            return f"{self.bootstrap_state}/controller-evidence.json"
        if role_value == "worker":
            return f"{self.bootstrap_state}/worker-evidence.json"
        raise ManagementError("role_invalid")

    def identity_path(self, role_value: str) -> str:
        if role_value == "controller":
            return f"{self.bootstrap_state}/controller-identity.json"
        if role_value == "worker":
            return f"{self.bootstrap_state}/worker-identity.json"
        raise ManagementError("role_invalid")

    def release_record_path(self, role_value: str) -> str:
        """The fixed, root-controlled installed-release manifest bootstrap records so status can
        rebind to a trusted release WITHOUT any caller-supplied bundle path."""
        if role_value in ("controller", "worker"):
            return f"{self.bootstrap_state}/{role_value}-installed-release.json"
        raise ManagementError("role_invalid")

    def release_sig_path(self, role_value: str) -> str:
        """The detached signature of the installed-release manifest (reverified during status)."""
        if role_value in ("controller", "worker"):
            return f"{self.bootstrap_state}/{role_value}-installed-release.sig.json"
        raise ManagementError("role_invalid")

    def evidence_attestation_path(self, role_value: str) -> str:
        """The detached, independently-signed attestation authenticating the evidence document
        (verified before evidence's mode/classification/ownership/timestamps are ever trusted)."""
        if role_value in ("controller", "worker"):
            return f"{self.bootstrap_state}/{role_value}-evidence.attestation.json"
        raise ManagementError("role_invalid")

    def controller_unit_path(self) -> str:
        """The EXACT controller management wrapper unit path (a fixed constant, never selected)."""
        return f"{self.systemd_dir}/{_CONTROLLER_UNIT_NAME}"

    def operator_unit_path(self) -> str:
        """The EXACT prepared operator unit path — installed DISABLED + STOPPED (fixed constant)."""
        return f"{self.systemd_dir}/{_OPERATOR_UNIT_NAME}"

    def controller_tls_dir(self) -> str:
        """The fixed controller-API TLS material directory (SECP-PR5H-B2)."""
        return f"{self.controller_config}/tls"

    def controller_ca_bundle_path(self) -> str:
        """The EXACT CA-bundle path the installer writes and the locator records — the one CA
        secpctl trusts for the controller HTTPS surface (never a caller-chosen path)."""
        return f"{self.controller_config}/tls/ca-bundle.pem"

    def controller_server_cert_path(self) -> str:
        return f"{self.controller_config}/tls/server-cert.pem"

    def controller_server_key_path(self) -> str:
        """The controller-API server private key — installed root-owned 0600 (never readable)."""
        return f"{self.controller_config}/tls/server-key.pem"

    def enrollment_signer_credential_path(self) -> str:
        """The fixed root-owned source file the installer writes the signer role's plaintext SCRAM
        secret to; systemd ``LoadCredential`` copies it into the broker unit's credential dir."""
        return f"{self.controller_config}/credentials/enrollment-signer-db"

    def broker_unit_path(self) -> str:
        """The EXACT root-gated enrollment-signer broker unit path (fixed constant, never selected).
        The ONLY unit that runs as root; installed present-but-disabled through the strict unit
        authority (:meth:`assert_unit_writable`)."""
        return f"{self.systemd_dir}/{_BROKER_UNIT_NAME}"

    def broker_runtime_dir(self) -> str:
        """The fixed broker socket RuntimeDirectory (systemd creates it root-owned; the installer
        never writes here — name-only, NOT ``assert_writable``-eligible)."""
        return _BROKER_RUNTIME_DIR

    def broker_socket_path(self) -> str:
        """The fixed AF_UNIX broker socket path (bound by the broker at runtime; name-only)."""
        return _BROKER_SOCKET_PATH

    def api_signer_readiness_gate_path(self) -> str:
        """The fixed host path of the enrollment-signer READINESS-ORIGIN GATE (2b-3c-c).

        A 256-bit root-owned, API-group-readable 0640 machine secret that authenticates the root
        management installer to the fixed readiness route. It is the ONLY authorization-only secret
        the ordinary API is permitted to receive, it is mounted read-only, and it is distinct in
        path, header, value and reason codes from the worker-admission proxy gate."""
        from secp_commissioning.enrollment_signer_binding_digest import (
            ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
        )

        return ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH

    def api_signer_marker_path(self) -> str:
        """The root-owned API signer-enablement MARKER — the SOLE positive production authority for
        the API signer client, written LAST. Host path == the API container read path (bind-mounted
        read-only), so it is a single fixed ``/etc/secp/controller`` path."""
        return f"{self.controller_config}/{_ENROLLMENT_SIGNER_MARKER_NAME}"

    def controller_api_locator_path(self) -> str:
        """The fixed public (root:root 0644) controller-API locator record path."""
        return f"{self.controller_config}/{_CONTROLLER_API_LOCATOR_NAME}"

    def provisioning_handoff_host_path(self) -> str:
        """The root-owned, exact-API-group 0640 provisioning-handoff SOURCE the installer writes and
        bind-mounts read-only into the provisioning one-shot (carries ONLY the SCRAM verifier)."""
        return f"{self.bootstrap_state}/handoff/{_PROVISIONING_HANDOFF_NAME}"

    def provisioning_handoff_container_path(self) -> str:
        """The fixed read-only container mount path of the provisioning handoff (name-only)."""
        return f"{_HANDOFF_CONTAINER_DIR}/{_PROVISIONING_HANDOFF_NAME}"

    def activation_handoff_host_path(self) -> str:
        """The root-owned, exact-API-group 0640 activation-handoff SOURCE the installer writes and
        bind-mounts read-only into the activation one-shot (carries no key, no DB credential)."""
        return f"{self.bootstrap_state}/handoff/{_ACTIVATION_HANDOFF_NAME}"

    def activation_handoff_container_path(self) -> str:
        """The fixed read-only container mount path of the activation handoff (name-only)."""
        return f"{_HANDOFF_CONTAINER_DIR}/{_ACTIVATION_HANDOFF_NAME}"

    def controller_compose_path(self) -> str:
        return f"{self.controller_config}/{_CONTROLLER_COMPOSE_NAME}"

    def worker_compose_path(self) -> str:
        return f"{self.worker_config}/{_WORKER_COMPOSE_NAME}"

    def worker_deployment_package_path(self) -> str:
        return f"{self.operator_deployment_config}/{_WORKER_DEPLOYMENT_PACKAGE_NAME}"

    def unit_path(self, role_value: str) -> str:
        """The single fixed unit path installed by each role's bootstrap (controller wrapper /
        worker operator).  There is no ``unit_path(path)`` — the caller selects a ROLE, never a
        path or filename, so a unit-path injection is structurally impossible."""
        if role_value == "controller":
            return self.controller_unit_path()
        if role_value == "worker":
            return self.operator_unit_path()
        raise ManagementError("role_invalid")

    def assert_unit_writable(self, path: str) -> None:
        """The strict unit write authority: a unit target must be EXACTLY one of the three fixed
        code-owned unit paths (controller wrapper, prepared operator, enrollment-signer broker) —
        never a prefix, wildcard, or caller filename in the systemd dir."""
        if path not in (
            self.controller_unit_path(),
            self.operator_unit_path(),
            self.broker_unit_path(),
        ):
            raise ManagementError("layout_unit_path_not_fixed")

    def assert_writable(self, path: str) -> None:
        """The single write authority: a managed write target must be a clean absolute path under a
        role/bootstrap/config root and never under a forbidden system root.  Systemd units are NOT
        writable here — they go only through the stricter ``assert_unit_writable``."""
        if not _is_clean_absolute(path):
            raise ManagementError("layout_path_unclean")
        for forbidden in self.forbidden_roots:
            if _under(path, forbidden):
                raise ManagementError("layout_path_forbidden_root")
        owned = (
            self.controller_root,
            self.worker_root,
            self.bootstrap_root,
            self.bootstrap_state,
            self.controller_config,
            self.worker_config,
            self.operator_deployment_config,
        )
        if not any(_under(path, root) for root in owned):
            raise ManagementError("layout_path_not_owned")
