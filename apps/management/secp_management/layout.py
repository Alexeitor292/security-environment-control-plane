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

    def assert_writable(self, path: str) -> None:
        """The single write authority: a managed write target must be a clean absolute path under a
        role/bootstrap root and never under a forbidden system root."""
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
        )
        if not any(_under(path, root) for root in owned):
            raise ManagementError("layout_path_not_owned")
