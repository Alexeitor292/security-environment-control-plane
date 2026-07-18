"""Fixed, reviewed, hardened systemd unit templates (SECP-PR5E).

Units are rendered from CODE-OWNED templates only — never from host input. Every unit sets
``NoNewPrivileges``, ``ProtectSystem=strict``, ``ProtectHome``, ``PrivateTmp``, a restricted address
family set, an empty capability bounding set, an explicit read/write path allowlist, an absolute
executable path, and NO shell / ``/usr/bin/env`` entrypoint. The SEALED controlled-live operator
unit
additionally has NO ``[Install]``/``WantedBy`` section and no auto-start line — it can never be
enabled
or started by the bootstrap, mirroring the operator-activation seal.
"""

from __future__ import annotations

from secp_commissioning.canonical import sha256_bytes

from secp_management import ManagementError

_HARDENING = (
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "RestrictNamespaces=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
)


def _validate(exec_argv: tuple[str, ...], read_write_paths: tuple[str, ...]) -> None:
    if not exec_argv or not exec_argv[0].startswith("/"):
        raise ManagementError("systemd_exec_not_absolute")
    if exec_argv[0] in ("/usr/bin/env", "/bin/env"):
        raise ManagementError("systemd_exec_env_forbidden")
    if exec_argv[0] in ("/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"):
        raise ManagementError("systemd_exec_shell_forbidden")
    for p in read_write_paths:
        if not p.startswith("/") or "\\" in p or ".." in p.split("/"):
            raise ManagementError("systemd_readwrite_path_unclean")


def render_service_unit(
    *,
    description: str,
    exec_argv: tuple[str, ...],
    user: str,
    group: str,
    read_write_paths: tuple[str, ...],
    wanted_by: str | None,
) -> str:
    """Render a hardened ``.service`` unit. ``wanted_by=None`` omits the ``[Install]`` section
    entirely
    (used for the sealed operator, which must never be enabled/auto-started)."""
    _validate(exec_argv, read_write_paths)
    lines = ["[Unit]", f"Description={description}", "", "[Service]", "Type=simple"]
    lines.append(f"User={user}")
    lines.append(f"Group={group}")
    lines.append("ExecStart=" + " ".join(exec_argv))
    for rw in read_write_paths:
        lines.append(f"ReadWritePaths={rw}")
    lines.extend(_HARDENING)
    if wanted_by is not None:
        lines.extend(["", "[Install]", f"WantedBy={wanted_by}"])
    return "\n".join(lines) + "\n"


def render_operator_unit_disabled(*, exec_argv: tuple[str, ...], user: str, group: str) -> str:
    """The SEALED controlled-live operator unit: hardened, and with NO [Install]/WantedBy and no
    auto-start, so it is installed present-but-disabled and can never be started by the
    bootstrap."""
    return render_service_unit(
        description="SECP controlled-live operator (SEALED — never auto-started)",
        exec_argv=exec_argv,
        user=user,
        group=group,
        read_write_paths=(),
        wanted_by=None,
    )


def unit_identity(content: str) -> str:
    return sha256_bytes(content.encode("utf-8"))
