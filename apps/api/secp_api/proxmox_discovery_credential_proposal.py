"""The exact read-only credential SECP proposes for Proxmox discovery. Rendered, never executed.

This exists as code rather than as a document for two reasons, and the second is the load-bearing
one:

* the guarded ``docs/proxmox/*.md`` set must stay free of concrete infrastructure values, and an
  approval artifact made of literals cannot live there;
* **the privilege set is derived, not written down.** It comes from
  :func:`secp_api.discovery_required_facts.privileges_required`, so the grant is exactly what the
  required facts need. A hand-maintained list in prose drifts from the fact table silently, and the
  direction it drifts is always toward asking for more.

Nothing here runs anything. There is no subprocess, no SSH, no client, and no function that executes
a command — the module renders strings for a human to review and run. The privileged worker never
imports it, and the commands describe a change to the TARGET's access control that only an operator
may make.
"""

from __future__ import annotations

from secp_api.discovery_required_facts import privileges_required

#: The dedicated PVE-realm user backing the token. Never an existing account, never a superuser: a
#: privilege-separated token backed by the cluster superuser is NOT intersected with its user's
#: rights, which would silently defeat the whole separation.
DISCOVERY_USER = "secpdisc@pve"
DISCOVERY_ROLE = "SECPDiscoveryReadOnly"
DISCOVERY_TOKEN_NAME = "discovery"
DISCOVERY_TOKEN_ID = f"{DISCOVERY_USER}!{DISCOVERY_TOKEN_NAME}"

#: One role at the root path. Proxmox OVERWRITES rather than unions inherited roles at a deeper
#: level, so an extra entry at a sub-path would replace the root grant for everything beneath it.
DISCOVERY_ACL_PATH = "/"
DISCOVERY_ACL_PROPAGATE = 1

#: Privilege classes that must never appear. Checked against the rendered commands by a test, so a
#: privilege added to the fact table cannot smuggle a write in behind the derivation.
WRITE_CLASS_PRIVILEGE_MARKERS: tuple[str, ...] = (
    "Allocate",
    "Modify",
    "Config",
    "PowerMgmt",
    "Console",
    "Migrate",
    "Backup",
    "Snapshot",
    "Clone",
    "Audit.Modify",
    "Permissions",
    "Realm",
    "User",
    "Group",
    "Sys.Syslog",
)


def proposed_privileges() -> tuple[str, ...]:
    """The exact privilege list, derived from the required-fact table and sorted for stability."""
    return tuple(sorted(privileges_required()))


def provisioning_commands() -> tuple[str, ...]:
    """The exact commands an operator would run. NOT executed by anything in this repository.

    The token gets its OWN acl entry: under ``privsep=1`` Proxmox checks the token's entries before
    the user's, so a token with none of its own resolves to nothing at all. Effective rights are
    then the intersection of the two, which is the property the separation exists for.
    """
    privileges = ",".join(proposed_privileges())
    return (
        f'pveum user add {DISCOVERY_USER} --comment "SECP read-only discovery"',
        f'pveum role add {DISCOVERY_ROLE} --privs "{privileges}"',
        f"pveum acl modify {DISCOVERY_ACL_PATH} --user {DISCOVERY_USER} "
        f"--role {DISCOVERY_ROLE} --propagate {DISCOVERY_ACL_PROPAGATE}",
        f"pveum user token add {DISCOVERY_USER} {DISCOVERY_TOKEN_NAME} --privsep 1",
        f"pveum acl modify {DISCOVERY_ACL_PATH} --tokens '{DISCOVERY_TOKEN_ID}' "
        f"--role {DISCOVERY_ROLE} --propagate {DISCOVERY_ACL_PROPAGATE}",
    )


def rollback_commands() -> tuple[str, ...]:
    """Exact reversal, in the order that leaves nothing orphaned. Also never executed."""
    return (
        f"pveum user token remove {DISCOVERY_USER} {DISCOVERY_TOKEN_NAME}",
        f"pveum acl delete {DISCOVERY_ACL_PATH} --tokens '{DISCOVERY_TOKEN_ID}' "
        f"--role {DISCOVERY_ROLE}",
        f"pveum acl delete {DISCOVERY_ACL_PATH} --user {DISCOVERY_USER} --role {DISCOVERY_ROLE}",
        f"pveum user delete {DISCOVERY_USER}",
        f"pveum role delete {DISCOVERY_ROLE}",
    )


def unauthorized_notice() -> str:
    """What this module is, in one line, for anything that renders it to an operator."""
    return (
        "PROPOSAL ONLY — these commands modify the target's access control and have not been "
        "executed. Approving them does not authorise live discovery, an OpenTofu plan, or an apply."
    )
