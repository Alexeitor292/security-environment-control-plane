"""The proposed credential must be exactly what the required facts need, and nothing more.

A privilege list written by hand drifts from the fact table silently, and it always drifts the same
way: toward asking for more. So the list is derived, and this file pins that it stays derived — a
literal privilege string appearing in the renderer would pass every test that only checks the output
against another literal.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from secp_api.discovery_required_facts import privileges_required
from secp_api.proxmox_discovery_credential_proposal import (
    DISCOVERY_ACL_PATH,
    DISCOVERY_ROLE,
    DISCOVERY_TOKEN_ID,
    DISCOVERY_USER,
    WRITE_CLASS_PRIVILEGE_MARKERS,
    proposed_privileges,
    provisioning_commands,
    rollback_commands,
    unauthorized_notice,
)

MODULE = (
    Path(__file__).resolve().parents[1] / "secp_api" / "proxmox_discovery_credential_proposal.py"
)


def test_the_privilege_set_is_the_derived_one():
    assert proposed_privileges() == tuple(sorted(privileges_required()))
    assert proposed_privileges() == ("Datastore.Audit", "SDN.Audit", "Sys.Audit", "VM.Audit")


def test_no_privilege_is_write_class():
    """The audit suffix is not enough on its own — Audit.Modify would end in neither."""
    for privilege in proposed_privileges():
        assert privilege.endswith(".Audit"), privilege
        for marker in WRITE_CLASS_PRIVILEGE_MARKERS:
            assert marker not in privilege, (privilege, marker)


def test_the_renderer_contains_no_literal_privilege_string():
    """A hardcoded privilege would satisfy every output comparison while ignoring the fact table."""
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    for privilege in privileges_required():
        assert not any(privilege in text for text in literals), privilege


def test_every_command_is_a_pveum_access_control_command_and_nothing_else():
    for command in provisioning_commands() + rollback_commands():
        assert command.startswith("pveum "), command
        for banned in ("pvesh", "qm ", "pct ", "ssh ", "curl", "tofu", "terraform", "&&", "|", ";"):
            assert banned not in command, (command, banned)


def test_the_token_gets_its_own_acl_entry():
    """Under privsep=1 Proxmox checks the token's entries BEFORE the user's, so a token with none of
    its own resolves to nothing at all."""
    commands = provisioning_commands()
    assert any(f"--tokens '{DISCOVERY_TOKEN_ID}'" in c for c in commands)
    assert any(f"--user {DISCOVERY_USER}" in c for c in commands)


def test_the_backing_user_is_never_a_superuser():
    """A privsep token backed by the cluster superuser is NOT intersected with its user's rights,
    which silently defeats the entire separation."""
    assert not DISCOVERY_USER.startswith("root@")
    assert DISCOVERY_USER.endswith("@pve")
    for command in provisioning_commands():
        assert "root@" not in command


def test_one_role_at_the_root_path_only():
    """Proxmox OVERWRITES rather than unions inherited roles at a deeper level, so a second entry at
    a sub-path would REPLACE the root grant for everything beneath it."""
    assert DISCOVERY_ACL_PATH == "/"
    acl_paths = [c.split()[3] for c in provisioning_commands() if c.startswith("pveum acl modify")]
    assert set(acl_paths) == {"/"}


def test_rollback_reverses_everything_provisioning_creates():
    created = {DISCOVERY_USER, DISCOVERY_ROLE, DISCOVERY_TOKEN_ID}
    rollback = " ".join(rollback_commands())
    for name in created:
        assert name in rollback, name
    # The token is removed before the user that owns it.
    assert rollback.index("token remove") < rollback.index("user delete")


def test_the_module_cannot_execute_anything():
    """It renders strings for a human. A single subprocess import would make it something else."""
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("subprocess", "os", "shutil", "paramiko", "httpx", "requests", "asyncio"):
        assert banned not in imported, banned
    assert imported == {"__future__", "secp_api"}


def test_nothing_in_the_repository_runs_the_proposed_commands():
    """Inverted: scan for a caller rather than list the approved ones."""
    root = Path(__file__).resolve().parents[3]
    callers = []
    for path in root.rglob("*.py"):
        parts = set(path.parts)
        if "__pycache__" in parts or ".venv" in parts:
            continue
        if path.name in ("proxmox_discovery_credential_proposal.py", Path(__file__).name):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "provisioning_commands" in text or "rollback_commands" in text:
            callers.append(str(path.relative_to(root)))
    assert callers == [], callers


def test_the_notice_says_what_approving_it_does_not_authorise():
    notice = unauthorized_notice()
    assert "not been" in notice and "executed" in notice
    for unauthorised in ("live discovery", "OpenTofu plan", "apply"):
        assert unauthorised in notice, unauthorised


@pytest.mark.parametrize("renderer", [provisioning_commands, rollback_commands])
def test_the_renderers_take_no_parameters(renderer):
    """Nothing about the proposal may be supplied by a caller — it is derived or it is fixed."""
    import inspect

    assert inspect.signature(renderer).parameters == {}
