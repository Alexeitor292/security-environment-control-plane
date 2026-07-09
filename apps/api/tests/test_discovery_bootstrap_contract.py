"""SECP-B7 — Proxmox read-only discovery bootstrap CONTRACT tests (pure, no I/O, no DB).

Proves the generated bootstrap artifact is safe by construction: the forced-command allowlist
matches the worker probe contract EXACTLY (no drift), denies every write verb / shell / injection,
the script pins the forced command + disables shell/forwarding + carries no private key, and the
public-key validator rejects private-key material.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from secp_api.discovery_bootstrap_contract import (
    AUTHORIZED_KEYS_OPTIONS,
    FORCE_COMMAND_PATH,
    BootstrapContractError,
    command_is_allowed,
    render_bootstrap_script,
    render_force_command_wrapper,
    validate_public_ssh_key,
)

# Make the worker probe contract importable so we can prove the allowlist == what the worker emits.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "apps" / "worker"))


def _ed25519_pubkey(comment: str = "worker@secp") -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    line = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return f"{line} {comment}"


def _all_worker_probe_commands() -> list[str]:
    from secp_worker.deployment.locators import (
        BridgeLocator,
        FirewallGroupLocator,
        GuestLocator,
        ServiceIdentityLocator,
    )
    from secp_worker.target_discovery.probes import (
        ProbeClusterStatus,
        ProbeNestedVirtualization,
        ProbeNodeCapacity,
        ProbeNodeIdentity,
        ProbeStorage,
        ProbeVersion,
        ProbeVmidAvailability,
        candidate_presence_probe,
        render_probe_argv,
    )

    probes = [
        ProbeVersion(),
        ProbeClusterStatus(),
        ProbeNodeIdentity(),
        ProbeNodeCapacity("pve-node-1"),
        ProbeStorage("pve-node-1"),
        ProbeVmidAvailability(),
        ProbeNestedVirtualization("kvm_intel"),
        ProbeNestedVirtualization("kvm_amd"),
        candidate_presence_probe(BridgeLocator("pve-node-1", "secpabcd1234br")),
        candidate_presence_probe(FirewallGroupLocator("secpabcd1234fw")),
        candidate_presence_probe(ServiceIdentityLocator("secpabcd1234@pam")),
        candidate_presence_probe(GuestLocator("pve-node-1", 9001)),
    ]
    return [" ".join(render_probe_argv(p)) for p in probes]


def test_allowlist_matches_every_worker_probe_command_no_drift():
    # DRIFT GUARD: the forced-command wrapper must permit every command the worker probe contract
    # can emit — otherwise a legitimate read-only probe would be denied on the host.
    for cmd in _all_worker_probe_commands():
        assert command_is_allowed(cmd), f"worker probe command not allowed by bootstrap: {cmd}"


@pytest.mark.parametrize(
    "denied",
    [
        "pvesh set /nodes/x --v y",
        "pvesh create /pools/x",
        "pvesh delete /nodes/x",
        "pvesh push a b",
        "pvesh pull a b",
        "bash -i",
        "sh",
        "/bin/sh",
        "cat /etc/shadow",
        "cat /etc/passwd",
        "cat /sys/module/kvm_intel/parameters/nested extra",
        "rm -rf /",
        "pvesh get /version --output-format json; id",
        "pvesh get /version --output-format json && id",
        "pvesh get /version --output-format json | id",
        "pvesh get /nodes/$(id)/status --output-format json",
        "pvesh get /nodes/`id`/status --output-format json",
        "pvesh get /access/users/x/../../etc --output-format json",
        "pvesh get /nodes/x/status",  # missing --output-format json
        "pveversion --help",
        "scp x y",
        "",
    ],
)
def test_allowlist_denies_write_shell_and_injection(denied):
    assert not command_is_allowed(denied)


def test_public_key_validator_rejects_private_key():
    for priv in (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----",
    ):
        with pytest.raises(BootstrapContractError) as exc:
            validate_public_ssh_key(priv)
        assert exc.value.reason_code == "public_key_looks_private"


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "notatype AAAA", "ssh-ed25519", "ssh-ed25519 not-base64!!", "ssh-ed25519\nAAAA"],
)
def test_public_key_validator_rejects_malformed(bad):
    with pytest.raises(BootstrapContractError):
        validate_public_ssh_key(bad)


def test_public_key_validator_accepts_and_fingerprints():
    normalized, fp = validate_public_ssh_key(_ed25519_pubkey())
    assert normalized.startswith("ssh-ed25519 ")
    assert fp.startswith("SHA256:") and len(fp) > 20


def test_public_key_type_blob_mismatch_rejected():
    # An ed25519-labeled line whose base64 blob declares ssh-rsa is rejected.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_line = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    blob = rsa_line.split()[1]
    with pytest.raises(BootstrapContractError) as exc:
        validate_public_ssh_key(f"ssh-ed25519 {blob}")
    assert exc.value.reason_code == "public_key_type_mismatch"


def test_script_pins_forced_command_and_restrictions_and_no_private_key():
    script = render_bootstrap_script(public_ssh_key=_ed25519_pubkey(), session_id="sess1234")
    assert f'command="{FORCE_COMMAND_PATH}"' in script
    for opt in AUTHORIZED_KEYS_OPTIONS:
        assert opt in script
    for restriction in ("no-pty", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding"):
        assert restriction in script
    assert "nologin" in script  # no interactive shell for the account
    assert "pveum role add" in script and "pveum acl modify" in script  # scoped audit role
    assert "SECPDISC-PROOF" in script  # bounded proof block
    assert "PRIVATE KEY" not in script  # never emits private key material


def test_script_requires_public_key_rejects_private():
    priv = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----"
    with pytest.raises(BootstrapContractError):
        render_bootstrap_script(public_ssh_key=priv)


def test_wrapper_is_deterministic_and_bounded():
    w1 = render_force_command_wrapper()
    w2 = render_force_command_wrapper()
    assert w1 == w2  # deterministic
    assert w1.startswith("#!/bin/sh")
    assert "exit 42" in w1  # denies with a fixed non-zero code
    assert "set -f" in w1  # no glob expansion of the original command


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
