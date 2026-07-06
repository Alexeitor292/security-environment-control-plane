"""SECP-B3 — host-bootstrap authority model (§1). Fake-only; no SSH/host/network is contacted.

Proves the generated SECP ownership namespace, the typed finite host-operation contract (no raw
shell / no caller free-strings), and the deployment-local bootstrap-credential seam (sealed default,
ephemeral disposal, redaction, non-serializable).
"""

from __future__ import annotations

import pickle

import pytest
from secp_worker.staging_live.bootstrap.credential_source import (
    BootstrapCredentialDisposed,
    BootstrapCredentialUnavailable,
    EphemeralBootstrapCredential,
    SealedBootstrapCredentialSource,
)
from secp_worker.staging_live.bootstrap.host_operations import (
    ApplyDefaultDenyFirewall,
    CreateIsolatedBridge,
    ProbeNestedVirtualization,
    RemoveOwnedBridge,
    render_host_command,
)
from secp_worker.staging_live.bootstrap.ownership import (
    OwnershipNamespaceError,
    ownership_namespace,
)

_SHELL_METACHARACTERS = set(";|&`$><\n\\'\" ")


# --- ownership namespace -------------------------------------------------------------------------


def test_namespace_is_deterministic_and_pins_ownership():
    a = ownership_namespace("staging-lab-01")
    b = ownership_namespace("staging-lab-01")
    assert a.ownership_tag == b.ownership_tag
    assert ownership_namespace("staging-lab-02").ownership_tag != a.ownership_tag
    # owns() is a strict tag pin: own tag only; a foreign tag, None, or untagged is NOT owned.
    assert a.owns(a.ownership_tag) is True
    assert a.owns(ownership_namespace("staging-lab-02").ownership_tag) is False
    assert a.owns(None) is False
    assert a.owns("") is False


@pytest.mark.parametrize("label", ["", "has space", "a/b", "user@host", "vault:x", "x" * 200])
def test_namespace_rejects_unsafe_ownership_labels(label):
    with pytest.raises(OwnershipNamespaceError):
        ownership_namespace(label)


def test_namespace_generated_names_are_bounded_and_closed():
    ns = ownership_namespace("staging-lab-01")
    assert ns.resource_name("bridge", 0).startswith("secp")
    with pytest.raises(OwnershipNamespaceError):
        ns.resource_name("unknown_kind", 0)
    with pytest.raises(OwnershipNamespaceError):
        ns.resource_name("bridge", 9999)  # out of the bounded range
    with pytest.raises(OwnershipNamespaceError):
        ns.resource_name("bridge", -1)


# --- typed host operations render to discrete-token argv (no raw shell) ---------------------------


def test_operations_render_to_discrete_tokens_confined_to_namespace():
    ns = ownership_namespace("staging-lab-01")
    for op in (
        ProbeNestedVirtualization(),
        CreateIsolatedBridge(bridge_index=0),
        ApplyDefaultDenyFirewall(),
        RemoveOwnedBridge(bridge_index=1),
    ):
        cmd = render_host_command(op, ns)
        assert cmd.operation_code == op.operation_code
        assert isinstance(cmd.argv, tuple) and all(isinstance(t, str) for t in cmd.argv)
        # No token contains a shell metacharacter — the argv is exec-style, not a shell string.
        for token in cmd.argv:
            assert not (_SHELL_METACHARACTERS & set(token)), f"token has shell metachar: {token!r}"


def test_bridge_operations_are_ownership_bound_and_isolated():
    ns = ownership_namespace("staging-lab-01")
    cmd = render_host_command(CreateIsolatedBridge(bridge_index=2), ns)
    assert ns.resource_name("bridge", 2) in cmd.argv  # the generated (not caller) name
    assert ns.ownership_tag in cmd.argv  # stamped with the immutable ownership tag
    # Isolation flags are always present on a created bridge.
    for flag in ("--no-uplink", "--no-gateway", "--no-dns"):
        assert flag in cmd.argv


def test_operations_expose_no_free_form_string_field():
    # The typed operations carry ONLY a bounded int index (or nothing) + a closed operation_code —
    # never a caller-supplied bridge name, path, command, username, or argument string.
    for op in (CreateIsolatedBridge(bridge_index=0), RemoveOwnedBridge(bridge_index=0)):
        caller_fields = {k: v for k, v in vars(op).items() if k != "operation_code"}
        assert set(caller_fields) == {"bridge_index"}
        assert isinstance(caller_fields["bridge_index"], int)


# --- deployment-local bootstrap credential -------------------------------------------------------


def test_sealed_bootstrap_credential_source_refuses():
    with pytest.raises(BootstrapCredentialUnavailable):
        SealedBootstrapCredentialSource().acquire()


def test_ephemeral_credential_exposes_only_in_block_then_disposes():
    cred = EphemeralBootstrapCredential(b"one-time-ssh-secret")
    with cred as c:
        assert c.reveal() == b"one-time-ssh-secret"
    assert cred.disposed is True
    with pytest.raises(BootstrapCredentialDisposed):
        cred.reveal()


def test_ephemeral_credential_disposes_on_exception():
    cred = EphemeralBootstrapCredential(b"secret")
    with pytest.raises(RuntimeError):  # noqa: PT012
        with cred:
            raise RuntimeError("bootstrap failed")
    assert cred.disposed is True  # disposed even on failure


def test_ephemeral_credential_is_redacted_and_not_serializable():
    cred = EphemeralBootstrapCredential(b"secret")
    assert repr(cred) == "EphemeralBootstrapCredential(<redacted>)"
    assert "secret" not in repr(cred)
    with pytest.raises(TypeError):
        pickle.dumps(cred)
