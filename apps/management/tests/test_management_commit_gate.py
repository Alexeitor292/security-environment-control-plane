"""The detached attestation is the TRUE commit point (SECP-PR5E round 6 blocker 2).

After writing evidence + attestation, bootstrap/adoption re-reads the COMPLETE installed
five-document
state through the hardened filesystem, re-parses the installed attestation, verifies the canonical
evidence bytes and the Ed25519 signature against ``evidence_trust_root``, and confirms the expected
key id / role / installation id / release aggregate / mode plus exact owner/mode/type/link-count
metadata. A bad authenticator (malformed hex, correctly-sized invalid signature, valid signature
under the wrong key, wrong key id, or a valid signature over an altered envelope) NEVER yields
mode=written or mode=adopted — the transaction compensates and refuses.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from _mgmt_support import (
    InvalidSignatureAuthenticator,
    MalformedHexAuthenticator,
    TamperingAuthenticator,
    WrongKeyAuthenticator,
    WrongKeyIdAuthenticator,
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.cli import run

_FIVE = (
    "/var/lib/secp/bootstrap/worker-identity.json",
    "/var/lib/secp/bootstrap/worker-installed-release.json",
    "/var/lib/secp/bootstrap/worker-installed-release.sig.json",
    "/var/lib/secp/bootstrap/worker-evidence.json",
    "/var/lib/secp/bootstrap/worker-evidence.attestation.json",
)

_DOUBLES = [
    (MalformedHexAuthenticator, "attestation_not_hex"),
    (InvalidSignatureAuthenticator, "evidence_attestation_untrusted"),
    (WrongKeyAuthenticator, "evidence_attestation_untrusted"),
    (WrongKeyIdAuthenticator, "evidence_attestation_untrusted"),
    (TamperingAuthenticator, "evidence_attestation_untrusted"),
]


def _seed(world):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    return fs, bd, deps_for(fs, world, trust)


@pytest.mark.parametrize("double,reason", _DOUBLES, ids=[d.__name__ for d, _ in _DOUBLES])
def test_bad_authenticator_never_returns_written(double, reason):
    fs, bd, deps = _seed(fresh_worker_world())
    deps = replace(deps, evidence_authenticator=double())
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["mode"] != "written"
    assert rep["reason_code"] == reason
    assert not any(p in set(fs.paths()) for p in _FIVE)  # every document compensated


@pytest.mark.parametrize("double,reason", _DOUBLES, ids=[d.__name__ for d, _ in _DOUBLES])
def test_bad_authenticator_never_returns_adopted(double, reason):
    fs, bd, deps = _seed(prepared_worker_world())
    deps = replace(deps, evidence_authenticator=double())
    code, rep = run(["adopt", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["mode"] != "adopted"
    assert rep["reason_code"] == reason
    assert not any(p in set(fs.paths()) for p in _FIVE)


def test_valid_authenticator_passes_the_commit_gate():
    fs, bd, deps = _seed(fresh_worker_world())  # the default is the valid ephemeral authenticator
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    assert all(p in set(fs.paths()) for p in _FIVE)
