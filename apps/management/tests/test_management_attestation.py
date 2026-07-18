"""Independent evidence authentication via a detached, signed attestation (SECP-PR5E round 5
blocker 1).

Evidence is NOT trusted until its detached attestation verifies against the reviewed evidence
anchor.
Status, ``evidence``, pre-existing classification, adoption, and rollback all verify the attestation
before trusting the evidence mode/classification/ownership/timestamps/object records. A canonical
evidence rewrite (including adopted→installed) is refused before rollback planning.
"""

from __future__ import annotations

import json
from dataclasses import replace

from _mgmt_support import (
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.canonical import canonical_json
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.adapters import SealedEvidenceAuthenticator
from secp_management.cli import run
from secp_management.signing import ReleaseTrustRoot, TrustAnchor, generate_keypair

_ID = "/var/lib/secp/bootstrap/worker-identity.json"
_EV = "/var/lib/secp/bootstrap/worker-evidence.json"
_ATT = "/var/lib/secp/bootstrap/worker-evidence.attestation.json"


def _installed():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(), trust)
    assert run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)[0] == 0
    return fs, trust


def _read(fs, path):
    return fs.safe_read(path, max_bytes=1 << 18, expected_uid=0)


def test_bootstrap_writes_the_detached_attestation():
    fs, _trust = _installed()
    assert _ATT in set(fs.paths())


def test_sealed_authenticator_refuses_bootstrap():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = replace(
        deps_for(fs, fresh_worker_world(), trust),
        evidence_authenticator=SealedEvidenceAuthenticator(),
    )
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "evidence_authenticator_not_provisioned"
    assert _EV not in set(fs.paths()) and _ATT not in set(fs.paths())


def test_status_refuses_missing_attestation():
    fs, trust = _installed()
    fs.remove_file(_ATT)
    _code, st = run(["status", "worker"], deps_for(fs, prepared_worker_world(), trust))
    assert st["ok"] is False
    assert st["dimensions"]["drift"] in ("attestation_unreadable", "fs_read_not_regular")


def test_status_refuses_untrusted_attestation_anchor():
    fs, trust = _installed()
    # keep the RELEASE trust root, but verify the evidence attestation against a DIFFERENT anchor
    # (same key_id, wrong public key) → the detached attestation no longer verifies.
    _p, pub = generate_keypair()
    wrong_anchor = ReleaseTrustRoot(
        anchors=(TrustAnchor("secp-test-evidence-anchor/v1", pub),), test_only=True
    )
    deps = replace(deps_for(fs, prepared_worker_world(), trust), evidence_trust_root=wrong_anchor)
    _code, st = run(["status", "worker"], deps)
    assert st["ok"] is False and st["dimensions"]["drift"] == "evidence_attestation_untrusted"


def test_evidence_command_reports_unauthenticated_on_tamper():
    # rewrite the transaction timestamp — an internally-consistent, parseable evidence whose ONLY
    # defect is that its bytes no longer match the detached attestation → reported unauthenticated.
    fs, trust = _installed()
    doc = json.loads(_read(fs, _EV))
    doc["transaction_timestamp"] = "2030-01-01T00:00:00+00:00"  # bound by the attestation
    fs.seed_file(_EV, canonical_json(doc).encode(), mode=0o640, uid=0)
    code, rep = run(["evidence", "worker"], deps_for(fs, prepared_worker_world(), trust))
    assert code == 2 and rep["authenticated"] is False
    assert rep["reason_code"] == "evidence_attestation_untrusted"


def test_adopted_to_installed_rewrite_refused_before_rollback():
    # forge an ADOPTED install's evidence to claim installed/created so rollback would own it; the
    # attestation (which binds mode + classification) refuses before any rollback planning.
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    assert (
        run(
            ["adopt", "worker", "--bundle", bd, "--write", "--confirm"],
            deps_for(fs, prepared_worker_world(), trust),
        )[0]
        == 0
    )
    doc = json.loads(_read(fs, _EV))
    doc["mode"] = "installed"
    for rec in doc["object_records"]:
        rec["classification"] = "created"
    fs.seed_file(_EV, canonical_json(doc).encode(), mode=0o640, uid=0)
    code, rep = run(
        ["rollback", "worker", "--write", "--confirm"], deps_for(fs, prepared_worker_world(), trust)
    )
    assert code == 2 and rep["reason_code"] == "evidence_attestation_untrusted"
    assert _EV in set(fs.paths()) and _ID in set(fs.paths())  # nothing removed
