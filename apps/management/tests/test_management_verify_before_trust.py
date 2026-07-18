"""Verify-before-trust ordering (SECP-PR5E round 6 blocker 4).

Neither pre-existing classification nor rollback branches on the evidence mode / created-or-adopted
classification / created_records BEFORE the detached attestation has verified. So a forged mode
rewrite (installed↔adopted, made internally consistent so it parses) always fails as
``evidence_attestation_untrusted`` / ``preexisting_evidence_unauthenticated`` — never as a
mode-specific refusal (``rollback_refused_adopted_installation`` /
``bootstrap_over_adopted_refused``
/ ``adopt_over_installed_refused``) and never reaching rollback planning.
"""

from __future__ import annotations

import json

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
from secp_management.cli import run

_ID = "/var/lib/secp/bootstrap/worker-identity.json"
_EV = "/var/lib/secp/bootstrap/worker-evidence.json"
_ATT = "/var/lib/secp/bootstrap/worker-evidence.attestation.json"
_FIVE = (
    _ID,
    "/var/lib/secp/bootstrap/worker-installed-release.json",
    "/var/lib/secp/bootstrap/worker-installed-release.sig.json",
    _EV,
    _ATT,
)


def _read(fs, path):
    return fs.safe_read(path, max_bytes=1 << 18, expected_uid=0)


def _forge_mode(fs, new_mode, new_class):
    """Rewrite the (canonical) evidence to a DIFFERENT mode + coherent classifications so it parses;
    the detached attestation — signed over the original — no longer matches it."""
    doc = json.loads(_read(fs, _EV))
    doc["mode"] = new_mode
    for r in doc["object_records"]:
        r["classification"] = new_class
    fs.seed_file(_EV, canonical_json(doc).encode(), mode=0o640, uid=0)


def _installed():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    assert (
        run(
            ["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"],
            deps_for(fs, fresh_worker_world(), trust),
        )[0]
        == 0
    )
    return fs, trust, bd


def _adopted():
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
    return fs, trust, bd


def test_forged_installed_to_adopted_rollback_fails_as_attestation_untrusted():
    fs, trust, _bd = _installed()
    _forge_mode(fs, "adopted", "adopted")  # would trigger rollback_refused_adopted_installation
    code, rep = run(
        ["rollback", "worker", "--write", "--confirm"], deps_for(fs, fresh_worker_world(), trust)
    )
    assert code == 2 and rep["reason_code"] == "evidence_attestation_untrusted"
    assert all(
        p in set(fs.paths()) for p in _FIVE
    )  # rollback planning never reached; nothing removed


def test_forged_installed_to_adopted_rebootstrap_fails_as_unauthenticated():
    fs, trust, bd = _installed()
    _forge_mode(fs, "adopted", "adopted")  # would trigger bootstrap_over_adopted_refused
    deps = deps_for(fs, fresh_worker_world(), trust)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "preexisting_evidence_unauthenticated"
    assert deps.worker_adapter._w.ops == []  # attestation checked before mode logic + any host op


def test_forged_adopted_to_installed_readopt_fails_as_unauthenticated():
    fs, trust, bd = _adopted()
    _forge_mode(fs, "installed", "created")  # would trigger adopt_over_installed_refused
    deps = deps_for(fs, prepared_worker_world(), trust)
    code, rep = run(["adopt", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "preexisting_evidence_unauthenticated"
    assert deps.worker_adapter._w.ops == []
