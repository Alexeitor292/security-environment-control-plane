"""Adapter receipts + partial-effect compensation (SECP-PR5E round 3 blocker 4).

Each mutation adapter accumulates a :class:`BootstrapReceipt` of the host objects it actually
created;
on a partial failure the engine compensates ONLY those objects using that exact receipt (and only
the
documents it newly created), reporting ``recovery_required`` when the compensation cannot be proven.
"""

from __future__ import annotations

from _mgmt_support import (
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.cli import run

_DOCS = (
    "/var/lib/secp/bootstrap/worker-identity.json",
    "/var/lib/secp/bootstrap/worker-installed-release.json",
    "/var/lib/secp/bootstrap/worker-installed-release.sig.json",
    "/var/lib/secp/bootstrap/worker-evidence.json",
)


def _worker(**overrides):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(**overrides), trust)
    return deps, bd, fs


def test_receipt_records_only_performed_operations():
    deps, bd, _fs = _worker()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    receipt = deps.worker_adapter.receipt()
    assert receipt.loaded_images  # the image archive was loaded
    assert receipt.installed_configs and receipt.installed_units and receipt.installed_packages
    assert receipt.started_services == ("ordinary",)  # ONLY the ordinary worker was started


def test_mid_operation_failure_compensates_partial_host_effect():
    # the deployment-package install fails after images + config were installed; the transaction
    # refuses, writes no document, and compensates the partial host effect (images discarded).
    deps, bd, fs = _worker(fail_on="install_deployment_package")
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "fake_host_op_failed"
    assert not any(d in set(fs.paths()) for d in _DOCS)
    assert deps.worker_adapter._w.loaded_images == set()  # compensated


def test_reobservation_failure_compensates_documents_and_started_service():
    # host ops succeed but the ordinary worker starts unhealthy; the final reobservation fails, so
    # the newly written identity/record/signature are removed AND the started service is
    # compensated.
    deps, bd, fs = _worker(start_healthy=False)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "worker_ordinary_not_ready"
    assert not any(d in set(fs.paths()) for d in _DOCS)
    assert deps.worker_adapter._w.ordinary_present is False  # started service compensated


def test_unprovable_compensation_reports_recovery_required():
    deps, bd, fs = _worker(start_healthy=False, compensation_fails=True)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"
    assert not any(d in set(fs.paths()) for d in _DOCS)  # documents still compensated


def test_sealed_adapter_needs_no_host_compensation():
    from dataclasses import replace

    from secp_management.adapters import SealedWorkerBootstrapAdapter

    deps, bd, fs = _worker()
    sealed = replace(deps, worker_adapter=SealedWorkerBootstrapAdapter())
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], sealed)
    # the sealed adapter performed nothing, so the original refusal propagates (not
    # recovery_required)
    assert code == 2 and rep["reason_code"] == "worker_bootstrap_adapter_not_provisioned"
    assert not any(d in set(fs.paths()) for d in _DOCS)


# --- round 5 blocker 3: once a host op is attempted, a lost/malformed/unprovable receipt is NOT
#     proof of no effect and MUST report recovery_required (never an ordinary refusal) ---


def test_partial_effect_then_receipt_retrieval_raises_reports_recovery_required():
    # the package install fails AFTER images + config were mutated, and receipt retrieval then
    # raises — the engine cannot account for the partial host effect, so it fails closed.
    deps, bd, fs = _worker(fail_on="install_deployment_package", receipt_raises=True)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"
    assert not any(d in set(fs.paths()) for d in _DOCS)


def test_partial_effect_then_malformed_receipt_reports_recovery_required():
    deps, bd, fs = _worker(fail_on="install_deployment_package", receipt_malformed=True)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"
    assert not any(d in set(fs.paths()) for d in _DOCS)


def test_partial_effect_then_compensation_raises_reports_recovery_required():
    deps, bd, fs = _worker(fail_on="install_deployment_package", compensation_raises=True)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"
    assert not any(d in set(fs.paths()) for d in _DOCS)


def test_partial_effect_with_residual_compensation_reports_recovery_required():
    # compensation returns a typed residual (host objects it could not prove removed) → fail closed.
    deps, bd, fs = _worker(fail_on="install_deployment_package", compensation_fails=True)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"
    assert not any(d in set(fs.paths()) for d in _DOCS)
