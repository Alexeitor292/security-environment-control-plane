"""Produce GENUINE authenticated pending content for tests, through the real path.

Not a backdoor and deliberately not a shortcut: this signs a real binding with a real Ed25519 key,
verifies it against a matching registered anchor, and authenticates content whose recomputed fact
commitment equals the signed ``facts_hash``. If any of those steps stopped working, every test that
builds a document through here would fail — which is the point. A helper that fabricated an
``AuthenticatedPendingContent`` directly would make the whole type decorative.

Filename starts with an underscore so pytest's ``test_*.py`` / ``*_test.py`` collection globs — and
the shard inventory that uses the same globs — do not treat it as a suite.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secp_api.discovery_fact_commitment import build_fact_commitment, canonical_value
from secp_api.discovery_fact_projection import REQUIRED_FACT_PROJECTION_ID
from secp_api.discovery_observation import Observation
from secp_api.discovery_verification import (
    DISCOVERY_CONTRACT_VERSION,
    DISCOVERY_SNAPSHOT_DOMAIN,
    DISCOVERY_SNAPSHOT_KIND,
    DiscoverySnapshotBinding,
    ExpectedWorkerRegistration,
    verify_discovery_snapshot,
)
from secp_api.sdn_pending_observation import authenticate_pending_content
from secp_commissioning.canonical import sha256_digest
from secp_commissioning.enrollment_attestation import key_id_for, sign_detached
from secp_management.signing import generate_keypair

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)

DEFAULT_ORG = "org-abc"
DEFAULT_TARGET = "target-abc"
DEFAULT_OPERATION = "op-1"
DEFAULT_GENERATION = 3
DEFAULT_WORKER = "wk-1"
DEFAULT_ROLE = "proxmox_privileged"
DEFAULT_RELEASE = "sha256:rel"
#: Matches the ``cluster_identity`` observation below, because the commitment binds the fingerprint
#: derived from it and the document reads the same derivation.
DEFAULT_CLUSTER_IDENTITY = {"kind": "cluster", "cluster_name": "lab"}


def cluster_fingerprint(observations) -> str:
    """The control plane's derivation, restated here so a test can assert the expected value."""
    identity = observations.get("cluster_identity")
    if identity is None or not identity.is_usable:
        return ""
    return sha256_digest({"cluster_identity": canonical_value(identity.value)})


def signed_snapshot(
    *,
    observations=None,
    required_facts=None,
    contributions=None,
    pending_sdn_state: str = "observed",
    organization_identity: str = DEFAULT_ORG,
    target_identity: str = DEFAULT_TARGET,
    operation_identity: str = DEFAULT_OPERATION,
    operation_generation: int = DEFAULT_GENERATION,
    observed_at: datetime | None = None,
    facts_hash: str | None = None,
):
    """A real authority plus the content it authenticates.

    ``pending_sdn_state`` is what the WORKER signs for that fact. Passing ``permission_denied`` here
    produces an authority that attests the worker could not read the pending SDN state — the exact
    premise a document must not be able to contradict.

    ``facts_hash`` overrides the signed digest, so a test can sign one thing and offer another.
    """
    observations = (
        observations
        if observations is not None
        else {"cluster_identity": Observation.observed(dict(DEFAULT_CLUSTER_IDENTITY))}
    )
    required_facts = required_facts if required_facts is not None else {}
    contributions = contributions if contributions is not None else {}
    completed = observed_at if observed_at is not None else NOW - timedelta(minutes=1)

    commitment = build_fact_commitment(
        observations=observations,
        required_facts=required_facts,
        contributions=contributions,
        organization_identity=organization_identity,
        target_identity=target_identity,
        cluster_fingerprint=cluster_fingerprint(observations),
        operation_identity=operation_identity,
        operation_generation=operation_generation,
    )

    priv, pub = generate_keypair()
    binding = DiscoverySnapshotBinding(
        discovery_contract_version=DISCOVERY_CONTRACT_VERSION,
        operation_identity=operation_identity,
        operation_generation=operation_generation,
        organization_identity=organization_identity,
        target_identity=target_identity,
        requested_target_authority="pve.example.test",
        worker_installation_id=DEFAULT_WORKER,
        worker_role=DEFAULT_ROLE,
        worker_release_fingerprint=DEFAULT_RELEASE,
        signer_fingerprint=key_id_for(pub),
        observation_started_at=(completed - timedelta(seconds=20)).isoformat(),
        observation_completed_at=completed.isoformat(),
        freshness_bound_seconds=1800,
        facts_hash=facts_hash if facts_hash is not None else commitment.digest(),
        operation_manifest_hash=sha256_digest({"manifest": {}}),
        projection_implementation_id=REQUIRED_FACT_PROJECTION_ID,
        required_fact_observation_states=(("pending_sdn_state", pending_sdn_state),),
    )
    attestation = sign_detached(
        priv,
        domain=DISCOVERY_SNAPSHOT_DOMAIN,
        kind=DISCOVERY_SNAPSHOT_KIND,
        digest=binding.digest(),
    )
    _projection, authority = verify_discovery_snapshot(
        binding=binding,
        attestation=attestation,
        registration=ExpectedWorkerRegistration(
            worker_installation_id=DEFAULT_WORKER,
            worker_release_fingerprint=DEFAULT_RELEASE,
            verification_anchor_fingerprint=key_id_for(pub),
            organization_identity=organization_identity,
        ),
        expected_operation_identity=operation_identity,
        expected_operation_generation=operation_generation,
        expected_target_identity=target_identity,
        expected_organization_identity=organization_identity,
        facts_hash=binding.facts_hash,
        operation_manifest_hash=binding.operation_manifest_hash,
        compilation_required_facts=(),
        apply_required_facts=(),
        now=NOW,
    )
    assert authority is not None, "the helper must produce a real authority"
    return authority, observations, required_facts, contributions


def authenticated(**kwargs):
    """Just the authenticated content, for tests that only need a document to exist."""
    authority, observations, required_facts, contributions = signed_snapshot(**kwargs)
    return authenticate_pending_content(
        authority=authority,
        observations=observations,
        required_facts=required_facts,
        contributions=contributions,
    )
