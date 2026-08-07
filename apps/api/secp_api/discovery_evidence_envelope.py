"""Authenticated discovery evidence — a signature over a binding, not a hash over a file.

``DiscoverySnapshot.evidence_hash`` is an unkeyed SHA-256 over canonical JSON. That is
tamper-EVIDENT against accidental corruption and proves nothing about who produced the bytes:
anyone who can write the row can recompute the hash. A plan that will authorise real infrastructure
changes cannot rest on it.

This module adds the missing half. It reuses ``secp_commissioning.enrollment_attestation`` — the
repository's existing primitive where a **worker signs** and the **control plane verifies** — rather
than inventing a discovery-only signing scheme. Two properties of that primitive are why it is the
right one and not merely an available one:

* it is domain-separated, so an attestation minted for one protocol cannot be replayed into
  another. Discovery gets its OWN domain here, not a new ``kind`` inside the enrollment domain,
  because a discovery observation must never be presentable as an enrollment proof;
* ``verify_detached`` refuses when ``key_id_for(public_key_hex) != key_id`` — the pinned id must
  derive from the presented key. There is no free-floating trust anchor to substitute.

**What is signed is the BINDING, not the file.** A signature over "the JSON at this location" says
nothing about which target was observed, by which worker, when, or with which probes — all of which
a later reader needs and none of which a file path carries. The binding names them, and the
signature covers the binding's digest.

**The facts hash is computed over the facts alone.** The envelope lives beside the facts, never
inside the dict it attests, so the signature never has to cover a structure that contains it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secp_commissioning.canonical import sha256_digest
from secp_commissioning.enrollment_attestation import (
    AttestationError,
    DetachedAttestation,
    key_id_for,
    sign_detached,
    verify_detached,
)

#: Discovery's OWN attestation domain. Deliberately not a new ``kind`` inside
#: ``ENROLLMENT_ATTESTATION_DOMAIN``: the domain is the cross-protocol replay barrier, so a signed
#: discovery observation must be unable to satisfy an enrollment verifier and vice versa.
DISCOVERY_ATTESTATION_DOMAIN = "secp.target-discovery.observation/v1"

#: The one ``kind`` within that domain today. A second observation kind (a re-observation, a
#: narrowed re-probe) would be a new member here rather than a reuse of this one.
SNAPSHOT_KIND = "target-discovery-snapshot"

#: The canonical schema tag carried inside the binding, so a reader can tell which shape it is
#: verifying before it starts reading fields.
DISCOVERY_BINDING_SCHEMA = "secp.target-discovery.binding/v1"

#: The key under which the envelope is stored beside the facts in ``DiscoverySnapshot.evidence``.
#: Reserved: the facts hash is computed over the dict with this key REMOVED, so a fact named
#: ``signed_binding`` would silently fall out of the attested set.
ENVELOPE_KEY = "signed_binding"


class DiscoveryEnvelopeError(ValueError):
    """The binding could not be built, or does not describe what it claims to."""


@dataclass(frozen=True)
class ProbeRecord:
    """One executed probe, as evidence rather than as a log line.

    The exact rendered argv is carried because "we ran the version probe" is a claim and
    ``('pvesh', 'get', '/version', '--output-format', 'json')`` is a fact — a later reviewer can
    confirm from the record alone that nothing mutating was executed, without trusting the
    producer's summary of itself.

    The argv is safe to persist for a structural reason, not by inspection: the probe grammar
    admits three executables and one verb, and every parameter it interpolates is a node, storage
    or group LABEL. No endpoint, credential or path can appear in it.
    """

    probe_code: str
    argv: tuple[str, ...]
    #: sha256 of the raw probe stdout. The output itself is deliberately NOT carried — it is
    #: unbounded, and the digest is what lets a re-run be compared against this one.
    result_digest: str
    #: The per-field observation state this probe produced, as a
    #: ``DiscoveryObservationState`` value. Present so a refusal is attributable to the probe that
    #: hit it rather than inferred from a missing field.
    outcome: str
    reason_code: str = ""


@dataclass(frozen=True)
class DiscoveryBinding:
    """Everything the signature covers.

    Each field answers a question a later reader must not have to take on trust: *which contract,
    of what, by whom, running what, when, how, and how complete.*
    """

    # --- which contract -----------------------------------------------------------------------
    discovery_document_version: str
    #: sha256 over the canonical FACTS — the evidence dict with the envelope key removed.
    facts_hash: str

    # --- of what ------------------------------------------------------------------------------
    target_identity: str
    #: Empty when the cluster identity was not observed. Empty is a real answer here and is
    #: distinguished from a wrong one by the observation states carried in ``unobserved_facts``.
    cluster_identity: str = ""

    # --- by whom, running what ----------------------------------------------------------------
    worker_installation_id: str = ""
    worker_role: str = ""
    worker_release_fingerprint: str = ""
    #: The signer's key id, carried INSIDE the signed bytes as well as on the attestation. Without
    #: it, an attestation could be swapped for one by a different trusted key over the same binding
    #: and the binding would not notice.
    signing_key_fingerprint: str = ""

    # --- when ---------------------------------------------------------------------------------
    observation_started_at: str = ""
    observation_completed_at: str = ""
    freshness_bound_seconds: int = 0

    # --- how ----------------------------------------------------------------------------------
    #: Ordered: the sequence is part of the evidence, because a probe's result can depend on what
    #: ran before it.
    probe_manifest: tuple[ProbeRecord, ...] = ()
    #: The exact parser/projection implementation that produced the facts. A snapshot parsed by a
    #: different implementation is a different observation even from identical raw output.
    projection_implementation_id: str = ""

    # --- how complete -------------------------------------------------------------------------
    observed_required_facts: tuple[str, ...] = ()
    #: ``(fact, observation_state)`` pairs. The state is inside the signature so a consumer cannot
    #: be told a fact was merely absent when the producer recorded it as permission-denied.
    unobserved_required_facts: tuple[tuple[str, str], ...] = ()
    refusal_reasons: tuple[str, ...] = field(default_factory=tuple)


def facts_hash(evidence: dict) -> str:
    """The canonical hash of the FACTS, with the envelope excluded.

    Excluding the envelope is what keeps the signature non-circular: the attestation attests a
    digest, and that digest must be computable both before the envelope exists (to sign) and after
    it is stored (to verify).
    """
    # `sha256_digest` canonicalises the payload itself — it takes the OBJECT, not encoded bytes.
    # Encoding first and passing the bytes double-encodes and raises, which is the kind of mistake
    # a signature layer must not make quietly.
    facts = {k: v for k, v in evidence.items() if k != ENVELOPE_KEY}
    return sha256_digest(facts)


def canonical_binding(binding: DiscoveryBinding) -> dict:
    """The binding as canonical, JSON-safe data. This is what gets digested and signed."""
    return {
        "schema": DISCOVERY_BINDING_SCHEMA,
        "discovery_document_version": binding.discovery_document_version,
        "facts_hash": binding.facts_hash,
        "target_identity": binding.target_identity,
        "cluster_identity": binding.cluster_identity,
        "worker_installation_id": binding.worker_installation_id,
        "worker_role": binding.worker_role,
        "worker_release_fingerprint": binding.worker_release_fingerprint,
        "signing_key_fingerprint": binding.signing_key_fingerprint,
        "observation_started_at": binding.observation_started_at,
        "observation_completed_at": binding.observation_completed_at,
        "freshness_bound_seconds": binding.freshness_bound_seconds,
        "probe_manifest": [
            {
                "probe_code": record.probe_code,
                "argv": list(record.argv),
                "result_digest": record.result_digest,
                "outcome": record.outcome,
                "reason_code": record.reason_code,
            }
            for record in binding.probe_manifest
        ],
        "projection_implementation_id": binding.projection_implementation_id,
        "observed_required_facts": list(binding.observed_required_facts),
        "unobserved_required_facts": [list(pair) for pair in binding.unobserved_required_facts],
        "refusal_reasons": list(binding.refusal_reasons),
    }


def binding_digest(binding: DiscoveryBinding) -> str:
    return sha256_digest(canonical_binding(binding))


def sign_discovery_binding(private_key_hex: str, binding: DiscoveryBinding) -> DetachedAttestation:
    """Sign a binding with the worker's dedicated enrollment key.

    Refuses when the binding's own ``signing_key_fingerprint`` does not match the key doing the
    signing. That field is inside the signed bytes precisely so it cannot be swapped afterwards,
    and a binding that names one signer while another signs it is incoherent rather than merely
    unusual.
    """
    attestation = sign_detached(
        private_key_hex,
        domain=DISCOVERY_ATTESTATION_DOMAIN,
        kind=SNAPSHOT_KIND,
        digest=binding_digest(binding),
    )
    if binding.signing_key_fingerprint and binding.signing_key_fingerprint != attestation.key_id:
        raise DiscoveryEnvelopeError(
            "binding names a different signing key than the one signing it"
        )
    return attestation


def verify_discovery_binding(
    binding: DiscoveryBinding,
    attestation: DetachedAttestation,
    *,
    expected_key_id: str,
    evidence: dict | None = None,
) -> tuple[str, ...]:
    """Every reason the envelope does not authenticate. Empty means it does.

    ``expected_key_id`` is the trust anchor and must come from the control plane's own record of
    the worker — ``WorkerIdentityRegistration.verification_anchor_fingerprint`` — never from the
    envelope. An envelope that supplies its own expected key verifies itself.

    Passing ``evidence`` additionally re-derives the facts hash and checks the binding against it,
    which is what stops a valid signature being reattached to different facts.
    """
    reasons: list[str] = []

    if not expected_key_id:
        # Fail closed rather than skipping the check. A caller with no anchor cannot verify
        # anything, and treating that as "no objections" is how an unverified snapshot passes.
        return ("discovery_evidence_no_trust_anchor",)

    try:
        verify_detached(
            attestation,
            domain=DISCOVERY_ATTESTATION_DOMAIN,
            kind=SNAPSHOT_KIND,
            digest=binding_digest(binding),
            expected_key_id=expected_key_id,
        )
    except AttestationError as exc:
        reasons.append(f"discovery_attestation_invalid:{exc}")

    # Carried in the signed bytes AND on the attestation, so a swap between two trusted keys over
    # the same binding is detectable.
    if binding.signing_key_fingerprint and binding.signing_key_fingerprint != attestation.key_id:
        reasons.append("discovery_binding_signer_mismatch")

    if evidence is not None:
        actual = facts_hash(evidence)
        if actual != binding.facts_hash:
            reasons.append("discovery_facts_hash_mismatch")

    return tuple(reasons)


def envelope_for_storage(binding: DiscoveryBinding, attestation: DetachedAttestation) -> dict:
    """The envelope as stored beside the facts under :data:`ENVELOPE_KEY`.

    Public material only — algorithm, key id, public key, signature. The repository already
    classifies exactly this triple as safe to persist; no private key, no endpoint, no credential
    and no raw probe output appears here.
    """
    return {
        "binding": canonical_binding(binding),
        "attestation": {
            "algorithm": attestation.algorithm,
            "key_id": attestation.key_id,
            "public_key_hex": attestation.public_key_hex,
            "signature": attestation.signature,
        },
    }


def anchor_matches(public_key_hex: str, expected_key_id: str) -> bool:
    """Whether a presented public key derives the expected anchor fingerprint.

    Thin, but named: the control plane stores only the FINGERPRINT of the worker's verification
    anchor, so the envelope supplies the key and this is the step that binds the two. Calling
    ``key_id_for`` inline at each site is how one of them ends up comparing the hex instead.
    """
    try:
        return key_id_for(public_key_hex) == expected_key_id
    except ValueError:
        return False
