"""The canonical document a discovery snapshot's signature actually covers.

The defect this module replaces: ``facts_hash`` was
``sha256({"observations": sorted((code, state) ...)})``. It bound the NAME and the STATE of every
fact and nothing else. Every value SECP makes a decision from — VMIDs, CTIDs, VLAN tags, CIDRs,
subnet ids, bridge names, VNet ids, storage and template identifiers, and the whole pending SDN
set — travelled outside the signature. Rewriting any of them left the digest, the signed
required-fact states and the verifier's projection byte-identical, so a snapshot with substituted
network values still verified as authentic and compilation-eligible.

What the commitment binds, and why each is separate rather than folded into the value:

``value``
    The semantic value itself, canonicalised. Nested mappings are ordered, so membership is part of
    the digest: dropping one node from ``node_capacity`` changes it.
``scope``
    The key structure, restated. Redundant with ``value`` on purpose — a canonicaliser bug that
    silently dropped keys would still be caught, and the scope answers "which nodes/storages does
    this fact speak for" without a consumer having to walk the value.
``state`` / ``reason_code`` / ``missing_privilege``
    Why an unusable fact is unusable. A snapshot whose ``permission_denied`` is rewritten to
    ``not_requested`` is a different snapshot: one names a grant to request, the other does not.
``contributions``
    Every operation that fed the fact, with what it produced — including the ones that FAILED.
    A refusal that another source overwrote is still in here, so "this fact is observed" and "one of
    its sources was denied" cannot both be true and only one be visible.
``required_facts``
    The projected completeness answer per required fact. The raw set says what endpoints reported;
    this says whether the cluster as a whole is known.
``binding``
    Target, cluster fingerprint, organization, operation and generation. Without these the same
    fact set is replayable against a different cluster or a different operation.

Everything is ordered deterministically, so two runs that observed the same thing produce the same
digest and any difference is a real difference.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from secp_commissioning.canonical import sha256_digest

from secp_api.discovery_observation import Observation

#: Bumping this changes every digest, which is the point: a change to what the signature covers must
#: not be silently compatible with snapshots signed under the old contract.
FACT_COMMITMENT_VERSION = "secp.discovery-fact-commitment/v1"


def canonical_value(value: object) -> object:
    """Normalise an observation value to a deterministic JSON-safe shape.

    The ONE canonicaliser. A second one would be a second answer to "what did we observe", and this
    repository has produced three of those already.

    Mappings are key-ordered and lists keep their order — a list's order is meaningful (it is what
    the target returned) while a mapping's is not. Anything not JSON-native becomes its ``repr``
    rather than being dropped, because a value the digest cannot see is a value nobody signed.
    """
    if isinstance(value, dict):
        return {
            str(k): canonical_value(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, (list, tuple)):
        return [canonical_value(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (str, int, float)):
        return value
    return repr(value)


def scope_of(value: object) -> tuple[str, ...]:
    """The keys a mapping-valued fact speaks for; empty for a scalar or sequence.

    Restated beside the value so "which nodes does this fact cover" is answerable without walking
    it, and so a dropped key is caught twice.
    """
    if isinstance(value, dict):
        return tuple(sorted(str(k) for k in value))
    return ()


@dataclass(frozen=True)
class FactContribution:
    """What ONE operation contributed to ONE field code, including a failure.

    A failing contribution is recorded exactly like a succeeding one. That is the whole point: the
    merge decides which answer the fact carries; this decides what the signature admits happened.
    """

    operation_code: str
    rendered_path: str
    state: str
    #: The dynamic identifier this operation spoke for — the node, or ``node/thing`` — or "" for a
    #: cluster-wide read. Without it, "which nodes did this fact actually cover" is only guessable
    #: by parsing paths, and a fact covering one node of three is exactly what must not pass.
    subject: str = ""
    reason_code: str = ""
    missing_privilege: str = ""
    #: Digest rather than the value: contributions are per-source and would otherwise duplicate the
    #: whole payload once per operation feeding a shared field code.
    value_digest: str = ""
    scope: tuple[str, ...] = ()

    def canonical(self) -> dict:
        return {
            "operation_code": self.operation_code,
            "rendered_path": self.rendered_path,
            "state": self.state,
            "subject": self.subject,
            "reason_code": self.reason_code,
            "missing_privilege": self.missing_privilege,
            "value_digest": self.value_digest,
            "scope": list(self.scope),
        }


def contribution_of(
    *, operation_code: str, rendered_path: str, observation: Observation, subject: str = ""
) -> FactContribution:
    """Build the record for one operation's answer about one fact."""
    return FactContribution(
        operation_code=operation_code,
        rendered_path=rendered_path,
        state=observation.state.value,
        subject=subject,
        reason_code=observation.reason_code,
        missing_privilege=observation.missing_privilege,
        value_digest=(
            sha256_digest({"value": canonical_value(observation.value)})
            if observation.is_usable
            else ""
        ),
        scope=scope_of(observation.value) if observation.is_usable else (),
    )


#: Per-node outcomes for a node-scoped fact. Exhaustive on purpose: every expected node lands in
#: exactly one of these, and ``missing`` is the one that a "did any node answer" check cannot see.
NODE_OBSERVED = "observed"
NODE_DENIED = "denied"
NODE_UNSUPPORTED = "unsupported"
NODE_FAILED = "failed"
NODE_MISSING = "missing"

_STATE_TO_NODE_OUTCOME: dict[str, str] = {
    "observed": NODE_OBSERVED,
    "permission_denied": NODE_DENIED,
    "observed_unsupported": NODE_UNSUPPORTED,
}


def node_accounting(
    expected_nodes: Sequence[str], contributions: Sequence[FactContribution]
) -> dict[str, str]:
    """Account for EVERY expected node, including the ones nothing spoke for.

    The rule this replaces accepted a node as covered if any key beginning with its name appeared
    anywhere in the value — so one successful storage read certified a whole node, and a node no
    operation was even planned for was indistinguishable from one that answered. Accounting starts
    from the EXPECTED set and assigns an outcome to each, so ``missing`` is a first-class result
    rather than an absence nobody looks for.
    """
    by_subject: dict[str, list[str]] = {}
    for contribution in contributions:
        node = contribution.subject.split("/", 1)[0]
        if node:
            by_subject.setdefault(node, []).append(contribution.state)

    out: dict[str, str] = {}
    for node in expected_nodes:
        states = by_subject.get(node)
        if not states:
            out[node] = NODE_MISSING
            continue
        # Worst outcome wins: one denied read about a node is not cured by another succeeding.
        outcomes = {_STATE_TO_NODE_OUTCOME.get(state, NODE_FAILED) for state in states}
        for outcome in (NODE_DENIED, NODE_FAILED, NODE_UNSUPPORTED, NODE_OBSERVED):
            if outcome in outcomes:
                out[node] = outcome
                break
    return out


@dataclass(frozen=True)
class FactCommitment:
    """Everything the worker attests to about what it observed."""

    commitment_version: str
    organization_identity: str
    target_identity: str
    cluster_fingerprint: str
    operation_identity: str
    operation_generation: int
    observations: Mapping[str, Observation] = field(default_factory=dict)
    required_facts: Mapping[str, Observation] = field(default_factory=dict)
    contributions: Mapping[str, Sequence[FactContribution]] = field(default_factory=dict)
    #: The node set every node-scoped fact is accounted against, taken from the observed cluster
    #: inventory. Bound into the digest so a snapshot cannot later be read against a different
    #: node set: adding, removing or renaming a node changes what "complete" meant.
    expected_node_identities: tuple[str, ...] = ()

    def _fact_rows(self, facts: Mapping[str, Observation]) -> list[dict]:
        rows = []
        for code in sorted(facts):
            obs = facts[code]
            row: dict = {
                "code": code,
                "state": obs.state.value,
                "usable": obs.is_usable,
                "reason_code": obs.reason_code,
                "missing_privilege": obs.missing_privilege,
                "scope": list(scope_of(obs.value) if obs.is_usable else ()),
            }
            # The key is ABSENT for an unusable fact rather than null: a null beside a state is an
            # invitation to read the null as the fact, which is the confusion this whole subsystem
            # exists to prevent.
            if obs.is_usable:
                row["value"] = canonical_value(obs.value)
            rows.append(row)
        return rows

    def canonical(self) -> dict:
        return {
            "commitment_version": self.commitment_version,
            "expected_node_identities": list(self.expected_node_identities),
            "node_accounting": [
                {
                    "code": code,
                    "nodes": node_accounting(
                        self.expected_node_identities, self.contributions[code]
                    ),
                }
                for code in sorted(self.contributions)
            ],
            "binding": {
                "organization_identity": self.organization_identity,
                "target_identity": self.target_identity,
                "cluster_fingerprint": self.cluster_fingerprint,
                "operation_identity": self.operation_identity,
                "operation_generation": self.operation_generation,
            },
            "observations": self._fact_rows(self.observations),
            "required_facts": self._fact_rows(self.required_facts),
            "contributions": [
                {
                    "code": code,
                    "sources": [c.canonical() for c in self.contributions[code]],
                }
                for code in sorted(self.contributions)
            ],
        }

    def digest(self) -> str:
        return sha256_digest(self.canonical())


def build_fact_commitment(
    *,
    observations: Mapping[str, Observation],
    required_facts: Mapping[str, Observation],
    contributions: Mapping[str, Sequence[FactContribution]],
    organization_identity: str,
    target_identity: str,
    cluster_fingerprint: str,
    operation_identity: str,
    operation_generation: int,
    expected_node_identities: Sequence[str] = (),
) -> FactCommitment:
    """Assemble the commitment. Takes no digest and no precomputed hash.

    Every argument is content; nothing here is an assertion about content. A caller cannot hand in
    a hash and have it adopted, which is the shape that made the previous version signable around.
    """
    return FactCommitment(
        commitment_version=FACT_COMMITMENT_VERSION,
        organization_identity=organization_identity,
        target_identity=target_identity,
        cluster_fingerprint=cluster_fingerprint,
        operation_identity=operation_identity,
        operation_generation=operation_generation,
        observations=dict(observations),
        required_facts=dict(required_facts),
        contributions={code: tuple(rows) for code, rows in contributions.items()},
        expected_node_identities=tuple(expected_node_identities),
    )
