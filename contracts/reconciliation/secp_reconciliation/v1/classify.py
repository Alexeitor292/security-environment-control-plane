"""Drift classification (v1): verified desired + observed state -> a bounded drift report.

Classification is *total* — it never refuses, because refusal is the verification gate's job and
has already happened by the time a :class:`~secp_reconciliation.v1.state.VerifiedStatePair` exists.
What classification must never do is invent agreement: a desired facet with no observed counterpart
is ``indeterminate``, not "in sync", and the planner refuses on it.

Every finding is a closed :class:`DriftKind` + one bounded :class:`DriftReason`. A finding carries
an ``element_ref`` **only** when that ref came from the desired (authored) side. An element observed
inside the scope but absent from the desired state is reported with an empty ref: its identity is
provider-supplied, so it is bounded to a kind and a count, and the operator learns that a decision
is required without any provider naming reaching the report.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_reconciliation.v1.codes import (
    DIVERGENCE_REASON_BY_FACET,
    DRIFT_KIND_ORDER,
    DRIFT_REASON_ORDER,
    ELEMENT_KIND_ORDER,
    FACETS_BY_ELEMENT_KIND,
    DriftKind,
    DriftReason,
    ElementKind,
)
from secp_reconciliation.v1.digest import document_digest
from secp_reconciliation.v1.state import (
    StateElement,
    VerifiedStatePair,
    desired_state_digest,
    observed_state_digest,
    require_verified,
)

DRIFT_REPORT_SCHEMA_VERSION = "secp-recon/drift-report/v1"

_KIND_RANK = {kind: index for index, kind in enumerate(DRIFT_KIND_ORDER)}
_REASON_RANK = {reason: index for index, reason in enumerate(DRIFT_REASON_ORDER)}
_ELEMENT_KIND_RANK = {kind: index for index, kind in enumerate(ELEMENT_KIND_ORDER)}


@dataclass(frozen=True)
class DriftFinding:
    """One bounded disagreement. Carries no observed value and no observed identity."""

    kind: DriftKind
    reason: DriftReason
    element_kind: ElementKind
    element_ref: str = ""

    def sort_key(self) -> tuple[int, int, int, str]:
        return (
            _KIND_RANK[self.kind],
            _REASON_RANK[self.reason],
            _ELEMENT_KIND_RANK[self.element_kind],
            self.element_ref,
        )


@dataclass(frozen=True)
class DriftReport:
    """The complete, deterministically ordered set of findings for one verified pair."""

    schema_version: str
    instance_id: str
    desired_digest: str
    observed_digest: str
    findings: tuple[DriftFinding, ...]
    report_digest: str

    def counts_by_kind(self) -> dict[DriftKind, int]:
        counts = {kind: 0 for kind in DRIFT_KIND_ORDER}
        for finding in self.findings:
            counts[finding.kind] += 1
        return counts

    def counts_by_reason(self) -> dict[DriftReason, int]:
        counts = {reason: 0 for reason in DRIFT_REASON_ORDER}
        for finding in self.findings:
            counts[finding.reason] += 1
        return counts

    def kinds_present(self) -> tuple[DriftKind, ...]:
        present = {finding.kind for finding in self.findings}
        return tuple(kind for kind in DRIFT_KIND_ORDER if kind in present)

    def leading_kind(self) -> DriftKind | None:
        """The most blocking kind present, by ``DRIFT_KIND_ORDER``; ``None`` when converged."""
        present = self.kinds_present()
        return present[0] if present else None


def _compare_facets(desired: StateElement, observed: StateElement) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    desired_facets = desired.facet_map()
    observed_facets = observed.facet_map()
    for facet in FACETS_BY_ELEMENT_KIND[desired.kind]:
        if facet not in desired_facets:
            # Nothing was declared for this facet, so there is nothing to reconcile.
            continue
        if facet not in observed_facets:
            findings.append(
                DriftFinding(
                    kind=DriftKind.indeterminate,
                    reason=DriftReason.facet_evidence_absent,
                    element_kind=desired.kind,
                    element_ref=desired.ref,
                )
            )
            continue
        if desired_facets[facet] != observed_facets[facet]:
            findings.append(
                DriftFinding(
                    kind=DriftKind.divergent,
                    reason=DIVERGENCE_REASON_BY_FACET[facet],
                    element_kind=desired.kind,
                    element_ref=desired.ref,
                )
            )
    return findings


def classify_drift(pair: VerifiedStatePair) -> DriftReport:
    """Classify a verified pair into a bounded, deterministically ordered drift report."""
    require_verified(pair)

    observed_by_ref = {element.ref: element for element in pair.observed.elements}
    findings: list[DriftFinding] = []

    for desired in pair.desired.elements:
        observed = observed_by_ref.get(desired.ref)
        if observed is None:
            findings.append(
                DriftFinding(
                    kind=DriftKind.missing,
                    reason=DriftReason.element_absent,
                    element_kind=desired.kind,
                    element_ref=desired.ref,
                )
            )
            continue
        if observed.kind is not desired.kind:
            findings.append(
                DriftFinding(
                    kind=DriftKind.identity_conflict,
                    reason=DriftReason.element_kind_conflict,
                    element_kind=desired.kind,
                    element_ref=desired.ref,
                )
            )
            continue
        findings.extend(_compare_facets(desired, observed))

    desired_refs = {element.ref for element in pair.desired.elements}
    for observed in pair.observed.elements:
        if observed.ref in desired_refs:
            continue
        findings.append(
            DriftFinding(
                kind=DriftKind.unmanaged,
                reason=DriftReason.element_unmanaged,
                element_kind=observed.kind,
                element_ref="",
            )
        )

    ordered = tuple(sorted(findings, key=lambda finding: finding.sort_key()))
    desired_digest = desired_state_digest(pair.desired)
    observed_digest = observed_state_digest(pair.observed)
    report_digest = document_digest(
        DRIFT_REPORT_SCHEMA_VERSION,
        {
            "instance_id": pair.desired.instance_id,
            "desired_digest": desired_digest,
            "observed_digest": observed_digest,
            "findings": [
                [
                    finding.kind.value,
                    finding.reason.value,
                    finding.element_kind.value,
                    finding.element_ref,
                ]
                for finding in ordered
            ],
        },
    )
    return DriftReport(
        schema_version=DRIFT_REPORT_SCHEMA_VERSION,
        instance_id=pair.desired.instance_id,
        desired_digest=desired_digest,
        observed_digest=observed_digest,
        findings=ordered,
        report_digest=report_digest,
    )
