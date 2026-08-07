"""Per-field observation state for discovery — because a snapshot is not one fact.

Discovery today reports a snapshot as a whole and a field as a value. That collapses questions an
operator and the plan compiler both need answered separately:

* an **observed empty list** and an **unobserved list** are different facts. The first says "this
  cluster has no SDN zones". The second says "nobody looked". Rendering both as ``[]`` makes the
  second read as the first, and the plan compiler cannot tell that it is about to allocate into
  space it never checked;
* **permission denied** and **not implemented** are different again — one is a grant to request,
  the other is code to write — and neither is an empty collection;
* a probe that **ran and returned garbage** is not a probe that **never ran**.

So every safety-relevant fact carries a state alongside its value, and the value is only meaningful
when the state says it is.

Relationship to the existing vocabularies, because this repository's largest structural risk is a
second system rather than a bug:

``DiscoveryProbeCode``
    WHICH probe. Unchanged, extended with ``host_package_version`` for the new typed probe.
``DiscoveryFailureCode``
    WHY a discovery run failed, as a closed secret-free set. Already owns ``probe_refused``,
    ``probe_timeout``, ``malformed_probe_output`` and ``unsupported_probe``, and keeps owning them.
:class:`DiscoveryObservationState` (here)
    WHAT KIND of non-observation this FIELD has. A different question from either: a run can
    succeed overall while one field is permission-denied and another is not implemented.

The states and the failure codes are therefore deliberately not merged. A field carries a state and,
where one applies, the existing failure code that explains it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from secp_api.enums import DiscoveryObservationState

T = TypeVar("T")

#: States in which the accompanying value carries meaning. Exactly one, deliberately: every other
#: state means the value is absent, and code that treats "not requested" as a value has already
#: made the mistake this module exists to prevent.
_USABLE_STATES = frozenset({DiscoveryObservationState.observed})

#: States that mean "SECP has not looked, or could not". Distinguished from ``observed_malformed``
#: and ``observed_unsupported``, where a probe DID run and the target answered — those tell you
#: something about the target; these tell you only about SECP or the grant.
_NOT_LOOKED_STATES = frozenset(
    {
        DiscoveryObservationState.not_requested,
        DiscoveryObservationState.not_implemented,
        DiscoveryObservationState.permission_denied,
        DiscoveryObservationState.probe_refused,
        DiscoveryObservationState.probe_failed,
        DiscoveryObservationState.source_unavailable,
    }
)


class ObservationStateError(ValueError):
    """An observation was constructed in a state that contradicts its value."""


@dataclass(frozen=True)
class Observation(Generic[T]):
    """One fact, its state, and the reason it is not usable when it is not.

    Construct through the classmethods rather than directly. They are what make an unobserved
    observation impossible to give a value to, and an observed one impossible to leave unexplained.
    """

    state: DiscoveryObservationState
    value: T | None = None
    #: A ``DiscoveryFailureCode`` value where one applies, or a bounded reason string. Never a
    #: host, endpoint, path or credential — this field is projected to operators.
    reason_code: str = ""
    #: The exact privilege the target refused for, when known. Populated only for
    #: ``permission_denied``, so an operator is told what to grant rather than that something
    #: failed. Never the credential itself.
    missing_privilege: str = ""

    def __post_init__(self) -> None:
        if self.state in _NOT_LOOKED_STATES and self.value is not None:
            raise ObservationStateError(
                f"observation in state {self.state.value!r} carries a value; an unobserved fact "
                "has no value, and giving it one is how an empty list starts reading as a fact"
            )
        if self.state in _NOT_LOOKED_STATES and not self.reason_code:
            raise ObservationStateError(
                f"observation in state {self.state.value!r} carries no reason code; an operator "
                "cannot act on an unexplained absence"
            )
        if self.state == DiscoveryObservationState.permission_denied and not self.missing_privilege:
            raise ObservationStateError(
                "permission_denied without a named privilege tells an operator to go looking; "
                "name the privilege the target refused for"
            )
        if self.state in _USABLE_STATES and self.value is None:
            raise ObservationStateError(
                "an observed fact must carry its value; use not_requested or probe_failed if "
                "nothing was obtained"
            )

    @property
    def is_usable(self) -> bool:
        """True only when the value may be relied on.

        The plan compiler asks this, never ``value``.
        """
        return self.state in _USABLE_STATES

    @property
    def was_looked_for(self) -> bool:
        """True when a probe actually ran against the target and it answered.

        ``observed_malformed`` and ``observed_unsupported`` are True: the target was asked and
        replied, and that is evidence about the target even though the value is unusable. Every
        state in :data:`_NOT_LOOKED_STATES` is False.
        """
        return self.state not in _NOT_LOOKED_STATES

    @classmethod
    def observed(cls, value: T) -> Observation[T]:
        """A usable value. An empty list passed here means the target genuinely has none."""
        return cls(state=DiscoveryObservationState.observed, value=value)

    @classmethod
    def malformed(cls, reason_code: str) -> Observation[T]:
        """The probe ran and the target answered, but the answer could not be parsed."""
        return cls(state=DiscoveryObservationState.observed_malformed, reason_code=reason_code)

    @classmethod
    def unsupported(cls, reason_code: str) -> Observation[T]:
        """The target answered that it does not support this — e.g. an older PVE without SDN."""
        return cls(state=DiscoveryObservationState.observed_unsupported, reason_code=reason_code)

    @classmethod
    def not_requested(cls, reason_code: str) -> Observation[T]:
        """This run did not ask. A narrower run is legitimate; silently empty output is not."""
        return cls(state=DiscoveryObservationState.not_requested, reason_code=reason_code)

    @classmethod
    def not_implemented(cls, reason_code: str) -> Observation[T]:
        """SECP has no probe for this fact. Code to write, not a grant to request."""
        return cls(state=DiscoveryObservationState.not_implemented, reason_code=reason_code)

    @classmethod
    def permission_denied(cls, *, missing_privilege: str, reason_code: str) -> Observation[T]:
        """The target refused for want of a privilege.

        The single most dangerous state to render as an empty collection: Proxmox can answer a
        privilege-denied SDN read with an empty list rather than a 403, so "no zones" and "not
        allowed to see zones" are indistinguishable at the wire unless the caller keeps them apart
        here.
        """
        return cls(
            state=DiscoveryObservationState.permission_denied,
            reason_code=reason_code,
            missing_privilege=missing_privilege,
        )

    @classmethod
    def probe_refused(cls, reason_code: str) -> Observation[T]:
        """The forced-command wrapper or the probe grammar refused to run it."""
        return cls(state=DiscoveryObservationState.probe_refused, reason_code=reason_code)

    @classmethod
    def probe_failed(cls, reason_code: str) -> Observation[T]:
        """The probe ran and did not complete — timeout, transport error, non-zero exit."""
        return cls(state=DiscoveryObservationState.probe_failed, reason_code=reason_code)

    @classmethod
    def source_unavailable(cls, reason_code: str) -> Observation[T]:
        """The producer itself could not be reached — no worker, no bootstrap, sealed source."""
        return cls(state=DiscoveryObservationState.source_unavailable, reason_code=reason_code)

    def projected(self) -> dict[str, object]:
        """The wire shape. Omits ``value`` entirely when it is not usable.

        Emitting ``"value": null`` beside a state would invite a consumer to read the null as the
        fact. The key is absent instead, so a consumer that ignores ``state`` gets a KeyError rather
        than a plausible wrong answer.
        """
        out: dict[str, object] = {"state": self.state.value}
        if self.is_usable:
            out["value"] = self.value
        if self.reason_code:
            out["reason_code"] = self.reason_code
        if self.missing_privilege:
            out["missing_privilege"] = self.missing_privilege
        return out


def unusable_facts(observations: dict[str, Observation[object]]) -> dict[str, str]:
    """Every fact that cannot be relied on, mapped to its state.

    Returned as a mapping rather than a list because the plan compiler must refuse differently
    depending on WHY a fact is missing: ``permission_denied`` is an operator action,
    ``not_implemented`` is a release blocker, and ``observed_unsupported`` may be an acceptable
    property of an older target.
    """
    return {name: obs.state.value for name, obs in observations.items() if not obs.is_usable}
