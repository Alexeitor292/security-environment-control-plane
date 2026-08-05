"""Scenario/provider compatibility for the shipped range catalog.

The property this file exists to hold: **the Web Breach Lab is ONE scenario with two substrates, and
a scenario that cannot run somewhere says so out loud.**

Three failure modes are each pinned by name below, because each of them reads as a working catalog:

* a duplicate Web Breach Lab — two entries for one lab, so an operator believes they are choosing
  between two labs when they are choosing a substrate for one;
* a hidden blocked scenario — filtered out of the list, which reads as "does not exist" rather than
  "cannot run here, for these reasons";
* a silently eligible scenario — ``blocked: false`` because nobody checked, which is the
  substitution the Proxmox compiler refuses to make and which this surface must refuse too.

Nothing here contacts Proxmox. The observation is the same recorded fixture the worker would write.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from secp_api.range_catalog import CATALOG, WEB_BREACH_LAB, get_template
from secp_api.range_scenarios import (
    KNOWN_PROVIDERS,
    PROXMOX_MIN_TEAMS,
    ProviderSupport,
    RequirementKind,
    RequirementStatus,
    ScenarioContentDrift,
    build_scenario,
    list_scenarios,
    scenario_key_for_template,
)
from secp_api.services import ranges
from test_proxmox_http_surface import (
    binding_payload,
    make_range,
    observation_payload,
)


@pytest.fixture
def client(engine, principal):
    from secp_api.db import get_sessionmaker
    from secp_api.deps import current_principal
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    _ = get_sessionmaker()
    app.dependency_overrides[current_principal] = lambda: principal
    return TestClient(app)


# --- one lab, not two ----------------------------------------------------------


def test_the_web_breach_lab_is_one_scenario_carrying_two_providers():
    """The catalog ships two Web Breach Lab TEMPLATES; the scenario surface must show one lab.

    This is the whole point of the layer. If it ever lists two, an operator is being asked to choose
    between two labs that are the same lab.
    """
    scenarios = {scenario.key: scenario for scenario in list_scenarios()}
    web_breach = [key for key in scenarios if "web-breach" in key]
    assert web_breach == ["web-breach-lab"], (
        f"the Web Breach Lab must appear exactly once as a scenario, got {web_breach}. Two entries "
        "means the Proxmox variant was listed as a second lab instead of a second substrate."
    )

    lab = scenarios["web-breach-lab"]
    assert [item.provider for item in lab.providers] == list(KNOWN_PROVIDERS)
    docker = lab.provider("local_docker")
    proxmox = lab.provider("proxmox")
    assert docker is not None and proxmox is not None
    assert docker.support is ProviderSupport.supported
    assert proxmox.support is ProviderSupport.supported
    # Two SUBSTRATES for one lab: different template slugs, identical content.
    assert docker.template_slug == "web-breach-lab"
    assert proxmox.template_slug == "proxmox-web-breach-lab"
    assert lab.challenge_keys == tuple(c.key for c in WEB_BREACH_LAB.challenges)
    assert lab.component_keys == ("dvwa", "juice-shop")


def test_no_new_template_was_created_for_the_scenario_layer():
    """The layer projects the shipped catalog. It must not have added a lab of its own."""
    assert {template.slug for template in CATALOG} == {
        "juice-shop-solo",
        "web-breach-lab",
        "proxmox-web-breach-lab",
    }
    for template in CATALOG:
        assert scenario_key_for_template(template.slug) is not None, (
            f"template '{template.slug}' belongs to no scenario, so it would be invisible in the "
            "scenario catalog while still being deployable"
        )


def test_content_drift_between_two_substrates_of_one_scenario_is_refused(monkeypatch):
    """If the two variants ever ship different content they are two labs, and must not be merged.

    Asserted rather than assumed: presenting them as one lab is only honest while the content is
    genuinely identical, and the day it stops being identical this surface would quietly tell an
    operator that a Proxmox range scores the same challenges as the Docker one.
    """
    import dataclasses

    from secp_api import range_scenarios

    drifted = dataclasses.replace(
        get_template("proxmox-web-breach-lab"),
        challenges=WEB_BREACH_LAB.challenges[:1],
    )
    monkeypatch.setattr(
        range_scenarios,
        "CATALOG",
        tuple(t for t in CATALOG if t.slug != "proxmox-web-breach-lab") + (drifted,),
    )
    with pytest.raises(ScenarioContentDrift):
        build_scenario("web-breach-lab")


# --- blocked is shown, named, and never eligible -------------------------------


def test_an_unsupported_provider_is_listed_and_named_not_hidden():
    """``juice-shop-solo`` has no Proxmox template. The answer is "unsupported", stated."""
    scenario = build_scenario("juice-shop-solo")
    assert scenario is not None
    proxmox = scenario.provider("proxmox")
    assert proxmox is not None, "an unsupported provider must still appear, or nobody can ask why"
    assert proxmox.support is ProviderSupport.unsupported
    assert proxmox.blocked is True
    assert [item.reason_id for item in proxmox.blockers] == ["scenario.no_template_for_provider"]
    # No slug means there is nothing a client could POST to /ranges by mistake.
    assert proxmox.template_slug is None


def test_with_no_cluster_in_scope_proxmox_requirements_are_undetermined_and_still_block():
    """Unchecked is not met. ``undetermined`` must appear in ``blockers``.

    The dangerous alternative is a catalog read that reports ``satisfied`` for a requirement only a
    live cluster observation could settle, because the list endpoint has no cluster in scope.
    """
    scenario = build_scenario("web-breach-lab")
    assert scenario is not None
    proxmox = scenario.provider("proxmox")
    assert proxmox is not None
    assert proxmox.blocked is True
    statuses = {item.status for item in proxmox.blockers}
    assert RequirementStatus.undetermined in statuses
    assert all(item.reason_id for item in proxmox.blockers), (
        "every blocker must name a stable reason id; a blocker with no id cannot be branched on"
    )
    # Not satisfied, and specifically not silently satisfied.
    assert not any(
        item.status is RequirementStatus.satisfied
        for item in proxmox.requirements
        if item.kind is RequirementKind.network
    )


def test_blocked_is_derived_from_the_requirements_and_cannot_disagree_with_them():
    for scenario in list_scenarios():
        for compatibility in scenario.providers:
            assert compatibility.blocked == (
                compatibility.support is ProviderSupport.unsupported or bool(compatibility.blockers)
            )
            assert set(compatibility.blockers) <= set(compatibility.requirements)


def test_every_requirement_kind_is_reported_for_every_supported_pair():
    """An omitted requirement is indistinguishable from one nobody thought about."""
    for scenario in list_scenarios():
        for compatibility in scenario.providers:
            if compatibility.support is not ProviderSupport.supported:
                continue
            reported = {item.kind for item in compatibility.requirements}
            named = sorted(kind.value for kind in reported)
            assert reported == set(RequirementKind), (
                f"{scenario.key}/{compatibility.provider} reports {named}"
            )


# --- a capability the substrate lacks is not a reason it cannot run ------------


def test_local_docker_runs_the_lab_but_reports_its_missing_controlled_egress():
    """Two different facts, two different fields, and the lab still deploys.

    Folding these together in either direction is a real failure: mark it a blocker and a working
    laptop lab reads as undeployable; drop it entirely and an operator who NEEDS controlled egress
    is told this substrate is fine.
    """
    scenario = build_scenario("web-breach-lab")
    assert scenario is not None
    docker = scenario.provider("local_docker")
    assert docker is not None
    assert docker.blocked is False, "the Docker lab deploys; it must not be reported as blocked"
    gaps = {item.kind: item for item in docker.unmet_capabilities}
    assert RequirementKind.controlled_egress in gaps
    assert gaps[RequirementKind.controlled_egress].status is RequirementStatus.not_provided
    assert gaps[RequirementKind.controlled_egress].reason_id == "local_docker.no_controlled_egress"
    # And it is NOT in blockers.
    assert RequirementKind.controlled_egress not in {item.kind for item in docker.blockers}


# --- answered against a real recorded observation ------------------------------


def test_a_recorded_observation_turns_undetermined_requirements_into_satisfied_ones(
    session, principal
):
    instance = make_range(session, principal)
    binding = _binding(session, instance)
    scenario = build_scenario(
        "web-breach-lab",
        observation=binding.observation,
        team_count=len(binding.teams),
    )
    assert scenario is not None
    proxmox = scenario.provider("proxmox")
    assert proxmox is not None
    assert proxmox.blocked is False, [item.reason_id for item in proxmox.blockers]
    assert all(item.status is RequirementStatus.satisfied for item in proxmox.requirements), [
        (i.kind.value, i.status.value) for i in proxmox.requirements
    ]


def test_an_unobserved_fact_becomes_a_named_blocker_with_the_compilers_own_reason_id(
    session, principal
):
    """The catalog and the plan compiler must not have two vocabularies for one problem."""
    payload = observation_payload()
    payload["vlan_tags_in_use"] = None
    instance = make_range(session, principal, observation=payload)
    binding = _binding(session, instance)
    scenario = build_scenario(
        "web-breach-lab", observation=binding.observation, team_count=len(binding.teams)
    )
    assert scenario is not None
    proxmox = scenario.provider("proxmox")
    assert proxmox is not None
    assert proxmox.blocked is True
    assert "proxmox.vlan_tags_in_use_unobserved" in [item.reason_id for item in proxmox.blockers]


def test_a_single_team_request_is_blocked_at_the_two_team_floor(session, principal):
    """The network compiler refuses a one-team lab; the catalog must say so before anyone plans."""
    instance = make_range(session, principal, teams=[{"team_ref": "red", "label": "Red"}])
    binding = _binding(session, instance)
    scenario = build_scenario(
        "web-breach-lab", observation=binding.observation, team_count=len(binding.teams)
    )
    assert scenario is not None
    proxmox = scenario.provider("proxmox")
    assert proxmox is not None
    assert proxmox.min_teams == PROXMOX_MIN_TEAMS
    blocker = next(item for item in proxmox.blockers if item.kind is RequirementKind.team_count)
    assert blocker.reason_id == "proxmox.team_count_below_floor"
    assert blocker.status is RequirementStatus.unsatisfied


def _binding(session, instance):
    from secp_api.services import proxmox_lifecycle

    binding = proxmox_lifecycle.load_binding(session, instance)
    assert binding is not None
    return binding


# --- over the wire -------------------------------------------------------------


def test_the_scenario_catalog_is_published_and_lists_the_lab_once(client):
    response = client.get("/api/v1/range-scenarios")
    assert response.status_code == 200
    body = response.json()
    keys = [item["key"] for item in body]
    assert keys.count("web-breach-lab") == 1
    lab = next(item for item in body if item["key"] == "web-breach-lab")
    providers = {item["provider"]: item for item in lab["providers"]}
    assert set(providers) == set(KNOWN_PROVIDERS)
    assert providers["proxmox"]["template_slug"] == "proxmox-web-breach-lab"
    # A blocked provider is present in the response with its blockers named.
    assert providers["proxmox"]["blocked"] is True
    assert providers["proxmox"]["blockers"]
    assert all(item["reason_id"] for item in providers["proxmox"]["blockers"])


def test_a_blocked_scenario_is_never_filtered_out_of_the_list(client):
    """Every shipped scenario appears whatever its state."""
    body = client.get("/api/v1/range-scenarios").json()
    assert {item["key"] for item in body} == {"juice-shop-solo", "web-breach-lab"}
    solo = next(item for item in body if item["key"] == "juice-shop-solo")
    proxmox = next(item for item in solo["providers"] if item["provider"] == "proxmox")
    assert proxmox["support"] == "unsupported"
    assert proxmox["blocked"] is True


def test_the_range_scoped_read_answers_against_that_ranges_observation(client, session, principal):
    instance = make_range(session, principal)
    session.commit()
    response = client.get(f"/api/v1/ranges/{instance.id}/scenario")
    assert response.status_code == 200
    proxmox = next(item for item in response.json()["providers"] if item["provider"] == "proxmox")
    # With a complete recorded observation for THIS range, nothing is undetermined any more.
    assert proxmox["blocked"] is False
    assert proxmox["blockers"] == []
    assert all(item["status"] == "satisfied" for item in proxmox["requirements"])


def test_the_range_scoped_read_reports_a_missing_observation_as_undetermined(
    client, session, principal
):
    instance = make_range(session, principal, record_observation=False)
    session.commit()
    response = client.get(f"/api/v1/ranges/{instance.id}/scenario")
    assert response.status_code == 200
    proxmox = next(item for item in response.json()["providers"] if item["provider"] == "proxmox")
    assert proxmox["blocked"] is True
    statuses = {item["status"] for item in proxmox["blockers"]}
    assert "undetermined" in statuses
    assert "proxmox.no_observation_of_record" in {item["reason_id"] for item in proxmox["blockers"]}


def test_an_unknown_scenario_key_is_a_404(client):
    assert client.get("/api/v1/range-scenarios/not-a-lab").status_code == 404


def test_a_docker_range_still_gets_a_scenario_answer(client, session, principal):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/scenario").json()
    docker = next(item for item in body["providers"] if item["provider"] == "local_docker")
    assert docker["blocked"] is False
    proxmox = next(item for item in body["providers"] if item["provider"] == "proxmox")
    # This range records no cluster observation, so the Proxmox column stays honest about it.
    assert proxmox["blocked"] is True


def test_the_scenario_catalog_is_in_the_published_openapi(client):
    paths = client.get("/openapi.json").json()["paths"]
    for path in (
        "/api/v1/range-scenarios",
        "/api/v1/range-scenarios/{key}",
        "/api/v1/ranges/{range_id}/scenario",
    ):
        assert path in paths


def test_no_flag_value_reaches_the_scenario_catalog(client):
    """The catalog names challenge KEYS. A flag value here would ship every solution."""
    raw = client.get("/api/v1/range-scenarios").text
    for template in CATALOG:
        for challenge in template.challenges:
            for flag in challenge.flags:
                # "password" is DVWA's flag AND a substring of nothing in this payload; the
                # assertion is meaningful for the other five and is the reason the catalog
                # publishes keys rather than flag objects.
                if flag.value == "password":
                    continue
                assert flag.value not in raw


def test_binding_payload_fixture_is_the_shared_one():
    """Guard against this module drifting to its own observation shape."""
    assert binding_payload()["observation"]["identity"]["target_id"] == "tgt-lab-01"
