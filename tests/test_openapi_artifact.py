"""The OpenAPI artifact is the contract, and these are the properties that make that true.

Three things have to hold or the artifact is decoration:

* it is **in step** with the application that serves it;
* it is **byte-reproducible**, and reproducible on any machine, so the staleness check is a real
  gate rather than a flake reviewers learn to re-run;
* the **specific fields that protect specific invariants** are in it, in the shape that keeps the
  invariant. A document that merely exists proves nothing.

The last group is the interesting one. Each test names the confusion the field prevents. Their
counterparts in ``apps/web/src/api/generated.contract.test.ts`` pin the same properties one step
further down, in the TypeScript a client actually consumes — a field can be correct here and still
arrive in the browser as ``unknown``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from export_openapi import ARTIFACT, REPO_ROOT, export_document, serialize  # noqa: E402


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    """The COMMITTED artifact, not a freshly exported one.

    Reading the file is the point: every assertion below is then a statement about what this
    repository publishes, and ``test_committed_artifact_is_in_step_with_the_application`` is what
    ties the file back to the code.
    """
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def schema(document: dict[str, Any], name: str) -> dict[str, Any]:
    schemas = document["components"]["schemas"]
    assert name in schemas, f"{name} is not in the published contract"
    return schemas[name]


def prop(document: dict[str, Any], model: str, field: str) -> dict[str, Any]:
    properties = schema(document, model)["properties"]
    assert field in properties, f"{model}.{field} is not in the published contract"
    return properties[field]


def is_nullable(spec: dict[str, Any]) -> bool:
    """True when the published type admits ``null`` as a distinct value."""
    return any(option.get("type") == "null" for option in spec.get("anyOf", []))


# --- the artifact is in step, and reproducible -------------------------------------------------


def test_committed_artifact_is_in_step_with_the_application() -> None:
    """The whole chain hangs off this. Everything else asserts things about a file; this asserts
    the file is what the running application publishes."""
    assert ARTIFACT.exists(), "contracts/openapi/openapi.json is missing"
    assert ARTIFACT.read_text(encoding="utf-8") == export_document(), (
        "the committed OpenAPI artifact is stale. "
        "Run: python scripts/export_openapi.py && (cd apps/web && npm run generate:api)"
    )


def test_export_is_byte_reproducible_in_process() -> None:
    assert export_document() == export_document()


def test_export_does_not_depend_on_the_exporting_machine() -> None:
    """Export under a HOSTILE environment and demand identical bytes.

    Inverted on purpose. The exporter pins the two settings it knows reach the document, but a
    list of variables that matter is a closed set someone will out-grow: the next setting to be
    interpolated into a description would sail past it. This instead states the property —
    ``SECP_*`` from the environment changes nothing in the artifact — and lets any new leak fail
    here, whether or not anybody thought of it.
    """
    hostile = {
        **os.environ,
        "SECP_APP_NAME": "Some Developer's Local Build",
        "SECP_APP_ENV": "dev",
        "SECP_CORS_ALLOW_ORIGINS": '["http://localhost:4173"]',
        "SECP_RANGE_LOCAL_DOCKER": "true",
        "SECP_AUTH_DEV_MODE": "true",
        "PYTHONHASHSEED": "12345",
    }
    result = subprocess.run(
        [sys.executable, "scripts/export_openapi.py", "--check"],
        cwd=REPO_ROOT,
        env=hostile,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "exporting under a perturbed environment produced a different document:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_serialize_sorts_keys_so_an_unrelated_edit_moves_nothing() -> None:
    """Diff stability is not cosmetic: an unsorted document produces a thousand-line diff when a
    router is re-ordered, and the one real change hides inside it."""
    text = serialize({"b": 1, "a": {"z": 1, "y": 2}})
    assert text == '{\n  "a": {\n    "y": 2,\n    "z": 1\n  },\n  "b": 1\n}\n'


# --- the browser client is a NARROWER surface than the contract --------------------------------

GENERATED_TS = REPO_ROOT / "apps" / "web" / "src" / "api" / "generated" / "openapi.ts"

#: Route prefixes the browser client does not carry, and the boundary that says so.
#:
#: `/internal/` is registered by ``secp_api.main`` explicitly NOT under ``/api/v1`` and is spoken
#: over internal CA-pinned transports by a worker or a root installer. ``/api/v1/worker-identity``
#: is the registration / approval / evidence / revocation interface that
#: ``apps/api/tests/test_resolution_lease_boundary.py`` and ``test_worker_identity_security.py``
#: forbid frontend source from carrying — those two scan every ``.ts`` under ``apps/web/src`` and
#: therefore scan the generated file, which is exactly why the generator filters rather than
#: emitting the whole contract and hoping nobody imports the wrong half.
BROWSER_EXCLUDED_PREFIXES = ("/internal/", "/api/v1/worker-identity")


def test_the_excluded_surfaces_exist_in_the_contract_and_not_in_the_browser_client(
    document: dict[str, Any],
) -> None:
    """Both halves matter.

    Asserting only the absence would pass just as happily if the routes had been deleted from the
    API, or if the generated file were empty — a filter that removes nothing and a contract that
    contains nothing are indistinguishable from the far side. So this asserts the contract HAS each
    excluded surface and the browser client does NOT.
    """
    generated = GENERATED_TS.read_text(encoding="utf-8")
    for prefix in BROWSER_EXCLUDED_PREFIXES:
        in_contract = [path for path in document["paths"] if path.startswith(prefix)]
        assert in_contract, f"{prefix} is not in the contract at all; this exclusion is stale"
        for path in in_contract:
            assert f'"{path}"' not in generated, (
                f"{path} is in the browser client. It is excluded by "
                "BROWSER_EXCLUDED_PREFIXES in apps/web/scripts/generate-api-types.mjs."
            )


def test_the_browser_client_still_carries_the_surface_the_web_app_uses(
    document: dict[str, Any],
) -> None:
    """The other direction: the filter must not have taken the product with it."""
    generated = GENERATED_TS.read_text(encoding="utf-8")
    for path in (
        "/api/v1/ranges/{range_id}/proxmox/plan",
        "/api/v1/ranges/{range_id}/proxmox/verification",
        "/api/v1/target-discovery/read-only-bootstrap/worker-nodes",
        "/api/v1/ranges",
        "/health",
    ):
        assert path in document["paths"]
        assert f'"{path}"' in generated, f"{path} is missing from the browser client"
    # And the schemas those paths reach, which pruning could have taken with the excluded routes.
    for name in ("ProxmoxPlanOut", "ProxmoxVerificationOut", "ApprovalOut", "WorkerNodeOut"):
        assert f"        {name}:" in generated, f"{name} was pruned out of the browser client"


def test_pruning_removed_the_schemas_only_the_excluded_routes_reached(
    document: dict[str, Any],
) -> None:
    """A route filter that leaves the schemas behind excludes nothing that matters: the request and
    response shapes are what a client would actually use."""
    generated = GENERATED_TS.read_text(encoding="utf-8")
    for name in ("RegisterWorkerIdentity", "WorkerIdentityEvidenceKind", "WorkerIdentityMechanism"):
        assert name in document["components"]["schemas"], f"{name} is no longer in the contract"
        assert f"        {name}:" not in generated, f"{name} survived pruning into the browser"


# --- the surface is actually published ---------------------------------------------------------

#: Read surfaces. Nothing here records a decision.
PROXMOX_READ_PATHS = {
    "/api/v1/ranges/{range_id}/proxmox",
    "/api/v1/ranges/{range_id}/proxmox/allocations",
    "/api/v1/ranges/{range_id}/proxmox/apply-authorization",
    "/api/v1/ranges/{range_id}/proxmox/commands",
    "/api/v1/ranges/{range_id}/proxmox/destroy-authorization",
    "/api/v1/ranges/{range_id}/proxmox/destroy-plan",
    "/api/v1/ranges/{range_id}/proxmox/evidence",
    "/api/v1/ranges/{range_id}/proxmox/observation",
    "/api/v1/ranges/{range_id}/proxmox/ownership",
    "/api/v1/ranges/{range_id}/proxmox/plan",
    "/api/v1/ranges/{range_id}/proxmox/readiness",
    "/api/v1/ranges/{range_id}/proxmox/reconciliation",
    "/api/v1/ranges/{range_id}/proxmox/reset-dispositions",
    "/api/v1/ranges/{range_id}/proxmox/reset-plan",
    "/api/v1/ranges/{range_id}/proxmox/residue",
    "/api/v1/ranges/{range_id}/proxmox/topology",
    "/api/v1/ranges/{range_id}/proxmox/verification",
    "/api/v1/ranges/{range_id}/proxmox/workload",
    "/api/v1/ranges/{range_id}/proxmox/worker",
}

#: The SIX authorization acts: approve and authorize, for each of apply, reset and destroy.
#: Reset joined them in SECP-P7-A because a reset destroys every guest in the range and rebuilds
#: it, so it cannot ride on the apply authorization.
PROXMOX_AUTHORIZATION_PATHS = {
    "/api/v1/ranges/{range_id}/proxmox/plan-approval",
    "/api/v1/ranges/{range_id}/proxmox/apply-authorization",
    "/api/v1/ranges/{range_id}/proxmox/reset-plan-approval",
    "/api/v1/ranges/{range_id}/proxmox/reset-authorization",
    "/api/v1/ranges/{range_id}/proxmox/destroy-plan-approval",
    "/api/v1/ranges/{range_id}/proxmox/destroy-authorization",
}

#: The operator COMMAND surface. Each persists intent; three of them enqueue.
PROXMOX_COMMAND_PATHS = {
    "/api/v1/ranges/{range_id}/proxmox/topology-compilation",
    "/api/v1/ranges/{range_id}/proxmox/plan-generation",
    "/api/v1/ranges/{range_id}/proxmox/plan-review-submission",
    "/api/v1/ranges/{range_id}/proxmox/execution-request",
    "/api/v1/ranges/{range_id}/proxmox/reset-request",
    "/api/v1/ranges/{range_id}/proxmox/reconciliation-request",
    "/api/v1/ranges/{range_id}/proxmox/destroy-plan-generation",
    "/api/v1/ranges/{range_id}/proxmox/destroy-execution-request",
}

PROXMOX_PATHS = PROXMOX_READ_PATHS | PROXMOX_AUTHORIZATION_PATHS | PROXMOX_COMMAND_PATHS


def test_every_proxmox_route_is_published(document: dict[str, Any]) -> None:
    published = {path for path in document["paths"] if "/proxmox" in path}
    assert published == PROXMOX_PATHS


#: Three paths answer BOTH: a GET reporting whether the act is authorized, and a POST recording
#: the authorization. That is deliberate — the state and the decision are the same resource — and
#: it is why the check below tests for the presence of a POST rather than the absence of a GET.
_AUTHORIZATION_PATHS_THAT_ALSO_READ = {
    "/api/v1/ranges/{range_id}/proxmox/apply-authorization",
    "/api/v1/ranges/{range_id}/proxmox/reset-authorization",
    "/api/v1/ranges/{range_id}/proxmox/destroy-authorization",
}


def test_every_recording_route_is_a_post_and_pure_reads_answer_only_get(
    document: dict[str, Any],
) -> None:
    """A decision must never be recorded by a GET: that makes it reachable from a link, a
    prefetch, or a browser history entry. Enforced in both directions — everything that records
    has a POST, and everything that only reports state accepts nothing but GET."""
    for path in PROXMOX_AUTHORIZATION_PATHS | PROXMOX_COMMAND_PATHS:
        assert "post" in document["paths"][path], f"{path} records a decision but has no POST"
    for path in PROXMOX_COMMAND_PATHS:
        assert "get" not in document["paths"][path], (
            f"{path} records a command and also answers GET — reachable from a link"
        )
    for path in PROXMOX_READ_PATHS - _AUTHORIZATION_PATHS_THAT_ALSO_READ:
        assert set(document["paths"][path]) == {"get"}, f"{path} publishes a non-GET method"


#: The three families, named as PAIRS rather than matched by substring — "plan-approval" and
#: "apply-authorization" share no word, so a substring rule would silently under-cover the apply
#: family while looking like it checked something.
_AUTHORIZATION_FAMILIES = {
    "apply": (
        "/api/v1/ranges/{range_id}/proxmox/plan-approval",
        "/api/v1/ranges/{range_id}/proxmox/apply-authorization",
    ),
    "reset": (
        "/api/v1/ranges/{range_id}/proxmox/reset-plan-approval",
        "/api/v1/ranges/{range_id}/proxmox/reset-authorization",
    ),
    "destroy": (
        "/api/v1/ranges/{range_id}/proxmox/destroy-plan-approval",
        "/api/v1/ranges/{range_id}/proxmox/destroy-authorization",
    ),
}


def test_each_authorization_family_is_two_separate_acts(document: dict[str, Any]) -> None:
    """Approve and authorize, for apply, reset and destroy — six paths, none shared.

    A single generic approval path would let one recorded decision stand for any of the three,
    which is the collapse the separate hash domains exist to prevent. Approving and authorizing are
    also kept apart WITHIN a family: "this is the right document" and "do it now" are two
    decisions, and the second is the one that touches real hardware.
    """
    declared = {path for pair in _AUTHORIZATION_FAMILIES.values() for path in pair}
    assert declared == PROXMOX_AUTHORIZATION_PATHS, (
        "every authorization path must belong to exactly one family; unassigned: "
        f"{sorted(PROXMOX_AUTHORIZATION_PATHS - declared)}"
    )
    assert len(declared) == 6, "three families of two, with no path serving two families"
    for family, (approve, authorize) in _AUTHORIZATION_FAMILIES.items():
        assert approve != authorize, f"{family} collapsed its two acts into one path"
        for path in (approve, authorize):
            assert "post" in document["paths"][path], f"{family}: {path} records nothing"


# --- three addresses stay three ----------------------------------------------------------------


def test_published_probe_and_observed_addresses_are_three_members(document: dict[str, Any]) -> None:
    """#103: a worker probed the address the range had PUBLISHED — a loopback, from inside a
    container where the port was not — so readiness could never be observed and the range hung."""
    address = schema(document, "ProxmoxGuestAddressOut")
    assert set(address["properties"]) >= {
        "published_address",
        "probe_address",
        "observed_address",
        "probe_is_distinct",
        "observed",
    }


def test_the_published_address_is_the_only_non_nullable_one(document: dict[str, Any]) -> None:
    """``probe_address: null`` means no distinct probe address was assigned — never "use the
    published one". ``observed_address: null`` means not observed, which is not an address."""
    assert not is_nullable(prop(document, "ProxmoxGuestAddressOut", "published_address"))
    assert is_nullable(prop(document, "ProxmoxGuestAddressOut", "probe_address"))
    assert is_nullable(prop(document, "ProxmoxGuestAddressOut", "observed_address"))


def test_the_observed_flag_separates_nobody_looked_from_no_address(
    document: dict[str, Any],
) -> None:
    observed = prop(document, "ProxmoxGuestAddressOut", "observed")
    assert observed["type"] == "boolean" and not is_nullable(observed)


# --- apply cannot authorize destroy ------------------------------------------------------------


def test_operation_kind_is_required_and_enum_valued(document: dict[str, Any]) -> None:
    """Without it a recorded approval is a bare hash plus a principal, and an apply approval is
    indistinguishable from a destroy approval once read out of the response that carried it."""
    approval = schema(document, "ApprovalOut")
    assert "operation_kind" in approval["required"]
    assert approval["properties"]["operation_kind"]["$ref"].endswith("/ApprovalKind")
    # SIX, not four. SECP-P7-A gave reset its own approval and authorization: a reset destroys
    # every guest in the range and rebuilds it, so an apply approval must not stand for it.
    assert schema(document, "ApprovalKind")["enum"] == [
        "plan_approval",
        "apply_authorization",
        "reset_plan_approval",
        "reset_authorization",
        "destroy_plan_approval",
        "destroy_authorization",
    ]


def test_no_authorization_request_body_validates_as_another(document: dict[str, Any]) -> None:
    """THREE families now, checked pairwise rather than as one pair.

    Each requires exactly one field, the field names are disjoint, and every model forbids extras —
    so no body posted to the wrong endpoint is accepted, in any of the six directions.
    """
    bodies = {
        "apply": (schema(document, "ProxmoxApplyAuthorizationRequest"), "plan_hash"),
        "reset": (schema(document, "ProxmoxResetAuthorizationRequest"), "reset_hash"),
        "destroy": (schema(document, "ProxmoxDestroyAuthorizationRequest"), "destroy_hash"),
    }
    for family, (body, field) in bodies.items():
        assert body["required"] == [field], f"{family} must require exactly {field}"
        assert body.get("additionalProperties") is False, (
            f"{family} does not publish extra='forbid'"
        )
    for left, (left_body, _) in bodies.items():
        for right, (right_body, _) in bodies.items():
            if left == right:
                continue
            shared = sorted(set(left_body["properties"]) & set(right_body["properties"]))
            assert shared == [], f"{left} and {right} share {shared}"


def test_the_apply_and_destroy_request_bodies_do_not_validate_as_each_other(
    document: dict[str, Any],
) -> None:
    """Both are required, both forbid extras, and the field names differ — so posting an apply
    authorization to the destroy endpoint is a 422, not a destroyed range."""
    apply_body = schema(document, "ProxmoxApplyAuthorizationRequest")
    destroy_body = schema(document, "ProxmoxDestroyAuthorizationRequest")
    assert apply_body["required"] == ["plan_hash"]
    assert destroy_body["required"] == ["destroy_hash"]
    assert set(apply_body["properties"]) & set(destroy_body["properties"]) == set()
    for body in (apply_body, destroy_body):
        assert body.get("additionalProperties") is False, "extra='forbid' is not published"


# --- ownership provenance ----------------------------------------------------------------------


def test_ownership_carries_both_generations_and_both_provenance_lists(
    document: dict[str, Any],
) -> None:
    """``generation`` separates this range's objects from another range's; ``operation_generation``
    separates THIS range's reset from its deploy. A sweep that reads only the first cannot tell
    them apart."""
    ownership = schema(document, "OwnershipClassOut")
    assert set(ownership["required"]) >= {
        "organization_id",
        "target_id",
        "range_id",
        "generation",
        "operation_generation",
        "tags",
        "acts_on",
        "never_touches",
    }


def test_each_published_guest_carries_both_generations(document: dict[str, Any]) -> None:
    guest = schema(document, "ProxmoxGuestOut")["properties"]
    assert "generation" in guest and "operation_generation" in guest


# --- unknown is not empty ----------------------------------------------------------------------

#: Members where ``null`` and ``[]`` (or ``0``) are DIFFERENT facts, with the confusion each one
#: prevents. Every entry is a nullable container: a missing key must never be able to produce the
#: empty value, because the empty value is the stronger claim.
UNKNOWN_IS_NOT_EMPTY: tuple[tuple[str, str, str], ...] = (
    (
        "ProxmoxDestroyPlanOut",
        "deletion_set",
        "an UNCOMPUTED deletion set vs a destroy that removes nothing — the second makes a destroy "
        "look safe when in truth nothing has been enumerated",
    ),
    ("ProxmoxDestroyPlanOut", "deletion_set_size", "null, never 0, when the set was not computed"),
    (
        "ProxmoxResidueOut",
        "uncovered_classes",
        "an EMPTY list is the strong claim that every residue class was probed, and must never be "
        "produced by a missing key",
    ),
    ("ProxmoxResidueOut", "resources", "a probe that has not run vs a probe that found nothing"),
    ("ProxmoxResidueOut", "probe_reachable", "unknown reachability vs an unreachable probe"),
    (
        "ProxmoxResetDispositionsOut",
        "dispositions",
        "a reset that has not run vs a reset that touched no guest",
    ),
    (
        "ProxmoxVerificationOut",
        "infrastructure_checks",
        "nothing recorded vs a report that carried no such key",
    ),
    ("ProxmoxVerificationOut", "isolation_checks", "the same, for the isolation half"),
    (
        "ProxmoxPlanOut",
        "isolation",
        "a plan that did not compile vs a plan claiming no isolation properties",
    ),
    (
        "ProxmoxPlanOut",
        "unguardable_flag_values",
        "an EMPTY list is a real finding: every flag this template ships CAN be substring-guarded",
    ),
    ("ProxmoxPlanOut", "approved_hash_is_current", "unanswerable vs answered no"),
    ("ProxmoxTopologyOut", "team_refs", "no plan compiled vs a lab with no teams"),
    ("ProxmoxTopologyOut", "guests", "no plan compiled vs a plan with no guests"),
    ("ProxmoxAllocationsOut", "allocations", "no identifiers computed vs a plan reserving none"),
    ("ProxmoxReadinessOut", "satisfied", "readiness not assessed vs assessed and found wanting"),
    ("ProxmoxReadinessOut", "findings", "nothing assessed vs no requirements"),
    (
        "ProxmoxObservationOut",
        "sdn_supported",
        "never observed vs observed and not supported — null never means no",
    ),
    ("ProxmoxObservationOut", "firewall_supported", "the same, for firewall support"),
    (
        "ProxmoxObservationOut",
        "management_cidrs",
        "no observation recorded vs a cluster declaring no management network, which is a claim no "
        "compiled plan may be built on",
    ),
)


@pytest.mark.parametrize(("model", "field", "confusion"), UNKNOWN_IS_NOT_EMPTY)
def test_unknown_has_somewhere_to_live(
    document: dict[str, Any], model: str, field: str, confusion: str
) -> None:
    assert is_nullable(prop(document, model, field)), (
        f"{model}.{field} is not nullable in the published contract, "
        f"so a client cannot distinguish: {confusion}"
    )


def test_unknown_is_a_member_of_every_lifecycle_enum(document: dict[str, Any]) -> None:
    """A verification that has not run is ``undetermined`` and never ``passed``; an authorization
    nobody recorded is ``absent`` and never ``authorized``."""
    assert set(schema(document, "RecordedStageState")["enum"]) == {"recorded", "undetermined"}
    assert "undetermined" in schema(document, "AuthorizationState")["enum"]
    assert "absent" in schema(document, "AuthorizationState")["enum"]
    assert "blocked" in schema(document, "PlanState")["enum"]
    assert "absent" in schema(document, "ObservationFreshness")["enum"]


# --- the opaque members, held to a declared list -----------------------------------------------

#: Every member the contract publishes as an untyped object, with the reason it stays untyped.
#:
#: Stated as "the members the live document leaves opaque are EXACTLY these", not "these members
#: are opaque". The second is a closed set that a newly-added blob simply walks past; the first
#: fails the moment anything is added, which is the point — a new opaque member is a decision, and
#: it should be made deliberately and get a narrowing entry in ``apps/web/src/api/recorded.ts``
#: rather than arriving as `unknown` in every client.
OPAQUE_MEMBERS: dict[tuple[str, str], str] = {
    ("AuditEventOut", "data"): "audit payloads are per-action and open by design",
    ("ChangeSetApprovalOut", "summary"): "change-set summary is provider-shaped",
    ("EnvironmentPublicationRequest", "definition"): "an environment definition document",
    ("ManifestOut", "content"): "a provisioning manifest document",
    ("OnboardingCreate", "declared_boundary"): "operator-declared boundary document",
    ("OnboardingOut", "declared_boundary"): "operator-declared boundary document",
    ("OperationOut", "result"): "operation results are per-operation",
    ("PlanOut", "summary"): "plan summary is provider-shaped",
    ("ProxmoxDestroyPlanOut", "deletion_set"): "recorded verbatim; narrowed by asDeletionSet",
    ("ProxmoxPlanOut", "document"): "the compiled desired-state document the plan hash is over",
    ("ProxmoxReadinessOut", "scoring_endpoints"): "scenario-shaped scoring endpoints",
    ("ProxmoxResetDispositionsOut", "dispositions"): (
        "recorded verbatim; narrowed by asResetActions"
    ),
    ("ProxmoxReconciliationOut", "findings"): (
        "recorded verbatim by the worker, whose reconcile decision vocabulary is its own; kept "
        "open for the same reason the verification checks are, and null when nothing was recorded "
        "rather than an empty list"
    ),
    ("ProxmoxResidueOut", "resources"): "recorded verbatim; narrowed by asAbsenceFindings",
    ("ProxmoxTopologyOut", "topology"): "the canonical document the plan hash is taken over",
    # ProxmoxVerificationOut.infrastructure_checks / .isolation_checks were declared here and are
    # now TYPED as CheckFindingOut — the (observed, ok) pair is in the contract rather than being
    # narrowed on the client. CheckFindingOut sets extra="allow", so the worker's additional keys
    # still travel; typing the shape did not become a reason to discard evidence.
    ("RangeEventOut", "data"): "range event payloads are per-event",
    ("RangeResourceOut", "detail"): "provider-shaped resource detail",
    ("ReadonlyPreflightOut", "readiness_facts"): "preflight facts are per-provider",
    ("ResourceOut", "attributes"): "provider-shaped resource attributes",
    ("SnapshotOut", "summary"): "discovery summary is per-plugin",
    ("StagingLabOut", "desired_state"): "a staging desired-state document",
    ("StagingLabOut", "simulated_observed_state"): "a simulated observation document",
    ("TargetCreate", "config"): "target config is per-plugin",
    ("TargetCreate", "scope_policy"): "scope policy is per-plugin",
    ("TargetOut", "config"): "target config is per-plugin",
    ("TargetOut", "scope_policy"): "scope policy is per-plugin",
    ("ToolchainProfileCreate", "profile"): "a toolchain profile document",
    ("ToolchainProfileOut", "content"): "a toolchain profile document",
    ("TopologyDraftCreate", "document"): "a topology authoring document",
    ("TopologyRevisionCreate", "document"): "a topology authoring document",
    ("TopologyRevisionDetailOut", "document_content"): "a topology authoring document",
    ("TopologyValidationOut", "findings"): "validator findings are schema-shaped",
    ("VersionCreate", "definition"): "an environment definition document",
    ("VersionOut", "spec"): "an environment definition document",
    ("WorkflowRunOut", "detail"): "workflow detail is per-runner",
}


def _is_open_object(spec: dict[str, Any]) -> bool:
    return (
        spec.get("type") == "object"
        and spec.get("additionalProperties") is True
        and "properties" not in spec
    )


def _opacity(spec: dict[str, Any]) -> bool:
    if _is_open_object(spec):
        return True
    if spec.get("type") == "array" and _is_open_object(spec.get("items", {})):
        return True
    return any(_opacity(option) for option in spec.get("anyOf", []))


def live_opaque_members(document: dict[str, Any]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for name, model in document["components"]["schemas"].items():
        for field, spec in model.get("properties", {}).items():
            if _opacity(spec):
                found.add((name, field))
    return found


def test_the_opaque_members_are_exactly_the_declared_ones(document: dict[str, Any]) -> None:
    live = live_opaque_members(document)
    declared = set(OPAQUE_MEMBERS)
    undeclared = live - declared
    assert not undeclared, (
        "these response members are published as untyped objects and are not declared in "
        f"OPAQUE_MEMBERS: {sorted(undeclared)}. Every client receives them as `unknown`. Either "
        "type them in the Pydantic model, or declare them here with the reason and add a reader "
        "to apps/web/src/api/recorded.ts."
    )
    assert not declared - live, (
        f"these members are declared opaque but are now typed: {sorted(declared - live)}. "
        "Delete the declaration, and the narrowing that existed for it."
    )


def test_the_opaque_guard_can_actually_see_an_opaque_member(document: dict[str, Any]) -> None:
    """The clause that keeps the guard above honest.

    A detector that matched nothing would let ``test_the_opaque_members_are_exactly_the_declared
    _ones`` pass by finding an empty set on both sides. This asserts the detector fires on a
    member we know is opaque, and does NOT fire on one we know is typed.
    """
    live = live_opaque_members(document)
    # Still genuinely opaque: the desired-state document is what the plan hash is taken over, and a
    # model over it would drop keys the hash covers.
    assert ("ProxmoxTopologyOut", "topology") in live
    assert ("ProxmoxTopologyOut", "guests") not in live
    assert ("ProxmoxPlanOut", "isolation") not in live
    # The check arrays used to be the example here. They are typed now, which is the outcome this
    # guard exists to make visible — so it points at a member that is still opaque instead.
    assert ("ProxmoxVerificationOut", "infrastructure_checks") not in live


def test_the_check_findings_carry_the_observed_ok_pair_in_the_contract(
    document: dict[str, Any],
) -> None:
    """The pair must be in the DOCUMENT, not merely preserved by the projection.

    These arrays were ``list[dict[str, Any]]``, so the generated TypeScript was
    ``{ [key: string]: unknown }[]`` and a client had no typed guarantee that ``observed`` was even
    present — "unknown is not false" was enforced by frontend convention rather than by the schema,
    in the one place the per-check tri-state actually lives.
    """
    for member in ("infrastructure_checks", "isolation_checks"):
        prop_schema = prop(document, "ProxmoxVerificationOut", member)
        assert "CheckFindingOut" in str(prop_schema), f"{member} is not typed"

    finding = schema(document, "CheckFindingOut")
    assert set(finding["required"]) >= {"check", "observed"}
    # `ok` is nullable and defaults to null: an unobserved check has NO verdict, and null is how
    # that is said. A non-nullable boolean here would force "could not run" to be reported as
    # "failed", which is the substitution the pair exists to prevent.
    assert is_nullable(finding["properties"]["ok"])
    assert not is_nullable(finding["properties"]["observed"])
    # Extra keys the worker records still travel; typing must not silently drop evidence.
    assert finding.get("additionalProperties") is not False


# --- no secret has a field to travel in ---------------------------------------------------------

FORBIDDEN_FIELD_SUBSTRINGS = (
    "password",
    "secret_value",
    "private_key",
    "api_token",
    "credential",
)


def test_no_proxmox_response_model_has_a_field_a_credential_could_travel_in(
    document: dict[str, Any],
) -> None:
    """The remote-state KEY is published — an operator reasoning about a stuck apply needs to know
    where state lives. The credential that opens it is not in this process at all.

    A field-NAME scan and nothing more. It cannot prove a credential is absent from a free-text
    ``detail``; it proves only that nobody added a field for one, which is the thing a review is
    most likely to miss.
    """
    for name, model in document["components"]["schemas"].items():
        if not name.startswith("Proxmox"):
            continue
        for field in model.get("properties", {}):
            lowered = field.lower()
            for forbidden in FORBIDDEN_FIELD_SUBSTRINGS:
                assert forbidden not in lowered, f"{name}.{field} could carry a credential"


def test_unguardable_flag_values_is_the_only_flag_shaped_member_and_stays_a_plan_member(
    document: dict[str, Any],
) -> None:
    """``ProxmoxPlanOut.unguardable_flag_values`` is the one member whose NAME says "flag value",
    and it is a deliberate exception rather than an oversight.

    ``proxmox_lifecycle.unguardable_flag_values`` returns the template's flag values that no
    substring scan can prove absent — DVWA's flag is the word ``password``, which occurs inside a
    public challenge key, so searching for it would fire on a clean payload. Naming them IS the
    finding, and an operator cannot act on "some flag is unguardable".

    Two things are pinned here. It stays on ``ProxmoxPlanOut`` and spreads to no other model, and
    it stays nullable so "no plan compiled" is distinguishable from "every flag is guardable" —
    the second is a real, and much stronger, claim. Whether an authenticated reader of
    ``/proxmox/plan`` should see template flag values at all is a question for the API owner; it is
    a deliberate published value today, and this test exists so a change to it is a decision.
    """
    flag_members = {
        (name, field)
        for name, model in document["components"]["schemas"].items()
        for field in model.get("properties", {})
        if "flag" in field.lower()
    }
    assert flag_members == {("ProxmoxPlanOut", "unguardable_flag_values")}
    assert is_nullable(prop(document, "ProxmoxPlanOut", "unguardable_flag_values"))
