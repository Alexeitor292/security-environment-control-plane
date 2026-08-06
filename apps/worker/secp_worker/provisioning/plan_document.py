"""The durable plan document an operator reviews before approving. Worker-only.

Built from the canonical, redacted change set produced by
:mod:`secp_worker.provisioning.plan_json` — never from raw plan JSON, never from provider state,
and never from anything carrying a credential.

WHY APPROVAL IS NOT EXECUTION
------------------------------
The document states :data:`EXECUTION_STATUS_NOT_APPLIED` and carries no handle that could start an
apply. Approving it records a decision about a hash; it does not call the runner. That separation
is structural rather than procedural: :func:`build_plan_document` returns plain data, and the
prepared plan's workspace and plan-file handles stay behind ``PreparedOpenTofuPlan``'s redacted
repr in the runner. There is no field in this document a caller could dereference to reach an
executable path, so "approval accidentally started an apply" is not expressible.

WHAT THE OPERATOR IS ACTUALLY APPROVING
----------------------------------------
``plan_document_hash`` — and it has to be, because ``change_set_hash`` alone is NOT enough.

Canonicalization deliberately keeps only address, mode, type, name, provider, action and
replacement, since before/after values are exactly where secrets live. The consequence is easy to
miss and load-bearing: changing a guest's vmid, its memory, a disk size, or a segment's subnet
produces a byte-identical canonical change set and therefore an identical ``change_set_hash``.
Treating that hash as the approval anchor would let an operator approve one plan and get a
materially different one.

So this document binds both — ``change_set_hash`` for the planned actions and
``desired_state_hash`` for the attributes those actions will create — and ``plan_document_hash``
covers the pair. That is the value an approval should be recorded against.

SCHEMA VERIFICATION IS REPORTED HONESTLY
-----------------------------------------
The bundle's provider resource types have not been checked against the pinned provider's real
schema — that needs the offline mirror, and no such check has run. The document says
``unverified`` rather than omitting the field, because a plan that looks complete while resting on
unchecked resource types is exactly the kind of quiet assumption this program refuses.
"""

from __future__ import annotations

from secp_scenario_schema import content_hash

from secp_worker.provisioning.provider_schema_evidence import (
    ProviderSchemaObservation,
    schema_validation_reasons,
    schema_validation_status,
)

#: The one status this module can ever emit. There is deliberately no "applied" variant here: a
#: document describing an apply is a different artifact produced by a different stage.
EXECUTION_STATUS_NOT_APPLIED = "NOT APPLIED"

#: NOT bumped for ``provider_schema_validation_reasons``, deliberately. The addition is purely
#: additive — ``provider_schema_validation`` keeps the same two-value domain and, until a real
#: mirror exists, the same value — so every v1 reader continues to read exactly what it read
#: before. This literal is mirrored in three other places across two planes
#: (``schemas_proxmox.py``, whose docstring is published as the OpenAPI description, the committed
#: spec, and ``apps/web/src/api/recorded-documents.ts``), so a bump is a cross-plane change and is
#: owed to consumers only when something a consumer reads actually changes meaning.
PLAN_DOCUMENT_VERSION = "secp-proxmox/plan-document/v1"


class PlanDocumentError(Exception):
    """The plan document could not be built. Messages are redacted."""


#: Keys that must never appear anywhere in a plan document, at any depth. Checked structurally
#: after the document is built rather than trusted from construction, because the whole value of
#: this artifact is that it is safe to persist and show.
_FORBIDDEN_KEY_TOKENS = (
    "token",
    "password",
    "passwd",
    "secret",
    "credential",
    "api_key",
    "apikey",
    "endpoint",
    "private_key",
)


def _assert_no_forbidden_keys(node: object, path: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = str(key).lower()
            for token in _FORBIDDEN_KEY_TOKENS:
                if token in lowered:
                    raise PlanDocumentError(
                        f"plan document would carry a forbidden key at {path}/{key}"
                    )
            _assert_no_forbidden_keys(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _assert_no_forbidden_keys(item, f"{path}[{index}]")


def build_plan_document(
    change_set: dict,
    change_set_hash_value: str,
    *,
    desired_state: dict,
    schema_observation: ProviderSchemaObservation | None = None,
    schema_attestation: object | None = None,
    expected_executor_implementation_id: str = "",
    expected_executor_implementation_digest: str = "",
) -> dict:
    """Build the durable, secret-free plan document for operator review.

    Two schema arguments, split by authority, replacing the former
    ``provider_schema_verified: bool``:

    ``schema_observation``
        What the inspection run saw. Public, freely constructible, and unable to produce
        ``verified`` on its own. It contributes the REASONS an operator reads.

    ``schema_attestation``
        The only thing that can produce ``verified``. Token-minted by the attested
        schema-inspection producer, and re-checked here against this document's own workspace hash
        and against the executor identity the caller is building under — so an attestation minted
        for another plan, another toolchain, or an earlier command grammar is refused rather than
        trusted. Typed ``object`` so a look-alike is rejected by type, not by duck typing.

    Omitting both yields ``unverified`` with a stated reason, which is the correct reading for every
    caller that has not run the check — today, all of them.
    """
    if not isinstance(change_set, dict):
        raise PlanDocumentError("change set must be an object")
    if not change_set_hash_value:
        raise PlanDocumentError("plan document requires the canonical change-set hash")

    summary = change_set.get("summary") or {}
    resources = change_set.get("resources") or []

    network = desired_state.get("network") or {}
    vnets = sorted(network.get("vnets", []), key=lambda v: str(v.get("name")))
    guests = sorted(desired_state.get("guests", []), key=lambda g: str(g.get("guest_ref")))

    document = {
        "plan_document_version": PLAN_DOCUMENT_VERSION,
        # First field an operator reads, and the only status this builder can produce.
        "execution_status": EXECUTION_STATUS_NOT_APPLIED,
        "approval_starts_apply": False,
        "change_set_hash": change_set_hash_value,
        # The change-set hash alone is NOT a sufficient approval anchor, and this field exists
        # because that is easy to assume and wrong. Canonicalization deliberately keeps only
        # address, type, action and replacement — so changing a guest's vmid, memory, disk size or
        # a segment's subnet produces a byte-identical change set and an identical change-set
        # hash. Binding the desired state as well is what makes "approve this plan" mean "approve
        # these resources with these attributes"; ``plan_document_hash`` covers both.
        "desired_state_hash": content_hash(desired_state),
        "change_set_version": change_set.get("change_set_version"),
        "workspace_hash": change_set.get("workspace_hash"),
        "kind": change_set.get("kind"),
        "provenance": dict(change_set.get("provenance") or {}),
        # The workspace hash is what makes an attestation non-transferable: it is read from THIS
        # change set, so an attestation minted for a different rendered workspace cannot verify
        # this document no matter how well-formed it is.
        "provider_schema_validation": schema_validation_status(
            schema_attestation,
            schema_observation,
            expected_workspace_hash=str(change_set.get("workspace_hash") or ""),
            expected_executor_implementation_id=expected_executor_implementation_id,
            expected_executor_implementation_digest=expected_executor_implementation_digest,
        ),
        # Why it is not verified, in the operator's own document. An `unverified` with no reason is
        # a field nobody can act on: it does not distinguish "the check has not been built yet"
        # from "the pinned provider is missing a type this plan needs", and those call for opposite
        # responses. Empty exactly when the status is `verified`.
        "provider_schema_validation_reasons": list(
            schema_validation_reasons(
                schema_attestation,
                schema_observation,
                expected_workspace_hash=str(change_set.get("workspace_hash") or ""),
                expected_executor_implementation_id=expected_executor_implementation_id,
                expected_executor_implementation_digest=expected_executor_implementation_digest,
            )
        ),
        "summary": {
            "resource_count": summary.get("count", len(resources)),
            "by_action": dict(summary.get("by_action") or {}),
            "segment_count": len(vnets),
            "guest_count": len(guests),
        },
        # The planned resources exactly as canonicalized: address, action and replacement only.
        "resources": [
            {
                "address": item.get("address"),
                "type": item.get("type"),
                "actions": list(item.get("actions") or []),
                "replace": bool(item.get("replace")),
            }
            for item in resources
        ],
        "segments": [
            {
                "name": vnet.get("name"),
                "role": vnet.get("role"),
                "team_ref": (vnet.get("ownership") or {}).get("team_ref"),
                "vlan_tag": vnet.get("vlan_tag"),
                "cidr": (vnet.get("subnet") or {}).get("cidr"),
                "routed": bool((vnet.get("subnet") or {}).get("routed")),
            }
            for vnet in vnets
        ],
        "guests": [
            {
                "guest_ref": guest.get("guest_ref"),
                "kind": guest.get("kind"),
                "vmid": guest.get("vmid"),
                "node_name": guest.get("node_name"),
                "team_ref": (guest.get("ownership") or {}).get("team_ref"),
            }
            for guest in guests
        ],
        "egress": (
            "none"
            if not network.get("egress")
            else {
                "vnet_name": network["egress"].get("vnet_name"),
                "allowed_destinations": list(network["egress"].get("allowed_destinations") or []),
                "approval_reference": network["egress"].get("approval_reference"),
            }
        ),
    }

    _assert_no_forbidden_keys(document)
    document["plan_document_hash"] = content_hash(document)
    return document


def render_plan_document_text(document: dict) -> str:
    """A human-readable rendering. The execution status is the first and last thing shown."""
    lines = [
        f"EXECUTION STATUS: {document['execution_status']}",
        "",
        f"change set hash : {document['change_set_hash']}",
        f"desired state   : {document['desired_state_hash']}",
        f"workspace hash  : {document.get('workspace_hash')}",
        f"operation       : {document.get('kind')}",
        f"provider schema : {document.get('provider_schema_validation')}",
        "",
        f"{document['summary']['resource_count']} resource(s), "
        f"{document['summary']['segment_count']} segment(s), "
        f"{document['summary']['guest_count']} guest(s)",
        "",
        "SEGMENTS",
    ]
    for segment in document["segments"]:
        lines.append(
            f"  {segment['name']:8} {str(segment['role']):10} "
            f"team={str(segment['team_ref']):6} vlan={segment['vlan_tag']} "
            f"{segment['cidr']} routed={segment['routed']}"
        )
    lines.append("")
    lines.append("GUESTS")
    for guest in document["guests"]:
        lines.append(
            f"  {guest['guest_ref']:16} {guest['kind']:5} vmid={guest['vmid']} "
            f"node={guest['node_name']} team={guest['team_ref']}"
        )
    lines.append("")
    lines.append("PLANNED CHANGES")
    for resource in document["resources"]:
        actions = ",".join(resource["actions"])
        lines.append(f"  {actions:16} {resource['address']}")
    lines.append("")
    lines.append(f"EGRESS: {document['egress']}")
    lines.append("")
    lines.append(
        "Approving this plan records a decision about the change set hash above. "
        "It does not start an apply."
    )
    lines.append(f"EXECUTION STATUS: {document['execution_status']}")
    return "\n".join(lines)
