"""Canonical topology-authoring document schema, canonicalization, and hashing.

SECP-B9 — durable topology draft authoring. This module is the pure, framework-
free core of the contract:

* :func:`validate_document` — explicit allowlist schema validation. Unknown
  fields, unsupported node/edge kinds, and secret-sensitive material are
  rejected with closed codes. There is no silent acceptance.
* :func:`canonicalize` / :func:`content_hash` — deterministic serialization and
  hashing (ADR-002 rules: sorted keys, no insignificant whitespace, UTF-8).
  Semantic collections (nodes, edges, networks, zones) are ordered by identity
  so equivalent documents hash identically regardless of input order.
* :func:`derive_findings` — deterministic, infrastructure-free validation
  findings (schema/reference/compatibility/consistency), used by the validation
  action. Findings never contact infrastructure and never imply approval.

Positions/layout metadata ARE part of the canonical content and hash: a moved
node is a meaningful authored change in a topology-builder context, and pinning
approval to the exact laid-out document is the safe default (documented
decision, mirrored in the tests).
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

CANONICAL_SCHEMA_VERSION = "secp.topology/v1"

# Supported object kinds are exactly those the product topology model already
# represents (apps/api/secp_api/services/topology.py + the plugin contract).
SUPPORTED_NODE_KINDS: frozenset[str] = frozenset({"attacker", "target", "sensor", "network"})
SUPPORTED_EDGE_KINDS: frozenset[str] = frozenset({"network", "monitors", "reaches"})

# Bounds (fail closed rather than accept unbounded input).
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_NODES = 500
MAX_EDGES = 2000
MAX_NETWORKS = 200
MAX_ZONES = 200
MAX_STRING = 200
MAX_LABEL = 120

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Any key or value that looks secret-shaped is refused outright — topology
# content must never carry credentials (Charter §12; PR-11 redaction model).
_SECRET_KEY_RE = re.compile(
    r"(secret|password|passwd|token|credential|private[_-]?key|api[_-]?key|apikey|"
    r"cookie|authorization|auth[_-]?header|access[_-]?key|secret[_-]?ref|bearer|ssh[_-]?key)",
    re.IGNORECASE,
)
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_SECRET_VALUE_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}|"
    r"xox[abps]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})"
)

# Explicit per-object allowlists. Unknown keys are rejected, not dropped.
_NODE_KEYS = frozenset({"id", "kind", "label", "role", "ip", "network", "x", "y"})
_EDGE_KEYS = frozenset({"id", "source", "target", "kind"})
_NETWORK_KEYS = frozenset({"id", "label", "cidr", "isolated"})
_ZONE_KEYS = frozenset({"id", "label", "kind", "member_ids"})
_DOC_KEYS = frozenset({"schema_version", "nodes", "edges", "networks", "zones"})


def reason_is_secret_shaped(text: str) -> bool:
    """True when a free-text decision/change note looks secret-shaped (a PEM
    block or a known credential-token pattern). Used to keep secrets out of the
    stored/audited reason fields, mirroring the document-content scan."""
    return bool(_PEM_RE.search(text) or _SECRET_VALUE_RE.search(text))


class TopologyDocumentError(Exception):
    """Raised for a rejected topology document. Carries a closed code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        # detail is for tests/logs only — the HTTP layer serializes the code.
        self.detail = detail


@dataclass(frozen=True)
class Finding:
    """A deterministic, infrastructure-free validation finding."""

    severity: str  # "error" | "warning"
    code: str
    node_id: str | None = None
    edge_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"severity": self.severity, "code": self.code}
        if self.node_id is not None:
            out["node_id"] = self.node_id
        if self.edge_id is not None:
            out["edge_id"] = self.edge_id
        return out


# ------------------------------------------------------------------ helpers


def _scan_secrets(value: Any, path: str = "") -> None:
    """Recursively refuse secret-shaped keys/values anywhere in the document."""
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k):
                raise TopologyDocumentError("topology_secret_field_forbidden", f"{path}.{k}")
            _scan_secrets(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _scan_secrets(v, f"{path}[{i}]")
    elif isinstance(value, str):
        if _PEM_RE.search(value) or _SECRET_VALUE_RE.search(value):
            raise TopologyDocumentError("topology_secret_field_forbidden", path)


def _require_id(value: Any, code: str = "topology_schema_invalid") -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise TopologyDocumentError(code, "identifier")
    return value


def _bounded_str(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise TopologyDocumentError("topology_schema_invalid", "string")
    # NFC-normalize so labels differing only in Unicode composition form
    # canonicalize — and therefore hash — identically.
    return unicodedata.normalize("NFC", value)


def _coord(value: Any) -> int | float:
    # bool is an int subclass — reject it explicitly so True/False can never be
    # accepted (and silently normalized to 1/0) as a position.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TopologyDocumentError("topology_schema_invalid", "position")
    return _norm_number(value)


def _only_keys(obj: dict[str, Any], allowed: frozenset[str]) -> None:
    extra = set(obj.keys()) - allowed
    if extra:
        # An unknown privileged field is never silently accepted.
        raise TopologyDocumentError("topology_schema_invalid", f"unknown fields: {sorted(extra)}")


# --------------------------------------------------------------- validation


def validate_document(raw: Any) -> dict[str, Any]:
    """Validate and normalize a topology document.

    Returns a normalized dict (canonical field set, defaults applied). Raises
    :class:`TopologyDocumentError` with a closed code on any violation. Does not
    contact infrastructure and does not mutate anything.
    """
    # Bound size before any structural work (measured on a compact encoding).
    try:
        encoded = json.dumps(raw, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise TopologyDocumentError("topology_schema_invalid", "not serializable") from exc
    if len(encoded.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise TopologyDocumentError("topology_document_too_large", "document")

    if not isinstance(raw, dict):
        raise TopologyDocumentError("topology_schema_invalid", "root")
    # Secret-shaped keys/values are refused first, with a specific code,
    # wherever they appear — before the field allowlist runs.
    _scan_secrets(raw)
    _only_keys(raw, _DOC_KEYS)

    schema_version = raw.get("schema_version", CANONICAL_SCHEMA_VERSION)
    if schema_version != CANONICAL_SCHEMA_VERSION:
        raise TopologyDocumentError("topology_schema_invalid", "schema_version")

    raw_nodes = raw.get("nodes", [])
    raw_edges = raw.get("edges", [])
    raw_networks = raw.get("networks", [])
    raw_zones = raw.get("zones", [])
    for coll, limit, name in (
        (raw_nodes, MAX_NODES, "nodes"),
        (raw_edges, MAX_EDGES, "edges"),
        (raw_networks, MAX_NETWORKS, "networks"),
        (raw_zones, MAX_ZONES, "zones"),
    ):
        if not isinstance(coll, list):
            raise TopologyDocumentError("topology_schema_invalid", name)
        if len(coll) > limit:
            raise TopologyDocumentError("topology_document_too_large", name)

    node_ids: set[str] = set()
    nodes: list[dict[str, Any]] = []
    for n in raw_nodes:
        if not isinstance(n, dict):
            raise TopologyDocumentError("topology_schema_invalid", "node")
        _only_keys(n, _NODE_KEYS)
        nid = _require_id(n.get("id"))
        if nid in node_ids:
            raise TopologyDocumentError("topology_schema_invalid", f"duplicate node {nid}")
        node_ids.add(nid)
        kind = n.get("kind")
        if kind not in SUPPORTED_NODE_KINDS:
            raise TopologyDocumentError("topology_unknown_object_kind", f"node kind {kind}")
        ip = _bounded_str(n.get("ip"), MAX_STRING)
        if ip is not None and not _IP_RE.match(ip):
            raise TopologyDocumentError("topology_schema_invalid", "ip")
        x = _coord(n.get("x", 0))
        y = _coord(n.get("y", 0))
        nodes.append(
            {
                "id": nid,
                "kind": kind,
                "label": _bounded_str(n.get("label"), MAX_LABEL) or nid,
                "role": _bounded_str(n.get("role"), MAX_STRING),
                "ip": ip,
                "network": _bounded_str(n.get("network"), MAX_STRING),
                "x": x,
                "y": y,
            }
        )

    net_ids: set[str] = set()
    networks: list[dict[str, Any]] = []
    for net in raw_networks:
        if not isinstance(net, dict):
            raise TopologyDocumentError("topology_schema_invalid", "network")
        _only_keys(net, _NETWORK_KEYS)
        net_id = _require_id(net.get("id"))
        if net_id in net_ids:
            raise TopologyDocumentError("topology_schema_invalid", f"duplicate network {net_id}")
        net_ids.add(net_id)
        cidr = _bounded_str(net.get("cidr"), MAX_STRING)
        if cidr is not None and not _CIDR_RE.match(cidr):
            raise TopologyDocumentError("topology_schema_invalid", "cidr")
        isolated = net.get("isolated")
        if isolated is not None and not isinstance(isolated, bool):
            raise TopologyDocumentError("topology_schema_invalid", "isolated")
        networks.append(
            {
                "id": net_id,
                "label": _bounded_str(net.get("label"), MAX_LABEL) or net_id,
                "cidr": cidr,
                "isolated": isolated,
            }
        )

    edge_ids: set[str] = set()
    edges: list[dict[str, Any]] = []
    for e in raw_edges:
        if not isinstance(e, dict):
            raise TopologyDocumentError("topology_schema_invalid", "edge")
        _only_keys(e, _EDGE_KEYS)
        eid = _require_id(e.get("id"))
        if eid in edge_ids:
            raise TopologyDocumentError("topology_schema_invalid", f"duplicate edge {eid}")
        edge_ids.add(eid)
        kind = e.get("kind")
        if kind not in SUPPORTED_EDGE_KINDS:
            raise TopologyDocumentError("topology_unknown_object_kind", f"edge kind {kind}")
        source = _require_id(e.get("source"), "topology_invalid_relationship")
        target = _require_id(e.get("target"), "topology_invalid_relationship")
        edges.append({"id": eid, "source": source, "target": target, "kind": kind})

    zones: list[dict[str, Any]] = []
    zone_ids: set[str] = set()
    for z in raw_zones:
        if not isinstance(z, dict):
            raise TopologyDocumentError("topology_schema_invalid", "zone")
        _only_keys(z, _ZONE_KEYS)
        zid = _require_id(z.get("id"))
        if zid in zone_ids:
            raise TopologyDocumentError("topology_schema_invalid", f"duplicate zone {zid}")
        zone_ids.add(zid)
        members = z.get("member_ids", [])
        if not isinstance(members, list) or len(members) > MAX_NODES:
            raise TopologyDocumentError("topology_schema_invalid", "member_ids")
        member_ids = [_require_id(m) for m in members]
        zones.append(
            {
                "id": zid,
                "label": _bounded_str(z.get("label"), MAX_LABEL) or zid,
                "kind": _bounded_str(z.get("kind"), MAX_STRING),
                "member_ids": member_ids,
            }
        )

    return {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "nodes": nodes,
        "edges": edges,
        "networks": networks,
        "zones": zones,
    }


def _norm_number(value: int | float) -> int | float:
    """Normalize numbers so 1, 1.0, and 1.00 canonicalize identically."""
    if isinstance(value, bool):  # bool is an int subclass — reject upstream, but be safe
        return int(value)
    f = float(value)
    return int(f) if f.is_integer() else f


# ------------------------------------------------------- canonicalization


def canonicalize(document: dict[str, Any]) -> str:
    """Deterministic JSON serialization of a *validated* document.

    Semantic collections are ordered by identity so equivalent documents (same
    content, different input order) serialize — and therefore hash — identically.
    Key order within objects is enforced by ``sort_keys``. This is the only
    allowed serializer for hashing (ADR-002).
    """
    ordered = {
        "schema_version": document.get("schema_version", CANONICAL_SCHEMA_VERSION),
        "nodes": sorted(document.get("nodes", []), key=lambda n: n["id"]),
        "edges": sorted(document.get("edges", []), key=lambda e: e["id"]),
        "networks": sorted(document.get("networks", []), key=lambda n: n["id"]),
        "zones": [
            {**z, "member_ids": sorted(z.get("member_ids", []))}
            for z in sorted(document.get("zones", []), key=lambda z: z["id"])
        ],
    }
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(document: dict[str, Any]) -> str:
    """SHA-256 of the canonicalized document, prefixed with the algorithm."""
    digest = hashlib.sha256(canonicalize(document).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# --------------------------------------------------------------- findings


def derive_findings(document: dict[str, Any]) -> list[Finding]:
    """Deterministic client-parity validation findings for a validated document.

    Never contacts infrastructure. Returns closed-code findings linked to the
    relevant node/edge. An empty list with no errors means schema-valid — which
    is explicitly NOT approval or deployability.
    """
    findings: list[Finding] = []
    node_by_id = {n["id"]: n for n in document["nodes"]}
    net_ids = {n["id"] for n in document["nodes"] if n["kind"] == "network"}

    for e in document["edges"]:
        s = node_by_id.get(e["source"])
        t = node_by_id.get(e["target"])
        if s is None or t is None:
            findings.append(Finding("error", "missing_reference", edge_id=e["id"]))
            continue
        valid = (
            (e["kind"] == "network" and s["kind"] != "network" and t["kind"] == "network")
            or (e["kind"] == "monitors" and s["kind"] == "sensor" and t["kind"] != "network")
            or (e["kind"] == "reaches" and s["kind"] != "network" and t["kind"] != "network")
        )
        if not valid:
            findings.append(Finding("error", "invalid_connection", edge_id=e["id"]))

    for n in document["nodes"]:
        if n["kind"] == "network":
            has_members = any(
                e["kind"] == "network" and e["target"] == n["id"] for e in document["edges"]
            )
            if not has_members:
                findings.append(Finding("warning", "empty_network", node_id=n["id"]))
        else:
            attached = any(
                e["kind"] == "network" and e["source"] == n["id"] for e in document["edges"]
            )
            if not attached:
                findings.append(Finding("warning", "unattached_host", node_id=n["id"]))
        if n["kind"] == "sensor":
            monitors = any(
                e["kind"] == "monitors" and e["source"] == n["id"] for e in document["edges"]
            )
            if not monitors:
                findings.append(Finding("warning", "idle_sensor", node_id=n["id"]))

    for z in document["zones"]:
        for m in z["member_ids"]:
            if m not in node_by_id and m not in net_ids:
                findings.append(Finding("error", "zone_member_missing", node_id=m))

    return findings
