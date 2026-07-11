// Adapter between the PR-13 local-draft workspace and the PR-14 durable
// topology-authoring backend contract (activated in PR-15). Pure translation
// only — it never validates, submits, approves, generates a plan, or contacts
// infrastructure. The backend content hash is authoritative; this module never
// claims to know the post-save hash.

/**
 * Whether the durable persistence UI is active. Defaults ON (this branch ships
 * the persistence UI); set VITE_TOPOLOGY_PERSISTENCE="off" to fall back to the
 * PR-13 local-draft-only workspace. Read via import.meta.env so tests and the
 * disabled path stay deterministic.
 */
export const TOPOLOGY_PERSISTENCE_ENABLED: boolean =
  ((import.meta as { env?: Record<string, string | undefined> }).env
    ?.VITE_TOPOLOGY_PERSISTENCE ?? "on") !== "off";

const SCHEMA_VERSION = "secp.topology/v1";

export interface WorkspaceDraftShape {
  nodes: {
    id: string;
    kind: string;
    label: string;
    role: string | null;
    ip: string | null;
    cidr: string | null;
    x: number;
    y: number;
  }[];
  edges: { id: string; source: string; target: string; kind: string }[];
}

/** Translate a local workspace draft into the canonical backend document.
 *  Network nodes contribute both a node and a `networks[]` entry (carrying the
 *  declared CIDR); host nodes carry no fabricated addressing. No viewport,
 *  selection, or minimap state is included — only contract-valid fields. */
export function draftToCanonicalDocument(
  draft: WorkspaceDraftShape,
): Record<string, unknown> {
  return {
    schema_version: SCHEMA_VERSION,
    nodes: draft.nodes.map((n) => ({
      id: n.id,
      kind: n.kind,
      label: n.label,
      ...(n.role !== null ? { role: n.role } : {}),
      ...(n.ip !== null ? { ip: n.ip } : {}),
      x: n.x,
      y: n.y,
    })),
    edges: draft.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      kind: e.kind,
    })),
    networks: draft.nodes
      .filter((n) => n.kind === "network")
      .map((n) => ({
        id: n.id,
        label: n.label,
        ...(n.cidr !== null ? { cidr: n.cidr } : {}),
      })),
    zones: [],
  };
}

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function asNumber(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

/**
 * Reconstruct the local workspace draft from an authoritative canonical
 * document (a saved revision's `document_content`). Only the allowlisted
 * contract fields are read; the declared CIDR from `networks[]` is merged back
 * onto its matching network node. Deterministic + pure.
 */
export function draftFromCanonicalDocument(
  content: Record<string, unknown> | null | undefined,
): WorkspaceDraftShape {
  const rawNodes = Array.isArray(content?.nodes) ? (content!.nodes as unknown[]) : [];
  const rawEdges = Array.isArray(content?.edges) ? (content!.edges as unknown[]) : [];
  const rawNets = Array.isArray(content?.networks) ? (content!.networks as unknown[]) : [];

  const cidrById = new Map<string, string | null>();
  for (const n of rawNets) {
    if (n && typeof n === "object") {
      const net = n as Record<string, unknown>;
      const id = asString(net.id);
      if (id !== null) cidrById.set(id, asString(net.cidr));
    }
  }

  const nodes = rawNodes
    .filter((n): n is Record<string, unknown> => n !== null && typeof n === "object")
    .map((n) => {
      const id = asString(n.id) ?? "";
      const kind = asString(n.kind) ?? "";
      return {
        id,
        kind,
        label: asString(n.label) ?? id,
        role: asString(n.role),
        ip: asString(n.ip),
        cidr: kind === "network" ? (cidrById.get(id) ?? null) : null,
        x: asNumber(n.x),
        y: asNumber(n.y),
      };
    })
    .filter((n) => n.id !== "" && n.kind !== "");

  const edges = rawEdges
    .filter((e): e is Record<string, unknown> => e !== null && typeof e === "object")
    .map((e) => ({
      id: asString(e.id) ?? "",
      source: asString(e.source) ?? "",
      target: asString(e.target) ?? "",
      kind: asString(e.kind) ?? "",
    }))
    .filter((e) => e.id !== "" && e.source !== "" && e.target !== "");

  return { nodes, edges };
}
