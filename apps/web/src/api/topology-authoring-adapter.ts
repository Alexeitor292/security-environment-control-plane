// Feature-flagged adapter between the PR-13 local-draft workspace and the
// PR-14 durable topology-authoring backend contract. It is INERT: the flag is
// off, so the PR-13 UI stays local-draft-only until a dedicated frontend PR
// (PR-15) wires it. This module only translates the pure workspace draft shape
// into the canonical document the backend accepts — no component imports it yet.

/** Off until PR-15 ships the persistence UI. */
export const TOPOLOGY_PERSISTENCE_ENABLED = false;

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
 *  declared CIDR); host nodes carry no fabricated addressing. Pure + testable. */
export function draftToCanonicalDocument(
  draft: WorkspaceDraftShape,
): Record<string, unknown> {
  return {
    schema_version: "secp.topology/v1",
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
