import {
  TOPOLOGY_PERSISTENCE_ENABLED,
  draftToCanonicalDocument,
} from "./topology-authoring-adapter";

describe("topology authoring adapter", () => {
  it("stays disabled: the PR-13 UI remains local-draft-only until PR-15", () => {
    expect(TOPOLOGY_PERSISTENCE_ENABLED).toBe(false);
  });

  it("translates a draft to the canonical document, fabricating no addressing", () => {
    const doc = draftToCanonicalDocument({
      nodes: [
        { id: "atk", kind: "attacker", label: "atk", role: "attacker", ip: null, cidr: null, x: 1, y: 2 },
        { id: "net", kind: "network", label: "team-net", role: null, ip: null, cidr: "10.20.0.0/24", x: 3, y: 4 },
      ],
      edges: [{ id: "e", source: "atk", target: "net", kind: "network" }],
    });
    expect(doc.schema_version).toBe("secp.topology/v1");
    const nodes = doc.nodes as Record<string, unknown>[];
    // no fabricated ip on the host
    expect(nodes[0]).not.toHaveProperty("ip");
    expect(nodes[0]).not.toHaveProperty("cidr");
    // the network contributes a networks[] entry carrying the declared CIDR
    const networks = doc.networks as Record<string, unknown>[];
    expect(networks).toEqual([{ id: "net", label: "team-net", cidr: "10.20.0.0/24" }]);
    expect(doc.zones).toEqual([]);
  });
});
