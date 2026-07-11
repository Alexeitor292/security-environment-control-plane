import {
  TOPOLOGY_PERSISTENCE_ENABLED,
  draftFromCanonicalDocument,
  draftToCanonicalDocument,
} from "./topology-authoring-adapter";

describe("topology authoring adapter", () => {
  it("persistence is enabled by default on this branch (VITE_TOPOLOGY_PERSISTENCE != off)", () => {
    expect(TOPOLOGY_PERSISTENCE_ENABLED).toBe(true);
  });

  it("round-trips a draft through canonical and back without loss or fabrication", () => {
    const draft = {
      nodes: [
        { id: "atk", kind: "attacker", label: "atk", role: "attacker", ip: null, cidr: null, x: 1, y: 2 },
        { id: "net", kind: "network", label: "team-net", role: null, ip: null, cidr: "10.20.0.0/24", x: 3, y: 4 },
      ],
      edges: [{ id: "e", source: "atk", target: "net", kind: "network" }],
    };
    const canonical = draftToCanonicalDocument(draft);
    const back = draftFromCanonicalDocument(canonical);
    // cidr re-merged onto the network node; host carries no fabricated ip
    expect(back.nodes.find((n) => n.id === "net")?.cidr).toBe("10.20.0.0/24");
    expect(back.nodes.find((n) => n.id === "atk")?.ip).toBeNull();
    expect(back.edges).toEqual(draft.edges);
  });

  it("draftFromCanonicalDocument drops malformed/incomplete entries safely", () => {
    const back = draftFromCanonicalDocument({
      nodes: [{ id: "ok", kind: "target", label: "ok", x: 0, y: 0 }, { id: "" }, "junk", null],
      edges: [{ id: "e", source: "ok", target: "ok", kind: "reaches" }, { id: "" }],
    });
    expect(back.nodes.map((n) => n.id)).toEqual(["ok"]);
    expect(back.edges.map((e) => e.id)).toEqual(["e"]);
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
