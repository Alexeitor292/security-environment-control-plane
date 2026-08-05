import { describe, expect, it } from "vitest";

import * as fixtures from "./proxmox-fixtures";
import {
  OFFLINE_DATA_LABEL,
  combineProvenance,
  isLive,
  isOffline,
  live,
  mapSourced,
  offlineFixture,
  provenanceSummary,
  type Sourced,
} from "./provenance";

describe("provenance constructors", () => {
  it("stamps a live record with the endpoint that returned it", () => {
    const r = live("GET /api/v1/targets", [1, 2]);
    expect(isLive(r)).toBe(true);
    expect(isOffline(r)).toBe(false);
    expect(r.provenance.endpoint).toBe("GET /api/v1/targets");
  });

  it("stamps an offline record with a reason and the module it models", () => {
    const r = offlineFixture("no endpoint", "some.module.Thing", 42);
    expect(isOffline(r)).toBe(true);
    expect(isLive(r)).toBe(false);
    expect(r.provenance.reason).toBe("no endpoint");
    expect(r.provenance.modelledOn).toBe("some.module.Thing");
  });

  it("keeps provenance through a projection — mapping cannot launder a fixture", () => {
    const mapped = mapSourced(offlineFixture("no endpoint", "m", 1), (n) => n + 1);
    expect(mapped.value).toBe(2);
    expect(mapped.provenance.kind).toBe("offline-fixture");
  });
});

describe("combineProvenance", () => {
  const liveP = live("GET /x", 0).provenance;
  const offlineP = offlineFixture("r", "m", 0).provenance;

  it("is offline-absorbing in both argument orders", () => {
    expect(combineProvenance(liveP, offlineP).kind).toBe("offline-fixture");
    expect(combineProvenance(offlineP, liveP).kind).toBe("offline-fixture");
  });

  it("stays live only when both sides are live", () => {
    expect(combineProvenance(liveP, liveP).kind).toBe("live");
  });
});

describe("provenanceSummary", () => {
  it("names the endpoint for live and the reason for offline", () => {
    expect(provenanceSummary(live("GET /a", 0).provenance)).toBe("GET /a");
    expect(provenanceSummary(offlineFixture("why", "m", 0).provenance)).toBe("why");
  });
});

/**
 * The load-bearing test of the whole module: every value the fixture module exports must carry
 * offline provenance.
 *
 * It iterates the namespace object rather than naming each export, so a fixture added later is
 * covered without anyone remembering to add it here. That is the point — the failure mode being
 * guarded is a NEW fixture shipped as live, and a test that enumerates today's exports would pass
 * happily while the new one rendered unlabelled.
 */
describe("proxmox-fixtures", () => {
  const entries = Object.entries(fixtures as Record<string, unknown>);

  it("exports at least one fixture (guards against the loop silently covering nothing)", () => {
    expect(entries.length).toBeGreaterThan(10);
  });

  it.each(entries)("%s is a Sourced record", (_name, value) => {
    expect(value).toBeTypeOf("object");
    expect(value).not.toBeNull();
    expect(value).toHaveProperty("provenance");
    expect(value).toHaveProperty("value");
  });

  it.each(entries)("%s carries OFFLINE provenance, never live", (_name, value) => {
    const record = value as Sourced<unknown>;
    expect(record.provenance.kind).toBe("offline-fixture");
    expect(isOffline(record)).toBe(true);
  });

  it.each(entries)("%s states a reason and the backend module it models", (_name, value) => {
    const record = value as Sourced<unknown>;
    if (record.provenance.kind !== "offline-fixture") throw new Error("expected offline");
    expect(record.provenance.reason.length).toBeGreaterThan(20);
    expect(record.provenance.modelledOn).toMatch(/^secp_(api|worker)\./);
  });
});

describe("the offline label", () => {
  it("says offline development data, not 'sample' or 'demo'", () => {
    expect(OFFLINE_DATA_LABEL).toBe("OFFLINE DEVELOPMENT DATA");
    expect(OFFLINE_DATA_LABEL.toLowerCase()).not.toContain("sample");
    expect(OFFLINE_DATA_LABEL.toLowerCase()).not.toContain("demo");
  });
});
