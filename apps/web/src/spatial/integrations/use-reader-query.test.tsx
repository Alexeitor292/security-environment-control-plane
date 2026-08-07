// @vitest-environment jsdom
//
// THE ORDER OF THE CHECKS IS THE DESIGN, and until now nothing asserted it.
//
// `query-state.ts` has its own tests and so does `principal.tsx`, but this is the
// only module that PRODUCES the six states, and it had no test file at all. Its
// header documents an ordering -- permission, then availability, then the request
// -- and an implementation that got that ordering wrong would still return six
// well-formed states, still typecheck, and still satisfy every page test, because
// the difference only shows in WHICH state comes back and WHETHER a request was
// made at all.
//
// So two things are asserted here that no rendered output can show:
//
//   1. THAT NO REQUEST WAS MADE. A page cannot tell the difference between "we
//      did not ask" and "we asked and rendered the refusal". The server can: a
//      certain-403 fired anyway is a real request, and reporting its rejection as
//      `failed` turns a permission fact into an outage.
//   2. WHICH CHECK WINS when more than one applies. A principal who lacks the
//      permission AND whose endpoint does not exist must see `refused` -- the
//      thing they can act on -- not `unavailable`. Reversing the two branches
//      passes every other test in this repository.

import { createElement } from "react";
import { describe, expect, it, vi } from "vitest";

import { mount } from "../../testing/dom-a11y";
import { SpatialPrincipalProvider } from "./principal";
import type { QueryState } from "./query-state";
import { useReaderQuery, type ReaderQuery } from "./use-reader-query";

/** Records every state the hook returns, in order, so transitions are observable. */
function Probe({ query, seen }: { query: ReaderQuery<string>; seen: QueryState<string>[] }) {
  seen.push(useReaderQuery<string>(query));
  return null;
}

async function run(query: ReaderQuery<string>, permissions: readonly string[] | null = []) {
  const seen: QueryState<string>[] = [];
  const mounted = mount(
    createElement(SpatialPrincipalProvider, {
      permissions,
      children: createElement(Probe, { query, seen }),
    }),
  );
  await mounted.runAsync();
  return { seen, final: seen[seen.length - 1] };
}

const HELD = ["audit:read"];

describe("permission is checked before anything is requested", () => {
  it("does not call the reader when the principal cannot hold the permission", async () => {
    // The load-bearing half is `not.toHaveBeenCalled`. A version that fires the
    // request and maps the 403 to `refused` produces an identical final state.
    const reader = vi.fn(async () => ["row"]);
    const { final } = await run({ requires: HELD, provenance: "live", run: reader }, []);

    expect(reader).not.toHaveBeenCalled();
    expect(final.status).toBe("refused");
    if (final.status === "refused") expect(final.requires).toEqual(HELD);
  });

  it("treats an absent principal as denied rather than as permitted", async () => {
    const reader = vi.fn(async () => ["row"]);
    const { final } = await run({ requires: HELD, provenance: "live", run: reader }, null);

    expect(reader).not.toHaveBeenCalled();
    expect(final.status).toBe("refused");
  });

  it("calls the reader when the route requires nothing", async () => {
    // Empty `requires` means the server asks for no permission -- it must not be
    // read as "no permission held", which would refuse every unguarded route.
    const reader = vi.fn(async () => ["row"]);
    const { final } = await run({ requires: [], provenance: "live", run: reader }, []);

    expect(reader).toHaveBeenCalledTimes(1);
    expect(final.status).toBe("ready");
  });
});

describe("availability is checked before the request, and after permission", () => {
  it("does not call the reader when there is no endpoint to call", async () => {
    const reader = vi.fn(async () => ["row"]);
    const { final } = await run(
      {
        requires: HELD,
        provenance: "live",
        blocked: { reason: "no-endpoint", detail: "No route serves this yet." },
        run: reader,
      },
      HELD,
    );

    expect(reader).not.toHaveBeenCalled();
    expect(final.status).toBe("unavailable");
    if (final.status === "unavailable") {
      expect(final.reason).toBe("no-endpoint");
      expect(final.detail).toBe("No route serves this yet.");
    }
  });

  it("reports refused, not unavailable, when both apply", async () => {
    // THE ORDERING ASSERTION. Swapping the two branches yields `unavailable` here
    // and passes every other test in this file. The operator is told the thing
    // they can act on: `unavailable` sends them to ask for a route that exists.
    const reader = vi.fn(async () => ["row"]);
    const { final } = await run(
      {
        requires: HELD,
        provenance: "live",
        blocked: { reason: "no-endpoint", detail: "No route serves this yet." },
        run: reader,
      },
      [],
    );

    expect(reader).not.toHaveBeenCalled();
    expect(final.status).toBe("refused");
  });
});

describe("a rejected request is failed, and can never be empty", () => {
  it("reports the error rather than an absence of rows", async () => {
    // `catch { setRows([]) }` looks like defensive coding and hides an outage
    // behind a clean screen. The states this must NOT be are asserted explicitly,
    // because `failed` and `empty` both render as "nothing on screen".
    const { final } = await run(
      {
        requires: HELD,
        provenance: "live",
        run: async () => {
          throw new Error("connection refused");
        },
      },
      HELD,
    );

    expect(final.status).toBe("failed");
    expect(final.status).not.toBe("empty");
    expect(final.status).not.toBe("ready");
    if (final.status === "failed") expect(final.error).toBe("connection refused");
  });

  it("still fails loudly when the rejection is not an Error", async () => {
    // A thrown string or a rejected undefined must not fall through to a state
    // that reads as success.
    const { final } = await run(
      {
        requires: HELD,
        provenance: "live",
        run: async () => {
          // eslint-disable-next-line @typescript-eslint/only-throw-error
          throw "socket hang up";
        },
      },
      HELD,
    );

    expect(final.status).toBe("failed");
    if (final.status === "failed") expect(final.error).toBe("request_failed");
  });

  it("never passes through empty or ready on the way to failed", async () => {
    // A transient `empty` between loading and failed would flash "no records" at
    // an operator during an outage.
    const { seen } = await run(
      {
        requires: HELD,
        provenance: "live",
        run: async () => {
          throw new Error("boom");
        },
      },
      HELD,
    );

    expect(seen.map((s) => s.status)).not.toContain("empty");
    expect(seen.map((s) => s.status)).not.toContain("ready");
  });
});

describe("a served answer splits empty from ready", () => {
  it("reports an answered-with-nothing as empty", async () => {
    const { final } = await run(
      { requires: HELD, provenance: "live", run: async () => [] },
      HELD,
    );

    expect(final.status).toBe("empty");
    expect(final.status).not.toBe("ready");
  });

  it("reports rows as ready and carries the declared provenance", async () => {
    const { final } = await run(
      { requires: HELD, provenance: "live", run: async () => ["a", "b"] },
      HELD,
    );

    expect(final.status).toBe("ready");
    if (final.status === "ready") {
      expect(final.rows).toEqual(["a", "b"]);
      expect(final.provenance).toBe("live");
    }
  });

  it("carries fixture provenance without pretending it is live", async () => {
    const { final } = await run(
      { requires: HELD, provenance: "fixture", run: async () => ["a"] },
      HELD,
    );

    if (final.status === "ready") expect(final.provenance).toBe("fixture");
  });

  it("starts from loading rather than from an empty result", async () => {
    // The first paint must not claim an answer nobody has given yet.
    const { seen } = await run(
      { requires: HELD, provenance: "live", run: async () => ["a"] },
      HELD,
    );

    expect(seen[0].status).toBe("loading");
  });
});
