// The two declarations of the unavailability taxonomy must be the same taxonomy.
//
// `api/reachability.ts` (transport) and `spatial/integrations/query-state.ts` (presentation) each
// declare `UnavailableReason` and an owner map. They were written by different owners, in
// different slices, on the same day, and they agree today because both authors were careful.
//
// CAREFUL IS NOT A MECHANISM. Two independent hand-written copies of one contract is the defect
// this whole slice exists to remove — it is why the OpenAPI artifact is generated rather than
// transcribed — and matching vocabulary by eye is exactly the copy that drifts. The lead's own
// argument for `as const satisfies` applies one level up: two modules that must agree should FAIL
// TO COMPILE when they stop agreeing.
//
// WHY NOT JUST IMPORT ONE FROM THE OTHER. Layering. The transport layer importing a presentation
// module is backwards, and `spatial/` belongs to another owner. A bidirectional type-equality
// assertion gets the guarantee without either module depending on the other, and without anyone
// having to remember. If a third module ever declares these categories, it should be given the
// same treatment rather than a comment asking people to keep them in step.
//
// These are TYPE assertions: they are checked by `npm run typecheck`, not by the runtime pass of
// this file. A green vitest run proves nothing here — `tsc` is the gate.

import { describe, expect, expectTypeOf, it } from "vitest";

import { REASON_OWNER, type UnavailableReason as TransportReason } from "./reachability";
import {
  UNAVAILABLE_OWNER,
  type UnavailableReason as PresentationReason,
} from "../spatial/integrations/query-state";

describe("the transport and presentation taxonomies are one taxonomy", () => {
  it("declares the same union in both directions", () => {
    // Both directions on purpose. One-directional assignability would pass if one side grew a
    // member the other lacked, which is precisely how a shared vocabulary drifts: somebody adds a
    // reason where they need it and the other module keeps rendering the ones it knows.
    expectTypeOf<TransportReason>().toEqualTypeOf<PresentationReason>();
    expectTypeOf<PresentationReason>().toEqualTypeOf<TransportReason>();
  });

  it("assigns the same owner to every reason", () => {
    // The union agreeing is not enough — `parent-unreachable` routed to `backend` in one module
    // and `frontend` in the other would send the same gap to two different teams, and each would
    // be told by its own code that it was right.
    expect(Object.keys(REASON_OWNER).sort()).toEqual(Object.keys(UNAVAILABLE_OWNER).sort());
    for (const reason of Object.keys(REASON_OWNER) as TransportReason[]) {
      expect(REASON_OWNER[reason], `${reason} is owned by different sides in the two modules`).toBe(
        UNAVAILABLE_OWNER[reason],
      );
    }
  });

  it("keeps the owner values literal in both, not widened to string", () => {
    // `as const satisfies` in both places. Without `as const` the values widen to `string` and the
    // equality above still passes while the compiler stops catching a typo like "backned".
    expectTypeOf(REASON_OWNER["parent-unreachable"]).toEqualTypeOf<"backend">();
    expectTypeOf(UNAVAILABLE_OWNER["parent-unreachable"]).toEqualTypeOf<"backend">();
    expectTypeOf(REASON_OWNER["parent-not-selected"]).toEqualTypeOf<"frontend">();
    expectTypeOf(UNAVAILABLE_OWNER["parent-not-selected"]).toEqualTypeOf<"frontend">();
  });

  it("covers exactly three reasons, so a fourth is a deliberate act in both places", () => {
    expect(Object.keys(REASON_OWNER)).toHaveLength(3);
  });
});
