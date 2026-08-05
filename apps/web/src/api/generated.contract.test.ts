// What must survive generation into TypeScript — checked in TypeScript, not inferred from Python.
//
// `tests/test_openapi_artifact.py` pins these same properties in the OpenAPI document. This file
// pins them one step further down the chain, where a client actually consumes them: a field can be
// present and correct in `contracts/openapi/openapi.json` and still arrive in the browser as
// `unknown`, or as an optional it is legal to ignore, or collapsed into a neighbour. Every
// assertion below is a TYPE assertion first — `npm run typecheck` fails the build if the generated
// type stops carrying the field or changes its shape — with a runtime assertion beside it only
// where a value, not a type, is the thing being pinned.

import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  ApprovalKind,
  ApprovalOut,
  AuthorizationState,
  BlockedReasonOut,
  OwnershipClassOut,
  PlanState,
  ProxmoxApplyAuthorizationRequest,
  ProxmoxDestroyAuthorizationRequest,
  ProxmoxDestroyPlanOut,
  ProxmoxGuestAddressOut,
  ProxmoxGuestOut,
  ProxmoxObservationOut,
  ProxmoxPlanOut,
  ProxmoxReadinessOut,
  ProxmoxResetDispositionsOut,
  ProxmoxResidueOut,
  ProxmoxTopologyOut,
  ProxmoxVerificationOut,
  RecordedStageState,
} from "./generated/openapi";

describe("three addresses stay three", () => {
  // #103: a worker probed the address the range had PUBLISHED — a loopback, from inside a
  // container where the port was not — so readiness could never be observed and the range hung.
  // Published, probe and observed are three concepts. Any two of them merged re-creates that bug
  // in every client at once.
  it("keeps published, probe and observed as separate members", () => {
    expectTypeOf<ProxmoxGuestAddressOut>().toHaveProperty("published_address");
    expectTypeOf<ProxmoxGuestAddressOut>().toHaveProperty("probe_address");
    expectTypeOf<ProxmoxGuestAddressOut>().toHaveProperty("observed_address");
  });

  it("makes the published address non-nullable and the other two nullable", () => {
    // `published_address` is always known: it is compiled, not observed. The other two are `null`
    // for reasons that are NOT "the same as published" — no distinct probe address was assigned,
    // and nothing has been observed. A client that falls back from one to another gets #103 back.
    expectTypeOf<ProxmoxGuestAddressOut["published_address"]>().toEqualTypeOf<string>();
    expectTypeOf<ProxmoxGuestAddressOut["probe_address"]>().toEqualTypeOf<
      string | null | undefined
    >();
    expectTypeOf<ProxmoxGuestAddressOut["observed_address"]>().toEqualTypeOf<
      string | null | undefined
    >();
  });

  it("carries the observed flag that tells 'nobody looked' from 'observed, no address'", () => {
    // `observed_address: null` alone is ambiguous. With `observed: false` it means nobody looked;
    // with `observed: true` it means the provider was read and reported no address.
    expectTypeOf<ProxmoxGuestAddressOut["observed"]>().toEqualTypeOf<boolean>();
    expectTypeOf<ProxmoxGuestAddressOut["probe_is_distinct"]>().toEqualTypeOf<boolean>();
  });
});

describe("operation_kind survives to the client", () => {
  it("is a required, enum-valued member of every recorded approval", () => {
    expectTypeOf<ApprovalOut["operation_kind"]>().toEqualTypeOf<ApprovalKind>();
    // Not `string`. A four-member union is what makes an apply approval structurally unable to
    // read as a destroy authorization once it has been taken out of the response that carried it.
    expectTypeOf<ApprovalKind>().toEqualTypeOf<
      "plan_approval" | "apply_authorization" | "destroy_plan_approval" | "destroy_authorization"
    >();
  });

  it("keeps the apply and destroy authorization request bodies non-interchangeable", () => {
    // `extra="forbid"` on both models plus disjoint required fields: neither body validates as the
    // other, so posting an apply authorization to the destroy endpoint is a 422 and not a
    // destroyed range. In TypeScript that shows up as mutual non-assignability.
    expectTypeOf<ProxmoxApplyAuthorizationRequest>().toEqualTypeOf<{ plan_hash: string }>();
    expectTypeOf<ProxmoxDestroyAuthorizationRequest>().toEqualTypeOf<{ destroy_hash: string }>();

    const applyBody: ProxmoxApplyAuthorizationRequest = { plan_hash: "sha256:aaa" };
    // @ts-expect-error an apply authorization body is not a destroy authorization body
    const destroyBody: ProxmoxDestroyAuthorizationRequest = applyBody;
    expect(destroyBody).toBeDefined();
  });
});

describe("ownership provenance survives to the client", () => {
  it("carries both generations, not just one", () => {
    // `generation` distinguishes this range's objects from a previous range's; the SAME range on
    // its second operation is `operation_generation`. Dropping the second is how a reset's objects
    // become indistinguishable from a deploy's.
    expectTypeOf<OwnershipClassOut["generation"]>().toEqualTypeOf<number>();
    expectTypeOf<OwnershipClassOut["operation_generation"]>().toEqualTypeOf<number>();
  });

  it("carries the tag set and both provenance lists", () => {
    expectTypeOf<OwnershipClassOut["tags"]>().toEqualTypeOf<{ [key: string]: string }>();
    expectTypeOf<OwnershipClassOut["acts_on"]>().toEqualTypeOf<string[]>();
    expectTypeOf<OwnershipClassOut["never_touches"]>().toEqualTypeOf<string[]>();
  });

  it("carries both generations per guest as well, where a sweep reads them", () => {
    expectTypeOf<ProxmoxGuestOut["generation"]>().toEqualTypeOf<number | null | undefined>();
    expectTypeOf<ProxmoxGuestOut["operation_generation"]>().toEqualTypeOf<
      number | null | undefined
    >();
  });
});

describe("unknown is not empty", () => {
  // Each of these is nullable so that "not computed" has somewhere to live. An empty array in the
  // same slot is a DIFFERENT and much stronger claim, and the two must not share a representation.
  it("keeps an uncomputed deletion set distinct from an empty one", () => {
    // "no destroy plan was generated" vs "the destroy plan removes nothing" — the second makes a
    // destroy look safe when in truth nothing has been enumerated.
    expectTypeOf<ProxmoxDestroyPlanOut["deletion_set"]>().toEqualTypeOf<
      { [key: string]: unknown }[] | null | undefined
    >();
    expectTypeOf<ProxmoxDestroyPlanOut["deletion_set_size"]>().toEqualTypeOf<
      number | null | undefined
    >();
  });

  it("keeps an unrun residue probe distinct from a clean one", () => {
    // `uncovered_classes: []` is the STRONG claim: every residue class was probed. It must never
    // be producible by a missing key, so the type has to admit null.
    expectTypeOf<ProxmoxResidueOut["uncovered_classes"]>().toEqualTypeOf<
      string[] | null | undefined
    >();
    expectTypeOf<ProxmoxResidueOut["resources"]>().toEqualTypeOf<
      { [key: string]: unknown }[] | null | undefined
    >();
    expectTypeOf<ProxmoxResidueOut["probe_reachable"]>().toEqualTypeOf<
      boolean | null | undefined
    >();
  });

  it("keeps an unrun reset distinct from a reset that touched nothing", () => {
    expectTypeOf<ProxmoxResetDispositionsOut["dispositions"]>().toEqualTypeOf<
      { [key: string]: unknown }[] | null | undefined
    >();
  });

  it("keeps a plan that did not compile distinct from a plan that claims nothing", () => {
    expectTypeOf<ProxmoxPlanOut["isolation"]>().toEqualTypeOf<
      import("./generated/openapi").IsolationFindingOut[] | null | undefined
    >();
    expectTypeOf<ProxmoxPlanOut["isolation_holds"]>().toEqualTypeOf<boolean | null | undefined>();
    expectTypeOf<ProxmoxPlanOut["unguardable_flag_values"]>().toEqualTypeOf<
      string[] | null | undefined
    >();
    expectTypeOf<ProxmoxTopologyOut["team_refs"]>().toEqualTypeOf<string[] | null | undefined>();
    expectTypeOf<ProxmoxReadinessOut["satisfied"]>().toEqualTypeOf<boolean | null | undefined>();
  });

  it("keeps an unobserved cluster fact distinct from a negative one", () => {
    // `sdn_supported: null` means the fact was never observed. It does NOT mean "no".
    expectTypeOf<ProxmoxObservationOut["sdn_supported"]>().toEqualTypeOf<
      boolean | null | undefined
    >();
    expectTypeOf<ProxmoxObservationOut["firewall_supported"]>().toEqualTypeOf<
      boolean | null | undefined
    >();
    expectTypeOf<ProxmoxObservationOut["management_cidrs"]>().toEqualTypeOf<
      string[] | null | undefined
    >();
  });
});

describe("unknown is a first-class member of every state enum", () => {
  it("gives a stage that has not run its own value", () => {
    expectTypeOf<RecordedStageState>().toEqualTypeOf<"undetermined" | "recorded">();
    expectTypeOf<ProxmoxVerificationOut["state"]>().toEqualTypeOf<RecordedStageState>();
  });

  it("gives a blocked plan and an unapproved one different values", () => {
    expectTypeOf<PlanState>().toEqualTypeOf<
      "blocked" | "compiled" | "approved" | "superseded"
    >();
    // `absent` (nothing recorded) and `undetermined` (recorded but not decidable) are BOTH
    // members, and neither is `authorized`. Three of the four are non-affirmative.
    expectTypeOf<AuthorizationState>().toEqualTypeOf<
      "absent" | "authorized" | "superseded" | "undetermined"
    >();
  });

  it("names each missing prerequisite with a stable id a client may branch on", () => {
    expectTypeOf<BlockedReasonOut>().toEqualTypeOf<{
      reason_id: string;
      observation: string;
      detail: string;
    }>();
  });
});

describe("the opaque members are opaque, and that is a fact about the CONTRACT", () => {
  // This is the delta the reconciliation turned up, pinned so it cannot regress silently in either
  // direction. `infrastructure_checks` is `{ [key: string]: unknown }[]` because
  // `secp_api.schemas_proxmox` declares it `list[dict[str, Any]]` and copies it verbatim from what
  // the worker recorded. The (observed, ok) PAIR therefore does NOT survive generation, and is
  // recovered at runtime by `asCheckFindings` in ./recorded.ts.
  //
  // If a future change types these in Pydantic, this test fails — and it SHOULD, because at that
  // point the narrowing layer is redundant and should be deleted rather than left to rot.
  it("leaves the verification check findings untyped on the wire", () => {
    expectTypeOf<ProxmoxVerificationOut["infrastructure_checks"]>().toEqualTypeOf<
      { [key: string]: unknown }[] | null | undefined
    >();
    expectTypeOf<ProxmoxVerificationOut["isolation_checks"]>().toEqualTypeOf<
      { [key: string]: unknown }[] | null | undefined
    >();
  });

  it("reports the two outcomes separately, so neither can mask the other", () => {
    // Every VM can exist, be running and have the right disks while the firewall lets one team
    // reach another. One verdict would let the first hide the second.
    expectTypeOf<ProxmoxVerificationOut["infrastructure_outcome"]>().toEqualTypeOf<
      string | null | undefined
    >();
    expectTypeOf<ProxmoxVerificationOut["isolation_outcome"]>().toEqualTypeOf<
      string | null | undefined
    >();
  });
});
