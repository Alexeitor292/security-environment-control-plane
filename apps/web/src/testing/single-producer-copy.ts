// The one claim this surface may never make about `recovery_required`, in one place.
//
// `recovery_required` has TWO producers: the controller's scheduled expiry sweep, and an operator
// holding enrollment:manage calling the recover route this interface ships. The service stamps a
// different bounded `refusal_reason` for each, and that record is the ONLY thing that distinguishes
// them — the lifecycle state does not carry the cause, so no browser may infer it.
//
// Twelve sites across four files asserted a single producer, six of them rendered in one document
// directly above a live "Mark for recovery" button. They were not caught because almost none of the
// copy was pinned: only two of the eight rendered sites had any assertion contradicting them, and a
// claim no test can contradict is decoration.
//
// This module exists so the constant-level guard and the two rendered-output guards share ONE list.
// Three independent copies of these patterns would drift, and the copy that drifted would be the
// one that stopped rejecting something.

/**
 * Claims of exclusivity that the shipped recover control falsifies.
 *
 * SCOPED TO ENROLLMENT COPY. These are phrase patterns, not a general-purpose lint: "the only
 * operator action is running it" is a true sentence about the Proxmox bootstrap script elsewhere in
 * this tree. They are only ever run against enrollment copy constants and the two enrollment pages'
 * rendered markup, and widening that input set would need the patterns narrowed first.
 *
 * DELIBERATELY APOSTROPHE-FREE. These run against `renderToStaticMarkup` output as well as against
 * raw constants, and React escapes `'` to `&#x27;` — a pattern containing a literal apostrophe
 * would silently never match rendered markup while still appearing to guard it. That is a failure
 * mode with no symptom, so `rejects rendered markup` below pins the constraint rather than trusting
 * it to be remembered.
 */
export const SINGLE_PRODUCER_CLAIMS: readonly RegExp[] = [
  // Singular only. The corrected copy says "the only operator writes are the two that end an
  // enrollment", which is TRUE and must not be flagged — so the plural is excluded rather than the
  // phrase being dropped, which would have lost the catch on "Revoking is the only operator write".
  /only operator (write|action)(?!s)/i,
  /one operator action/i,
  /produced only by/i,
  /expiry sweep closed this/i,
  /expired before completing/i,
  /not by this page/i,
  /sweep — not this interface/i,
];

/**
 * The exact wording that shipped, paired with the pattern each one exists to reject.
 *
 * This is the anti-vacuity half and it is not optional: a denylist that matches nothing passes
 * against every string ever written. Each entry is real text taken from the tree at `a26a8ae`.
 */
export const SHIPPED_SINGLE_PRODUCER_COPY: ReadonlyArray<readonly [string, RegExp]> = [
  ["the one operator action is revoking it", /one operator action/i],
  [
    "Revoking is the only operator write, and it is how you cancel an enrollment.",
    /only operator (write|action)(?!s)/i,
  ],
  [
    "The controller's expiry sweep closed this enrollment before the exchange finished.",
    /expiry sweep closed this/i,
  ],
  ["Recovery required — expired before completing", /expired before completing/i],
  [
    "moved to recovery required by the controller's own expiry sweep, not by this page",
    /not by this page/i,
  ],
  ["`recovery_required` is produced only by the controller-side expiry sweep", /produced only by/i],
  [
    "The controller's expiry sweep — not this interface — moves an unfinished enrollment",
    /sweep — not this interface/i,
  ],
];

/**
 * Every single-producer claim `text` makes, as pattern sources — empty when it makes none.
 *
 * Returns the offenders rather than a boolean so a failure names the claim that was made and the
 * assertion reads as `toEqual([])`, which prints the offending pattern instead of `true !== false`.
 */
export function singleProducerClaims(text: string): string[] {
  return SINGLE_PRODUCER_CLAIMS.filter((pattern) => pattern.test(text)).map((p) => p.source);
}
