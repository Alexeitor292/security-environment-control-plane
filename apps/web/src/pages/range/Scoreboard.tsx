import "./range.css";

import { SafetyNotice } from "../../components/ui";
import { PendingContractPanel } from "./PendingContractPanel";
import {
  FLAGS_ARE_NEVER_RETURNED_NOTE,
  SCOREBOARD_AUTHORITY_NOTE,
} from "./scoreboard-view";

/**
 * Page 7 — Live Scoreboard.
 *
 * NOT WIRED. There is no scoring endpoint. This page renders no standings at all rather than a
 * zeroed table: every team showing 0 is a statement about the competition, and it would be a false
 * one.
 *
 * When the endpoint lands, `orderScoreboard` and `displayRank` in scoreboard-view.ts are the only
 * transforms this page needs — both are pure presentation over server-supplied values and neither
 * computes a score. That property is enforced by tests, not just by convention.
 */
export function Scoreboard() {
  return (
    <div className="rng">
      <SafetyNotice role="note" tone="info">
        {SCOREBOARD_AUTHORITY_NOTE}
      </SafetyNotice>

      <SafetyNotice role="note" tone="info">
        {FLAGS_ARE_NEVER_RETURNED_NOTE}
      </SafetyNotice>

      <PendingContractPanel
        heading="Live scoreboard"
        title="No scoreboard is available for this range"
        body="The scoreboard route is specified and frozen, but it is not on main yet — the range backend branch is unmerged, so nothing answers it. This page will not display a placeholder or zeroed scoreboard: scores are authoritative on the server, and a table this UI made up would be read as a result."
        endpoints={[
          "GET /api/v1/competitions/{cid}/scoreboard — authoritative scores and ranking (poll 3s while active)",
          "GET /api/v1/competitions/{cid}/challenges — challenge definitions and per-team solve state",
        ]}
      />
    </div>
  );
}
