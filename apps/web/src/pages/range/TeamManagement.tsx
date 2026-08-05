import "./range.css";

import { SafetyNotice } from "../../components/ui";
import { PendingContractPanel } from "./PendingContractPanel";
import { useRange } from "./RangeLayout";

/**
 * Page 6 — Team Management.
 *
 * NOT WIRED, and now wholly so. On the exercise surface this page could at least list the per-team
 * environment instances; a range has no per-team instances — one range is one environment, and
 * teams are a COMPETITION concept: named rosters with a join code and a server-held score.
 *
 * Those routes are frozen but not reachable: the backend serves them competition-scoped
 * (`/competitions/{cid}/teams`) and is adding range-scoped aliases, and team MEMBERSHIP has no
 * model at all yet. So this renders the gap rather than an empty roster — an empty table would say
 * these teams have no members, when the truth is that teams themselves are not yet readable here.
 */
export function TeamManagement() {
  const { range } = useRange();

  return (
    <div className="rng">
      <SafetyNotice role="status" tone="info">
        {range.competition_id === null
          ? "No competition exists on this range yet, so it has no teams. Teams belong to a competition, not to the range itself."
          : "This range has a competition, but the team routes are not reachable from this build yet."}
      </SafetyNotice>

      <PendingContractPanel
        heading="Competition teams"
        title="Competition teams are not available yet"
        body="Teams are named rosters with a join code and a server-held score, created against a competition rather than against the range. The routes are specified and frozen, but the backend currently serves them competition-scoped and the range-scoped aliases have not landed. Team membership — assigning a person to a team — has no model at all yet. This is shown as a missing surface rather than an empty roster, because an empty table would claim these teams exist and have no members."
        endpoints={[
          "POST|GET /api/v1/ranges/{id}/teams — range-scoped alias, pending",
          "POST|GET /api/v1/competitions/{cid}/teams — served today, but requires a competition this UI cannot create yet",
          "DELETE /api/v1/competitions/{cid}/teams/{tid} — remove a team before the competition starts",
          "POST /api/v1/ranges/{id}/teams/{team}/members — feature gap, no membership model exists",
        ]}
      />
    </div>
  );
}
