import "./range.css";

import { PendingContractPanel } from "./PendingContractPanel";
import { useRange } from "./RangeLayout";
import { RANGE_PHASE_LABEL, hasLiveInfrastructure } from "./range-lifecycle";
import {
  COMPETITION_UNAVAILABLE_BODY,
  COMPETITION_UNAVAILABLE_TITLE,
} from "./scoreboard-view";
import { SafetyNotice } from "../../components/ui";

/**
 * Page 5 — Competition Control.
 *
 * NOT WIRED. The control plane exposes no competition routes, so there is nothing to start, pause
 * or stop. The page states that and names the missing endpoints rather than rendering disabled
 * start/stop buttons, which would imply the capability exists and is merely unavailable right now.
 *
 * The one live thing here is the range's own phase, which does bear on competition readiness: a
 * competition cannot run on a range that is not deployed.
 */
export function CompetitionControl() {
  const { range, lifecycle } = useRange();
  const ready = hasLiveInfrastructure(lifecycle.phase);

  return (
    <div className="rng">
      <SafetyNotice role="status" tone={ready ? "info" : "warn"}>
        {ready
          ? `${range.name} is ${RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}. A competition could run against it once the competition API exists.`
          : `${range.name} is ${RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}. A competition needs a deployed range regardless of the missing API.`}
      </SafetyNotice>

      <PendingContractPanel
        heading="Competition control"
        title={COMPETITION_UNAVAILABLE_TITLE}
        body={COMPETITION_UNAVAILABLE_BODY}
      />
    </div>
  );
}
