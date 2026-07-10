import clsx from "clsx";
import { Check } from "lucide-react";

export interface ApprovedValuePickerProps {
  label: string;
  /** Server-approved catalog — the only selectable values, by design. */
  approvedValues: string[];
  /** Currently selected values (the caller owns the draft round-trip). */
  selectedValues: string[];
  /** Selected values NOT in the approved catalog (e.g. after the approved
   *  set narrowed) — rendered as out-of-bound, never silently dropped. */
  outOfBound?: string[];
  helper?: string;
  /** Shown when the approved catalog is empty. */
  emptyText?: string;
  onToggle: (value: string, checked: boolean) => void;
}

/** Constrained multi-select over server-approved values. Free-form widening
 *  is impossible by construction: every control is a checkbox over the
 *  approved catalog. */
export function ApprovedValuePicker({
  label,
  approvedValues,
  selectedValues,
  outOfBound = [],
  helper,
  emptyText,
  onToggle,
}: ApprovedValuePickerProps) {
  const selected = new Set(selectedValues);
  return (
    <fieldset className="ui-avp">
      <legend className="ui-avp__legend">{label}</legend>
      {helper && <p className="ui-avp__helper">{helper}</p>}
      {approvedValues.length === 0 ? (
        <div className="error-box">
          {emptyText ?? `No approved values configured for ${label}.`}
        </div>
      ) : (
        <>
          <p className="ui-avp__approved mono">
            approved values: {approvedValues.join(", ")}
          </p>
          <div className="ui-avp__grid">
            {approvedValues.map((value) => {
              const isSelected = selected.has(value);
              return (
                <label
                  key={value}
                  className={clsx("ui-avp__chip", isSelected && "ui-avp__chip--selected")}
                >
                  <input
                    type="checkbox"
                    className="ui-option__input"
                    checked={isSelected}
                    onChange={(e) => onToggle(value, e.target.checked)}
                  />
                  <span className="ui-avp__check" aria-hidden>
                    {isSelected && <Check size={11} />}
                  </span>
                  <span className="mono">{value}</span>
                </label>
              );
            })}
          </div>
          {outOfBound.length > 0 && (
            <div className="error-box" role="alert">
              Selected values outside the approved catalog:{" "}
              <span className="mono">{outOfBound.join(", ")}</span>. Deselect
              them — the server will reject a boundary containing them.
            </div>
          )}
        </>
      )}
    </fieldset>
  );
}
