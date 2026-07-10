import clsx from "clsx";
import { Check } from "lucide-react";
import type { ReactNode } from "react";

export interface OptionCardOption<T extends string> {
  value: T;
  label: string;
  help?: string;
  /** Extra content on the right (badges, status). */
  meta?: ReactNode;
  disabled?: boolean;
  /** Truthful explanation of why the option cannot be chosen. */
  disabledReason?: string;
}

export interface OptionCardGroupProps<T extends string> {
  /** Radio-group name (real radio semantics). */
  name: string;
  legend: string;
  /** Visually hide the legend when the surrounding step already titles it. */
  legendHidden?: boolean;
  options: OptionCardOption<T>[];
  value: T | "";
  onChange: (value: T) => void;
}

/** Selectable option cards backed by real radio inputs: keyboard operation,
 *  focus ring, and a check-mark selected indicator (never color alone). */
export function OptionCardGroup<T extends string>({
  name,
  legend,
  legendHidden,
  options,
  value,
  onChange,
}: OptionCardGroupProps<T>) {
  return (
    <fieldset className="ui-options">
      <legend className={legendHidden ? "ui-sr-only" : "ui-options__legend"}>
        {legend}
      </legend>
      {options.map((option) => {
        const selected = value === option.value;
        return (
          <label
            key={option.value}
            className={clsx(
              "ui-option",
              selected && "ui-option--selected",
              option.disabled && "ui-option--disabled",
            )}
            title={option.disabled ? option.disabledReason : undefined}
          >
            <input
              type="radio"
              className="ui-option__input"
              name={name}
              value={option.value}
              checked={selected}
              disabled={option.disabled}
              onChange={() => onChange(option.value)}
            />
            <span className="ui-option__check" aria-hidden>
              {selected && <Check size={12} />}
            </span>
            <span className="ui-option__body">
              <span className="ui-option__label">{option.label}</span>
              {option.help && <span className="ui-option__help">{option.help}</span>}
              {option.disabled && option.disabledReason && (
                <span className="ui-sr-only"> — {option.disabledReason}</span>
              )}
            </span>
            {option.meta !== undefined && (
              <span className="ui-option__meta">{option.meta}</span>
            )}
          </label>
        );
      })}
    </fieldset>
  );
}
