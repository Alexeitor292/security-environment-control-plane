import clsx from "clsx";
import { useId, type SelectHTMLAttributes } from "react";

/** Matches the Option<T> {value, label, help} catalogs the page logic modules
 *  already export — pass those catalogs through unchanged. */
export interface CyberSelectOption {
  value: string;
  label: string;
  help?: string;
}

export interface CyberSelectProps
  extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  hint?: string;
  errorText?: string;
  options: CyberSelectOption[];
  /** Surface the selected option's help copy under the control (the bare
   *  <select> idiom loses it today). Requires a controlled `value`. */
  showHelp?: boolean;
}

export function CyberSelect({
  label,
  hint,
  errorText,
  options,
  showHelp,
  className,
  id,
  value,
  ...rest
}: CyberSelectProps) {
  const autoId = useId();
  const selectId = id ?? autoId;
  const hintId = hint ? `${selectId}-hint` : undefined;
  const errorId = errorText ? `${selectId}-error` : undefined;
  const selected =
    showHelp && typeof value === "string"
      ? options.find((o) => o.value === value)
      : undefined;
  const helpId = selected?.help ? `${selectId}-help` : undefined;
  return (
    <div className="ui-field">
      {label && <label htmlFor={selectId}>{label}</label>}
      <select
        id={selectId}
        className={clsx("ui-select", errorText && "ui-input--error", className)}
        aria-invalid={errorText ? true : undefined}
        aria-describedby={clsx(helpId, hintId, errorId) || undefined}
        value={value}
        {...rest}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {selected?.help && (
        <div id={helpId} className="ui-field__hint">
          {selected.help}
        </div>
      )}
      {hint && (
        <div id={hintId} className="ui-field__hint">
          {hint}
        </div>
      )}
      {errorText && (
        <div id={errorId} className="ui-field__error">
          {errorText}
        </div>
      )}
    </div>
  );
}
