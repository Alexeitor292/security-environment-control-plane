import clsx from "clsx";
import { useId, type InputHTMLAttributes } from "react";

export interface CyberInputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: string;
  /** Field-level validation text (frontend-authored copy only). */
  errorText?: string;
  /** Render the value in the mono evidence typeface (hashes, refs). */
  mono?: boolean;
}

export function CyberInput({
  label,
  hint,
  errorText,
  mono,
  className,
  id,
  ...rest
}: CyberInputProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const hintId = hint ? `${inputId}-hint` : undefined;
  const errorId = errorText ? `${inputId}-error` : undefined;
  return (
    <div className="ui-field">
      {label && <label htmlFor={inputId}>{label}</label>}
      <input
        id={inputId}
        className={clsx(
          "ui-input",
          mono && "mono",
          errorText && "ui-input--error",
          className,
        )}
        aria-invalid={errorText ? true : undefined}
        aria-describedby={clsx(hintId, errorId) || undefined}
        {...rest}
      />
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
