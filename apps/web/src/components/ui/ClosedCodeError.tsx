import { ShieldAlert } from "lucide-react";

import { CyberButton } from "./CyberButton";
import { resolveClosedCodeCopy } from "./closed-code-error";

export interface ClosedCodeErrorProps {
  /** The thrown error (ApiClientError or anything else). Its message is never
   *  rendered — only the mapped closed-code copy. */
  error: unknown;
  /** Page-specific closed code → fixed copy map (checked before the common map). */
  codeText?: Record<string, string>;
  onDismiss?: () => void;
}

/** Error surface for mutations: fixed copy from the closed-code map, with the
 *  code itself kept visible for operators and support. */
export function ClosedCodeError({
  error,
  codeText,
  onDismiss,
}: ClosedCodeErrorProps) {
  const copy = resolveClosedCodeCopy(error, codeText);
  return (
    <div className="ui-closed-error" role="alert">
      <ShieldAlert className="ui-closed-error__icon" size={14} aria-hidden />
      <div className="ui-closed-error__body">
        <div>{copy.text}</div>
        <code className="ui-closed-error__code">{copy.code}</code>
      </div>
      {onDismiss && (
        <CyberButton variant="ghost" size="sm" onClick={onDismiss}>
          Dismiss
        </CyberButton>
      )}
    </div>
  );
}
