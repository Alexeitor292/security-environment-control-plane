// Closed-code error copy resolution.
//
// The interface never renders backend free-form messages. Errors are mapped
// from closed codes to fixed UI copy; the code itself stays visible for
// operators and support. Unknown codes get fixed generic copy — the backend
// message is dropped, by design.

export interface ClosedCodeCopy {
  code: string;
  text: string;
}

/** Fixed copy for errors whose code has no specific mapping. */
export const GENERIC_ERROR_TEXT =
  "The request could not be completed. Backend details are not shown here by design.";

/** Fixed copy for codes the shared API client can produce anywhere. */
export const COMMON_ERROR_TEXT: Record<string, string> = {
  api_unreachable:
    "Cannot reach the control-plane API. Check that the backend is running.",
  permission_denied:
    "You are not permitted to perform this action. Viewing is available; ask an organization admin to grant the required permission.",
  error: GENERIC_ERROR_TEXT,
};

/** Closed codes have a grammar. Anything outside it (free text stuffed into a
 *  code field, prototype keys like "constructor") is not a code. */
const CODE_GRAMMAR = /^[a-z0-9_.:-]{1,64}$/i;

function extractCode(err: unknown): string | null {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code: unknown }).code;
    if (typeof code === "string" && CODE_GRAMMAR.test(code)) return code;
  }
  return null;
}

/** Own-property, string-only lookup — inherited Object.prototype members
 *  (e.g. code "constructor") must never resolve as copy. */
function ownText(
  map: Record<string, string> | undefined,
  code: string,
): string | undefined {
  if (!map || !Object.prototype.hasOwnProperty.call(map, code)) return undefined;
  const text = map[code];
  return typeof text === "string" ? text : undefined;
}

/**
 * Resolve an error to closed-code copy.
 * `codeText` supplies the page's own closed map (checked first); the shared
 * COMMON_ERROR_TEXT map is the fallback. The error's `message` is never used
 * as user-visible text.
 */
export function resolveClosedCodeCopy(
  err: unknown,
  codeText?: Record<string, string>,
): ClosedCodeCopy {
  const code = extractCode(err) ?? "error";
  const text =
    ownText(codeText, code) ?? ownText(COMMON_ERROR_TEXT, code) ?? GENERIC_ERROR_TEXT;
  return { code, text };
}
