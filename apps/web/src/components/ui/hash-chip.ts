// Centralized hash/id truncation for HashChip and mono metadata lines.
// Replaces the ad-hoc `x.slice(a, b) + "…"` expressions scattered through
// page JSX.

const ELLIPSIS = "…";

export interface TruncateHashOptions {
  /** Digest characters to keep (after any `algo:` prefix). Default 12. */
  digits?: number;
  /** Keep or strip the `algo:` prefix. Pages today use both dialects
   *  (`content_hash.slice(0, 23)` keeps it; `hash.slice(7, 19)` strips it).
   *  Default "keep". */
  prefix?: "keep" | "strip";
  /** Append an ellipsis when truncating. Default true; today's bare
   *  `id.slice(0, 8)` call sites migrate with `ellipsis: false`. */
  ellipsis?: boolean;
}

/**
 * Truncate a hash or opaque id for display.
 * - `sha256:<digest>` keeps (or strips) the algorithm prefix and truncates
 *   the digest.
 * - Plain values (UUIDs, opaque ids) are truncated to `digits` characters.
 * - Values already short enough are returned unchanged (no trailing ellipsis).
 */
export function truncateHash(value: string, opts: TruncateHashOptions = {}): string {
  const digits = opts.digits ?? 12;
  const ellipsis = opts.ellipsis === false ? "" : ELLIPSIS;
  const colon = value.indexOf(":");
  const hasAlgoPrefix = colon > 0 && /^[a-z0-9-]+$/.test(value.slice(0, colon));
  const prefix =
    hasAlgoPrefix && opts.prefix !== "strip" ? value.slice(0, colon + 1) : "";
  const digest = hasAlgoPrefix ? value.slice(colon + 1) : value;
  if (digest.length <= digits) return `${prefix}${digest}`;
  return `${prefix}${digest.slice(0, digits)}${ellipsis}`;
}

/** Short id form used for entity ids in metadata lines (8 chars). */
export function shortId(value: string): string {
  return truncateHash(value, { digits: 8 });
}
