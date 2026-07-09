// Principal display derivation — pure, no fabricated org names or roles.
// The Principal type carries email / permissions / is_dev_fallback only, so
// the user card renders values derived from those fields and nothing else.

export interface PrincipalDisplay {
  /** Primary line: the email's local part (e.g. "dev-admin"). */
  name: string;
  /** Secondary line: the full email — real identity, never an invented role. */
  detail: string;
  /** 1–2 letter avatar monogram derived from the name. */
  initials: string;
}

export function principalDisplay(principal: {
  email: string;
  is_dev_fallback: boolean;
}): PrincipalDisplay {
  const email = principal.email;
  const at = email.indexOf("@");
  const name = at > 0 ? email.slice(0, at) : email;
  const parts = name.split(/[.\-_+]/).filter(Boolean);
  const initials =
    parts.length >= 2
      ? `${parts[0][0]}${parts[1][0]}`.toUpperCase()
      : name.slice(0, 2).toUpperCase();
  const detail = principal.is_dev_fallback ? `${email} · dev fallback` : email;
  return { name, detail, initials };
}
