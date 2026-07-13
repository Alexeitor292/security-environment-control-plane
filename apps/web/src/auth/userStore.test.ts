import { User, WebStorageStateStore } from "oidc-client-ts";
import { describe, expect, it } from "vitest";

import { SanitizingUserStore, stripRefreshToken } from "./userStore";

// A distinctive value we can grep for across the entire underlying storage — it must never survive.
const RT_SENTINEL = "REFRESH-SENTINEL-do-not-persist-3f9a7c";

function fakeStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (k) => (map.has(k) ? (map.get(k) as string) : null),
    key: (i) => Array.from(map.keys())[i] ?? null,
    removeItem: (k) => void map.delete(k),
    setItem: (k, v) => void map.set(k, String(v)),
  } as Storage;
}

/** Every raw value currently in the underlying storage (what actually lands on disk/session). */
function allRawValues(store: Storage): string[] {
  const out: string[] = [];
  for (let i = 0; i < store.length; i++) {
    const k = store.key(i);
    if (k !== null) {
      const v = store.getItem(k);
      if (v !== null) out.push(v);
    }
  }
  return out;
}

function userWithRefreshToken(): User {
  return new User({
    access_token: "ACCESS-TOKEN-abc",
    id_token: "ID-TOKEN-def",
    refresh_token: RT_SENTINEL,
    token_type: "Bearer",
    scope: "openid profile email",
    profile: { sub: "user-1", iss: "https://idp.test", aud: "secp-web", exp: 0, iat: 0 },
    expires_at: 4102444800, // far future — the user is not expired
    session_state: "sess-123",
  });
}

const KEY = "user:https://idp.test:secp-web";

describe("stripRefreshToken", () => {
  it("removes refresh_token and preserves every other field", () => {
    const input = JSON.stringify({
      access_token: "ACCESS-TOKEN-abc",
      id_token: "ID-TOKEN-def",
      refresh_token: RT_SENTINEL,
      token_type: "Bearer",
      scope: "openid profile email",
      expires_at: 4102444800,
      session_state: "sess-123",
      profile: { sub: "user-1" },
    });
    const out = stripRefreshToken(input);
    const parsed = JSON.parse(out) as Record<string, unknown>;
    expect(parsed.refresh_token).toBeUndefined();
    expect("refresh_token" in parsed).toBe(false);
    expect(parsed.access_token).toBe("ACCESS-TOKEN-abc");
    expect(parsed.id_token).toBe("ID-TOKEN-def");
    expect(parsed.token_type).toBe("Bearer");
    expect(parsed.scope).toBe("openid profile email");
    expect(parsed.expires_at).toBe(4102444800);
    expect(parsed.session_state).toBe("sess-123");
    expect(out).not.toContain(RT_SENTINEL);
    expect(out).not.toContain("refresh_token");
  });

  it("is a structural no-op when there is no refresh_token", () => {
    const input = JSON.stringify({ access_token: "a", token_type: "Bearer" });
    expect(JSON.parse(stripRefreshToken(input))).toEqual({
      access_token: "a",
      token_type: "Bearer",
    });
  });

  it("fails closed to '' on malformed / non-object JSON (never echoes the input)", () => {
    expect(stripRefreshToken(`{"refresh_token": ${RT_SENTINEL}`)).toBe(""); // truncated JSON
    expect(stripRefreshToken("not json at all")).toBe("");
    expect(stripRefreshToken("null")).toBe("");
    expect(stripRefreshToken("42")).toBe("");
    expect(stripRefreshToken(`["${RT_SENTINEL}"]`)).toBe(""); // arrays are not a User
  });
});

describe("SanitizingUserStore — Section 4A: persistence sanitization", () => {
  it("never writes the refresh_token to the underlying storage", async () => {
    const raw = fakeStorage();
    const store = new SanitizingUserStore(raw);
    await store.set(KEY, userWithRefreshToken().toStorageString());

    const values = allRawValues(raw);
    expect(values.length).toBeGreaterThan(0);
    for (const v of values) {
      expect(v).not.toContain(RT_SENTINEL);
      expect(v).not.toContain("refresh_token");
    }
  });

  it("restores a usable User (access token, id token, expiry) with NO refresh token", async () => {
    const raw = fakeStorage();
    const store = new SanitizingUserStore(raw);
    await store.set(KEY, userWithRefreshToken().toStorageString());

    const stored = await store.get(KEY);
    expect(stored).not.toBeNull();
    const restored = await User.fromStorageString(stored as string);

    expect(restored.refresh_token).toBeUndefined();
    expect(restored.access_token).toBe("ACCESS-TOKEN-abc"); // API calls still work
    expect(restored.id_token).toBe("ID-TOKEN-def"); // logout id_token hint still works
    expect(restored.scope).toBe("openid profile email");
    expect(restored.token_type).toBe("Bearer");
    expect(restored.expired).toBe(false); // expiry is preserved (far-future)
  });

  it("fails closed on malformed stored data — returns null, never the raw contents", async () => {
    const raw = fakeStorage();
    // A legacy/corrupt entry written by anything other than us (same default 'oidc.' prefix).
    const legacy = new WebStorageStateStore({ store: raw });
    await legacy.set(KEY, `{ this is not valid json ${RT_SENTINEL}`);

    const store = new SanitizingUserStore(raw);
    const got = await store.get(KEY);
    expect(got).toBeNull(); // contents never surfaced to app code
    // and the malformed entry is cleared, not left behind
    expect(await legacy.get(KEY)).toBeNull();
  });

  it("refuses to persist an unsanitizable value on write (fail closed)", async () => {
    const raw = fakeStorage();
    const store = new SanitizingUserStore(raw);
    await store.set(KEY, "not json"); // malformed -> nothing persisted
    expect(allRawValues(raw)).toHaveLength(0);
    expect(await store.get(KEY)).toBeNull();
  });
});

describe("SanitizingUserStore — Section 4C: legacy / stale storage", () => {
  it("re-sanitizes a legacy stored User that still carries a refresh token", async () => {
    const raw = fakeStorage();
    // Simulate a value persisted by an EARLIER build that did not sanitize (raw refresh_token on disk).
    const legacy = new WebStorageStateStore({ store: raw });
    await legacy.set(KEY, userWithRefreshToken().toStorageString());
    expect(allRawValues(raw).some((v) => v.includes(RT_SENTINEL))).toBe(true); // present beforehand

    const store = new SanitizingUserStore(raw);
    const got = await store.get(KEY);

    // the value handed back to app code carries no refresh token...
    expect(got).not.toBeNull();
    expect(got).not.toContain(RT_SENTINEL);
    const restored = await User.fromStorageString(got as string);
    expect(restored.refresh_token).toBeUndefined();
    expect(restored.access_token).toBe("ACCESS-TOKEN-abc");

    // ...and the underlying storage has been rewritten in sanitized form (no lingering token).
    for (const v of allRawValues(raw)) expect(v).not.toContain(RT_SENTINEL);
  });

  it("delegates remove/getAllKeys to the underlying store", async () => {
    const raw = fakeStorage();
    const store = new SanitizingUserStore(raw);
    await store.set(KEY, userWithRefreshToken().toStorageString());
    expect(await store.getAllKeys()).toContain(KEY);
    await store.remove(KEY);
    expect(await store.getAllKeys()).not.toContain(KEY);
    expect(await store.get(KEY)).toBeNull();
  });
});
