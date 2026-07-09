import {
  COMMON_ERROR_TEXT,
  GENERIC_ERROR_TEXT,
  resolveClosedCodeCopy,
} from "./closed-code-error";

class FakeApiError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

describe("resolveClosedCodeCopy", () => {
  it("maps known common codes to fixed copy", () => {
    const copy = resolveClosedCodeCopy(
      new FakeApiError("api_unreachable", "fetch failed: http://10.0.0.5:8080"),
    );
    expect(copy.code).toBe("api_unreachable");
    expect(copy.text).toBe(COMMON_ERROR_TEXT.api_unreachable);
  });

  it("never renders the backend message for unknown codes", () => {
    const backendMessage =
      "Traceback: psycopg error at postgresql://secp:hunter2@db:5432/secp";
    const copy = resolveClosedCodeCopy(
      new FakeApiError("some_new_backend_code", backendMessage),
    );
    expect(copy.code).toBe("some_new_backend_code");
    expect(copy.text).toBe(GENERIC_ERROR_TEXT);
    expect(copy.text).not.toContain("Traceback");
    expect(copy.text).not.toContain("hunter2");
  });

  it("prefers the page-supplied closed map over the common map", () => {
    const copy = resolveClosedCodeCopy(
      new FakeApiError("readonly_preflight_queue_conflict", "raw backend text"),
      {
        readonly_preflight_queue_conflict:
          "A preflight is already active for this authorization.",
      },
    );
    expect(copy.text).toBe(
      "A preflight is already active for this authorization.",
    );
    expect(copy.text).not.toContain("raw backend text");
  });

  it("handles errors without a code (network failures, plain throws)", () => {
    expect(resolveClosedCodeCopy(new TypeError("Failed to fetch"))).toEqual({
      code: "error",
      text: GENERIC_ERROR_TEXT,
    });
    expect(resolveClosedCodeCopy(null)).toEqual({
      code: "error",
      text: GENERIC_ERROR_TEXT,
    });
    expect(resolveClosedCodeCopy("string error")).toEqual({
      code: "error",
      text: GENERIC_ERROR_TEXT,
    });
  });

  it("resolves Object.prototype keys to fixed generic copy, never inherited members", () => {
    for (const code of ["constructor", "toString", "valueOf", "hasOwnProperty"]) {
      const copy = resolveClosedCodeCopy(new FakeApiError(code, "raw"), {
        page_code: "Page copy.",
      });
      expect(typeof copy.text).toBe("string");
      expect(copy.text).toBe(GENERIC_ERROR_TEXT);
    }
  });

  it("rejects codes outside the closed-code grammar (free text, over-length)", () => {
    const freeText = resolveClosedCodeCopy(
      new FakeApiError("Traceback at postgresql://db:5432 !!", "raw"),
    );
    expect(freeText.code).toBe("error");
    expect(freeText.text).toBe(GENERIC_ERROR_TEXT);
    const overlong = resolveClosedCodeCopy(new FakeApiError("a".repeat(65), "raw"));
    expect(overlong.code).toBe("error");
  });

  it("keeps fixed copy free of endpoints, secrets, and raw-message markers", () => {
    const allCopy = [GENERIC_ERROR_TEXT, ...Object.values(COMMON_ERROR_TEXT)];
    for (const text of allCopy) {
      expect(text).not.toMatch(/:\/\//);
      expect(text).not.toMatch(/:\d{4,5}\b/);
      expect(text.toLowerCase()).not.toContain("token");
      expect(text.toLowerCase()).not.toContain("secret");
    }
  });
});
