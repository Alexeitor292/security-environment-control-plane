import { principalDisplay } from "./identity";

describe("principalDisplay", () => {
  it("derives the name from the email local part", () => {
    const d = principalDisplay({ email: "dev-admin@example.com", is_dev_fallback: true });
    expect(d.name).toBe("dev-admin");
    expect(d.initials).toBe("DA");
  });

  it("labels dev-fallback identities truthfully", () => {
    expect(
      principalDisplay({ email: "dev-admin@example.com", is_dev_fallback: true }).detail,
    ).toBe("dev-admin@example.com · dev fallback");
    expect(
      principalDisplay({ email: "ops@org.io", is_dev_fallback: false }).detail,
    ).toBe("ops@org.io");
  });

  it("never invents a role or organization name", () => {
    const d = principalDisplay({ email: "someone@org.io", is_dev_fallback: false });
    for (const text of [d.name, d.detail]) {
      expect(text.toLowerCase()).not.toContain("admin ·");
      expect(text.toLowerCase()).not.toContain("org ·");
    }
  });

  it("handles emails without an @ and single-word names", () => {
    const d = principalDisplay({ email: "root", is_dev_fallback: false });
    expect(d.name).toBe("root");
    expect(d.initials).toBe("RO");
  });
});
