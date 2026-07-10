import { intensityClass } from "./bg";

describe("intensityClass", () => {
  it("maps each intensity to a stable suffix", () => {
    expect(intensityClass("subtle")).toBe("is-subtle");
    expect(intensityClass("standard")).toBe("is-standard");
    expect(intensityClass("hero")).toBe("is-hero");
  });

  it("defaults undefined/unknown to the cheapest 'subtle' — never accidental hero", () => {
    expect(intensityClass(undefined)).toBe("is-subtle");
    // @ts-expect-error exercising the defensive default
    expect(intensityClass("bogus")).toBe("is-subtle");
  });
});
