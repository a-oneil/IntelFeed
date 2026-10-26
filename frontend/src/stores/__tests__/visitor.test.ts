import { describe, expect, it } from "vitest";
import { selectCanWrite, selectIsVisitor } from "@/stores/authStore";

const base = { accessToken: null, refreshToken: null, user: null, publicReadOnly: false };

describe("public read-only mode selectors", () => {
  it("is a visitor only with no session while the instance allows visitors", () => {
    expect(selectIsVisitor({ ...base, publicReadOnly: true })).toBe(true);
    expect(selectIsVisitor(base)).toBe(false);
    expect(selectIsVisitor({ ...base, publicReadOnly: true, accessToken: "a" })).toBe(false);
    expect(selectIsVisitor({ ...base, publicReadOnly: true, refreshToken: "r" })).toBe(false);
  });

  it("can write only when signed in", () => {
    expect(selectCanWrite({ ...base, publicReadOnly: true })).toBe(false);
    expect(selectCanWrite({ ...base, accessToken: "a" })).toBe(true);
  });
});
