import { describe, it, expect } from "vitest";
import { apiErrorInfo, apiErrorReason, hasErrorEnvelope } from "../errors";

const axiosErr = (error: Record<string, unknown>) => ({ response: { data: { error } } });

describe("apiErrorInfo", () => {
  it("returns the envelope's code and message", () => {
    expect(apiErrorInfo(axiosErr({ code: "forbidden", message: "Nope", details: [] }))).toEqual({
      code: "forbidden",
      message: "Nope",
      details: [],
    });
  });

  it("exposes object details raw, so a refusal's reason can be read", () => {
    const err = axiosErr({ code: "user_ai_key_required", message: "Over cap", details: { reason: "monthly_cap" } });
    expect(apiErrorInfo(err)).toEqual({ code: "user_ai_key_required", message: "Over cap", details: { reason: "monthly_cap" } });
    expect(apiErrorReason(err)).toBe("monthly_cap");
  });

  it("has no reason without object details", () => {
    expect(apiErrorReason(axiosErr({ code: "validation_error", message: "x", details: [{ msg: "y" }] }))).toBeNull();
    expect(apiErrorReason(axiosErr({ code: "forbidden", message: "x" }))).toBeNull();
    expect(apiErrorReason(new Error("boom"))).toBeNull();
    expect(apiErrorInfo(axiosErr({ code: "forbidden", message: "x" })).details).toBeNull();
  });

  it("knows an envelope from a bare error", () => {
    expect(hasErrorEnvelope(axiosErr({ code: "x", message: "y" }))).toBe(true);
    expect(hasErrorEnvelope(new Error("boom"))).toBe(false);
    expect(hasErrorEnvelope({ response: { status: 429 } })).toBe(false);
  });

  it("appends the first validation detail, with its field, so a refused cap says why", () => {
    const err = axiosErr({
      code: "validation_error",
      message: "Request validation failed",
      details: [{ field: "monthly_cap_usd", message: "Input should be greater than 0", code: "greater_than" }],
    });
    expect(apiErrorInfo(err)).toMatchObject({
      code: "validation_error",
      message: "Request validation failed: monthly_cap_usd — Input should be greater than 0",
    });
  });

  it("accepts pydantic's raw loc/msg shape too", () => {
    const err = axiosErr({
      code: "validation_error",
      message: "Request validation failed",
      details: [{ loc: ["body", "name"], msg: "Field required" }],
    });
    expect(apiErrorInfo(err).message).toBe("Request validation failed: name — Field required");
  });

  it("falls back to the thrown message without an envelope", () => {
    expect(apiErrorInfo(new Error("boom"))).toEqual({ code: null, message: "boom", details: null });
    expect(apiErrorInfo("x")).toEqual({ code: null, message: "Request failed", details: null });
  });
});
