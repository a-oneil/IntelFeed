import { describe, it, expect } from "vitest";
import { blockedReasonShort, fallbackFixLabel, fallbackMessage, isCapReason } from "../aiProvenance";

describe("fallbackFixLabel", () => {
  it("names the fix for the reason: add a key, raise a cap, or open My AI", () => {
    expect(fallbackFixLabel("no_key")).toBe("Add a key");
    expect(fallbackFixLabel("monthly_cap")).toBe("Raise my cap");
    expect(fallbackFixLabel("daily_cap")).toBe("Raise my cap");
    expect(fallbackFixLabel("key_paused")).toBe("My AI settings");
    expect(fallbackFixLabel("key_disabled")).toBe("My AI settings");
    expect(fallbackFixLabel(undefined)).toBe("My AI settings");
  });
});

describe("blockedReasonShort", () => {
  it("gives the row's short words for every reason, and nothing for none", () => {
    expect(blockedReasonShort("key_paused")).toBe("key paused");
    expect(blockedReasonShort("key_disabled")).toBe("key disabled");
    expect(blockedReasonShort("type_not_allowed")).toBe("type not allowed");
    expect(blockedReasonShort("endpoint_blocked")).toBe("endpoint blocked");
    expect(blockedReasonShort("monthly_cap")).toBe("over monthly cap");
    expect(blockedReasonShort("daily_cap")).toBe("over daily cap");
    expect(blockedReasonShort("no_key")).toBe("no key");
    expect(blockedReasonShort("some_new_reason")).toBe("some new reason");
    expect(blockedReasonShort(null)).toBeNull();
    expect(blockedReasonShort("")).toBeNull();
  });
});

describe("isCapReason / fallbackMessage", () => {
  it("tells the cap reasons apart and keeps a sentence for each code", () => {
    expect(isCapReason("monthly_cap")).toBe(true);
    expect(isCapReason("daily_cap")).toBe(true);
    expect(isCapReason("no_key")).toBe(false);
    expect(fallbackMessage("daily_cap")).toMatch(/daily request cap/);
    expect(fallbackMessage(null)).toBeNull();
  });
});
