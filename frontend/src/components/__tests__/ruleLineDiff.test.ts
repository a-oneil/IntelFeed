import { describe, it, expect } from "vitest";
import { lineDiff } from "../ruleBench/lineDiff";

describe("lineDiff", () => {
  it("keeps shared lines and marks only what differs", () => {
    const theirs = "SigninLogs\n| where ResultType == 0\n| project User";
    const mine = "SigninLogs\n| where ResultType == 0\n| where AppId in (Ids)\n| project User";
    const lines = lineDiff(theirs, mine);
    expect(lines.filter((l) => l.op === "same")).toHaveLength(3);
    expect(lines.filter((l) => l.op === "add").map((l) => l.text)).toEqual(["| where AppId in (Ids)"]);
    expect(lines.filter((l) => l.op === "remove")).toHaveLength(0);
  });

  it("marks a replaced line as one removal and one addition", () => {
    const lines = lineDiff("a\nb\nc", "a\nB\nc");
    expect(lines.map((l) => l.op)).toEqual(["same", "remove", "add", "same"]);
  });

  it("degrades to a whole-body replace rather than building a huge LCS table", () => {
    const long = Array.from({ length: 12 }, (_, i) => `line ${i}`).join("\n");
    const lines = lineDiff(long, long, 5);
    // Identical input, but past the cap nothing is reported as unchanged.
    expect(lines.some((l) => l.op === "same")).toBe(false);
    expect(lines).toHaveLength(24);
  });
});
