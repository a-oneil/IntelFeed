import { describe, expect, it } from "vitest";
import type { RelRow } from "../relationshipBrowser";
import { reasonOf, sourceLabel, sourcesOf, statusOf } from "../relationshipSource";

const row = (item: Record<string, unknown>): RelRow =>
  ({ type: "ttp", label: "T1486 Data Encrypted for Impact", item: { id: "x", relationship_id: "r", ...item } }) as unknown as RelRow;

describe("relationship source wording", () => {
  it("names MITRE, and a feed that also lists it", () => {
    const r = row({ relationship_source: "external_feed", relationship_description: "MITRE ATT&CK", relationship_confidence: "confirmed" });
    const parts = sourcesOf(r, ["ransomware.live"]);
    expect(sourceLabel(parts)).toBe("MITRE ATT&CK + ransomware.live");
    // "MITRE ATT&CK" is the source's name, not a reason.
    expect(reasonOf(r, parts)).toEqual({ quote: null, text: "MITRE ATT&CK lists this. ransomware.live lists it too." });
    expect(statusOf(r.item)).toBe("Confirmed");
  });

  it("quotes a feed's note and the reviewer's reason", () => {
    const feed = row({ relationship_source: "enrichment", relationship_description: "Observed during a sandbox detonation", relationship_confidence: "probable" });
    const parts = sourcesOf(feed, ["ransomware.live"]);
    expect(reasonOf(feed, parts).quote).toBe("Observed during a sandbox detonation");
    expect(statusOf(feed.item)).toBe("Reported by the source, not checked against articles");

    const reviewed = row({
      relationship_source: "co_occurrence",
      relationship_adjudication: "corroborated",
      relationship_confidence: "confirmed",
      relationship_description: "The headline states it.",
    });
    expect(sourceLabel(sourcesOf(reviewed))).toBe("AI-reviewed articles");
    expect(statusOf(reviewed.item)).toBe("Confirmed by articles from two or more sources");
  });

  it("says plainly when nobody has checked it", () => {
    const r = row({ relationship_source: "co_occurrence", relationship_confidence: "possible" });
    const parts = sourcesOf(r);
    expect(sourceLabel(parts)).toBe("Articles, not reviewed");
    expect(reasonOf(r, parts).text).toBe("Linked from articles that mention both. No reviewer has checked it yet.");
    expect(statusOf(r.item)).toBe("Not confirmed yet");
  });

  it("names an AI extraction as such, not as a source or a co-mention", () => {
    const r = row({ relationship_source: "auto_extracted", relationship_confidence: "probable" });
    const parts = sourcesOf(r);
    expect(sourceLabel(parts)).toBe("AI, from an article");
    expect(reasonOf(r, parts).text).toBe("The AI read it in an article. No reviewer has checked it yet.");
    expect(statusOf(r.item)).toBe("Stated in an article, not confirmed by a second source yet");
  });
});
