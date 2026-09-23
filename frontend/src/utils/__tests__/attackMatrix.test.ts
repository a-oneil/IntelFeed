import { describe, expect, it } from "vitest";
import { buildNavigatorLayer, heatAlpha, type AttackMatrixData, type MatrixTechnique } from "../attackMatrix";

function tech(overrides: Partial<MatrixTechnique>): MatrixTechnique {
  return {
    id: "00000000-0000-0000-0000-000000000001",
    technique_id: "T1566",
    name: "Phishing",
    article_count: 0,
    rule_count: 0,
    has_rule: false,
    coverage: "no_rule",
    deployable: false,
    missing_data_sources: [],
    is_deprecated: false,
    ...overrides,
  };
}

function matrix(overrides: Partial<AttackMatrixData> = {}): AttackMatrixData {
  return {
    domain: "enterprise",
    days: 30,
    generated_at: "2026-07-04T00:00:00Z",
    technique_count: 2,
    max_article_count: 9,
    coverage_summary: { total: 2, covered: 1, library_only: 0, no_rule: 1, coverage_percentage: 50 },
    tactics: [
      {
        id: "initial-access",
        name: "Initial Access",
        techniques: [
          tech({
            article_count: 7,
            rollup_article_count: 9,
            rule_count: 2,
            has_rule: true,
            coverage: "covered",
            deployable: true,
            subtechniques: [
              tech({ technique_id: "T1566.001", name: "Spearphishing Attachment", article_count: 2 }),
            ],
          }),
        ],
      },
    ],
    ...overrides,
  };
}

describe("heatAlpha", () => {
  it("returns 0 for unseen techniques and empty matrices", () => {
    expect(heatAlpha(0, 10)).toBe(0);
    expect(heatAlpha(5, 0)).toBe(0);
  });

  it("ramps monotonically and caps at 1", () => {
    const low = heatAlpha(1, 100);
    const mid = heatAlpha(25, 100);
    const max = heatAlpha(100, 100);
    expect(low).toBeGreaterThan(0);
    expect(mid).toBeGreaterThan(low);
    expect(max).toBeGreaterThan(mid);
    expect(max).toBeLessThanOrEqual(1);
  });
});

describe("buildNavigatorLayer", () => {
  it("emits one entry per technique and sub-technique with score = article count", () => {
    const layer = buildNavigatorLayer(matrix());
    expect(layer.domain).toBe("enterprise-attack");
    expect(layer.techniques).toHaveLength(2);

    const parent = layer.techniques.find((t) => t.techniqueID === "T1566");
    expect(parent).toMatchObject({ tactic: "initial-access", score: 7 });
    expect(parent?.comment).toContain("7 articles");
    expect(parent?.comment).toContain("2 rules");

    const sub = layer.techniques.find((t) => t.techniqueID === "T1566.001");
    expect(sub?.score).toBe(2);
  });

  it("scales the gradient to the matrix max and labels the window", () => {
    const layer = buildNavigatorLayer(matrix());
    expect(layer.gradient.maxValue).toBe(9);
    expect(layer.name).toContain("last 30 days");

    const allTime = buildNavigatorLayer(matrix({ days: null, max_article_count: 0 }));
    expect(allTime.name).toContain("all time");
    expect(allTime.gradient.maxValue).toBe(1); // never a degenerate 0..0 gradient
  });
});
