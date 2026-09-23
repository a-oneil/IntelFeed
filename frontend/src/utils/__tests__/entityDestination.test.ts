import { describe, it, expect, beforeEach } from "vitest";
import { entityDestination } from "../entityDestination";
import { useIntelStore } from "@/stores/intelStore";

describe("entityDestination", () => {
  beforeEach(() => {
    useIntelStore.getState().setActiveSection("threat_actors");
  });

  describe("entity profile types", () => {
    // Every canonical entity type with a full-width profile route.
    const profileTypes = [
      "threat_actor",
      "malware",
      "cve",
      "ttp",
      "country",
      "tool",
      "mitigation",
      "vendor",
      "product",
    ];

    it.each(profileTypes)("routes %s to its profile page", (type) => {
      const dest = entityDestination(type, "abc-123");
      expect(dest.path).toBe(`/workbench/${type}/abc-123`);
      expect(dest.before).toBeUndefined();
    });

    it("maps the legacy 'actor' slug onto the threat_actor profile", () => {
      expect(entityDestination("actor", "abc-123").path).toBe("/workbench/threat_actor/abc-123");
    });
  });

  describe("object kinds with dedicated routes", () => {
    it("routes detection_rule to the rule detail page", () => {
      expect(entityDestination("detection_rule", "r1").path).toBe("/workbench/rule/r1");
    });

    it("accepts the short 'rule' spelling used by the type: filter", () => {
      expect(entityDestination("rule", "r1").path).toBe("/workbench/rule/r1");
    });

    it("routes intel_report to the report builder", () => {
      expect(entityDestination("intel_report", "rep1").path).toBe("/workbench/report/rep1");
    });

    it("routes entry to the feed reader deep link", () => {
      expect(entityDestination("entry", "e1").path).toBe("/?entry=e1");
    });
  });

  describe("section-scoped destinations", () => {
    it("sends campaigns to explore with the campaigns section pre-selected", () => {
      const dest = entityDestination("campaign", "c1");
      expect(dest.path).toBe("/workbench/explore");
      expect(dest.before).toBeTypeOf("function");
      dest.before!();
      expect(useIntelStore.getState().activeSection).toBe("campaigns");
    });

    it("sends PIRs to explore with the requirements section pre-selected", () => {
      const dest = entityDestination("pir", "p1");
      expect(dest.path).toBe("/workbench/explore");
      expect(dest.before).toBeTypeOf("function");
      dest.before!();
      expect(useIntelStore.getState().activeSection).toBe("requirements");
    });

    it("does not mutate the store until before() is called", () => {
      entityDestination("campaign", "c1");
      expect(useIntelStore.getState().activeSection).toBe("threat_actors");
    });
  });

  describe("fallback", () => {
    it("falls back to explore for ransomware_victim (no profile route yet)", () => {
      const dest = entityDestination("ransomware_victim", "v1");
      expect(dest.path).toBe("/workbench/explore");
      expect(dest.before).toBeUndefined();
    });

    it("falls back to explore for an unknown type", () => {
      expect(entityDestination("not_a_type", "x").path).toBe("/workbench/explore");
    });
  });

  it("does not escape or alter the id", () => {
    expect(entityDestination("cve", "CVE-2026-1234").path).toBe("/workbench/cve/CVE-2026-1234");
    expect(entityDestination("ttp", "T1059.001").path).toBe("/workbench/ttp/T1059.001");
  });
});
