import { describe, expect, it } from "vitest";
import type { EntitySearchResult } from "@/api/types";
import { getEntityProfileConfig } from "../entityProfileConfig";
import { editableFieldsFor, isEditableEntityType } from "../EntityEditModal";

const entity = (partial: Partial<EntitySearchResult>) => partial as EntitySearchResult;

const fieldsFor = (type: Parameters<typeof getEntityProfileConfig>[0], e: EntitySearchResult) =>
  editableFieldsFor(getEntityProfileConfig(type), e);

describe("editableFieldsFor", () => {
  it("offers a named entity its name, aliases, editable badges and description", () => {
    const fields = fieldsFor("threat_actor", entity({ name: "APT29", motivation: "espionage" }));

    expect(fields.map((f) => f.key)).toEqual([
      "name",
      "aliases",
      "motivation",
      "country",
      "description",
    ]);
    expect(fields.find((f) => f.key === "aliases")?.kind).toBe("aliases");
    expect(fields.find((f) => f.key === "description")?.kind).toBe("textarea");
  });

  it("skips name and aliases for types identified by an external id", () => {
    const cve = fieldsFor("cve", entity({ cve_id: "CVE-2024-1234", severity: "high" }));
    expect(cve.map((f) => f.key)).toEqual(["severity", "exploit_availability", "description"]);

    const ttp = fieldsFor("ttp", entity({ technique_id: "T1059", tactic: "execution" }));
    expect(ttp.map((f) => f.key)).toEqual(["tactic", "description"]);
  });

  it("includes identity fields, giving the vendor picker its own kind", () => {
    const fields = fieldsFor("product", entity({ name: "Exchange", vendor_id: "v1" }));

    expect(fields.map((f) => f.key)).toEqual([
      "name",
      "aliases",
      "product_type",
      "vendor_id",
      "website",
      "description",
    ]);
    expect(fields.find((f) => f.key === "vendor_id")?.kind).toBe("vendor");
  });

  it("never repeats a field a badge and an identity row both name", () => {
    const fields = fieldsFor("country", entity({ name: "Iran", region: "Middle East" }));
    const keys = fields.map((f) => f.key);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys).toContain("region");
    expect(keys).toContain("iso_code");
  });

  it("only reports a badge as editable when the profile makes it editable", () => {
    // tool_type is a read-only badge; the tool form must not offer it.
    const fields = fieldsFor("tool", entity({ name: "Mimikatz", tool_type: "credential_access" }));
    expect(fields.map((f) => f.key)).not.toContain("tool_type");
  });
});

describe("isEditableEntityType", () => {
  it("covers the types with a PUT endpoint", () => {
    for (const type of ["threat_actor", "malware", "cve", "ttp", "country", "tool", "vendor", "product"]) {
      expect(isEditableEntityType(type)).toBe(true);
    }
  });

  it("excludes mitigation, which has no update endpoint", () => {
    expect(isEditableEntityType("mitigation")).toBe(false);
  });
});
