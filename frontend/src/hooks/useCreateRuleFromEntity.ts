import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { DetectionRule } from "@/api/types";

interface RuleFromEntityParams {
  entityType: "cve" | "ttp";
  entityValue: string;
  entryId?: string;
  ruleType?: string;
}

/** Rule templates keyed by entity type and sub-type */
function generateRuleContent(params: RuleFromEntityParams): {
  title: string;
  rule_content: string;
  rule_type: string;
  severity: string;
  tags: string[];
} {
  const { entityType, entityValue, ruleType = "sigma" } = params;

  if (entityType === "ttp") {
    return {
      title: `Detect ${entityValue}`,
      rule_type: "sigma",
      rule_content: `title: Detect ${entityValue}
status: experimental
description: Detects activity matching MITRE ATT&CK technique ${entityValue}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # REPLACE-ME: add the process/command-line pattern that indicates ${entityValue} activity
        CommandLine|contains: 'REPLACE-ME'
    condition: selection
level: medium
tags:
    - attack.${entityValue.toLowerCase().replace(/\./g, "")}`,
      severity: "medium",
      tags: ["ttp", entityValue],
    };
  }

  if (entityType === "cve") {
    return {
      title: `Detect Exploitation of ${entityValue}`,
      rule_type: "sigma",
      rule_content: `title: Detect Exploitation of ${entityValue}
status: experimental
description: Detects potential exploitation attempts of ${entityValue}
logsource:
    category: webserver
detection:
    selection:
        # REPLACE-ME: add the request pattern that indicates ${entityValue} exploitation attempts
        cs-uri-query|contains: 'REPLACE-ME'
    condition: selection
level: high
tags:
    - attack.initial_access
    - cve.${entityValue.toLowerCase().replace(/-/g, "_")}`,
      severity: "high",
      tags: ["cve", entityValue],
    };
  }

  return {
    title: `Detection Rule for ${entityValue}`,
    rule_type: ruleType,
    rule_content: `# Detection rule for: ${entityValue}`,
    severity: "medium",
    tags: [],
  };
}

/** Creates a detection rule pre-populated with entity context */
export function useCreateRuleFromEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (params: RuleFromEntityParams) => {
      const template = generateRuleContent(params);
      const { data } = await api.post<DetectionRule>("/detection-rules", {
        ...template,
        entry_id: params.entryId || null,
        source_ttps: params.entityType === "ttp" ? [params.entityValue] : [],
        is_draft: true,
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

export { generateRuleContent };
