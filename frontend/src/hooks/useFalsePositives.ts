import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

/** How far a "wrong match" report reaches.
 *  - `entry`  — unlink from this one article.
 *  - `alias`  — drop the surface form from the entity's aliases and unlink every
 *               article that matched only via it.
 *  - `global` — block the surface form from matching any entity, anywhere. */
export type FalsePositiveScope = "entry" | "alias" | "global";

export interface ReportFalsePositiveParams {
  entity_type: string;
  entity_id: string;
  entity_value: string;
  source_entry_id?: string;
  reason?: string;
  scope: FalsePositiveScope;
}

export interface ReportFalsePositiveResult {
  id: string;
  unlinked_from_entry: boolean;
  added_to_autolinker_fp_list: boolean;
  alias_removed: boolean;
  links_removed: number;
}

/** Reader/profile feedback loop: unlink a wrong entity match, optionally teaching
 * the autolinker to stop matching that surface form on future entries. */
export function useReportFalsePositive() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (params: ReportFalsePositiveParams) => {
      const { data } = await api.post<ReportFalsePositiveResult>("/false-positives", params);
      return data;
    },
    onSuccess: (_, vars) => {
      if (vars.source_entry_id) {
        qc.invalidateQueries({ queryKey: ["pivot", vars.entity_type, vars.entity_id] });
        qc.invalidateQueries({ queryKey: ["entity-timeline", vars.entity_type, vars.entity_id] });
        qc.invalidateQueries({ queryKey: ["entity-graph", vars.entity_type, vars.entity_id] });
        qc.invalidateQueries({ queryKey: ["entry-graph", vars.source_entry_id] });
        qc.invalidateQueries({ queryKey: ["entry", vars.source_entry_id] });
        // The reader's inline highlighter is fed by the per-type entry-entity
        // queries (["entry-vendors", id], ["entry-threat-actors", id], …), not by
        // ["entry", id] — without these the reported word stays underlined until
        // the article is reopened. Match them by shape so every type is covered.
        qc.invalidateQueries({
          predicate: (q) =>
            typeof q.queryKey[0] === "string" &&
            (q.queryKey[0] as string).startsWith("entry-") &&
            q.queryKey[1] === vars.source_entry_id,
        });
      }
      // An alias drop or a global block changes links on other articles too.
      if (vars.scope !== "entry") {
        qc.invalidateQueries({ queryKey: ["pivot", vars.entity_type, vars.entity_id] });
        qc.invalidateQueries({ queryKey: ["workbench"] });
      }
    },
  });
}
