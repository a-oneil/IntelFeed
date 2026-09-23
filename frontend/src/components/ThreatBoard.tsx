import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { AsyncStateLoading } from "@/components/AsyncState";
import { Segmented } from "@/components/primitives";
import { useCoverageWorkspace } from "@/hooks/useCoverageWorkspace";
import {
  useBoardRules,
  usePrecedent,
  useSetThreatState,
  useThreatBoard,
  type BoardFacet,
  type ThreatBoardItem,
} from "@/hooks/useThreatBoard";
import { useIntelStore } from "@/stores/intelStore";
import { useOpenThread } from "@/utils/openEntry";
import styles from "./ThreatBoard.module.css";

/** The Threats board: one briefing row per resolved threat.

    A collapsed row is four things — identity, story, one quiet caption line,
    actions. No chip band: the evidence detail lives in the drawer the row
    expands into. The story is the nightly AI brief when one is cached (built
    only from the window's entries) and the window's lead headline otherwise —
    never a template sentence over three integers.

    There is deliberately no coverage percentage: source_ttps tag equality
    returns 88-90% for every actor in the database. `prior_rules` is an
    inventory to open, not a verdict. */

const WINDOWS = [
  { value: "7d", label: "7d" },
  { value: "14d", label: "14d" },
  { value: "30d", label: "30d" },
] as const;

const STATE_FILTERS = [
  { value: "open", label: "Open" },
  { value: "handled", label: "Handled" },
] as const;

const ENTITY_COLOR: Record<string, string> = {
  threat_actor: "var(--entity-actor)",
  malware: "var(--entity-malware)",
  cve: "var(--entity-cve)",
  ttp: "var(--entity-ttp)",
  // A story row is not an entity, and the board says so with the intel accent
  // rather than borrowing an entity colour it would then be lying about.
  story: "var(--accent-intel)",
};

const FACET_LABEL: Record<string, string> = {
  threat_actor: "actor",
  malware: "malware",
  cve: "vuln",
  story: "story",
};

/** The button names the job, derived from the counts server-side — in words a
    first-time visitor can read aloud, not board shorthand. */
function actionLabel(item: ThreatBoardItem): string {
  switch (item.action) {
    case "write":
      return "Draft detection rule →";
    case "extend":
      return `Extend ${item.prior_rules_strong} rule${item.prior_rules_strong === 1 ? "" : "s"} →`;
    case "diff":
      return `Check ${item.prior_rules} weak match${item.prior_rules === 1 ? "" : "es"} →`;
    case "audit":
      return `Audit ${item.on_record} known TTP${item.on_record === 1 ? "" : "s"} →`;
    case "adopt":
      return `Adopt ${item.prior_rules} ready rule${item.prior_rules === 1 ? "" : "s"} →`;
    case "collect":
      return item.is_story ? "Read the story →" : "Rules need telemetry →";
    case "merge":
      return "Send to merge";
    default:
      return "Review";
  }
}

/** Hover text that spells out what clicking the action actually does. */
function actionTitle(item: ThreatBoardItem): string {
  switch (item.action) {
    case "write":
      return "No rule covers this yet — draft one from the reported tradecraft";
    case "extend":
      return "Rules already name this threat — extend them with the newly reported techniques";
    case "diff":
      return "Only loosely-matching rules exist — compare them against what was reported";
    case "audit":
      return "Coverage looks current — audit it against everything on record";
    case "adopt":
      return "Matching rules can fire on your telemetry today — adopt them";
    case "collect":
      return item.is_story
        ? "No actor, malware or CVE has been named yet — read and identify it"
        : "Rules exist but need telemetry you don't collect yet";
    case "merge":
      return "This row duplicates another threat — merge them";
    default:
      return "Open the detail drawer";
  }
}

/** True once threading has an opinion about this row: its articles are fewer
    stories than they are outlets, which is the whole claim the feature makes. */
function foldsCoverage(item: ThreatBoardItem): boolean {
  return item.stories > 0 && item.stories !== item.attention;
}

/** Rows this one absorbed. Defensive because a freshly-deployed bundle can be
    served before the API container finishes restarting, and a row without the
    field must render, not throw. */
function absorbed(item: ThreatBoardItem): ThreatBoardItem["merged_from"] {
  return item.merged_from ?? [];
}

/** One quiet mono line under the story — the collapsed row's trace of what is
    behind it. Text, not furniture; the drawer carries the detail. */
function captionText(item: ThreatBoardItem): string {
  const parts: string[] = [];
  if (foldsCoverage(item)) parts.push(`${item.stories} stor${item.stories === 1 ? "y" : "ies"}`);
  parts.push(`${item.articles || item.attention} article${(item.articles || item.attention) === 1 ? "" : "s"}`);
  if (item.echoes_folded > 0)
    parts.push(`${item.echoes_folded} duplicate${item.echoes_folded === 1 ? "" : "s"} hidden`);
  if (item.writable_observables > 0) {
    parts.push(
      `${item.writable_observables} rule-ready indicator${item.writable_observables === 1 ? "" : "s"}`
    );
  }
  // A story row has no entity, so it can have no rule inventory. Saying
  // "nothing matches" about it would report a coverage gap that does not
  // exist — the gap is that nothing has named the story yet.
  if (item.is_story) {
    parts.push(
      item.beats > 1 ? `${item.beats} beats, still developing` : "no actor, malware or CVE resolved yet"
    );
    return parts.join(" · ");
  }
  // Posture only speaks when the library actually resolves rules to this CVE —
  // classify_cves also matches on title mentions, and "defended · nothing
  // matches" is a contradiction no caption should print.
  if (item.posture === "blind" && item.prior_rules > 0)
    parts.push("rules exist but need telemetry you don't collect");
  else if (item.posture === "defended" && item.prior_rules > 0)
    parts.push("a rule can fire on your telemetry today");
  if (item.prior_rules === 0) parts.push("no rule coverage yet");
  else if (item.prior_rules_strong === 0 && item.entity_type !== "cve")
    parts.push(`${item.prior_rules} rule${item.prior_rules === 1 ? "" : "s"} loosely match${item.prior_rules === 1 ? "es" : ""}`);
  else if (item.entity_type === "cve") {
    parts.push(`${item.prior_rules} rule${item.prior_rules === 1 ? "" : "s"} in the library`);
  } else {
    const weak = item.prior_rules - item.prior_rules_strong;
    parts.push(
      `${item.prior_rules_strong} rule${item.prior_rules_strong === 1 ? " names" : "s name"} it${weak > 0 ? ` · +${weak} weak` : ""}`
    );
  }
  return parts.join(" · ");
}

/** Story line: brief > headline > nothing. Never a computed template sentence —
    that is the exact thing this row exists to replace. */
function Story({ item }: { item: ThreatBoardItem }) {
  if (item.is_generic) {
    return (
      <p className={styles.story}>
        Held out of the ranking — a category, not a threat. The extractor accepted a genre word as an
        entity; resolve it in entity hygiene.
      </p>
    );
  }
  if (item.brief) {
    return (
      <p className={styles.story} title={`AI brief from ${item.brief_sources.length || "the window's"} window articles — open the row for the sources`}>
        {item.brief}
      </p>
    );
  }
  if (item.headline?.title) {
    const outlets = item.headline.outlets ?? 0;
    return (
      <p className={styles.story}>
        <span className={styles.storyQuote}>“{item.headline.title}”</span>
        {item.headline.source && <span className={styles.storySrc}> — {item.headline.source}</span>}
        {item.headline.is_origin && (
          <span className={styles.storySrc}>
            {" · first"}
            {outlets > 1 ? ` of ${outlets} outlets` : ""}
          </span>
        )}
      </p>
    );
  }
  return null;
}

/** "Have we seen this shape before" — the nearest prior story by centroid.
    One line, and only when there is a real neighbour above the floor. */
function PrecedentLine({ item, onOpenStory }: { item: ThreatBoardItem; onOpenStory: (slug: string) => void }) {
  const { data } = usePrecedent(item.thread_slug, !!item.thread_slug);
  const top = data?.[0];
  if (!top) return null;
  return (
    <>
      <div className={styles.dsubhead}>Precedent</div>
      <div className={styles.drow}>
        <button
          className={styles.dlink}
          onClick={() => onOpenStory(top.slug)}
          title={`${top.title} — open that story`}
        >
          {top.title}
        </button>
        <i>
          {" · "}
          {Math.round(top.similarity * 100)}% match · {top.entry_count} articles
        </i>
      </div>
    </>
  );
}

/** A story row's drawer. There is no coverage workspace to fetch — the row has
    no entity — so this shows what the thread itself knows. */
function StoryDrawer({
  item,
  onOpenArticle,
  onOpenStory,
}: {
  item: ThreatBoardItem;
  onOpenArticle: (entryId: string) => void;
  onOpenStory: (slug: string) => void;
}) {
  return (
    <div className={styles.drawer}>
      <div className={styles.dcol}>
        <div className={styles.dhead}>
          Coverage · {item.beats || 1} beat{(item.beats || 1) === 1 ? "" : "s"}, {item.attention} outlets
        </div>
        {item.headline && (
          <div className={styles.drow}>
            <button className={styles.dlink} onClick={() => onOpenArticle(item.headline!.entry_id)}>
              {item.headline.title}
            </button>
            <i className={item.headline.is_origin ? styles.dfirst : undefined}>
              {" "}
              {item.headline.source}
              {item.headline.is_origin ? " · first" : ""}
            </i>
          </div>
        )}
        {item.echoes_folded > 0 && (
          <div className={styles.dmore}>+ {item.echoes_folded} more article{item.echoes_folded === 1 ? "" : "s"} in the story</div>
        )}
        <button className={styles.dlinkQuiet} onClick={() => onOpenStory(item.entity_key)}>
          Read the spine ↗
        </button>
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>What's extractable</div>
        <div className={styles.drow}>
          <b>{item.on_record}</b> technique{item.on_record === 1 ? "" : "s"} ·{" "}
          <b>{item.writable_observables}</b> rule-ready indicator{item.writable_observables === 1 ? "" : "s"}
        </div>
        {item.product && (
          <div className={styles.drow}>
            product <b>{item.product}</b>
            {item.in_stack && <i> · in your stack</i>}
          </div>
        )}
        <div className={styles.dmore}>
          Nothing in the library can resolve to a story with no entity — Collect is how it gets one.
        </div>
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>Why this rank · score {item.score}</div>
        <div className={styles.drow}>
          beats <b>{item.beats || 1}</b> <i>· waves of coverage, × 2.5 as tradecraft</i>
        </div>
        <div className={styles.drow}>
          outlets <b>{item.attention}</b>
          <i>
            {" — "}
            {item.sources.slice(0, 4).join(", ")}
            {item.sources.length > 4 ? ` +${item.sources.length - 4}` : ""}
          </i>
        </div>
        {item.in_stack && (
          <div className={styles.drow}>
            your stack <b>× 1.5</b> <i>· exposure's own multiplier</i>
          </div>
        )}
        <PrecedentLine item={item} onOpenStory={onOpenStory} />
      </div>
    </div>
  );
}

/** Expansion drawer: a three-column preview of the workspace, served by the
    workspace endpoint that already exists. Fetched lazily on first expand. */
function ThreatDrawer({
  item,
  window,
  onOpenRule,
  onOpenArticle,
  onOpenStory,
}: {
  item: ThreatBoardItem;
  window: string;
  onOpenRule: (ruleId: string) => void;
  onOpenArticle: (entryId: string) => void;
  onOpenStory: (slug: string) => void;
}) {
  const { data, isLoading } = useCoverageWorkspace(item.entity_type, item.entity_key, window, true);
  // The full inventory behind the caption's "N rules name it" — every library
  // rule that resolves to this row, strongest claim first.
  const { data: rules } = useBoardRules(item.entity_type, item.entity_key, item.prior_rules > 0);

  if (isLoading) return <div className={styles.drawer}><div className={styles.drawerLoading}>Assembling…</div></div>;
  if (!data) return null;

  const newBehaviours = data.behaviours.filter((b) => b.is_new).slice(0, 6);
  const moreNew = Math.max(0, item.new_techniques - newBehaviours.length);

  return (
    <div className={styles.drawer}>
      <div className={styles.dcol}>
        <div className={styles.dhead}>
          {foldsCoverage(item)
            ? `Coverage · ${item.stories} stor${item.stories === 1 ? "y" : "ies"}, ${item.attention} outlets`
            : `Articles · ${data.articles.length}`}
        </div>
        {data.articles.slice(0, 6).map((a) => (
          <div key={a.entry_id} className={styles.drow}>
            <button className={styles.dlink} onClick={() => onOpenArticle(a.entry_id)} title="Open in the reader">
              {a.title}
            </button>
            <i>
              {a.source}
              {a.published_at ? ` · ${a.published_at.slice(5, 10)}` : ""}
              {a.technique_count ? ` · ${a.technique_count} techniques` : ""}
            </i>
            {a.url && (
              <a
                className={styles.dext}
                href={a.url}
                target="_blank"
                rel="noreferrer"
                title="Open the original"
                onClick={(e) => e.stopPropagation()}
              >
                ↗
              </a>
            )}
          </div>
        ))}
        {data.articles.length > 6 && (
          <div className={styles.dmore}>+ {data.articles.length - 6} more in the workspace</div>
        )}
        {item.echoes_folded > 0 && (
          <div className={styles.dmore}>
            {item.echoes_folded} of them re-report a story already listed here
          </div>
        )}
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>New this window · {item.new_techniques}</div>
        {newBehaviours.length === 0 && <div className={styles.dmore}>No first-seen techniques in this window.</div>}
        {newBehaviours.map((b) => (
          <div key={b.technique_id} className={styles.drow}>
            <b className={styles.dttp}>{b.technique_id}</b> {b.technique_name}
            <i>{b.tier ? " · telemetry collected" : b.below_line ? " · no source" : ""}</i>
          </div>
        ))}
        {moreNew > 0 && <div className={styles.dmore}>+ {moreNew} more</div>}
        <PrecedentLine item={item} onOpenStory={onOpenStory} />
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>Why this rank · score {item.score}</div>
        {foldsCoverage(item) && (
          <div className={styles.drow}>
            stories <b>{item.stories}</b>
            <i>
              {item.stories === 1
                ? ` — one wave, ${item.attention} outlets`
                : ` — separate stories, not one re-reported`}
            </i>
          </div>
        )}
        <div className={styles.drow}>
          {foldsCoverage(item) ? "outlets" : "attention"} <b>{item.attention}</b>
          <i> — {item.sources.slice(0, 4).join(", ")}{item.sources.length > 4 ? ` +${item.sources.length - 4}` : ""}</i>
        </div>
        {item.entity_type === "cve" ? (
          <div className={styles.drow}>
            exploitation lift{" "}
            <b>
              {item.is_kev
                ? "KEV × 2.5"
                : (item.epss_score ?? 0) >= 0.5
                  ? "EPSS × 2.0"
                  : item.exploit_status && item.exploit_status !== "none"
                    ? `${item.exploit_status} × 1.8`
                    : "× 1.0"}
            </b>{" "}
            <i>· base 1.5 — Vendor Watch's own multipliers</i>
          </div>
        ) : (
          <div className={styles.drow}>
            new tradecraft <b>{item.new_techniques}</b> <i>× 2.5</i>
          </div>
        )}
        {item.writable_observables > 0 && (
          <div className={styles.drow}>
            rule-ready indicators <b>{item.writable_observables}</b>
          </div>
        )}
        <div className={styles.drow}>
          rules: <b>{item.prior_rules_strong} strong</b>
          {item.prior_rules - item.prior_rules_strong > 0 && (
            <> · {item.prior_rules - item.prior_rules_strong} weak</>
          )}
          {Object.keys(item.prior_rule_repos).length > 0 && (
            <i>
              {" — "}
              {Object.entries(item.prior_rule_repos)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 3)
                .map(([r, n]) => `${r} ${n}`)
                .join(" · ")}
            </i>
          )}
        </div>
        {item.brief && item.brief_sources.length > 0 && (
          <div className={styles.dmore}>story line built from {item.brief_sources.length} window articles</div>
        )}
      </div>

      {rules && rules.items.length > 0 && (
        <div className={styles.dRules}>
          <div className={styles.dhead}>
            Rules that resolve here · {rules.total}
            {rules.weak > 0 && (
              <span className={styles.dheadNote}>
                {rules.strong} name it outright · {rules.weak} weak (body text or story tag)
              </span>
            )}
          </div>
          {rules.items.map((r) => (
            <div key={r.rule_id} className={styles.dRule}>
              <span className={styles.dRuleType}>{r.rule_type}</span>
              <button className={styles.dRuleTitle} onClick={() => onOpenRule(r.rule_id)}>
                {r.title}
              </button>
              <span className={styles.dRuleMeta}>
                {r.repo}
                {r.license ? ` · ${r.license}` : ""}
                {r.is_draft ? " · draft" : ""}
              </span>
              <span className={styles.dRuleMatch}>
                {r.via} — {r.matched_on ?? "—"}
                {r.confidence === "low" && <i className={styles.dRuleWeak}> · weak</i>}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type VulnFilter = "all" | "stack" | "kev" | "epss" | "norule";

export default function ThreatBoard({ facet = "all" }: { facet?: string }) {
  const [window, setWindow] = useState("14d");
  const [stateFilter, setStateFilter] = useState<string>("open");
  const [vulnFilter, setVulnFilter] = useState<VulnFilter>("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const navigate = useNavigate();
  const setState = useSetThreatState();

  // The server owns the two rankings; actor/malware are client-side cuts of
  // the threats facet. "all" interleaves both by score server-side, with CVEs
  // claimed by a visible cluster folded onto that cluster's row.
  const serverFacet: BoardFacet = facet === "vulns" ? "vulns" : facet === "all" ? "all" : "threats";
  const { data, isLoading } = useThreatBoard(window, stateFilter === "handled", serverFacet);

  const items = useMemo(() => {
    const all = data?.items ?? [];
    const byState = all.filter((i) =>
      stateFilter === "handled" ? i.state === "handled" : i.state !== "handled"
    );
    const byFacet =
      facet === "all" || facet === "vulns" ? byState : byState.filter((i) => i.facets.includes(facet));
    if (facet !== "vulns" || vulnFilter === "all") return byFacet;
    return byFacet.filter((i) => {
      if (vulnFilter === "stack") return i.in_stack;
      if (vulnFilter === "kev") return i.is_kev;
      if (vulnFilter === "epss") return (i.epss_score ?? 0) >= 0.5;
      return i.prior_rules === 0;
    });
  }, [data, facet, stateFilter, vulnFilter]);

  // The board is a workbench surface: a story opens in the dock beside it,
  // the same place its articles open.
  const openStory = useOpenThread();

  const openThreat = (item: ThreatBoardItem) => {
    // A story row's key is a thread slug, and the thread is its page — the
    // queue opens it directly, which is what the story has instead of a
    // profile.
    if (item.is_story) {
      openStory(item.entity_key);
      return;
    }
    if (item.is_generic) {
      toast.info(`"${item.label}" is flagged as an extraction artefact — resolve it in entity hygiene`);
      return;
    }
    // CVE rows land on the CVE face of the Detection tab — the same view the
    // workspace's cluster strip opens, so board and profile can never disagree.
    if (item.entity_type === "cve") {
      navigate(`/workbench/cve/${item.profile_id ?? item.entity_key}?tab=detection`);
      return;
    }
    navigate(`/workbench/${item.entity_type}/${item.entity_key}`);
  };

  const mark = (item: ThreatBoardItem, next: "handled" | "open") => {
    setState.mutate(
      { entityType: item.entity_type, entityKey: item.entity_key, state: next, window },
      {
        onSuccess: () =>
          toast.success(
            next === "handled"
              ? `${item.label} marked handled — returns if new tradecraft arrives`
              : `${item.label} reopened`
          ),
        onError: () => toast.error(`Could not update ${item.label}`),
      }
    );
  };

  return (
    <div className={styles.board}>
      <div className={styles.head}>
        <div className={styles.headText}>
          <span className={styles.sub}>{data ? `${items.length} shown · ${window}` : "…"}</span>
        </div>
        <div className={styles.controls}>
          {facet === "vulns" && (
            <Segmented<VulnFilter>
              label="Vulnerability filter"
              size="sm"
              value={vulnFilter}
              onChange={setVulnFilter}
              options={[
                { value: "all", label: "All" },
                { value: "stack", label: "In your stack" },
                { value: "kev", label: "KEV" },
                { value: "epss", label: "EPSS ≥ 50%" },
                { value: "norule", label: "No rule" },
              ]}
            />
          )}
          <Segmented<string>
            label="Window"
            size="sm"
            value={window}
            onChange={setWindow}
            options={WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
          />
          <Segmented<string>
            label="State"
            size="sm"
            value={stateFilter}
            onChange={setStateFilter}
            options={STATE_FILTERS.map((s) => ({ value: s.value, label: s.label }))}
          />
        </div>
      </div>

      {isLoading ? (
        <AsyncStateLoading label="Ranking threats…" />
      ) : !items.length ? (
        <div className={styles.empty}>
          {stateFilter === "handled"
            ? "Nothing marked handled yet."
            : "No threats above the attention threshold in this window."}
        </div>
      ) : (
        <div className={styles.rows}>
          {items.map((item, index) => {
            const key = `${item.entity_type}:${item.entity_key}`;
            const isOpen = expanded === key;
            // The landscape divider: below it, CVEs that affect nothing you
            // run and have no fireable rule — context, not your write-queue.
            // Same honesty as the workspace's below-the-line rule.
            const showSurfaceDivider =
              facet === "vulns" &&
              !item.on_surface &&
              (index === 0 || items[index - 1].on_surface);
            return (
              <div key={key}>
              {showSurfaceDivider && (
                <div className={styles.surfaceDivider}>
                  Outside your surface — no stack vendor/product match, no fireable rule. Follow a
                  vendor or tick a telemetry source to claim these.
                </div>
              )}
              <div
                className={`${styles.row} ${item.is_generic ? styles.generic : ""} ${!item.on_surface ? styles.offSurface : ""} ${isOpen ? styles.rowOpen : ""}`}
                style={{ borderLeftColor: ENTITY_COLOR[item.entity_type] ?? "var(--text-muted)" }}
              >
                <div
                  className={styles.rowBody}
                  role="button"
                  tabIndex={0}
                  onClick={() => setExpanded(isOpen ? null : key)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setExpanded(isOpen ? null : key);
                    }
                  }}
                >
                  <div className={styles.idl}>
                    <button
                      className={styles.name}
                      onClick={(e) => {
                        e.stopPropagation();
                        openThreat(item);
                      }}
                    >
                      {item.label}
                    </button>
                    {absorbed(item).slice(0, 2).map((m) => (
                      <span key={m.entity_key} className={styles.coName}>
                        · {m.label}
                      </span>
                    ))}
                    {absorbed(item).length > 2 && (
                      <span className={styles.coName}>· +{absorbed(item).length - 2} more</span>
                    )}
                    {item.facets.map((f) => (
                      <span
                        key={f}
                        className={styles.tag}
                        style={{ color: ENTITY_COLOR[f] ?? "var(--text-muted)" }}
                      >
                        {FACET_LABEL[f] ?? f}
                      </span>
                    ))}
                    {absorbed(item).length > 0 && (
                      <span className={styles.tag} style={{ color: "var(--accent-intel)" }}>
                        same story
                      </span>
                    )}
                    {item.product && (
                      <span className={styles.tag} style={{ color: "var(--entity-product, #ec4899)" }}>
                        {item.product}
                      </span>
                    )}
                    {item.in_stack && (
                      <span className={styles.tag} style={{ color: "var(--warning, #d29922)" }}>
                        in your stack
                      </span>
                    )}
                    {item.state === "tracked" && (
                      <span className={styles.tag} style={{ color: "var(--accent)" }}>
                        tracked
                      </span>
                    )}
                    <span className={styles.counts}>
                      {foldsCoverage(item) ? (
                        <>
                          <b>
                            {item.stories} {item.stories === 1 ? "story" : "stories"}
                          </b>
                          <b>{item.attention} outlets</b>
                        </>
                      ) : (
                        <b title="Independent outlets covering this threat in the window">
                          {item.attention} outlet{item.attention === 1 ? "" : "s"}
                        </b>
                      )}
                      {item.is_story ? (
                        <>
                          <b>
                            {item.beats || 1} beat{(item.beats || 1) === 1 ? "" : "s"}
                          </b>
                          <b>no entity yet</b>
                        </>
                      ) : item.entity_type === "cve" ? (
                        <>
                          {item.is_kev && <b style={{ color: "var(--danger, #f85149)" }}>KEV</b>}
                          {item.cvss_score != null && <b>CVSS {item.cvss_score.toFixed(1)}</b>}
                          {!item.is_kev && item.epss_score != null && (
                            <b>EPSS {Math.round(item.epss_score * 100)}%</b>
                          )}
                        </>
                      ) : (
                        <>
                          <b title="Techniques reported for this threat for the first time in the window">
                            {item.new_techniques} new TTP{item.new_techniques === 1 ? "" : "s"}
                          </b>
                          <b title="Techniques on record for this threat overall">
                            {item.on_record} on record
                          </b>
                        </>
                      )}
                      <span className={styles.why}>why ranked <span className="caret-glyph">{isOpen ? "▾" : "▸"}</span></span>
                    </span>
                  </div>

                  <Story item={item} />

                  <div className={styles.cap}>
                    <span className={styles.capText}>{captionText(item)}</span>
                    <span className={styles.actions} onClick={(e) => e.stopPropagation()}>
                      <button
                        className={`${styles.btn} ${item.is_generic ? "" : styles.btnPrimary}`}
                        title={actionTitle(item)}
                        onClick={() => openThreat(item)}
                      >
                        {actionLabel(item)}
                      </button>
                      {!item.is_generic && (
                        <button
                          className={styles.btn}
                          disabled={setState.isPending}
                          aria-label={`${item.state === "handled" ? "Reopen" : item.state === "tracked" ? "Untrack" : "Mark handled"}: ${item.label}`}
                          onClick={() =>
                            mark(item, item.state === "handled" || item.state === "tracked" ? "open" : "handled")
                          }
                        >
                          {item.state === "handled" ? "Reopen" : item.state === "tracked" ? "Untrack" : "Mark handled"}
                        </button>
                      )}
                    </span>
                  </div>
                </div>

                {isOpen && !item.is_generic && (
                  item.is_story ? (
                    <StoryDrawer
                      item={item}
                      onOpenArticle={(entryId) => useIntelStore.getState().openWorkbenchReader(entryId)}
                      onOpenStory={openStory}
                    />
                  ) : (
                    <ThreatDrawer
                      item={item}
                      window={window}
                      onOpenRule={(ruleId) => navigate(`/workbench/rule/${ruleId}`)}
                      onOpenArticle={(entryId) => {
                        // The workbench's docked reader — the board stays put
                        // as the list; the original is one ↗ away.
                        useIntelStore.getState().openWorkbenchReader(entryId);
                      }}
                      onOpenStory={openStory}
                    />
                  )
                )}
              </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
