import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { AsyncStateLoading } from "@/components/AsyncState";
import { Segmented } from "@/components/primitives";
import { useCoverageWorkspace } from "@/hooks/useCoverageWorkspace";
import { HuntPackPanel, huntApiMessage } from "@/components/hunt/HuntPackPanel";
import { PROFILE_SCOPE, downloadHuntPackage, useHuntPack } from "@/hooks/useHuntPacks";
import {
  useBoardRules,
  usePrecedent,
  useSetThreatState,
  useThreatBoard,
  type BoardFacet,
  type ThreatBoardItem,
  type ThreatState,
} from "@/hooks/useThreatBoard";
import { useIntelStore } from "@/stores/intelStore";
import { useOpenThread } from "@/utils/openEntry";
import styles from "./ThreatBoard.module.css";

/** The Threats board: one briefing row per resolved threat.

    A collapsed row shows four things: identity, story, one caption line, and actions. There is no chip band; the evidence detail lives in the drawer the row expands into. The story is the nightly AI brief when one is cached (built only from the window's entries) and the window's lead headline otherwise, never a template sentence built from counts.

    There is deliberately no coverage percentage: source_ttps tag equality returns 88-90% for every actor in the database. `prior_rules` is an inventory to open, not a verdict. */

const WINDOWS = [
  { value: "7d", label: "7d" },
  { value: "14d", label: "14d" },
  { value: "30d", label: "30d" },
] as const;

const STATE_FILTERS = [
  { value: "open", label: "Open" },
  { value: "tracked", label: "Tracked" },
  { value: "handled", label: "Handled" },
  { value: "muted", label: "Muted" },
] as const;
type StateFilter = (typeof STATE_FILTERS)[number]["value"];

const EMPTY_TEXT: Record<StateFilter, string> = {
  open: "No threats with enough coverage in this window.",
  tracked: "Nothing pinned. Track a row from its ⋯ menu to keep it above the ranking.",
  handled: "Nothing marked handled yet.",
  muted: "Nothing dismissed. Dismissed rows stay here until you reopen them.",
};

/** The ⋯ menu for one row: every state the row can move to from its current state. `tracked` and `open` both keep the row on the board; handled and muted differ in what brings a row back: newly reported techniques for handled, only a manual reopen for muted. */
function menuItems(item: ThreatBoardItem): { label: string; hint: string; state: ThreatState }[] {
  switch (item.state) {
    case "handled":
      return [
        { label: "Reopen", hint: "Back on the board.", state: "open" },
        { label: "Dismiss", hint: "Hide it until you reopen it.", state: "muted" },
      ];
    case "muted":
      return [
        { label: "Reopen", hint: "Back on the board.", state: "open" },
        { label: "Track", hint: "Pin it above the ranking.", state: "tracked" },
      ];
    case "tracked":
      return [
        { label: "Mark handled", hint: "Done for now. Returns when new techniques are reported.", state: "handled" },
        { label: "Dismiss", hint: "Hide it until you reopen it.", state: "muted" },
        { label: "Untrack", hint: "Unpin it. The row returns to its ranked position.", state: "open" },
      ];
    default:
      return [
        { label: "Mark handled", hint: "Done for now. Returns when new techniques are reported.", state: "handled" },
        { label: "Dismiss", hint: "Hide it until you reopen it.", state: "muted" },
        { label: "Track", hint: "Pin it above the ranking regardless of coverage.", state: "tracked" },
      ];
  }
}

const STATE_TOAST: Record<ThreatState, (label: string) => string> = {
  handled: (l) => `${l} marked handled. Returns if new techniques are reported.`,
  muted: (l) => `${l} dismissed. Find it under Muted.`,
  tracked: (l) => `${l} pinned above the ranking`,
  open: (l) => `${l} reopened`,
};

const ENTITY_COLOR: Record<string, string> = {
  threat_actor: "var(--entity-actor)",
  malware: "var(--entity-malware)",
  cve: "var(--entity-cve)",
  ttp: "var(--entity-ttp)",
  // A story row is not an entity, so it uses the intel accent instead of an entity color.
  story: "var(--accent-intel)",
};

const FACET_LABEL: Record<string, string> = {
  threat_actor: "actor",
  malware: "malware",
  cve: "vuln",
  story: "story",
};

/** The button names the next job (the server derives `action` from the counts), in plain words rather than shorthand. */
function actionLabel(item: ThreatBoardItem): string {
  switch (item.action) {
    case "write":
      return "Draft detection rule →";
    case "extend":
      return `Extend ${item.prior_rules_strong} rule${item.prior_rules_strong === 1 ? "" : "s"} →`;
    case "diff":
      return `Review ${item.prior_rules} rule${item.prior_rules === 1 ? "" : "s"} →`;
    case "audit":
      return `Audit ${item.on_record} known TTP${item.on_record === 1 ? "" : "s"} →`;
    case "adopt":
      return `Adopt ${item.prior_rules} ready rule${item.prior_rules === 1 ? "" : "s"} →`;
    case "collect":
      return item.is_story ? "Read the story →" : "Rules need telemetry →";
    case "merge":
      return "Merge duplicate";
    default:
      return "Review";
  }
}

/** Hover text that spells out what clicking the action actually does. */
function actionTitle(item: ThreatBoardItem): string {
  switch (item.action) {
    case "write":
      return "No detection rule covers this threat. Draft one from the reported techniques.";
    case "extend":
      return "Rules already cover this threat. Extend them with the techniques reported this window.";
    case "diff":
      return "Rules reference this threat. Compare them with what was reported.";
    case "audit":
      return "Coverage looks current. Audit it against every technique on record.";
    case "adopt":
      return "Matching rules exist and can run on telemetry you already collect. Review and adopt them.";
    case "collect":
      return item.is_story
        ? "No actor, malware or CVE has been identified yet. Read the story and name it."
        : "Rules exist, but they need telemetry you do not collect yet.";
    case "merge":
      return "This entry duplicates another threat. Merge them.";
    default:
      return "Open the detail drawer";
  }
}

/** True when threading has grouped this row's coverage: its articles form fewer stories than there are outlets. */
function foldsCoverage(item: ThreatBoardItem): boolean {
  return item.stories > 0 && item.stories !== item.attention;
}

/** Threat rows this one absorbed (one thread holds both), excluding CVEs. Defaults to an empty list because a freshly deployed bundle can be served before the API container finishes restarting, and a row without the field must render, not throw. */
function absorbed(item: ThreatBoardItem): ThreatBoardItem["merged_from"] {
  return (item.merged_from ?? []).filter((m) => m.entity_type !== "cve");
}

/** CVEs folded into this row on the All view, listed so a vulnerability stays visible when an actor's row carries its story. */
function carried(item: ThreatBoardItem): ThreatBoardItem["merged_from"] {
  return (item.merged_from ?? []).filter((m) => m.entity_type === "cve");
}

/** One caption line under the story, only for a story row: its update count when it is still developing, otherwise that no actor, malware or CVE has been identified yet. Entity rows have no caption; their numbers are on the identity line and the rule inventory is in the drawer. */
function captionText(item: ThreatBoardItem): string {
  if (item.is_story) {
    return item.beats > 1 ? `${item.beats} updates, still developing` : "no actor, malware or CVE identified yet";
  }
  return "";
}

/** Story line: the AI brief, else the lead headline, else nothing (generic-word rows get an exclusion notice instead). Never a computed template sentence, which is what this row replaces. */
function Story({ item }: { item: ThreatBoardItem }) {
  if (item.is_generic) {
    return (
      <p className={styles.story}>
        Excluded from the ranking: this is a category name, not a threat. The extractor created an entity
        from a generic word. Resolve it in Engine review.
      </p>
    );
  }
  if (item.brief) {
    return (
      <p className={styles.story} title={`AI summary of ${item.brief_sources.length || "the"} articles from this window. Expand the row to see the sources.`}>
        {item.brief}
      </p>
    );
  }
  if (item.headline?.title) {
    const outlets = item.headline.outlets ?? 0;
    return (
      <p className={styles.story}>
        <span className={styles.storyQuote}>“{item.headline.title}”</span>
        {item.headline.source && <span className={styles.storySrc}> · {item.headline.source}</span>}
        {item.headline.is_origin && (
          <span className={styles.storySrc}>
            {outlets > 1 ? ` · first of ${outlets} outlets` : " · first report"}
          </span>
        )}
      </p>
    );
  }
  return null;
}

/** "Have we seen this before": the nearest prior story by centroid similarity. One line, shown only when there is a neighbor above the similarity floor. */
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
          title="Open this story"
        >
          {top.title}
        </button>
        <i>
          {" · "}
          {Math.round(top.similarity * 100)}% similar · {top.entry_count} articles
        </i>
      </div>
    </>
  );
}

/** A story row's drawer. The row has no entity, so there is no coverage workspace to fetch; this shows what the thread itself knows. */
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
          Coverage · {item.beats || 1} update{(item.beats || 1) === 1 ? "" : "s"}, {item.attention} outlets
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
          Open the story timeline ↗
        </button>
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>Extracted so far</div>
        <div className={styles.drow}>
          <b>{item.on_record}</b> technique{item.on_record === 1 ? "" : "s"} ·{" "}
          <b>{item.writable_observables}</b> usable indicator{item.writable_observables === 1 ? "" : "s"}
        </div>
        {item.product && (
          <div className={styles.drow}>
            product <b>{item.product}</b>
            {item.in_stack && <i> · in your stack</i>}
          </div>
        )}
        <div className={styles.dmore}>
          No entity named yet, so no rule can match.
        </div>
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>Why this rank · score {item.score}</div>
        <div className={styles.drow}>
          updates <b>{item.beats || 1}</b> <i>· × 2.5, the same weight as new techniques</i>
        </div>
        <div className={styles.drow}>
          outlets <b>{item.attention}</b>
          <i>
            {" ("}
            {item.sources.slice(0, 4).join(", ")}
            {item.sources.length > 4 ? ` +${item.sources.length - 4}` : ""}
            {")"}
          </i>
        </div>
        {item.in_stack && (
          <div className={styles.drow}>
            in your stack <b>× 1.5</b>
          </div>
        )}
        <PrecedentLine item={item} onOpenStory={onOpenStory} />
      </div>
    </div>
  );
}

/** The row's hunts: the shared hunt cards (components/hunt/HuntPackPanel) for this window, a Download hunt package button for the whole zip, and a link to the profile's all-reporting hunts when they exist. These are a starting point for a hunt that is run in the SIEM and recorded in the ATHF workspace; IntelFeed tracks nothing past the draft. */
function HuntSection({ item, window }: { item: ThreatBoardItem; window: string }) {
  const navigate = useNavigate();
  const { data: profile } = useHuntPack(item.entity_type, item.entity_key, PROFILE_SCOPE);
  const [downloading, setDownloading] = useState(false);
  const profileCount = profile?.pack?.hypotheses.length ?? 0;

  const download = async () => {
    setDownloading(true);
    try {
      await downloadHuntPackage(item.entity_type, item.entity_key, item.label);
    } catch (err) {
      toast.error(huntApiMessage(err, "Could not build the hunt package"));
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className={styles.dHunt}>
      <HuntPackPanel
        entityType={item.entity_type}
        entityKey={item.entity_key}
        label={item.label}
        scope={window}
        scopeLabel={`last ${window.replace("d", " days")}`}
        actions={
          <button className={styles.btn} onClick={download} disabled={downloading}>
            {downloading ? "Preparing…" : "Download hunt package"}
          </button>
        }
        footer={
          profileCount > 0 ? (
            <>
              All-reporting hunts for {item.label}: {profileCount}, on its profile.{" "}
              <button
                className={styles.dHuntLink}
                onClick={() => navigate(`/workbench/${item.entity_type}/${item.profile_id ?? item.entity_key}`)}
              >
                Open
              </button>
            </>
          ) : undefined
        }
      />
    </div>
  );
}

/** Expansion drawer: a three-column preview of the coverage workspace, from the existing workspace endpoint. Fetched on first expand. */
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
  // The full inventory behind the row's `prior_rules` count: every library rule that resolves to this row, strongest claim first.
  const { data: rules } = useBoardRules(item.entity_type, item.entity_key, item.prior_rules > 0);
  // The article and new-technique lists show six items and expand in place, so "+ N more" never sends the reader to another page.
  const [allArticles, setAllArticles] = useState(false);
  const [allNew, setAllNew] = useState(false);

  if (isLoading) return <div className={styles.drawer}><div className={styles.drawerLoading}>Loading…</div></div>;
  if (!data) return null;

  const LIST_CAP = 6;
  const articles = allArticles ? data.articles : data.articles.slice(0, LIST_CAP);
  const newAll = data.behaviours.filter((b) => b.is_new);
  const newBehaviors = allNew ? newAll : newAll.slice(0, LIST_CAP);

  return (
    <div className={styles.drawer}>
      <div className={styles.dcol}>
        <div
          className={styles.dhead}
          title={item.echoes_folded > 0 ? `${item.echoes_folded} repeat report${item.echoes_folded === 1 ? "" : "s"} of the same stories grouped into these` : undefined}
        >
          {foldsCoverage(item)
            ? `Coverage · ${item.stories} stor${item.stories === 1 ? "y" : "ies"}, ${item.attention} outlets`
            : `Articles · ${data.articles.length}`}
        </div>
        {articles.map((a) => (
          <div key={a.entry_id} className={`${styles.drow} ${styles.darticle}`}>
            <button className={styles.dlink} onClick={() => onOpenArticle(a.entry_id)} title="Open in the reader">
              {a.title}
            </button>
            <i className={styles.dmeta}>
              {[
                a.source,
                a.published_at ? a.published_at.slice(5, 10) : null,
                a.technique_count ? `${a.technique_count} technique${a.technique_count === 1 ? "" : "s"}` : null,
              ]
                .filter(Boolean)
                .join(" · ")}
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
        {data.articles.length > LIST_CAP && (
          <button className={styles.dmoreBtn} onClick={() => setAllArticles((v) => !v)}>
            {allArticles ? "Show fewer" : `Show ${data.articles.length - LIST_CAP} more`}
          </button>
        )}
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>New techniques this window · {item.new_techniques}</div>
        {newBehaviors.length === 0 && <div className={styles.dmore}>None this window.</div>}
        {newBehaviors.map((b) => (
          <div key={b.technique_id} className={styles.drow}>
            <b className={styles.dttp}>{b.technique_id}</b> {b.technique_name}
            <i>{b.tier ? " · telemetry collected" : b.below_line ? " · no telemetry source" : ""}</i>
          </div>
        ))}
        {newAll.length > LIST_CAP && (
          <button className={styles.dmoreBtn} onClick={() => setAllNew((v) => !v)}>
            {allNew ? "Show fewer" : `Show ${newAll.length - LIST_CAP} more`}
          </button>
        )}
        <PrecedentLine item={item} onOpenStory={onOpenStory} />
      </div>

      <div className={styles.dcol}>
        <div className={styles.dhead}>Why this rank · score {item.score}</div>
        {foldsCoverage(item) && (
          <div className={styles.drow}>
            stories <b>{item.stories}</b>
          </div>
        )}
        <div className={styles.drow}>
          outlets <b>{item.attention}</b>
          <i> ({item.sources.slice(0, 4).join(", ")}{item.sources.length > 4 ? ` +${item.sources.length - 4}` : ""})</i>
        </div>
        {item.entity_type === "cve" ? (
          <div className={styles.drow}>
            exploitation multiplier{" "}
            <b>
              {item.is_kev
                ? "KEV × 2.5"
                : (item.epss_score ?? 0) >= 0.5
                  ? "EPSS × 2.0"
                  : item.exploit_status && item.exploit_status !== "none"
                    ? `${item.exploit_status} × 1.8`
                    : "× 1.0"}
            </b>{" "}

          </div>
        ) : (
          <div className={styles.drow}>
            new techniques <b>{item.new_techniques}</b> <i>× 2.5</i>
          </div>
        )}
        {item.writable_observables > 0 && (
          <div className={styles.drow}>
            usable indicators <b>{item.writable_observables}</b>
          </div>
        )}
        <div className={styles.drow}>
          rules <b>{item.prior_rules}</b>
          {Object.keys(item.prior_rule_repos).length > 0 && (
            <i>
              {" ("}
              {Object.entries(item.prior_rule_repos)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 3)
                .map(([r, n]) => `${r} ${n}`)
                .join(", ")}
              {")"}
            </i>
          )}
        </div>
      </div>

      {rules && rules.items.length > 0 && (
        <div className={styles.dRules}>
          <div className={styles.dhead}>
            {rules.total} potential rule{rules.total === 1 ? "" : "s"} could detect this threat
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
                {r.via}
                {r.matched_on ? ` · ${r.matched_on}` : ""}

              </span>
            </div>
          ))}
        </div>
      )}

      <HuntSection item={item} window={window} />
    </div>
  );
}

type VulnFilter = "all" | "stack" | "kev" | "epss" | "norule";

export default function ThreatBoard({ facet = "all" }: { facet?: string }) {
  const [window, setWindow] = useState("14d");
  const [stateFilter, setStateFilter] = useState<StateFilter>("open");
  // The open row menu, portaled to the body because .row clips its overflow for the rounded corners: the row key plus the trigger's position.
  const [menuFor, setMenuFor] = useState<{ key: string; top: number; right: number } | null>(null);
  const [vulnFilter, setVulnFilter] = useState<VulnFilter>("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const navigate = useNavigate();
  const setState = useSetThreatState();

  // The server owns the two rankings; actor/malware are client-side filters of the threats facet. "all" interleaves both by score server-side, with CVEs claimed by a visible cluster folded onto that cluster's row.
  const serverFacet: BoardFacet = facet === "vulns" ? "vulns" : facet === "all" ? "all" : "threats";
  // Handled and muted rows are only returned when asked for; open and tracked rows are the board's default view.
  const includeDecided = stateFilter === "handled" || stateFilter === "muted";
  const { data, isLoading } = useThreatBoard(window, includeDecided, serverFacet);

  // The ⋯ menu closes on any click outside it, on Escape, and when the page scrolls or resizes (its fixed position would drift from the trigger).
  useEffect(() => {
    if (!menuFor) return;
    const onDown = (e: MouseEvent) => {
      if (!(e.target as HTMLElement | null)?.closest?.("[data-rowmenu]")) setMenuFor(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuFor(null);
    };
    const close = () => setMenuFor(null);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    // `window` is the board's view window in this component; the global is globalThis.
    globalThis.addEventListener("scroll", close, true);
    globalThis.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      globalThis.removeEventListener("scroll", close, true);
      globalThis.removeEventListener("resize", close);
    };
  }, [menuFor]);

  const items = useMemo(() => {
    const all = data?.items ?? [];
    const byState = all.filter((i) =>
      stateFilter === "open" ? i.state === "open" || i.state === "tracked" : i.state === stateFilter
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

  // The board is a workbench page, so a story opens in the dock beside it, the same place its articles open.
  const openStory = useOpenThread();

  const openThreat = (item: ThreatBoardItem) => {
    // A story row's key is a thread slug, and a story has no entity profile, so the row opens the thread itself.
    if (item.is_story) {
      openStory(item.entity_key);
      return;
    }
    if (item.is_generic) {
      toast.info(`"${item.label}" is flagged as a generic word, not a threat. Resolve it in Engine review.`);
      return;
    }
    // CVE rows open the CVE profile's Detection tab, the same view the workspace's cluster strip opens, so the board and the profile show the same thing.
    if (item.entity_type === "cve") {
      navigate(`/workbench/cve/${item.profile_id ?? item.entity_key}?tab=detection`);
      return;
    }
    navigate(`/workbench/${item.entity_type}/${item.entity_key}`);
  };

  const mark = (item: ThreatBoardItem, next: ThreatState) => {
    setMenuFor(null);
    setState.mutate(
      { entityType: item.entity_type, entityKey: item.entity_key, state: next, window },
      {
        onSuccess: () => toast.success(STATE_TOAST[next](item.label)),
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
          <Segmented<StateFilter>
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
        <div className={styles.empty}>{EMPTY_TEXT[stateFilter]}</div>
      ) : (
        <div className={styles.rows}>
          {items.map((item) => {
            const key = `${item.entity_type}:${item.entity_key}`;
            const isOpen = expanded === key;
            return (
              <div key={key}>
              <div
                className={`${styles.row} ${item.is_generic ? styles.generic : ""} ${isOpen ? styles.rowOpen : ""}`}
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
                    {carried(item).map((c) => (
                      <span
                        key={c.entity_key}
                        className={styles.tagCve}
                        title={`${c.label} is reported in this threat's articles. Decisions on this row apply to it too.`}
                      >
                        exploits {c.label}
                        {c.is_kev ? " · KEV" : ""}
                        {c.in_stack ? " · in your stack" : ""}
                      </span>
                    ))}
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
                            {item.beats || 1} update{(item.beats || 1) === 1 ? "" : "s"}
                          </b>
                          <b>no entity identified</b>
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
                          <b title="All techniques recorded for this threat">
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
                        <span className={styles.menuWrap} data-rowmenu>
                          <button
                            className={styles.btn}
                            aria-label={`More actions: ${item.label}`}
                            aria-haspopup="menu"
                            aria-expanded={menuFor?.key === key}
                            onClick={(e) => {
                              if (menuFor?.key === key) {
                                setMenuFor(null);
                                return;
                              }
                              const r = e.currentTarget.getBoundingClientRect();
                              setMenuFor({ key, top: r.bottom + 4, right: globalThis.innerWidth - r.right });
                            }}
                          >
                            ⋯
                          </button>
                          {menuFor?.key === key &&
                            createPortal(
                              <div
                                className={styles.menu}
                                role="menu"
                                data-rowmenu
                                style={{ top: menuFor.top, right: menuFor.right }}
                              >
                                {menuItems(item).map((mi) => (
                                  <button
                                    key={mi.label}
                                    role="menuitem"
                                    className={styles.menuItem}
                                    disabled={setState.isPending}
                                    onClick={() => mark(item, mi.state)}
                                  >
                                    {mi.label}
                                    <small className={styles.menuHint}>{mi.hint}</small>
                                  </button>
                                ))}
                              </div>,
                              document.body
                            )}
                        </span>
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
                        // Opens the workbench's docked reader, so the board stays in place as the list; the original article is one ↗ click away.
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
