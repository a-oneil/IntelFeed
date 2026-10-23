# Frontend Architecture

IntelFeed's frontend is a modern React 18 + TypeScript single-page application (SPA) built with Vite. It provides a rich, responsive interface for threat intelligence feed consumption, analysis, and detection rule development. This document outlines the architectural patterns, state management, routing, component hierarchy, and conventions that guide frontend development.

## Project Layout

```
frontend/
├── src/
│   ├── App.tsx                          # Root routing & layout branching
│   ├── main.tsx                         # Entry point with provider setup + SW registration
│   ├── index.css                        # Global CSS variables & theming system
│   ├── queryClient.ts                   # TanStack Query client config
│   │
│   ├── api/
│   │   ├── client.ts                    # Axios instance, token refresh logic
│   │   └── types.ts                     # TypeScript interfaces for API responses
│   │
│   ├── stores/
│   │   ├── authStore.ts                 # Auth state + Zustand persist
│   │   ├── uiStore.ts                   # UI layout, sidebar, reader, copilot dock state
│   │   ├── intelStore.ts                # Workbench section, pivots, rule format prefs
│   │   ├── playerStore.ts               # Audio & speech playback state
│   │   └── triageViewStore.ts           # Triage-specific view settings
│   │
│   ├── hooks/
│   │   ├── useEntries.ts                # Entry queries: useEntries, useEntry, mutations
│   │   ├── useIntelligence.ts           # Entity extraction hooks
│   │   ├── useFeeds.ts                  # Feed CRUD operations
│   │   ├── useAI.ts                     # AI tasks, copilot chat streaming, conversations
│   │   ├── useCopilotAuth.ts            # Copilot Claude OAuth status / re-auth flow
│   │   ├── useCopilotContext.ts         # Route-derived ambient copilot context
│   │   ├── useDailySummary.ts           # Shared per-day AI triage summaries
│   │   ├── useSearch.ts                 # Unified search queries
│   │   ├── useThemes.ts                 # Theme queries & CSS var injection
│   │   ├── useDetectionRules.ts         # Rule creation, versioning, coverage, telemetry gaps
│   │   ├── useAutomation.ts             # Automation flow management
│   │   ├── useCampaigns.ts              # Campaign CRUD & correlation
│   │   ├── useTags.ts                   # Tag CRUD, merge, recolor
│   │   ├── useWidgetData.ts             # Dashboard widget data hooks
│   │   ├── useMediaQuery.ts             # Responsive design helpers
│   │   ├── useSwipe.ts                  # Touch gesture handling
│   │   ├── useGlobalShortcuts.ts        # App-wide shortcuts (⌘⇧K copilot toggle)
│   │   ├── useSSE.ts                    # Server-Sent Events for real-time updates
│   │   ├── useTts.ts                    # Server-side Piper read-aloud (enqueue, poll, play MP3)
│   │   ├── useDocumentation.ts          # In-app documentation (docs/) content queries
│   │   └── [60+ domain-specific hooks]
│   │
│   ├── utils/
│   │   ├── entityTheme.ts               # Entity color & icon mappings
│   │   ├── colorSchemes.ts              # Shared TLP + severity color scales
│   │   ├── queryParser.ts               # Search DSL parsing (AST + filter extraction)
│   │   ├── pivotLinks.ts                # Intelligence pivot link building
│   │   ├── dashboardTemplates.ts        # Widget preset layouts
│   │   ├── groupEntries.ts              # Entry list grouping (consecutive same-feed runs)
│   │   └── [10+ utility modules]
│   │
│   ├── pages/                           # Route-level components + CSS modules
│   │   ├── MainLayout.tsx               # Three-panel feed reader (eager)
│   │   ├── SidebarLayout.tsx            # Tool pages wrapper (eager)
│   │   ├── WorkbenchPage.tsx            # Intelligence workspace + WorkbenchLayout (lazy)
│   │   ├── EntityProfilePage.tsx        # Unified config-driven entity profile (lazy)
│   │   ├── DashboardPage.tsx            # Workbench dashboard: correlation browser + widgets (lazy)
│   │   ├── ExposurePage.tsx             # Workbench → Vendor Watch exposure view (lazy)
│   │   ├── DocumentationPage.tsx        # In-app docs at /documentation/* (lazy)
│   │   ├── AutomationPage.tsx           # Automation rules (lazy)
│   │   ├── DetectionWorkbenchPage.tsx   # Rule editor (rendered inside Workbench)
│   │   ├── GlossaryPage.tsx             # Glossary (rendered inside Workbench)
│   │   ├── RuleDetailPage.tsx           # Single rule detail / versioning
│   │   ├── SettingsPage.tsx             # Settings sections (account → system)
│   │   ├── CampaignsPage.tsx            # Campaign management
│   │   ├── CampaignProfilePage.tsx      # Campaign detail
│   │   ├── RegionsPage.tsx              # Region/sub-region aggregation
│   │   ├── ReportBuilderPage.tsx        # Intelligence report composition
│   │   ├── LoginPage.tsx / RegisterPage.tsx
│   │   ├── SharedEntryPage.tsx          # Public entry sharing (no auth)
│   │   └── SharedCopilotPage.tsx        # Public copilot conversation sharing (no auth)
│   │
│   ├── components/                      # Flat directory; one .tsx + one .module.css per component
│   │   ├── Sidebar.tsx, EntryList.tsx, EntryReader.tsx, AppHeader.tsx, ...
│   │   ├── CopilotDockPanel.tsx, ToolTraceChip.tsx, ConfirmCard.tsx, ...
│   │   ├── TagManager.tsx, TagPicker.tsx, TagInput.tsx, ...
│   │   ├── automation/                  # FlowBuilder, TemplateGallery, nodes/
│   │   ├── engine/                      # Settings → Engine console (matrix, stages, jobs, plans)
│   │   ├── entityProfile/               # Config-driven profile: header, tabs/, actions
│   │   ├── ransomware/                  # Ransomware tracker: LeakWatchFeed, RansomwareLandscape
│   │   ├── triage/                      # TriageControls, corrEventCards
│   │   ├── widgets/                     # 50+ dashboard widgets + registry
│   │   └── __tests__/                   # Vitest + RTL component tests
│   │
│   └── test/
│       └── setup.ts                     # Vitest environment init
│
├── tests/
│   └── e2e/
│       ├── auth.spec.ts
│       ├── feeds.spec.ts
│       └── relationships.spec.ts
│
├── vite.config.ts                       # Build config with manual chunking + Vitest config
├── package.json
└── tsconfig.json
```

## Routing & Layouts

IntelFeed uses React Router v6 with two distinct layout branches in `App.tsx`. A few globals mount at the App level, outside the router: `AudioPlayer`, `ReportWizardModal`, `OnboardingWizard` (shown until `user.settings.onboarding_completed`), and — for authenticated users — the global `CopilotDockPanel`.

### MainLayout Route Tree
**Path:** `/feeds`, `/` (catch-all for authenticated users), and `/priority-queue` (renders `<MainLayout priorityMode />` — the same entry list + reader shell pinned to the signal-engine "radar" sort, with a Why-ranked card in the reader and inline story-thread rows in the list; `?thread=<slug>` opens a thread's spine in the reader, which is the only way a thread is read — threads have no page of their own)

Renders a **three-panel layout**:
1. **Sidebar** (collapsible, resizable) — feeds, categories, virtual folders, nav links
2. **Entry List** (resizable, collapsible when the reader is open) — feed entries with cursor pagination
3. **Entry Reader** (fluid) — full-width entry content + side panels

Keyboard shortcuts registered in `MainLayout.tsx`:
- `Cmd/Ctrl+K` → Open command palette (Shift is reserved for the copilot: `Cmd/Ctrl+Shift+K` toggles the copilot dock via `useGlobalShortcuts`)
- `Escape` → Close reader or search
- `n` / `w` → Toggle workbench side panel
- `t` → Toggle tag side panel
- `e` → Export current entry as Markdown
- `?` → Keyboard shortcuts help

List navigation (`j`/`k`, `m`, `s`, `b`, `o`, etc.) is handled inside `EntryList`/`EntryReader`; the full list lives in `KeyboardShortcutsHelp.tsx`.

### SidebarLayout Route Tree
**Paths:** `/settings`, `/automation`, `/campaigns`, `/workbench/*`, `/regions`, etc.

Renders **app header + sidebar + content area**, used for tools and admin pages.

**Routes (all lazy):**
- `/settings` → SettingsPage
- `/automation` → AutomationPage
- `/campaigns` → CampaignsPage
- `/documentation/*` → DocumentationPage (in-app docs; splat slug is a docs/ path, `/documentation` redirects to `/documentation/README`; `/handbook/*` also redirects here)
- `/regions` → RegionsPage (`/regions/:name` redirects back to `/regions`)
- `/workbench` → WorkbenchLayout with nested routes:
  - index → redirects to `dashboard`
  - `dashboard` → DashboardPage (correlation browser + widget grid — the workbench landing page)
  - `explore` → WorkbenchPage (entity/section browser)
  - `exposure` → ExposurePage (Vendor Watch)
  - `threat_actor|malware|cve|ttp|country|tool|mitigation|vendor|product/:id` → EntityProfilePage (unified, config-driven; slug prop selects the entity config)
  - `actor/:id` → redirects to `threat_actor/:id` (pre-2026-08 vocabulary)
  - `campaign/:id` → CampaignProfilePage
  - `rule/:id` → RuleDetailPage
  - `report/new`, `report/:id` → ReportBuilderPage

**Redirects:**
- `/triage`, `/workbench/triage` → `/workbench/dashboard` (query params preserved — the Dashboard is the workbench landing page)
- `/atlas` → `/workbench/dashboard`
- `/dashboards` → `/workbench/dashboard`
- `/intelligence`, `/detection-workbench` → `/workbench/explore`
- `/glossary` → `/workbench/explore?section=glossary`, `/workbench/rules` → `/workbench/explore?section=rules`
- `/workbench/engine` → `/settings?section=engine` (query string preserved, so old console deep links still resolve)
- `/feed-health` → `/settings?section=engine&tab=pipeline&stage=feeds` (feed health lives in Settings → Engine)
- `/countries/:id` → `/workbench/country/:id`
- `/intelligence/threat_actor/:id`, `/intelligence/malware/:id` → still render EntityProfilePage directly for old links (`/intelligence/actor/:id` redirects to the `threat_actor` form)

**Unauthenticated routes:** `/login`, `/register`, `/shared/:token` (SharedEntryPage), `/shared/copilot/:token` (SharedCopilotPage).

### Dynamic Entity Resolution
Routes like `/workbench/ttp/T1490` accept either a UUID or a natural key (technique ID, CVE ID, name); `EntityProfilePage`/`useEntityProfile` resolve non-UUID IDs via API lookup.

### Lazy Loading & Code Splitting
All routes except MainLayout and SidebarLayout use `React.lazy()` + `Suspense`. Vite automatically creates separate chunks for each lazy-loaded page, reducing initial bundle size.

## API Client & HTTP

**File:** `frontend/src/api/client.ts`

Axios instance with intelligent JWT handling (see the [JWT refresh flow diagram](diagrams/frontend-jwt-refresh.md)):

### Token Refresh Strategy
- Proactive refresh (request interceptor): Before every request, checks if the access token expires within 5 minutes via the JWT `exp` claim and refreshes first if so.
- Automatic refresh on 401 (response interceptor): If a request returns 401, attempts refresh and retries the original request once (`_retry` flag).
- Deduplication: Concurrent refresh attempts share a single promise (`doRefresh`) to avoid race conditions.
- Hard logout only on explicit 401/403 from the refresh endpoint (revoked/expired refresh token); transient network errors during refresh do not wipe the session.

### Error Handling
- Rate limit (429): Rejected immediately, no retry to prevent storms.
- Auth errors (401/403 on refresh): Hard logout clears auth store.
- Transient errors: Retry up to 1 time for non-auth failures (configured in `queryClient.ts` `defaultOptions.queries.retry`; 429/401/403 never retry).

### Global Error Toast
`queryClient.ts` installs `QueryCache`/`MutationCache` `onError` handlers that show toast notifications via Sonner for all query/mutation errors, except validation errors (`validation_error` code) and 401s.

## State Management

### Zustand Stores with Persistence
All stores use Zustand's `persist` middleware to hydrate from localStorage on app load. Each store saves a `name` prefix (`intelfeed-*`) and `partialize` to control which slices are persisted.

#### `authStore` (frontend/src/stores/authStore.ts)
**Owns:** JWT tokens, current user, auth status
**Persisted:** accessToken, refreshToken, user
**Key methods:**
- `setTokens(access, refresh)` — Called by API client on successful refresh
- `setUser(user)` — Called on login/registration
- `logout()` — Clears state, revokes token server-side (fire-and-forget), invalidates all queries
- `isAuthenticated()` — Returns true if tokens exist

#### `uiStore` (frontend/src/stores/uiStore.ts, ~550 lines)
**Owns:** Layout state for MainLayout (sidebar width, reader open, entry selection, etc.), reader preferences, and the global copilot dock
**Persisted:** viewMode, sortOrder, sidebar/list/panel widths, reader typography, section collapse states, copilot width/collapsed, per-table DataTable state (`tables`)

**Table layouts start from a curated preset:** `components/table/defaultLayouts.ts` holds the instance's out-of-the-box arrangement per `tableId` — column visibility, widths, and order. `DataTable` consults it only where the user has no preference of their own (`stored ?? preset ?? column default`, per column; a stored column *order* replaces the preset order wholesale). Filters and sort are deliberately not part of it. Refresh the snapshot from a `state.tables` dump when the reference layout changes. A column declaring `sticky: "right"` (the entity tables' actions cell) is always ordered last and can't be dragged, whatever the stored order says.

**Table layouts follow the user, not the browser:** `tables[tableId]` holds each DataTable's column visibility/widths/order plus its filters and client sort. The column layout half also lives on the user profile under the `table_layouts` setting — `useTableLayoutSync` (mounted once in `App.tsx`) pulls it on load, merges per table by `layoutUpdatedAt` (newest edit wins; a table this device never touched adopts the server copy), and debounce-saves local changes back via `PATCH /api/auth/me/settings`. Filters and sort stay device-local on purpose. `tablesOwnerId` records whose layouts the map holds so a second account signing in on the same browser gets its own columns instead of inheriting — and uploading — the previous user's.
**Key layout methods:**
- `setSelectedEntry(id)` — Opens reader, auto-closes sidebar on mobile, resets panels
- `setActivePanel(panel)` — Switches between entries/search/notes; clears search when switching away
- `setActiveReaderPanel(panel)` — Reader side panels: `"note" | "tag" | "workbench" | "glossary" | "create_entity" | "add_alias" | "link_entity" | null`

**Reader preferences:**
- `readerFontSize`: 13 | 14 | 15 | 16 | 18 | 20 px (default 16)
- `readerLineHeight`: default 1.7
- `readerMaxWidth`: default 720px

**Copilot dock state:**
- `copilotOpen` / `copilotCollapsed` / `copilotWidth` (width + collapsed persisted)
- `copilotActiveConversationId` — resume the last thread
- `openCopilotWith(seed)` — open the dock pre-scoped from "Ask Copilot" buttons: a `CopilotSeed` can pin an entity/entry/campaign context and/or auto-send a starter question
- `toggleCopilot()` — bound to `Cmd/Ctrl+Shift+K` via `useGlobalShortcuts`

#### `intelStore` (frontend/src/stores/intelStore.ts, ~250 lines)
**Owns:** Workbench state (active section, nav section collapse, pivots, rule format preferences)
**Persisted:** activeSection, autoExtractOnOpen, autoOpenIntelPanel, preferredRuleFormats, nav section collapse flags, recentPivots, recentSearches
**Key methods:**
- `setActiveSection(section)` — Switch workbench section (threat_actors, malware, rules, etc.)
- Recent pivots/searches are capped rolling lists used by the workbench nav

The workbench's rail collapse now lives in `uiStore` (`sidebarCollapsed`), because the app sidebar *is* the workbench nav in Workbench mode — there is no second rail to track.

#### `playerStore` (frontend/src/stores/playerStore.ts, ~210 lines)
**Owns:** Audio & text-to-speech (TTS) playback state
**Persisted:** playbackRate, volume (not queue or active track)
**Dual modes:**
- **Audio mode**: Queue-based playback of media files (audio, video). Tracks carry a `kind` (`"podcast" | "tts"`) — server-side Piper read-aloud (`useTts.ts`: enqueue synthesis, poll until the MP3 is ready) plays through this mode.
  - `play(track)` → Set current track, clear speech state
  - `playNext()` → Dequeue next track
- **Speech mode**: Paragraph-by-paragraph browser Web Speech TTS (the fallback when Piper synthesis fails)
  - `playSpeech(track)` → Set speech paragraphs, clear audio track
  - `setSpeechWord(start, length)` → Update highlighted word position (consumed by SpeechHighlighter)

#### `triageViewStore` (frontend/src/stores/triageViewStore.ts)
**Owns:** Triage-specific filters and view settings for the swipe UI.

## Server State Management

**TanStack Query v5** (`@tanstack/react-query`) manages all server state with a centralized `queryClient` (frontend/src/queryClient.ts).

### Query Configuration
- **Stale time:** 30 seconds (data considered fresh for 30s)
- **Retry:** 1 retry for transient failures; no retry for 429/401/403
- **Window focus:** Disabled (`refetchOnWindowFocus: false`)
- **Cache invalidation:** Mutations invalidate related queries by key pattern

### Infinite Query Pattern
Used for paginated lists (entries, rules, etc.). Example from `useEntries.ts`:

```typescript
export function useEntries(filters: EntryFilters) {
  return useInfiniteQuery({
    queryKey: ["entries", filters],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, string | boolean | undefined> = {
        ...filters, limit: "50"
      };
      if (pageParam) params.cursor = pageParam;
      const res = await api.get<CursorPaginatedResponse<Entry>>("/entries", { params });
      return res.data;
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
}
```

- `cursor`-based pagination for stable streaming behavior
- 50 items per page
- `getNextPageParam` extracts next cursor from response

### Mutation & Cache Invalidation
Mark-read mutations in `useEntries.ts` invalidate entries, entry counts, and feeds:

```typescript
export function useMarkRead() {
  const queryClient = useQueryClient();
  const debouncedFeedsInvalidate = useDebouncedFeedsInvalidation();
  return useMutation({
    mutationFn: async (entryId: string) => {
      await api.put(`/entries/${entryId}/read`);
    },
    onSuccess: (_data, entryId) => {
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entries-count"] });
      queryClient.invalidateQueries({ queryKey: ["entry", entryId] });
      debouncedFeedsInvalidate();
    },
  });
}
```

Debounced feeds invalidation prevents request storms when markReadOnScroll is enabled.

## Theming System

**Files:** `frontend/src/index.css`, `frontend/src/hooks/useThemes.ts`, `frontend/src/utils/entityTheme.ts`, `frontend/src/utils/colorSchemes.ts`

### CSS Variables Architecture (index.css)

Organized into five design dimensions:

**D1: Base colors** (light/dark mode)
- `--bg-primary`, `--bg-secondary`, `--bg-tertiary` (backgrounds)
- `--text-primary`, `--text-secondary`, `--text-muted` (text)
- `--border` (dividers)

**D2: Domain accent colors** (feeds, intelligence, detection, dashboards)
- `--accent-feeds`, `--accent-intel`, `--accent-detect`, `--accent-dash`
- Paired with lighter `*-bg` variants for highlights

**D3: Entity type colors**
- `--entity-actor`, `--entity-malware`, `--entity-ttp`, `--entity-cve`, etc.
- Mapped via `getEntityColor(type)` in `entityTheme.ts`

**D4: Elevation** (shadows for depth)
- `--elevation-1` (subtle), `--elevation-3` (prominent)

**D5: Heatmap palette** (part of the theme variable contract; currently unused by core UI)
- `--heatmap-empty` through `--heatmap-5` (GitHub-style gradient)

**Cross-cutting badge scales** live in `utils/colorSchemes.ts` rather than per-component constants: `getTLPColor()` (TLP:CLEAR/GREEN/AMBER/AMBER+STRICT/RED) and `getSeverityColor()` (critical→info, resolving through `--severity-*` CSS variables set at runtime by `applyTheme()` with theme defaults as fallbacks). Entity-type colors stay in `entityTheme.ts`.

### Runtime Theme Switching
`applyTheme(theme)` in `useThemes.ts`:

1. Sets all CSS variables on `:root`
2. Auto-computes contrast-safe text colors using WCAG luminance
3. Auto-generates hover states if not provided
4. Updates favicon + PWA theme-color meta tag
5. Caches theme ID + background color in localStorage for instant restore

**Auto-contrast text:** Calculates luminance of background color; returns white for dark backgrounds, black for light backgrounds.

### useAutoTheme Hook
On app boot:
1. If user has a saved theme preference, apply it
2. Else, apply the admin-set instance default theme (`is_default`)
3. Else, load from localStorage cache (instant restore on revisit)
4. Else, fall back to "GitHub Dark" theme

Logged-out pages (login/register) get the instance default via a public `/themes/default` endpoint.

## Component Library

Most components live flat in `src/components/` (colocated `.tsx` + `.module.css` per component); domain clusters with many files get subdirectories (`automation/`, `engine/`, `entityProfile/`, `triage/`, `widgets/`). The groupings below are by purpose, not by directory.

### Core Layout Components
- **Sidebar** (Sidebar.tsx) — Two modes behind a Reading/Workbench switch at the top. Reading: category tree, feed list, virtual-folder chips (starred, bookmarked, today, last_24h, this_week) plus a Priority Queue chip under the Unread-articles hero, nav links (Notes, Automation), saved searches. Workbench: renders `WorkbenchNav` — the workbench's section list, which no longer has a rail of its own
- **EntryList** (EntryList.tsx) — Virtualized row list using `@tanstack/react-virtual`, day dividers with shared AI daily summaries (`DayDividerSummary`) and day intel chips (`DayIntelChips`)
- **EntryReader** (EntryReader.tsx) — Content pane with note/tag/workbench/glossary/entity side panels, text selection context menu, article inline entity highlighting, TTS
- **AppHeader** (AppHeader.tsx) — Top nav with logo, search, user menu
- **ResizeHandle** (ResizeHandle.tsx) — Draggable layout dividers

### Global Copilot Dock
- **CopilotDockPanel** (CopilotDockPanel.tsx) — App-level, resizable right-hand dock mounted in `App.tsx` for all authenticated users; toggled with `Cmd/Ctrl+Shift+K` or the header button. Streams chat responses (`streamCopilotChat` in `useAI.ts`) and interleaves them with:
  - **ToolTraceChip** — live trace chips for each IntelFeed tool the copilot calls while answering
  - **ConfirmCard** — proposed writes (e.g. create rule/tag) held for explicit user confirmation
  - **ContextPill** — ambient context derived from the current route (`useCopilotContext`), or a pinned context when opened via an "Ask Copilot" seed (`openCopilotWith`)
  - **SlashCommandMenu** — `/` command completion (`copilotCommands.ts`)
- Conversation history via `useConversations`; conversations can be shared publicly (`POST /ai/conversations/:id/share` → `/shared/copilot/:token`, rendered by **SharedCopilotPage**)
- **CopilotAuthCard** / **CopilotReauthModal** — copilot Claude OAuth sign-in status and in-app re-auth (Settings → AI Configuration); the dock shows an admin-only re-auth banner when `useCopilotAuthStatus` reports the session expired
- Copilot token spend surfaces in the **Cost** tab of Settings → AI Configuration (`useAICostSummary`)

### Search Components
Search is one input and one results surface, on every route and every breakpoint.
`HeaderSearch` is the input; `/search` (**SearchPage**) is the only place results
are drawn. There is no second engine: the workbench's mobile overlay and its
`useIntelSearch` against `/intelligence/search` were removed — that path knew
only `type:` filters, discarded every other field, and never returned articles,
so a phone got different answers from a laptop.

- **HeaderSearch** (HeaderSearch.tsx) — The app's one search field. Carries the `in:`
  scope chip (Tab cycles `everything` → `workbench` → `feeds`) and completes against
  `/search/autocomplete` or the local intelligence dictionary depending on scope. Typing
  routes to `/search`; it renders no results of its own.
- **queryFields.ts** (components/search/) — The query language as data: field groups
  (one per entity type, each carrying its entity colour), known values, hints, examples,
  and `queryFieldColor()`. The reference card, the autocomplete dots and the intelligence
  completion dictionary all derive from it, so they cannot drift apart.
- **SearchPage** (pages/SearchPage.tsx) — The results route, under `SidebarLayout`. Owns
  the debounced query, the scope, the facet state, and an `EntryReader` pane. Its facet
  rail is a second sidebar inside the content area, like the workbench and settings rails,
  so the app sidebar is untouched.
- **SearchFacetSidebar** (components/search/) — Scope, entity type (server counts),
  matched-on (identity vs mention), and the entry facets (date window, read state, feed,
  content type, tags, media, language). Entry facets are written into the query string as
  `field:value`, so they are visible, hand-editable and saveable.
- **SearchResults** (components/search/) — Direct matches (with an expanded card for the
  top one) above per-type mention groups, then articles via the shared `EntryRow`. Also
  hosts saved/recent searches, the query builder and the syntax reference.
- **EntityResults** (components/search/) — Per-type grouping, labels (`ENTITY_TYPE_LABELS`),
  row naming and click routing for every entity type, **notes included**. A note has no
  route of its own, so the row opens whichever surface holds it: an entity note goes to
  `/workbench/{type}/{id}?tab=notes`, an entry note selects the entry and opens the reader's
  notes panel, and a standalone note opens the notes browser with `setPendingNoteSearch()`
  seeding its filter so the clicked row lands on top.
- **QueryBuilder** (QueryBuilder.tsx) — DSL syntax helper for advanced queries
- **CommandPalette** (CommandPalette.tsx) — Cmd+K action menu; fuzzy search actions like "Mark all read", "Export", "Share"

The `in:` chip is a **content** contract, not a routing one: `feeds` renders articles only,
`workbench` renders entities only, `everything` renders both. Nothing else moves. Entering
search seeds the chip from the route you came from, then it sticks.

**Mobile.** The same page, with the facet rail as a slide-over sheet opened from the
toolbar's Filters button (the desktop rail toggle is a hover affordance that does not
exist on touch) and the reader as a full-screen overlay. The workbench keeps one mobile
affordance of its own — a "Sections" button for its section nav.

### Intelligence Components
- **entityProfile/** — Config-driven entity profile used by the unified `EntityProfilePage`: `ProfileHeader`, `ProfileTabs` + `tabs/` (overview, articles, relationships, detection, etc.), `EntityActionsMenu` (watch, convert, merge, export, delete), `EntityEditModal`, `IdentityFields`, `SignalBadges`, `StatGrid`, `ActivityFeed`, `PivotTrail`, `WhatsNewStrip` — all driven by `entityProfileConfig.tsx`
- **EntityActionsMenu** is shared by the profile hero (`variant="header"`) and each workbench table row (`variant="row"`, via `EntityRowActionsCell`, which mounts the menu's ~20 data hooks only after the row's ⋯ is first clicked). The row variant adds Open profile and Edit…, and portals its popovers to `document.body` — a virtualized row's `transform` would otherwise become the containing block for anything `position: fixed`.
- **EntityEditModal** gathers the profile's inline editors into one form for table-side maintenance. Its fields are derived from `entityProfileConfig` (name when `nameEditable`, aliases, every click-to-edit signal badge, identity fields, description), and only fields the operator changed are sent — so a value the row payload didn't carry can't be blanked by saving. `mitigation` has no PUT endpoint and gets no Edit item.
- **EntityGraph** (EntityGraph.tsx) — Relationship network visualization (@xyflow/react)
- **EntityTimeline** (EntityTimeline.tsx) — Activity timeline, entry mentions, rule matches
- **EntityTableSection** (EntityTableSection.tsx) — Sortable/filterable table (threat_actors, malware, CVEs, TTPs, etc.). Appends the shared relationship/coverage columns plus a right-pinned ⋯ actions column, and offers Export / Merge / Delete over the checkbox selection
- **EntityMergeSelectionModal** — folds the checked rows into one keeper (defaulting to the profile with the most articles) via a single `POST /entities/{type}/merge`. Only offered for `MERGEABLE_ENTITY_TYPES` with 2+ rows checked; shares `EntityMergeIntoModal`'s stylesheet since it's the same flow sourced from a selection rather than a search
- **EntityPopover / EntityActionMenu / EntityMergeModal / EntityMergeIntoModal** — inline entity hover cards, actions, and dedup/merge flows
- **CreateEntityPanel** (CreateEntityPanel.tsx) — Form to create new entity
- **AddAliasPanel** / **LinkEntityPanel** — Link aliases or text spans to existing entities
- **EnrichmentPanel** (EnrichmentPanel.tsx) — Entity enrichment status/results
- **AttackMatrixSection** (AttackMatrixSection.tsx) — ATT&CK matrix with per-technique detection coverage ("covered" badges)

### Reader Experience Components
- **SafeHTML** (SafeHTML.tsx) — DOMPurify renderer for entry content
- **ExternalLinkGuard** (ExternalLinkGuard.tsx, ExternalLinkModal.tsx, `utils/externalLinks.ts`) — one capture-phase `click`/`auxclick` listener mounted in `GlobalModals` that holds off-site links for a confirmation dialog. `SafeHTML` marks its wrapper `data-untrusted-content`; that attribute is what the default "article content" scope keys on (add it to any other renderer of feed text). Preferences and the trusted-host list live in `user.settings` (`external_link_mode`, `external_link_trusted_hosts`), saved with `PATCH /auth/me/settings`
- **ReaderTypography** (ReaderTypography.tsx) — Font size, line height, max-width controls
- **FindInArticle** (FindInArticle.tsx) — Ctrl+F-like text search within entry
- **AudioPlayer** (AudioPlayer.tsx, 200+ lines) — Playback controls, queue management, speed/volume
- **YouTubePlayer** (YouTubePlayer.tsx) — Embedded video player with transcript
- **SpeechHighlighter** (SpeechHighlighter.tsx) — Highlights currently-spoken word in TTS mode
- **EntryIntelBadges** (EntryIntelBadges.tsx) — Inline entity badges (click to pivot)
- **InlineEntityHighlighter** (InlineEntityHighlighter.tsx) — Highlights entities extracted from content

### Notes Components
The notes experience is split into viewer and editor:
- **NoteBrowser** (NoteBrowser.tsx) — Full-panel notes view in MainLayout (`activePanel === "notes"`), listing entry and entity notes
- **NoteCard** / **NoteBody** — Read-only note rendering (markdown; single newlines render as hard breaks)
- **InlineNoteEditor** (InlineNoteEditor.tsx) — Editing surface, separate from the viewer
- **EntryNotePanel** (EntryNotePanel.tsx) — Reader side panel for the current entry's note
- **EntityNotesSection** (EntityNotesSection.tsx) — Notes on entity profiles, with per-note titles (`useEntityNotes`)

### Triage Components
- **TriageControls** (triage/TriageControls.tsx) — Filter/range controls for the triage dashboard
- **corrEventCards** (triage/corrEventCards.tsx) — Correlation-event card components + helpers shared by the Dashboard (correlation browser) and the Priority Queue (inline row expansions)

### Automation Components
- **FlowBuilder** (FlowBuilder.tsx) — No-code automation rule editor (nodes: trigger, filter, action, fork)
- **TemplateGallery** (TemplateGallery.tsx) — Preset automation templates
- **ImportExportDialog** (ImportExportDialog.tsx) — Flow YAML/JSON import/export
- **flowSerializer** (flowSerializer.ts) — Serialization logic for flows (node graph ↔ JSON)

### Widget System
**Location:** `frontend/src/components/widgets/`

30+ dashboard widgets registered in `widgets/registry.ts`, rendered on the Dashboard's widget grid, including:
- **OverviewWidget** — Key stats (feeds, entries, rules)
- **FeedActivityChart** — Feed volume over time
- **NewActorsWidget** — Recently discovered threat actors
- **DetectionCoverageWidget** / **AttackCoverageGapWidget** — Technique coverage ("covered" vs. gaps)
- **CorrelationEventsWidget** — Related entry cluster visualization
- **IntelVelocityWidget** — Entity discovery rate
- **AutomationLogsWidget** — Automation execution history
- **AIUsageWidget**, **KEVMatchesWidget**, **SourceReliabilityWidget**, **TriageQueueStatsWidget**, and other domain-specific widgets

**Widget API:**
```typescript
interface Widget {
  id: string;
  type: string;              // "overview", "feed_activity", etc.
  title: string;
  config: Record<string, unknown>;  // Widget-specific settings
  size: "small" | "medium" | "large";  // Grid layout
  filters?: {
    feedId?: string;
    entityType?: string;
    dateRange?: TimeRange;
  };
}
```

**WidgetRenderer** — Generic component that instantiates widgets by type
**WidgetPicker** — Modal to add widgets to dashboard

### Detection Rule Components
- **RuleBuilderShell** (RuleBuilderShell.tsx) — Layout for rule editor (editor + preview pane)
- **CodeMirrorEditor** (CodeMirrorEditor.tsx) — Syntax-highlighted code editor (SIGMA, YARA, etc.)
- **RuleEntryCard** (RuleEntryCard.tsx) — Card showing rule match against entry
- **SaveRuleModal** (SaveRuleModal.tsx) — Dialog to save/publish rule

### Settings & System Components
- **SystemSettings** — Admin system toggles (image proxy, backup, etc.)
- **ThemeEditor** — Create/edit custom themes with live CSS variable preview
- **AISettings** — Providers | Prompts | Cost | User keys tabs; includes CopilotAuthCard for in-app Claude re-auth; the Prompts tab renders the master–detail **PromptWorkspace**; the Providers tab, health banner and assignment pickers show the instance's providers only; the Cost tab's tiles split instance spend from people's own keys and its By-user table (`ByUserTable`) carries allowance meters
- **UserKeysSection** (UserKeysSection.tsx) — the User keys tab: the personal-key policy as one segmented control (Off / Optional / Required, writing both flags), allowed key types as chips, the private-endpoint switch, the four limits (monthly and daily caps on personal keys, the per-person site allowance, the share-link limit), the per-task eligibility table (pipeline tasks locked), and everyone's keys to disable or delete
- **MyAISection** (MyAISection.tsx) — Settings → My AI (`?section=myai`): this month's spend against the cap with a per-key meter, the person's keys (test, edit, delete, set as default; the add form tests-and-saves and refuses Claude Code), per-task route and model pickers with the "no tools" chip and an "Instance default" opt-out, the fallback switch (hidden under Required) and the personal cap; `utils/aiProvenance.ts` holds the fallback-reason wording that result cards (`AIResultsDisplay`'s Who-answered hover and fallback stripe), task rows (`AIAnalysisSection`'s key dot) and the copilot dock share
- **engine/EngineSection** — the Settings → Engine console (rendered by SettingsPage's `engine` section at `/settings?section=engine`): a single-surface table card (entries matrix, links, relationships, Review, in-card stage settings) with Jobs / Feeds / Plans as separate views; hosts feed health, enrichment, and job schedules, and maps bookmarked `?tab=` / `?section=` deep links onto console states
- **TagManager** (TagManager.tsx) — Settings → Tags: rename, recolor, merge, and delete tags with usage counts; **TagPicker** is the reusable tag-selection dropdown used by the reader tag panel, report wizard, and automation editor
- **TelegramSection** (in SettingsPage.tsx) — Admin walkthrough for Telegram user-session setup

## Page Components & Routes

**Pages in `frontend/src/pages/`:**

- **MainLayout.tsx** (eager) — Three-panel feed reader with keyboard shortcuts; also serves `/priority-queue` in `priorityMode` (EntryList pinned to the radar sort, docked reader with a Why-ranked card, inline story-thread rows)
- **SidebarLayout.tsx** (eager) — Tool pages wrapper
- **WorkbenchPage.tsx** (lazy) — Intelligence entity workbench; also exports `WorkbenchLayout` for the nested route tree, and hosts the glossary and detection workbench as workbench sections
- **EntityProfilePage.tsx** (lazy) — Unified, config-driven profile for all entity types (threat_actor, malware, cve, ttp, country, tool, mitigation, vendor, product)
- **DashboardPage.tsx** (lazy) — Workbench dashboard (correlation browser + widget grid via `useDashboards` + WidgetPicker)
- **ExposurePage.tsx** (lazy) — Workbench → Vendor Watch (`/workbench/exposure`)
- **DocumentationPage.tsx** (lazy) — In-app docs (`/documentation/*`, backed by `useDocumentation` with `MermaidDiagram` rendering for diagram fences)
- **AutomationPage.tsx** (lazy) — Automation flow management
- **DetectionWorkbenchPage.tsx** — Rule creation & testing (rendered inside the workbench; `/detection-workbench` redirects to `/workbench`)
- **GlossaryPage.tsx** — Glossary term management (rendered inside the workbench)
- **RuleDetailPage.tsx** (lazy) — Single rule versioning & testing
- **SettingsPage.tsx** (lazy) — Section-based settings (Account, AI Configuration, Appearance, My AI, Claude Code Skill, Engine, Telegram Setup, Feeds & Import, Logs, Reading, Tags, System, Users). Engine is the admin-only pipeline console section (`?section=engine`, hosting `engine/EngineSection`); legacy `?section=schedules|enrichment|feed-health|workbench` deep links resolve onto it.
- **CampaignsPage.tsx** (lazy) — Campaign management & correlation
- **CampaignProfilePage.tsx** (lazy) — Campaign detail with related entities
- **RegionsPage.tsx** (lazy) — Region/sub-region aggregation
- **ReportBuilderPage.tsx** (lazy) — Intelligence report composition
- **LoginPage.tsx** (lazy) → Auth guard redirects here
- **RegisterPage.tsx** (lazy) → Self-service registration
- **SharedEntryPage.tsx** (lazy) → Public entry sharing (no auth required)
- **SharedCopilotPage.tsx** (lazy) → Public copilot conversation sharing (no auth required)
- **OnboardingWizard** → Modal overlay for new users (triggered by `!user.settings.onboarding_completed`)

Country profiles use the unified EntityProfilePage (`/countries/:id` redirects to `/workbench/country/:id`); the former standalone RuleLibraryPage, FeedHealthPage, and PriorityQueuePage were removed (rule library lives in the workbench, feed health in Settings → Engine, and the priority queue is MainLayout's `priorityMode`).

## Hooks (Custom React Hooks)

**60+ custom hooks in `frontend/src/hooks/`**, organized by domain:

### Data Fetching Hooks (TanStack Query wrappers)
- **useEntries(filters)** — Infinite query for paginated entries
- **useEntry(entryId)** — Single entry detail
- **useFeeds()** — All feeds
- **useIntelligence()** — Workbench entity hooks
  - `useEntryCVEs(entryId)` — Extract CVEs from entry
  - `useEntryTTPs(entryId)` — Extract TTPs
  - `useEntryThreatActors(entryId)` — Extract actors
  - (etc. for all entity types)
- **useUnifiedSearch(query, opts)** — The search page's data source: `POST /search/unified`, running the whole query language. `opts` accepts `limit`/`offset` plus `entityLimit` (how much of the graph may match, server default 200) and `entityGroupLimit` (rows per entity type, server default 25). Omit them and the server defaults apply; SearchPage passes `entityGroupLimit: 500` because its facet rail needs the whole set.
- **useSearchAutocomplete(query)** — Field/value completions for `HeaderSearch`
- **useSearch(filters)** — Structured `POST /search/advanced` (explicit filter object, no query language). Used by the saved-search and filter-object paths, not by the search page.
- **useCampaigns()** — Campaign CRUD
- **useDetectionRules(filters)** — Rule queries
- **usePlayback()** → Entry media playback progress

### Mutation Hooks
- **useMarkRead() / useMarkUnread()** — Entry read status
- **useToggleStar() / useToggleBookmark()** — Entry favorites
- **useAddTagsToEntry() / useRemoveTagFromEntry() / useBulkTag()** — Entry tagging; **useCreateTag() / useUpdateTag() / useMergeTags() / useDeleteTag()** back the Tags settings section
- **useCreateDetectionRule() / useValidateRule() / useToggleRuleStatus()** — Rule mutations
- **useRollbackVersion() / useVersionDiff()** — Rule versioning
- **useAddFeed() / useUpdateFeed() / useDeleteFeed() / useRefreshFeed()** — Feed management

### UI & Interaction Hooks
- **useUIStore()** → Zustand store accessors
- **useAuthStore()** → Auth store accessors
- **useIntelStore()** → Workbench store accessors
- **useIsMobile()** — Media query hook
- **useMediaQuery(query)** — Generic media query
- **useSwipe(config)** → Swipe gesture detection (threshold, direction callbacks)
- **useLongPress(timeout)** → Long-press gesture
- **useFocusTrap(containerRef)** → Modal focus management
- **usePullToRefresh(callback)** → Mobile pull-to-refresh
- **useUndoableDelete(onDelete)** → Undo/redo delete mutations

### Specialized Hooks
- **useThemes()** → Theme queries & mutations
- **useAutoTheme()** → Auto-apply user theme on load
- **useDomainTheme()** → Get domain-specific theme (feeds vs. workbench vs. detection)
- **useDetectGlossaryTerms(entryId)** → Detect glossary matches in an entry
- **useSSE()** → Server-Sent Events subscription (real-time entry updates, rule matches)
- **useIngest(feedConfig)** → Feed ingestion status polling
- **useJobSchedules()** → Background job scheduling
- **useGlobalShortcuts()** → App-wide shortcuts (mounted once in App.tsx; `Cmd/Ctrl+Shift+K` toggles the copilot dock)
- **useCopilotAuthStatus() / useStartCopilotAuth() / useSubmitCopilotAuthCode()** → Copilot Claude OAuth status and in-app re-auth flow
- **useCopilotContext()** → Derives the copilot's ambient context (entity/entry/campaign) from the current route
- **useDailySummary(dayKey) / useGenerateDailySummary()** → Shared per-day AI triage summaries shown in entry-list day dividers

## Utilities

**10+ utility modules in `frontend/src/utils/`:**

### `entityTheme.ts`
Centralized visual language for entities:
```typescript
getEntityColor(type: string): string        // Hex color
getEntityCssVar(type: string): string       // CSS variable reference
getEntityLabel(type: string): string        // Singular label
getEntityPluralLabel(type: string): string  // Plural label
getEntityIcon(type: string): string         // Lucide icon name
getEntityTheme(type: string): EntityTheme   // Full theme object
```

Example:
```typescript
const color = getEntityColor("threat_actor");  // "#f97316"
const icon = getEntityIcon("malware");        // "shield-alert"
```

### `queryParser.ts`
Tokenizer + recursive-descent parser for the search DSL. Builds an AST (`TextNode | FieldNode | BoolNode | NotNode`), with helpers for the UI:
```typescript
parseQuery(query: string): ASTNode
extractFilters(node: ASTNode): ParsedFilter[]   // → structured filters for API params
getTokenAtCursor(query, cursorPos): CursorToken // autocomplete support
removeFilterFromQuery(query, filterRaw): string // filter-chip removal
```
Syntax examples: `feed:xyz title:"New APT" is:starred after:2024-01-01` (full grammar in [query-language.md](query-language.md)).

### `colorSchemes.ts`
Shared TLP and severity color scales (see Theming above): `getTLPColor(tlp)`, `getSeverityColor(severity)`.

### `pivotLinks.ts`
Builds intelligence pivot links from an entity type + value:
```typescript
getPivotLinks(type: string, value: string): PivotLink[]
// e.g. workbench profile, filtered search, external references (MITRE, NVD, ...)
```

### `dashboardTemplates.ts`
Preset widget layouts for the Dashboard:
```typescript
DASHBOARD_TEMPLATES: DashboardTemplate[]
```

### `groupEntries.ts`
Entry list grouping — collapses consecutive runs of same-feed entries into expandable groups:
```typescript
groupConsecutiveEntries(entries, ...): DisplayItem[]  // SingleItem | GroupItem
```

### `mapTopology.ts`
World topology loading and ISO-code utilities for the choropleth:
```typescript
loadWorldTopology(): Promise<TopologyFeature[]>
alpha3FromNumeric(id): string | null
buildIsoCountMap(countryStats): Record<string, number>
```

## Testing

### Unit & Component Tests (Vitest + RTL)
**Location:** `frontend/src/**/__tests__/` (colocated with source files)

Test setup in `frontend/src/test/setup.ts` (Vitest config lives in the `test` block of `vite.config.ts`):
- jsdom environment with globals enabled
- In-memory `localStorage` shim (jsdom's Storage proxy breaks Zustand persist)
- `window.matchMedia` mock
- Module CSS with non-scoped classNameStrategy (stable class names in tests)

Example test (`Sidebar.test.tsx`):
```typescript
import { render, screen } from "@testing-library/react";
import { useUIStore } from "@/stores/uiStore";
import { Sidebar } from "@/components/Sidebar";

describe("Sidebar", () => {
  it("renders feed categories", () => {
    render(<Sidebar />);
    expect(screen.getByText("My Feeds")).toBeInTheDocument();
  });
});
```

Tests cover:
- Component rendering with mocked hooks
- User interactions (click, type, keyboard)
- Store state updates
- API calls mocked by stubbing the Axios client / hooks with `vi.mock` (no MSW)

### End-to-End Tests (Playwright)
**Location:** `frontend/tests/e2e/`

Tests run against a live backend instance:
- **auth.spec.ts** — Registration, login, auth guards
- **feeds.spec.ts** — Feed list, entry open, mark read
- **relationships.spec.ts** — Entity relationship browser and graph

Playwright configuration in `frontend/playwright.config.ts` (baseURL `localhost:3001`, workers: 1, retries: 2 in CI).

## Build & Optimization

**Vite config:** `frontend/vite.config.ts`

### Code Splitting
Manual chunk configuration (function-form `manualChunks` — required by Vite 8 / rolldown) creates separate bundles:
- `vendor-react` → React, React DOM, React Router
- `vendor-tanstack` → TanStack Query (large, separate for caching)
- `vendor-misc` → Zustand, Axios, DOMPurify
- **Page bundles** → Each lazy-loaded page in its own chunk

### Development Server
- Proxy `/api` (plus `/docs`, `/redoc`, `/openapi.json`) to `http://localhost:8000` (configurable via `VITE_API_URL`)
- Port 3000 (3001 when run through docker-compose.dev.yml)
- HMR enabled for instant hot reloads

### Build Output
- No sourcemaps in production (`sourcemap: false`)
- Minified + mangled code
- CSS extracted into per-chunk stylesheets

## Conventions & Best Practices

### Component Structure
1. Imports (React, hooks, components, styles)
2. Type definitions (`interface ComponentProps { ... }`)
3. Utility functions (formatters, helpers)
4. Main component function with JSDoc
5. Error boundary / suspense handling
6. Event handlers (in logical order: click, change, submit)
7. Return JSX

### Naming Conventions
- **Components:** PascalCase (`EntryReader`, `EntityProfilePanel`)
- **Hooks:** camelCase with `use` prefix (`useEntries`, `useSwipe`)
- **Utilities:** camelCase (`getEntityColor`, `bucketByDay`)
- **Stores:** camelCase (`useUIStore`, `useAuthStore`)
- **Events:** on-prefixed (`onItemClick`, `onModalClose`)
- **CSS modules:** kebab-case (`.container`, `.entry-title`)

### CSS Module Usage
Every component has a colocated `.module.css` file:

```typescript
// EntryReader.tsx
import styles from "./EntryReader.module.css";

export function EntryReader({ entryId }: EntryReaderProps) {
  return <div className={styles.root}>...</div>;
}
```

CSS variables are inherited globally from `:root`; component-scoped variables are uncommon.

### State Management Decision Tree
1. **Component-local state** — useState for UI state (open/closed, selected tab)
2. **Zustand store** — Persistent, cross-page state (auth, layout, entity selection)
3. **TanStack Query** — Server state (entries, feeds, rules)
4. **Context** — Rare; used only for deeply nested provider configs

### Error Handling Pattern
```typescript
function useMyQuery() {
  const { data, isLoading, error } = useQuery({...});
  if (error) {
    // Auto-handled by queryClient error interceptor → toast
    // OR handle UI-specific error in component
  }
  return { data, isLoading, error };
}
```

Toast notifications are the primary error feedback mechanism (Sonner library).

### Accessibility
- Semantic HTML (`<button>`, `<nav>`, `<article>`, etc.)
- ARIA roles for custom widgets (`role="dialog"`, `role="listbox"`)
- Keyboard navigation (Tab, Enter, Escape, arrow keys)
- Color contrast: WCAG AA minimum (verified by `contrastText()` in theme system)
- Focus visible outlines (2px solid accent color, 2px offset)

### Performance Optimization
- **Virtualization:** EntryList (and large workbench tables) use `@tanstack/react-virtual` for 10K+ rows
- **Memoization:** `useMemo` for expensive calculations (entity extraction, grouping)
- **Code splitting:** Lazy-loaded pages + manual chunks reduce initial load
- **Query caching:** 30s stale time prevents redundant API calls
- **Debouncing:** Search input, sidebar drag handlers
- **PWA support:** Service worker registration in `main.tsx`

### Git Workflow
- Feature branches: `feature/entity-comparison` or `fix/auth-logout`
- No CI pipeline is configured — run `pnpm lint` + `pnpm build` (and backend `ruff` + `pytest`) locally before pushing
- Deployment: push to the Git remote, then run `update.sh` on the production host (see the `/deploy` skill)

---

## Summary

IntelFeed's frontend is a sophisticated React SPA balancing feature richness with maintainability. Key architectural pillars:

1. **Routing** — Two-layout pattern (MainLayout for feeds, SidebarLayout for tools) plus a global copilot dock mounted above both
2. **State** — Zustand for persistent UI/app state, TanStack Query for server state
3. **Styling** — Global CSS variables for runtime theming + scoped CSS modules + shared color scales (`entityTheme.ts`, `colorSchemes.ts`)
4. **Components** — Domain-organized, colocated with styles, reusable across pages
5. **Hooks** — 60+ custom hooks encapsulate domain logic (queries, mutations, gestures, copilot)
6. **Testing** — Vitest + RTL for components, Playwright for e2e
7. **Build** — Vite with manual code splitting and lazy-loaded pages

The codebase prioritizes **clarity** (explicit over implicit), **reusability** (hooks + utilities), and **performance** (code splitting, caching, virtualization).
