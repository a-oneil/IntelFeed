# Frontend Architecture

This is a guide to IntelFeed's web app for developers who want to change it. After reading it you will know where pages, state, data fetching, theming and tests live, and the patterns to follow.

The app is a single-page app built with React 19, TypeScript and Vite. It uses React Router 7, TanStack Query 5 for server data, Zustand 5 for browser state, and CSS Modules for styling.

## Project Layout

```text
frontend/
├── src/
│   ├── App.tsx              # Routes, layouts, app-wide components
│   ├── main.tsx             # Entry point; registers the service worker
│   ├── index.css            # Global CSS variables and themes
│   ├── queryClient.ts       # TanStack Query defaults and error toasts
│   ├── api/
│   │   ├── client.ts        # Axios instance, token refresh, visitor write block
│   │   └── types.ts         # API response types
│   ├── stores/              # Zustand stores (see State Management)
│   ├── hooks/               # 88 hook modules, mostly TanStack Query wrappers
│   ├── utils/               # 44 helper modules
│   ├── pages/               # Route-level pages
│   ├── components/          # One .tsx + one .module.css per component;
│   │                        # subfolders for larger areas (automation/, engine/,
│   │                        # entityProfile/, primitives/, search/, table/,
│   │                        # triage/, widgets/, onboarding/)
│   └── test/setup.ts        # Vitest setup
├── tests/e2e/               # Playwright tests
├── vite.config.ts           # Build, dev server and Vitest config
└── playwright.config.ts
```

## Routing & Layouts

Routes are in `App.tsx`. There are two layouts:

- **MainLayout:** the three-panel reader.
- **SidebarLayout:** app header, sidebar and a content area, for tool pages.

Some things mount once at the app level, outside any route: `AudioPlayer`, `GlobalModals` (add-feed, the shortcut help, the external-link guard), and for signed-in users `ReportWizardModal`, `SendToReportModal` and `CopilotDockPanel`. `App.tsx` also starts `useSSE` (one live-event connection per session), `useTableLayoutSync`, `useReadingPrefsSync`, `useGlobalShortcuts` and `useAutoTheme`.

Protected routes go through `ProtectedRoute`. It sends signed-out users to `/login`, unless the instance is in public read-only mode, where visitors can browse. Pages wrapped in `SignedInOnly` show a "not available" message to visitors. New users see the `OnboardingWizard` until they finish or dismiss it.

### MainLayout Route Tree

**Paths:** `/`, `/feeds`, `/priority-queue`, and any path no other route matches.

The three panels:
1. **Sidebar** (resizable, can collapse): feeds, categories, folders, links.
2. **Entry list** (resizable): the entries, loaded page by page.
3. **Entry reader:** the article and its side panels.

`/priority-queue` renders `<MainLayout priorityMode />`: the same layout with the list sorted by score (`radar`), story threads shown as single rows, and a "why ranked" card in the reader. `?thread=<slug>` opens a thread in the reader; threads have no page of their own.

Keyboard shortcuts set in `MainLayout.tsx`:
- `Cmd/Ctrl+K`: command palette. (`Cmd/Ctrl+Shift+K` opens the copilot, from `useGlobalShortcuts`.)
- `Escape`: close the reader or the shortcut help.
- With the reader open: `w` intel panel, `a` AI panel, `n` notes panel, `t` tags panel, `e` export as Markdown.
- `?`: shortcut help.

List keys (`j`/`k`, `m`, `s`, `b`, `o` and others) are handled in `EntryList` and `EntryReader`. The full list is in `KeyboardShortcutsHelp.tsx`.

### SidebarLayout Route Tree

All lazy-loaded:

- `/settings`: SettingsPage
- `/search`: SearchPage
- `/automation`: AutomationPage
- `/campaigns`: CampaignsPage
- `/documentation/*`: DocumentationPage. The bare path is the docs home page; anything after it is a page in `docs/`.
- `/workbench`: WorkbenchLayout, with:
  - index: redirects to `dashboard`
  - `dashboard`: DashboardPage, the Workbench home
  - `explore`: WorkbenchPage, the entity and section browser
  - `threats`: ThreatsPage (tabs: All, Actors, Malware, Vulnerabilities)
  - `{type}/:id`: EntityProfilePage, for `threat_actor`, `malware`, `cve`, `cwe`, `ttp`, `country`, `sector`, `tool`, `mitigation`, `observable`, `vendor`, `product` and `campaign`
  - `rule/:id`: RuleDetailPage
  - `report/new`, `report/:id`: ReportBuilderPage
  - `report/exposure`: ExposureBuilderPage

**Redirects** (kept so old links work):
- `/triage`, `/workbench/triage`, `/atlas`, `/dashboards` → `/workbench/dashboard` (`/triage` keeps its query string)
- `/intelligence`, `/detection-workbench` → `/workbench/explore`
- `/glossary` → `/workbench/explore?section=glossary`; `/workbench/rules` → `/workbench/explore?section=rules`
- `/workbench/exposure` → `/workbench/threats?tab=vulns`
- `/workbench/engine` → `/settings?section=engine` (query string kept)
- `/feed-health` → `/settings?section=engine&tab=pipeline&stage=feeds`
- `/countries/:id` → `/workbench/country/:id`
- `/intelligence/threat_actor/:id`, `/intelligence/malware/:id` → the `/workbench/` profile
- `/workbench/actor/:id`, `/intelligence/actor/:id` → `/workbench/threat_actor/:id`
- `/handbook/*` → `/documentation/*`

**Public routes** (no sign-in): `/login`, `/register`, `/shared/:token` (SharedEntryPage), `/shared/copilot/:token` (SharedCopilotPage).

### Dynamic Entity Resolution

A profile URL can use a UUID or a natural key, such as `/workbench/ttp/T1490` or a CVE ID. The profile page looks up non-UUID IDs through the API.

### Lazy Loading & Code Splitting

Every page except MainLayout and SidebarLayout is loaded with `React.lazy()`, so each gets its own bundle.

## API Client & HTTP

`frontend/src/api/client.ts` is the Axios instance every hook uses. See the [JWT refresh flow diagram](diagrams/frontend-jwt-refresh.md).

### Token Refresh Strategy

- **Before a request:** if the access token has less than 5 minutes left, refresh it first.
- **After a 401:** refresh and retry the request once (`_retry` flag).
- **One refresh at a time:** requests that need a new token share one refresh promise (`doRefresh`).
- **Sign-out:** only when the refresh endpoint returns 401 or 403. A network error keeps the session. After sign-out the page reloads to `/login`, or to `/` in public read-only mode.

### Visitors

In public read-only mode, a visitor's write request is stopped in the browser with a `ReadOnlyViewError`, except a short list of read-only POSTs (`VISITOR_READ_POSTS`). One quiet "read-only" toast is shown instead of an error.

### Error Handling

- **429 (rate limited):** rejected at once, never retried.
- **Other failures:** queries retry once, except 401, 403 and 429 (`queryClient.ts`).
- **Toasts:** `queryClient.ts` shows a Sonner toast for every failed query or mutation, except validation errors, 401s, visitor write blocks, and queries that set `meta.silenceToast`.

## State Management

There are three kinds of state:

1. **Server data:** TanStack Query. Never copy it into a store.
2. **Browser state:** Zustand stores in `frontend/src/stores/`.
3. **Component state:** `useState`, for things like an open menu.

### Zustand Stores with Persistence

Stores saved to localStorage use Zustand's `persist` with a `name` of `intelfeed-*` and a `partialize` that picks what to save.

| Store | Saved as | Holds |
|---|---|---|
| `authStore` | `intelfeed-auth` | Tokens and the current user (saved), plus whether public read-only mode is on (not saved) |
| `uiStore` | `intelfeed-ui` | Layout, view and sort, panel widths, reader typography, collapsed sections, copilot dock, table layouts, dashboard lock, docs chat |
| `intelStore` | `intelfeed-intel` | Workbench section, rule-format preferences, Workbench menu collapse, recent pivots and searches, last profile visits |
| `playerStore` | `intelfeed-player` | Audio and read-aloud playback. Only speed and volume are saved |
| `triageViewStore` | `intelfeed-triage-view` | A local copy of the user's dashboard view; the real copy is the `triage_view` user setting |
| `dialogStore` | not saved | Queue of confirm, alert and prompt dialogs |
| `externalLinkStore` | not saved | The link waiting for confirmation, and hosts trusted for this tab |

On sign-out, `clearUserScopedState()` removes each account's saved state, so the next person on the same browser starts clean. Theme and player volume are kept.

#### `authStore`

- `setTokens(access, refresh)`: called after a refresh.
- `setUser(user)`: called after sign-in.
- `logout()`: tells the server to revoke the token, clears the store and the query cache, and clears user state.
- `isAuthenticated()`: true if any token exists.
- Helpers: `useIsVisitor()`, `useIsAdmin()`, `useCanWrite()`.

#### `uiStore`

The largest store (`frontend/src/stores/uiStore.ts`, about 1,000 lines). Main parts:

- **Selection:** `setSelectedEntry(id)` opens the reader (and closes the sidebar on phones). `setActivePanel(panel)` switches the main panel. `setActiveReaderPanel(panel)` opens a reader side panel: `"intel" | "ai" | "notes" | "tag" | "create_entity" | "add_alias" | "link_entity" | null`.
- **View:** `viewMode` (`compact`, `expanded`, `magazine` or `table`; default `magazine`), `sortOrder` (including `radar`), `showUnreadOnly`, `markReadOnScroll`.
- **Reader typography:** `readerFontSize` 13, 14, 15, 16, 18 or 20 px (default 15); `readerLineHeight` 1.4 to 2.0 (default 1.7); `readerMaxWidth` 600, 720, 860, 1000 or unlimited (default 1000).
- **Copilot dock:** `copilotOpen`, `copilotCollapsed`, `copilotWidth` (the last two saved), `openCopilotWith(seed)` to open it with an entity, entry or campaign in context and an optional first question, and `toggleCopilot()`.
- **Dashboard lock:** `dashboardLocked` (default on), so widgets can't be dragged by accident.
- **Tables:** `tables[tableId]` holds each `DataTable`'s columns, widths, order, filters and sort.

**Table layouts.** `components/table/defaultLayouts.ts` holds the starting column layout for each table. `DataTable` uses it for any column the user hasn't changed. The column part of `tables` is also saved on the user's profile as the `table_layouts` setting. `useTableLayoutSync` (mounted in `App.tsx`) loads it, keeps the newest edit per table, and saves changes back with `PATCH /api/auth/me/settings`. Filters and sort stay on the device. `tablesOwnerId` records whose layouts are stored, so a second account on the same browser doesn't inherit them. A column marked `sticky: "right"` (the actions column) always stays last.

#### `intelStore`

`setActiveSection(section)` switches the Workbench section (such as `threat_actors` or `rules`). Recent pivots and searches are short rolling lists. The Workbench menu's open/closed state for the whole sidebar is `uiStore.sidebarCollapsed`, because the app sidebar *is* the Workbench menu in Workbench mode.

#### `playerStore`

Two modes:
- **Audio:** a queue of tracks with a `kind` of `"podcast"` or `"tts"`. Read-aloud uses server-side Piper speech (`useTts.ts` asks for the audio, waits until the MP3 is ready, then plays it here). `play(track)`, `playNext()`.
- **Speech:** the browser's own speech, paragraph by paragraph, used when Piper fails. `playSpeech(track)`, and `setSpeechWord(start, length)` to highlight the current word (`SpeechHighlighter`).

#### `triageViewStore`

A local copy of the dashboard view (widget layout, collapsed state, time range). The real copy is the `triage_view` user setting. The store gives the page an instant value and keeps edits safe across a reload while a save is in progress. `viewOwnerId` stops one account's view being saved onto another's.

## Server State Management

TanStack Query (`@tanstack/react-query`) handles all server data, using the client in `frontend/src/queryClient.ts`.

### Query Configuration

- **Stale time:** 30 seconds.
- **Retry:** once; never for 401, 403 or 429.
- **Refetch on window focus:** off.
- **After a change:** mutations invalidate the queries they affect, by key.

### Infinite Query Pattern

Long lists use `useInfiniteQuery` with cursor paging. From `useEntries.ts`:

```typescript
export function useEntries(filters: EntryFilters, { enabled = true } = {}) {
  return useInfiniteQuery({
    enabled,
    queryKey: ["entries", filters],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, string | boolean | undefined> = {
        ...filters,
        limit: String(currentReadingPrefs().entries_per_page),
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

Page size comes from the user's reading preferences: 25, 50 or 100 (default 50).

### Mutation & Cache Invalidation

`useMarkRead()` and `useMarkUnread()` update the cache *before* the server answers (an optimistic update). They flip the entry's read flag in every cached list and in the open reader, drop it from lists filtered to unread, and undo the change if the request fails. A debounced refetch then syncs with the server, so fast scrolling doesn't flood the API. For a visitor they do nothing.

## Theming System

**Files:** `frontend/src/index.css`, `frontend/src/hooks/useThemes.ts`, `frontend/src/utils/entityTheme.ts`, `frontend/src/utils/colorSchemes.ts`.

### CSS Variables Architecture (index.css)

Themes are sets of CSS variables on `:root`:

- **Base colors:** `--bg-primary`, `--bg-secondary`, `--bg-tertiary`, `--text-primary`, `--text-secondary`, `--text-muted`, `--border`.
- **Area accents:** `--accent-feeds`, `--accent-intel`, `--accent-detect`, `--accent-dash`, each with a lighter `*-bg` version.
- **Entity colors:** `--entity-actor`, `--entity-malware`, `--entity-cve`, `--entity-ttp`, `--entity-vendor`, `--entity-product` and more. Read them with `getEntityColor(type)` in `entityTheme.ts`.
- **Elevation:** shadows `--elevation-0` to `--elevation-3`.
- **Heatmap:** `--heatmap-empty` to `--heatmap-5`.
- **Severity:** `--severity-critical` to `--severity-info`.

`utils/colorSchemes.ts` holds the shared badge colors: `getTLPColor()` (TLP:CLEAR, GREEN, AMBER, AMBER+STRICT, RED) and `getSeverityColor()`, which reads the `--severity-*` variables.

### Runtime Theme Switching

`applyTheme(theme)` in `useThemes.ts`:

1. Sets every CSS variable on `:root`.
2. Picks readable text colors using WCAG luminance (light text on dark backgrounds, dark on light).
3. Makes hover colors if the theme has none.
4. Updates the favicon and the browser theme color.
5. Saves the theme to localStorage so it loads instantly next time.

### useAutoTheme Hook

When the app loads, it picks a theme in this order:
1. The user's own theme.
2. The admin's instance default (`is_default`).
3. The theme saved in localStorage.
4. "GitHub Dark".

Signed-out pages use the instance default from the public `/themes/default` endpoint.

## Component Library

Most components sit directly in `src/components/`, each with its own `.module.css`. Bigger areas have subfolders. The groups below are by purpose, not folder.

### Core Layout Components

- **Sidebar:** has a Reading / Workbench switch at the top. Reading shows categories, feeds, folders (starred, bookmarked, watched, today, last 24 hours, this week), a Priority Queue chip, links and saved searches. Workbench shows `WorkbenchNav`, the Workbench menu.
- **EntryList:** a virtualized list (only on-screen rows are drawn, via `@tanstack/react-virtual`), with day dividers that show AI daily summaries (`DayDividerSummary`) and entity chips (`DayIntelChips`).
- **EntryReader:** the article, its side panels, a text-selection menu, entity highlighting and read-aloud.
- **AppHeader:** logo, search and user menu.
- **ResizeHandle:** drag handles between panels.
- **primitives/:** shared building blocks: `PageHeader`, `Segmented`, `Panel`, `Chip`, `Hint`, `FacetSection`, `RailToggle`, `MobileNavSheet`, `Spinner`.
- **table/DataTable:** the shared table used by the entry list's table view and the Workbench entity tables.

### Global Copilot Dock

- **CopilotDockPanel:** a resizable dock on the right for signed-in users, opened with `Cmd/Ctrl+Shift+K` or the header button. It streams answers (`streamCopilotChat` in `useAI.ts`) and shows:
  - **ToolTraceChip:** each IntelFeed lookup the copilot makes.
  - **ConfirmCard:** a proposed change, which runs only if you confirm.
  - **ContextPill:** the context taken from the current page (`useCopilotContext`), or the one passed by an "Ask Copilot" button.
  - **SlashCommandMenu:** `/` commands (`copilotCommands.ts`).
- Past conversations come from `useConversations`. A conversation can be shared read-only (`POST /ai/conversations/:id/share` → `/shared/copilot/:token`).
- **CopilotAuthCard** and **CopilotReauthModal:** sign-in status and re-auth for the Claude Code provider, on Settings → AI Configuration. Admins see a banner in the dock when that sign-in has expired.
- Copilot spending shows on the **Cost** tab of Settings → AI Configuration.

### Search Components

There is one search box and one results page. `HeaderSearch` is the box; `/search` (SearchPage) is the only place results appear, on every screen size.

- **HeaderSearch:** the search field. Its `in:` chip sets the scope (Tab cycles `everything` → `workbench` → `feeds`). It suggests completions from `/search/autocomplete` or the local entity list. Typing goes to `/search`.
- **search/queryFields.ts:** the query language as data: fields, known values, hints, examples and colors. The syntax help, autocomplete and completion list all read from it.
- **SearchPage** (`pages/SearchPage.tsx`): owns the query, scope, filters and a reader pane. Its filter rail is a second sidebar inside the page.
- **search/SearchFacetSidebar:** filters for scope, entity type (with counts), match type, and entry fields (date, read state, feed, content type, tags, media, language). Entry filters are written into the query as `field:value`, so you can see, edit and save them.
- **search/SearchResults:** direct matches first, then mentions grouped by type, then articles (shared `EntryRow`). Also holds saved and recent searches, the query builder and syntax help.
- **search/EntityResults:** groups, labels and click targets for every result type, including notes. An entity note opens `/workbench/{type}/{id}?tab=notes`; an article note opens the reader's notes panel; a standalone note opens the notes browser filtered to it.
- **QueryBuilder:** helps build advanced queries.
- **CommandPalette:** the `Cmd+K` action menu.

The `in:` scope controls content only: `feeds` shows articles, `workbench` shows entities, `everything` shows both. It starts from the page you came from.

**On phones** the filter rail opens as a sheet from a Filters button, and the reader opens full screen.

Full query syntax: [query-language.md](query-language.md).

### Intelligence Components

- **entityProfile/:** the config-driven profile used by `EntityProfilePage`: `ProfileHeader`, `ProfileTabs` and `tabs/`, `EntityActionsMenu` (watch, convert, merge, export, delete), `EntityEditModal`, `IdentityFields`, `SignalBadges`, `ActivityFeed` and others, all driven by `entityProfileConfig.tsx`.
- **EntityActionsMenu** is shared by the profile header and each Workbench table row. In a row it adds Open profile and Edit, loads its data only after the row's ⋯ is clicked, and draws its popovers on `document.body` (a virtualized row's CSS `transform` would otherwise break fixed positioning).
- **EntityEditModal** puts a profile's editable fields in one form for editing from a table. It sends only the fields you changed, so values the table didn't load can't be wiped. Mitigations can't be edited this way.
- **EntityGraph:** the relationship graph, a custom SVG drawing with its own layout code (`entityGraphLayout.ts`).
- **EntityTableSection:** the sortable, filterable Workbench tables. Adds relationship and coverage columns and a pinned actions column, plus Export, Merge and Delete for checked rows.
- **EntityMergeSelectionModal:** merges the checked rows into one (default: the one with the most articles) with `POST /entities/{type}/merge`.
- **EntityPopover**, **EntityActionMenu**, **EntityMergeModal**, **EntityMergeIntoModal:** hover cards, actions and merge flows.
- **CreateEntityPanel**, **AddAliasPanel**, **LinkEntityPanel:** create an entity, add an alias, or link selected text to an entity.
- **entityProfile/ContextPanel:** the profile's Context section, the first row of the Overview: each enrichment source's facts, its last answer and freshness, Refresh and per-source ↻ buttons, and CVSS by source on a CVE.
- **engine/EnrichmentConsole:** Settings → Engine → Enrichment: every source's status, limits, queue, fill rates and jobs, plus the global pause.
- **AttackMatrixSection:** the ATT&CK matrix with rule coverage per technique.

### Reader Experience Components

- **SafeHTML:** renders article HTML through DOMPurify. It marks its wrapper `data-untrusted-content`.
- **ExternalLinkGuard** (with `ExternalLinkModal` and `utils/externalLinks.ts`): one click listener, mounted in `GlobalModals`, that asks before opening off-site links from untrusted content. Preferences and trusted hosts are in `user.settings` (`external_link_mode`, `external_link_trusted_hosts`).
- **ReaderTypography:** font size, line height and width controls.
- **FindInArticle:** find text in the article.
- **AudioPlayer:** playback controls, queue, speed and volume.
- **YouTubePlayer:** embedded video with transcript.
- **SpeechHighlighter:** highlights the word being read aloud.
- **EntryIntelBadges:** entity count badges.
- **InlineEntityHighlighter:** highlights entities in the article.

### Notes Components

- **NoteBrowser:** the full notes view in MainLayout (`activePanel === "notes"`).
- **NoteCard** and **NoteBody:** read-only notes in Markdown (a single line break shows as a line break).
- **InlineNoteEditor:** the note editor.
- **EntryNotePanel:** the reader's notes panel.
- **EntityNotesSection:** notes on entity profiles (`useEntityNotes`).

### Triage Components

- **triage/TriageControls:** filters and time range for the Dashboard.
- **triage/corrEventCards:** correlation event cards, used by the Dashboard and the Priority Queue.

### Automation Components

In `components/automation/`:
- **FlowBuilder:** the no-code rule editor (trigger, filter, action and fork nodes).
- **TemplateGallery:** ready-made rule templates.
- **ImportExportDialog:** import and export rules as YAML or JSON.
- **flowSerializer.ts:** converts between the node graph and JSON.

### Widget System

**Location:** `frontend/src/components/widgets/`.

`registry.ts` lists 51 widget types (5 are hidden from the picker but still render on boards that have them). Each `WidgetDefinition` has:

```typescript
interface WidgetDefinition {
  type: string;            // stable ID saved in dashboards; never rename
  label: string;
  description: string;
  defaultW: number;        // default grid width
  defaultH: number;        // default grid height
  component: ComponentType<WidgetComponentProps>;
  configPatch?: WidgetConfig;          // defaults merged under the user's config
  configFields?: WidgetConfigField[];  // shows the settings gear
  hidden?: boolean;                    // left out of the picker
}
```

- **WidgetRenderer:** draws a widget by type.
- **WidgetPicker:** adds widgets to a board.
- **WidgetSettingsPopover:** edits a widget's `configFields`.
- **DashboardTabs:** the board tabs.

Examples: `OverviewWidget`, `FeedActivityChart`, `NewActorsWidget`, `DetectionCoverageWidget`, `AttackCoverageGapWidget`, `CorrelationEventsWidget`, `IntelVelocityWidget`, `MorningBriefingWidget`, `RansomwarePulseWidget`, `KEVMatchesWidget`.

### Detection Rule Components

- **RuleBuilderShell:** the rule editor layout (editor and preview).
- **CodeMirrorEditor:** the code editor with syntax highlighting.
- **RuleEntryCard:** a rule matched against an article.

### Settings & System Components

- **SystemSettings:** renders system settings, filtered by group or key. Used across Settings and the Engine console.
- **ThemeEditor:** create and edit themes with a live preview.
- **AISettings:** the AI Configuration tabs: Providers, Prompts (`PromptWorkspace`), User keys and Cost. Includes `CopilotAuthCard`.
- **UserKeysSection:** the User keys tab: whether people may use their own keys (Off, Optional, Required), allowed key types, private addresses, limits, which tasks may use personal keys, and everyone's keys.
- **MyAISection:** Settings → My AI: this month's spend, your own keys, which key and model each task uses, the fallback switch and your cap. `utils/aiProvenance.ts` holds the wording for why a fallback happened.
- **engine/EngineSection:** the Settings → Engine console (`/settings?section=engine`): one table card (entries, links, relationships, Review, stage settings) and the Jobs, Feeds, Plans, Enrichment, Publishing and Maintenance screens. Old `?tab=` and `?section=` links still open the right screen.
- **TagManager:** Settings → Tags: rename, recolor, merge and delete tags. **TagPicker** is the tag dropdown used in the reader, the report wizard and automation.
- **TelegramSection** (in `SettingsPage.tsx`): admin steps for Telegram setup.

## Page Components & Routes

In `frontend/src/pages/`:

- **MainLayout.tsx** (loaded up front): the reader. Also serves `/priority-queue`.
- **SidebarLayout.tsx** (loaded up front): the tool-page frame.
- **WorkbenchPage.tsx:** the entity browser. Also exports `WorkbenchLayout` and hosts the glossary and detection workbench as sections.
- **EntityProfilePage.tsx:** one profile page for every entity type and campaigns.
- **DashboardPage.tsx:** the Workbench dashboard (widget boards via `useDashboards`).
- **ThreatsPage.tsx:** `/workbench/threats`, ranked by story. Its Vulnerabilities tab uses `FollowView` from `ExposurePage.tsx`.
- **ExposureBuilderPage.tsx:** `/workbench/report/exposure`.
- **SearchPage.tsx:** `/search`.
- **DocumentationPage.tsx:** in-app docs (`useDocumentation`, with `MermaidDiagram` for diagrams).
- **AutomationPage.tsx:** automation rules.
- **DetectionWorkbenchPage.tsx**, **GlossaryPage.tsx:** shown inside the Workbench.
- **RuleDetailPage.tsx:** one rule, its versions and tests.
- **SettingsPage.tsx:** settings sections in three groups. You: Account, Appearance, My AI, Reading, Tags. Connect: Claude Code Skill, Feeds & Export, Telegram. Administration (admins only): AI Configuration, Engine, Logs, System, Users.
- **CampaignsPage.tsx:** the campaign list.
- **ReportBuilderPage.tsx:** write a report.
- **LoginPage.tsx**, **RegisterPage.tsx**, **SharedEntryPage.tsx**, **SharedCopilotPage.tsx:** public pages.

`OnboardingWizard` (`components/onboarding/`) is a modal, not a page.

## Hooks (Custom React Hooks)

`frontend/src/hooks/` has 88 modules. Most wrap TanStack Query for one area of the API. A few to know:

### Data Fetching Hooks

- **useEntries(filters)**, **useEntry(id)**, **useEntriesCount(filters)** (`useEntries.ts`).
- **useFeeds()** (`useFeeds.ts`).
- **useIntelligence.ts:** per-entry entities (`useEntryTTPs`, `useEntryCVEs`, `useEntryThreatActors`, …) and on-demand extraction (`useExtractTTPs`, `useExtractCVEs`, `useExtractThreatActors`, `useExtractMalware`, `useExtractCountries`, `useExtractMitigations`, `useExtractTools`).
- **useCorrelation.ts:** `usePivot`, `useEntityGraph`, `useEntityTimeline`, `useEntitySearch`, `useDetectionSummary`.
- **useUnifiedSearch(query, opts):** the search page's data, `POST /search/unified`. `opts` takes `limit`, `offset`, `entityLimit` (server default 200) and `entityGroupLimit` (rows per type, server default 25). SearchPage passes `entityGroupLimit: 500` so its filter counts cover everything.
- **useSearchAutocomplete(query):** completions for `HeaderSearch`.
- **useSearch(filters):** `POST /search/advanced` with a filter object, for saved searches. Not used by the search page.
- **useCampaigns()**, **useDetectionRules(filters)**, **useDashboards()**.
- **usePlayback.ts:** podcast and media progress.
- **useWidgetData.ts**, **useAnalytics.ts** and the `useWidget*Data.ts` files: dashboard widget data.

### Mutation Hooks

- **useMarkRead() / useMarkUnread()**, **useToggleStar() / useToggleBookmark()**.
- **useAddTagsToEntry() / useRemoveTagFromEntry() / useBulkTag()**; **useCreateTag() / useUpdateTag() / useMergeTags() / useDeleteTag()** for Settings → Tags.
- **useCreateDetectionRule() / useValidateRule() / useToggleRuleStatus()**; **useDetectionRuleVersions() / useRollbackVersion() / useVersionDiff()**.
- **useAddFeed() / useUpdateFeed() / useDeleteFeed() / useRefreshFeed()**.

### UI & Interaction Hooks

- **useIsMobile()**, **useMediaQuery(query)**.
- **useSwipe(config)**, **useLongPress()**, **usePullToRefresh(callback)**: touch gestures.
- **useFocusTrap(ref)**: keeps focus inside a modal.
- **useUndoableDelete(onDelete)**: delete with an undo toast.

### Specialized Hooks

- **useThemes()**, **useAutoTheme()**.
- **useSSE()**: the live-event connection (mounted once in `App.tsx`).
- **useTableLayoutSync()**, **useReadingPrefsSync()**: sync preferences with the user profile.
- **useIngest.ts:** manual upload batches.
- **useJobSchedules()**: scheduled jobs.
- **useGlobalShortcuts()**: app-wide shortcuts.
- **useCopilotAuthStatus() / useStartCopilotAuth() / useSubmitCopilotAuthCode()**: copilot sign-in.
- **useCopilotContext()**: the copilot's context from the current page.
- **useDailySummary(dayKey) / useGenerateDailySummary()**: the AI daily summaries on day dividers.
- **useTts.ts:** server-side read-aloud.

## Utilities

`frontend/src/utils/` has 44 helper modules. Some common ones:

### `entityTheme.ts`

Colors, labels and icons for entity types:

```typescript
getEntityColor(type: string): string        // hex color
getEntityCssVar(type: string): string       // CSS variable reference
getEntityLabel(type: string): string        // singular label
getEntityPluralLabel(type: string): string  // plural label
getEntityIcon(type: string): string         // Lucide icon name
getEntityTheme(type: string): EntityTheme   // all of the above
```

### `queryParser.ts`

Parses the search language into a tree (`TextNode | FieldNode | BoolNode | NotNode`):

```typescript
parseQuery(query: string): ASTNode
extractFilters(node: ASTNode): ParsedFilter[]   // filters for API params
getTokenAtCursor(query, cursorPos): CursorToken // for autocomplete
removeFilterFromQuery(query, filterRaw): string // for removing a filter chip
```

Example: `feed:xyz title:"New APT" is:starred after:2024-01-01`. Full grammar: [query-language.md](query-language.md).

### Others

- **colorSchemes.ts:** `getTLPColor(tlp)`, `getSeverityColor(severity)`.
- **pivotLinks.ts:** `getPivotLinks(type, value)`, links to a profile, a search, or outside references such as MITRE and NVD.
- **dashboardTemplates.ts:** `DASHBOARD_TEMPLATES`, preset widget layouts on the Dashboard.
- **groupEntries.ts:** `groupConsecutiveEntries()`, folds runs of entries from the same feed into one group.
- **threads.ts:** flattens Priority Queue rows and story threads for display.
- **aiProvenance.ts:** wording for which AI key answered and why.

## Testing

### Unit & Component Tests (Vitest + RTL)

Tests live in `__tests__/` folders next to the code. Run them in `frontend/`:

```bash
pnpm test          # run once
pnpm test:watch    # watch mode
```

`frontend/src/test/setup.ts` (Vitest config is the `test` block in `vite.config.ts`):
- jsdom, with global test functions.
- An in-memory `localStorage`, because jsdom's breaks Zustand `persist`.
- A `window.matchMedia` mock.
- Plain (non-hashed) CSS Module class names, so tests can find them.
- At most 2 worker processes, to save memory.

Tests mock hooks or the Axios client with `vi.mock` (no MSW). Example: `components/__tests__/Sidebar.test.tsx`.

### End-to-End Tests (Playwright)

`frontend/tests/e2e/` runs against a running dev stack:
- **auth.spec.ts:** register, sign in, protected routes.
- **feeds.spec.ts:** feed list, open an entry, mark read.
- **relationships.spec.ts:** the relationship browser and graph.

Config: `frontend/playwright.config.ts` (base URL `localhost:3001`, 1 worker, 2 retries in CI). E2E tests are not run in CI.

```bash
pnpm exec playwright install chromium   # once
pnpm exec playwright test
```

## Build & Optimization

**Config:** `frontend/vite.config.ts`.

### Code Splitting

`manualChunks` (the function form, which Vite 8 requires) makes these shared bundles:
- `vendor-react`: React, React DOM, React Router DOM
- `vendor-tanstack`: TanStack Query
- `vendor-misc`: Zustand, Axios, DOMPurify

Each lazy-loaded page gets its own bundle too.

### Development Server

- Port 3000 (`pnpm dev`). In `docker-compose.dev.yml` it is published on 3001.
- Sends `/api`, `/docs`, `/redoc` and `/openapi.json` to `http://localhost:8000`, or to `VITE_API_URL` if set.
- Hot reload is on. The `.git` folder is not watched.

### Build Output

- No source maps (`sourcemap: false`).
- The build stamp (version, commit, build time) comes from build args, `git`, or the mounted `.git` folder, in that order, and shows in the footer.

## Conventions & Best Practices

### Naming Conventions

- **Components:** PascalCase (`EntryReader`).
- **Hooks:** `use` + camelCase (`useEntries`).
- **Utilities:** camelCase (`getEntityColor`).
- **Stores:** `use…Store` (`useUIStore`).
- **Event props:** `on…` (`onItemClick`).

### CSS Module Usage

Each component has its own `.module.css` file:

```typescript
// EntryReader.tsx
import styles from "./EntryReader.module.css";

export function EntryReader({ entryId }: EntryReaderProps) {
  return <div className={styles.root}>...</div>;
}
```

Colors come from the global CSS variables on `:root`. Don't hard-code colors.

### Error Handling Pattern

Failed queries and mutations show a toast automatically (see [Error Handling](#error-handling)). Handle an error in the component only when the page needs to show something specific.

### Accessibility

- Use real elements (`<button>`, `<nav>`, `<article>`).
- Give custom widgets ARIA roles (`role="dialog"`, `role="listbox"`).
- Everything should work from the keyboard (Tab, Enter, Escape, arrows).
- Themes keep text contrast at WCAG AA (`contrastText()`).

### Performance Optimization

- Long lists and tables are virtualized with `@tanstack/react-virtual`.
- `useMemo` for expensive work such as grouping.
- Pages load lazily, and shared libraries are in separate bundles.
- The 30-second stale time avoids repeat requests.
- Search input and drag handlers are debounced.
- A service worker is registered in `main.tsx`.

### Checks before you push

Run these in `frontend/`. CI runs the same three:

```bash
pnpm lint
pnpm build   # also type-checks
pnpm test
```

Pushing to `main` deploys: the production host runs `update.sh` every few minutes. See [operations.md](operations.md).
