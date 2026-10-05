import { lazy, Suspense } from "react";
import { Navigate, Route, Routes, useLocation, useParams } from "react-router-dom";
import { Toaster } from "sonner";
import { useAuthStore } from "@/stores/authStore";
import { useAutoTheme } from "@/hooks/useThemes";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useGlobalShortcuts } from "@/hooks/useGlobalShortcuts";
import { useSSE } from "@/hooks/useSSE";
import { useTableLayoutSync } from "@/hooks/useTableLayoutSync";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AudioPlayer } from "@/components/AudioPlayer";
import { OnboardingWizard } from "@/components/onboarding/OnboardingWizard";
import { ReportWizardModal } from "@/components/ReportWizardModal";
import { SendToReportModal } from "@/components/SendToReportModal";
import { GlobalModals } from "@/components/GlobalModals";
import { CopilotDockPanel } from "@/components/CopilotDockPanel";
import { RouteFallback } from "@/components/RouteFallback";

// Eager — always needed for the main feed view
import { MainLayout } from "@/pages/MainLayout";
import { SidebarLayout } from "@/pages/SidebarLayout";

// Lazy — loaded on demand per route
const LoginPage = lazy(() =>
  import("@/pages/LoginPage").then((m) => ({ default: m.LoginPage }))
);
const RegisterPage = lazy(() =>
  import("@/pages/RegisterPage").then((m) => ({ default: m.RegisterPage }))
);
const SettingsPage = lazy(() =>
  import("@/pages/SettingsPage").then((m) => ({ default: m.SettingsPage }))
);
const AutomationPage = lazy(() =>
  import("@/pages/AutomationPage").then((m) => ({ default: m.AutomationPage }))
);
const CampaignsPage = lazy(() =>
  import("@/pages/CampaignsPage").then((m) => ({
    default: m.CampaignsPage,
  }))
);
const WorkbenchPage = lazy(() =>
  import("@/pages/WorkbenchPage").then((m) => ({
    default: m.WorkbenchPage,
  }))
);
const WorkbenchLayout = lazy(() =>
  import("@/pages/WorkbenchPage").then((m) => ({
    default: m.WorkbenchLayout,
  }))
);
const EntityProfilePage = lazy(() =>
  import("@/pages/EntityProfilePage").then((m) => ({
    default: m.EntityProfilePage,
  }))
);
const RuleDetailPage = lazy(() =>
  import("@/pages/RuleDetailPage")
);
const ReportBuilderPage = lazy(() =>
  import("@/pages/ReportBuilderPage").then((m) => ({
    default: m.ReportBuilderPage,
  }))
);
const ExposureBuilderPage = lazy(() =>
  import("@/pages/ExposureBuilderPage").then((m) => ({
    default: m.ExposureBuilderPage,
  }))
);
const DashboardPage = lazy(() =>
  import("@/pages/DashboardPage").then((m) => ({
    default: m.DashboardPage,
  }))
);
const RegionsPage = lazy(() =>
  import("@/pages/RegionsPage").then((m) => ({
    default: m.RegionsPage,
  }))
);
const SharedEntryPage = lazy(() =>
  import("@/pages/SharedEntryPage").then((m) => ({
    default: m.SharedEntryPage,
  }))
);
const SharedCopilotPage = lazy(() =>
  import("@/pages/SharedCopilotPage").then((m) => ({
    default: m.SharedCopilotPage,
  }))
);
const ThreatsPage = lazy(() =>
  import("@/pages/ThreatsPage").then((m) => ({
    default: m.ThreatsPage,
  }))
);
const DocumentationPage = lazy(() => import("@/pages/DocumentationPage"));
const SearchPage = lazy(() =>
  import("@/pages/SearchPage").then((m) => ({ default: m.SearchPage }))
);

// Legacy /countries/:id → unified workbench profile.
function CountryRedirect() {
  const { id } = useParams<{ id: string }>();
  return <Navigate to={`/workbench/country/${id}`} replace />;
}

// Engine moved back into Settings > Administration. Keep the workbench URL
// working, query string and all, so old deep links resolve the right console
// state instead of landing on the Settings default pane.
function EngineRedirect() {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  if (!params.get("section")) params.set("section", "engine");
  return <Navigate to={`/settings?${params.toString()}`} replace />;
}

// Pre-2026-08 vocabulary: the threat_actor slug used to be "actor".
function LegacyActorRedirect({ base }: { base: string }) {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  return <Navigate to={`${base}/threat_actor/${id}${location.search}`} replace />;
}

/**
 * Legacy /intelligence/<type>/:id → the canonical /workbench/<type>/:id.
 *
 * These used to mount EntityProfilePage a second time, outside WorkbenchLayout.
 * That layout is the only host for the docked reader, so on the /intelligence
 * copy every article link on the profile (essential reading, latest
 * developments, the timeline) set the reader entry id and then nothing rendered
 * it — the click did visibly nothing. `entityProfilePath()` has emitted
 * /workbench/... for a while, so these paths only survive as old bookmarks:
 * redirecting is enough, and it keeps one mount point for the profile.
 */
function LegacyProfileRedirect({ type }: { type: string }) {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  return <Navigate to={`/workbench/${type}/${id}${location.search}`} replace />;
}

// The handbook was renamed to "documentation" — keep old links and bookmarks alive.
function HandbookRedirect() {
  const { "*": splat } = useParams();
  return <Navigate to={`/documentation/${splat || "README"}`} replace />;
}

// Legacy /triage → workbench dashboard, preserving any query params.
function TriageRedirect() {
  const location = useLocation();
  return <Navigate to={`/workbench/dashboard${location.search}`} replace />;
}

function HomeRedirect() {
  return <MainLayout />;
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuth = useAuthStore((s) => s.isAuthenticated());
  const user = useAuthStore((s) => s.user);
  if (!isAuth) return <Navigate to="/login" replace />;
  // Auto-open until they finish it — but a close counts too, otherwise every
  // hard refresh reopens the tour over a user who already dismissed it. Both
  // keys are cleared from Settings → Account.
  const onboarding = user?.settings as
    | { onboarding_completed?: boolean; onboarding_deferred_at?: string | null }
    | undefined;
  const showOnboarding =
    !!user && !onboarding?.onboarding_completed && !onboarding?.onboarding_deferred_at;
  return (
    <>
      {children}
      {showOnboarding && <OnboardingWizard />}
    </>
  );
}

export default function App() {
  useAutoTheme();
  useGlobalShortcuts();
  // One live-events connection per session, not per layout mount. It used to
  // live in MainLayout, so every trip between the feed reader and a
  // SidebarLayout route (search, settings, workbench) tore down the connection
  // and built a new one — six of those exhausted the browser's per-origin
  // connection pool and hung every request in the app. It also no-ops until
  // there is a token, so the login screen opens nothing.
  useSSE();
  // Table column layouts live on the user profile, not just this browser.
  useTableLayoutSync();
  const isMobile = useIsMobile();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated());

  return (
    <ErrorBoundary>
      <Toaster
        position={isMobile ? "top-center" : "bottom-right"}
        toastOptions={{
          style: {
            background: "var(--bg-primary)",
            color: "var(--text-primary)",
            border: "1px solid var(--border)",
          },
        }}
      />

      <AudioPlayer />
      <ReportWizardModal />
      <SendToReportModal />
      {/* Add-feed and the shortcut cheatsheet live here, not in a layout: the
          command palette opens them from anywhere, and add-feed used to render
          inside the sidebar, which hides it whenever the sidebar is collapsed. */}
      <GlobalModals />
      {/* App shell: routed content + the copilot dock as an in-flow flex
          sibling, so opening/collapsing the dock shifts content naturally
          (same mechanism as the sidebars) instead of overlaying it. */}
      <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
      {/* Outermost boundary — only the routes with no layout above them
          (login, register, shared pages) actually land here; the layouts
          carry their own so the shell survives a route swap. */}
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/shared/copilot/:token" element={<SharedCopilotPage />} />
          <Route path="/shared/:token" element={<SharedEntryPage />} />
          <Route
            element={
              <ProtectedRoute>
                <SidebarLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/settings" element={<SettingsPage />} />
            {/* Search is a route, not a panel: it carries its own facet rail
                and has to be reachable from the workbench and settings without
                displacing the feed reader. */}
            <Route path="/search" element={<SearchPage />} />
            <Route path="/automation" element={<AutomationPage />} />
            <Route path="/dashboards" element={<Navigate to="/workbench/dashboard" replace />} />
            <Route path="/intelligence" element={<Navigate to="/workbench/explore" replace />} />
            <Route path="/detection-workbench" element={<Navigate to="/workbench/explore" replace />} />
            <Route path="/campaigns" element={<CampaignsPage />} />
            <Route path="/intelligence/threat_actor/:id" element={<LegacyProfileRedirect type="threat_actor" />} />
            {/* Pre-2026-08 vocabulary; kept so existing links and bookmarks resolve. */}
            <Route path="/intelligence/actor/:id" element={<LegacyActorRedirect base="/workbench" />} />
            <Route path="/intelligence/malware/:id" element={<LegacyProfileRedirect type="malware" />} />
            <Route path="/workbench" element={<WorkbenchLayout />}>
              {/* The dashboard is the workbench landing page — index redirects to
                  its canonical /workbench/dashboard URL so it still opens first. */}
              <Route index element={<Navigate to="/workbench/dashboard" replace />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="engine" element={<EngineRedirect />} />
              <Route path="explore" element={<WorkbenchPage />} />
              <Route path="threats" element={<ThreatsPage />} />
              {/* Vendor Watch retired into the Threats page's Vulnerabilities tab. */}
              <Route path="exposure" element={<Navigate to="/workbench/threats?tab=vulns" replace />} />
              <Route path="triage" element={<Navigate to="/workbench/dashboard" replace />} />
              <Route path="threat_actor/:id" element={<EntityProfilePage slug="threat_actor" />} />
              <Route path="actor/:id" element={<LegacyActorRedirect base="/workbench" />} />
              <Route path="malware/:id" element={<EntityProfilePage slug="malware" />} />
              <Route path="cve/:id" element={<EntityProfilePage slug="cve" />} />
              <Route path="cwe/:id" element={<EntityProfilePage slug="cwe" />} />
              <Route path="ttp/:id" element={<EntityProfilePage slug="ttp" />} />
              <Route path="country/:id" element={<EntityProfilePage slug="country" />} />
              <Route path="sector/:id" element={<EntityProfilePage slug="sector" />} />
              <Route path="tool/:id" element={<EntityProfilePage slug="tool" />} />
              <Route path="mitigation/:id" element={<EntityProfilePage slug="mitigation" />} />
              <Route path="observable/:id" element={<EntityProfilePage slug="observable" />} />
              <Route path="vendor/:id" element={<EntityProfilePage slug="vendor" />} />
              <Route path="product/:id" element={<EntityProfilePage slug="product" />} />
              <Route path="campaign/:id" element={<EntityProfilePage slug="campaign" />} />
              <Route path="rules" element={<Navigate to="/workbench/explore?section=rules" replace />} />
              <Route path="rule/:id" element={<RuleDetailPage />} />
              <Route path="report/exposure" element={<ExposureBuilderPage />} />
              <Route path="report/new" element={<ReportBuilderPage />} />
              <Route path="report/:id" element={<ReportBuilderPage />} />
            </Route>
            <Route path="/triage" element={<TriageRedirect />} />
            <Route path="/atlas" element={<Navigate to="/workbench/dashboard" replace />} />
            <Route path="/countries/:id" element={<CountryRedirect />} />
            {/* Splat "" is the landing page (API references + docs copilot);
                any slug after it is a docs/ page. */}
            <Route path="/documentation/*" element={<DocumentationPage />} />
            <Route path="/handbook/*" element={<HandbookRedirect />} />
            <Route path="/regions" element={<RegionsPage />} />
            <Route path="/regions/:name" element={<Navigate to="/regions" replace />} />
            <Route path="/glossary" element={<Navigate to="/workbench/explore?section=glossary" replace />} />
            <Route path="/feed-health" element={<Navigate to="/settings?section=engine&tab=pipeline&stage=feeds" replace />} />
          </Route>
          <Route
            path="/feeds"
            element={
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          />
          {/* Priority Queue is the entry list + reader shell, pinned to the
              signal-engine "radar" sort — a second, ranked entry list. */}
          <Route
            path="/priority-queue"
            element={
              <ProtectedRoute>
                <MainLayout priorityMode />
              </ProtectedRoute>
            }
          />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <HomeRedirect />
              </ProtectedRoute>
            }
          />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          />
        </Routes>
      </Suspense>
        </div>
        {isAuthenticated && <CopilotDockPanel />}
      </div>
    </ErrorBoundary>
  );
}
