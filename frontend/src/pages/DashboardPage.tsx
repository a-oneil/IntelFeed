import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { Responsive, WidthProvider, type Layout, type LayoutItem } from "react-grid-layout/legacy";
import "react-grid-layout/css/styles.css";
import {
  useDashboards,
  useDashboard,
  useCreateDashboard,
  useSeedDefaultDashboards,
  useUpdateDashboard,
  useDeleteDashboard,
  useReorderDashboards,
  useAddWidget,
  useUpdateWidget,
  useRemoveWidget,
  useUpdateLayout,
} from "@/hooks/useDashboards";
import WidgetRenderer from "@/components/widgets/WidgetRenderer";
import WidgetPicker from "@/components/widgets/WidgetPicker";
import WidgetSettingsPopover from "@/components/widgets/WidgetSettingsPopover";
import DashboardTabs from "@/components/widgets/DashboardTabs";
import { getWidgetDefinition } from "@/components/widgets/registry";
import { DASHBOARD_TEMPLATES } from "@/utils/dashboardTemplates";
import { TriageControls, TriageActions } from "@/components/triage/TriageControls";
import { useTriageView } from "@/hooks/useTriageView";
import { useUIStore } from "@/stores/uiStore";
import { scalePx } from "@/utils/uiScale";
import { PageHeader } from "@/components/primitives";
import styles from "./DashboardPage.module.css";

const ResponsiveGridLayout = WidthProvider(Responsive);
const ROW_HEIGHT = scalePx(80);
const COLS = 12;
const TRIAGE_PREFIX = "__triage__/";
/** Which board tab is selected. Board ids are server-side; this is just a pointer. */
const ACTIVE_BOARD_KEY = "intelfeed-active-dashboard";

/* ── Page ── */

export function DashboardPage() {
  const [showPicker, setShowPicker] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [settingsWidgetId, setSettingsWidgetId] = useState<string | null>(null);

  // Layout lock: keeps a stray touch on mobile from dragging or resizing
  // widgets. Persisted per device via uiStore.
  const dashboardLocked = useUIStore((s) => s.dashboardLocked);
  const toggleDashboardLocked = useUIStore((s) => s.toggleDashboardLocked);

  // ── Triage view (global range shared with the correlation browser widget) ──
  const { view, setGlobalRange } = useTriageView();

  // ── Dashboards: every `__triage__/`-prefixed board is a tab ──

  const { data: dashboardsData } = useDashboards();
  const boards = useMemo(() => {
    const items = dashboardsData?.items ?? [];
    return items
      .filter((d) => d.name.startsWith(TRIAGE_PREFIX))
      .sort(
        (a, b) =>
          (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.created_at.localeCompare(b.created_at),
      );
  }, [dashboardsData]);

  const [activeBoardId, setActiveBoardId] = useState<string | null>(
    () => localStorage.getItem(ACTIVE_BOARD_KEY),
  );

  // Keep the selection valid: fall back to the first board whenever the stored
  // id points at a board that no longer exists (deleted here or elsewhere).
  const dashboardId = useMemo(() => {
    if (boards.length === 0) return null;
    const match = boards.find((b) => b.id === activeBoardId);
    return match ? match.id : boards[0].id;
  }, [boards, activeBoardId]);

  useEffect(() => {
    if (dashboardId) localStorage.setItem(ACTIVE_BOARD_KEY, dashboardId);
  }, [dashboardId]);

  const createDashboard = useCreateDashboard();
  const seedDefaults = useSeedDefaultDashboards();
  const updateDashboard = useUpdateDashboard();
  const deleteDashboard = useDeleteDashboard();
  const reorderDashboards = useReorderDashboards();
  const addWidget = useAddWidget();
  const updateWidget = useUpdateWidget();
  const removeWidget = useRemoveWidget();
  const updateLayout = useUpdateLayout();
  const { data: dashboard } = useDashboard(dashboardId);

  // Widget time range — shares the view's global range so the dashboard grid
  // stays in sync with the correlation browser.
  const widgetTimeRange = view.global_range;
  const customStart = view.global_custom_start ?? undefined;
  const customEnd = view.global_custom_end ?? undefined;

  // Seed the instance's default boards once, the first time we see a user with
  // none of their own. The ref guards against double-seeding across rerenders;
  // the endpoint is idempotent regardless.
  const autoCreateRef = useRef(false);
  useEffect(() => {
    if (!dashboardsData) return;
    if (dashboardsData.items.length > 0) return;
    if (autoCreateRef.current) return;
    autoCreateRef.current = true;
    seedDefaults.mutate();
  }, [dashboardsData, seedDefaults]);

  const handleCreateBoard = async (name: string) => {
    const created = await createDashboard.mutateAsync({ name: `${TRIAGE_PREFIX}${name}` });
    setActiveBoardId(created.id);
  };

  const handleRenameBoard = async (id: string, name: string) => {
    await updateDashboard.mutateAsync({ id, name: `${TRIAGE_PREFIX}${name}` });
  };

  const handleReorderBoards = (ids: string[]) => {
    reorderDashboards.mutate(ids);
  };

  const handleDeleteBoard = async (id: string) => {
    await deleteDashboard.mutateAsync(id);
    if (id === dashboardId) {
      const next = boards.find((b) => b.id !== id);
      setActiveBoardId(next?.id ?? null);
    }
  };

  // Widget grid layout
  const layout = useMemo<LayoutItem[]>(() => {
    if (!dashboard) return [];
    return dashboard.widgets.map((w) => ({
      i: w.id,
      x: w.position_x,
      y: w.position_y,
      w: Math.min(w.width, COLS),
      h: w.height,
      minW: 2,
      minH: 2,
    }));
  }, [dashboard]);

  // Grid config objects are memoized so an incidental re-render (background
  // refetch, SSE tick, etc.) doesn't hand react-grid-layout a fresh `layouts`
  // reference mid-drag — that reconciliation cancels an in-progress
  // drag/resize, which manifests as "can't resize widgets".
  const layouts = useMemo(() => ({ lg: layout, md: layout, sm: layout }), [layout]);
  const breakpoints = useMemo(() => ({ lg: 1200, md: 768, sm: 0 }), []);
  const cols = useMemo(() => ({ lg: COLS, md: COLS, sm: 1 }), []);

  const handleAddWidget = async (widgetType: string, title: string, width: number, height: number) => {
    if (!dashboardId) return;
    const maxY = dashboard?.widgets?.reduce((max, w) => Math.max(max, w.position_y + w.height), 0) ?? 0;
    await addWidget.mutateAsync({
      dashboardId,
      widget_type: widgetType,
      title,
      width,
      height,
      position_x: 0,
      position_y: maxY,
    });
    setShowPicker(false);
  };

  // Templates seed a NEW board rather than wiping the current one — with tabs,
  // there's no reason for applying a template to be destructive.
  const handleApplyTemplate = async (templateIdx: number) => {
    const template = DASHBOARD_TEMPLATES[templateIdx];
    if (!template) return;
    const created = await createDashboard.mutateAsync({ name: `${TRIAGE_PREFIX}${template.name}` });
    for (const w of template.widgets) {
      await addWidget.mutateAsync({
        dashboardId: created.id,
        widget_type: w.widget_type,
        title: w.title,
        width: w.width,
        height: w.height,
        position_x: w.position_x,
        position_y: w.position_y,
        config: w.config || {},
      });
    }
    setActiveBoardId(created.id);
    setShowTemplates(false);
  };

  const handleRemoveWidget = async (widgetId: string) => {
    if (!dashboardId) return;
    await removeWidget.mutateAsync({ dashboardId, widgetId });
  };

  const handleSaveWidgetConfig = async (widgetId: string, patch: Record<string, unknown>) => {
    if (!dashboardId || !dashboard) return;
    const widget = dashboard.widgets.find((w) => w.id === widgetId);
    await updateWidget.mutateAsync({
      dashboardId,
      widgetId,
      config: { ...(widget?.config ?? {}), ...patch },
    });
    setSettingsWidgetId(null);
  };

  // Persist layout only on intentional user drag/resize — NOT on responsive
  // breakpoint reflows, which would overwrite stored widths with narrow values.
  const handleUserLayoutChange = useCallback(
    (currentLayout: Layout) => {
      if (!dashboardId || !dashboard || currentLayout.length === 0) return;
      const layoutItems = currentLayout.map((item) => ({
        id: item.i,
        position_x: item.x,
        position_y: item.y,
        width: item.w,
        height: item.h,
      }));
      updateLayout.mutate({ dashboardId, items: layoutItems });
    },
    [dashboardId, dashboard, updateLayout],
  );

  return (
    <div className={styles.container}>
      {/* Board tabs and the global range are the dashboard's header controls;
          the widget actions are its header actions — same two slots as every
          other workbench route. */}
      <PageHeader
        title="Dashboard"
        flush
        className={styles.pageHead}
        actions={
          dashboardId ? (
            <TriageActions
              onAddWidget={() => setShowPicker(true)}
              onShowTemplates={() => setShowTemplates(true)}
              locked={dashboardLocked}
              onToggleLocked={toggleDashboardLocked}
            />
          ) : undefined
        }
        controls={
          <TriageControls
            view={view}
            onGlobalRangeChange={setGlobalRange}
            tabs={
              boards.length > 0 ? (
                <DashboardTabs
                  boards={boards.map((b) => ({ id: b.id, name: b.name.slice(TRIAGE_PREFIX.length) }))}
                  activeId={dashboardId}
                  onSelect={setActiveBoardId}
                  onCreate={handleCreateBoard}
                  onRename={handleRenameBoard}
                  onDelete={handleDeleteBoard}
                  onReorder={handleReorderBoards}
                  locked={dashboardLocked}
                />
              ) : undefined
            }
          />
        }
      />

      {/* ── Widget Area ── */}
      <div className={styles.widgetSection}>
        {dashboardId && dashboard && dashboard.widgets.length > 0 ? (
          <ResponsiveGridLayout
            key={dashboardId}
            className={styles.widgetGrid}
            layouts={layouts}
            breakpoints={breakpoints}
            cols={cols}
            rowHeight={ROW_HEIGHT}
            draggableHandle={`.${styles.dragHandle}`}
            onDragStop={(layout) => handleUserLayoutChange(layout)}
            onResizeStop={(layout) => handleUserLayoutChange(layout)}
            isResizable={!dashboardLocked}
            isDraggable={!dashboardLocked}
            compactType="vertical"
            margin={[12, 12]}
            /* react-grid-layout defaults containerPadding to `margin`, which
               inset the whole grid by 12px and left the widgets narrower than
               the controls bar directly above them. Zero it so both align. */
            containerPadding={[0, 0]}
          >
            {dashboard.widgets.map((widget) => {
              const def = getWidgetDefinition(widget.widget_type);
              const configFields = def?.configFields;
              return (
                <div key={widget.id} className={styles.widgetCell}>
                  <div className={styles.widgetCard}>
                    <div className={styles.widgetHeader}>
                      <div
                        className={`${styles.dragHandle} ${styles.dragArea} ${dashboardLocked ? styles.dragLocked : ""}`}
                      >
                        {!dashboardLocked && <span className={styles.dragGrip}>&#x2630;</span>}
                        <span className={styles.widgetTitle}>
                          {widget.title || widget.widget_type.replace(/_/g, " ")}
                        </span>
                      </div>
                      {/* Settings + remove sit OUTSIDE the drag handle, or
                          react-grid-layout swallows the click as a drag. */}
                      {configFields && configFields.length > 0 && (
                        <button
                          onClick={() =>
                            setSettingsWidgetId((id) => (id === widget.id ? null : widget.id))
                          }
                          className={styles.removeBtn}
                          title="Widget settings"
                          aria-label="Widget settings"
                        >
                          ⚙
                        </button>
                      )}
                      <button onClick={() => handleRemoveWidget(widget.id)} className={styles.removeBtn} title="Remove widget">x</button>
                      {settingsWidgetId === widget.id && configFields && (
                        <WidgetSettingsPopover
                          fields={configFields}
                          config={widget.config as Record<string, unknown>}
                          onSave={(patch) => handleSaveWidgetConfig(widget.id, patch)}
                          onClose={() => setSettingsWidgetId(null)}
                        />
                      )}
                    </div>
                    <div className={styles.widgetBody}>
                      <WidgetRenderer widget={widget} timeRange={widgetTimeRange} timeRangeStart={customStart} timeRangeEnd={customEnd} />
                    </div>
                  </div>
                </div>
              );
            })}
          </ResponsiveGridLayout>
        ) : (
          <div className={styles.widgetEmpty}>
            <p>No widgets yet</p>
            <span>Add widgets or apply a template to get started.</span>
          </div>
        )}
      </div>

      {/* ── Widget Picker Modal ── */}
      {showPicker && (
        <WidgetPicker
          onAdd={handleAddWidget}
          onClose={() => setShowPicker(false)}
          timeRange={widgetTimeRange}
          timeRangeStart={customStart}
          timeRangeEnd={customEnd}
        />
      )}

      {/* ── Template Modal ── */}
      {showTemplates && (
        <div className={styles.templateOverlay} onClick={() => setShowTemplates(false)}>
          <div className={styles.templateModal} onClick={(e) => e.stopPropagation()}>
            <h3 className={styles.templateTitle}>Widget Templates</h3>
            <p className={styles.templateDesc}>Apply a pre-configured set of widgets</p>
            <div className={styles.templateGrid}>
              {DASHBOARD_TEMPLATES.map((t, i) => (
                <button key={t.name} className={styles.templateCard} onClick={() => handleApplyTemplate(i)}>
                  <span className={styles.templateName}>{t.name}</span>
                  <span className={styles.templateInfo}>{t.description}</span>
                  <span className={styles.templateWidgets}>{t.widgets.length} widgets</span>
                </button>
              ))}
            </div>
            <button className={styles.templateClose} onClick={() => setShowTemplates(false)}>Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}
