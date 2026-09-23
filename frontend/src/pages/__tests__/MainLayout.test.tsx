import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock react-router-dom
vi.mock("react-router-dom", () => ({
  useSearchParams: () => [new URLSearchParams(), vi.fn()],
}));

// Mock child components
vi.mock("@/components/Sidebar", () => ({
  Sidebar: () => <div data-testid="sidebar">Sidebar</div>,
}));
vi.mock("@/components/EntryList", () => ({
  EntryList: () => <div data-testid="entry-list">EntryList</div>,
}));
vi.mock("@/components/EntryReader", () => ({
  EntryReader: ({ entryId }: { entryId: string }) => (
    <div data-testid="entry-reader">EntryReader: {entryId}</div>
  ),
}));
vi.mock("@/components/AudioPlayer", () => ({
  AudioPlayer: () => <div data-testid="audio-player">AudioPlayer</div>,
}));
vi.mock("@/components/NoteBrowser", () => ({
  NoteBrowser: () => <div data-testid="note-browser">NoteBrowser</div>,
}));
vi.mock("@/components/KeyboardShortcutsHelp", () => ({
  KeyboardShortcutsHelp: () => <div data-testid="shortcuts-help">ShortcutsHelp</div>,
}));
vi.mock("@/components/CommandPalette", () => ({
  CommandPalette: () => null,
}));
vi.mock("@/components/AppHeader", () => ({
  AppHeader: () => <div data-testid="app-header">Header</div>,
}));
vi.mock("@/components/ResizeHandle", () => ({
  ResizeHandle: () => null,
}));

// Mock hooks
vi.mock("@/hooks/useSwipe", () => ({
  useSwipe: () => () => {},
}));

// Mock CSS module
vi.mock("./MainLayout.module.css", () => ({
  default: {
    layout: "layout",
    sidebar: "sidebar",
    collapsed: "collapsed",
    main: "main",
    entryList: "entryList",
    withReader: "withReader",
    reader: "reader",
    fullPanel: "fullPanel",
    withPlayer: "withPlayer",
  },
}));

// Mock hooks and stores
const mockUseSSE = vi.fn();
vi.mock("@/hooks/useSSE", () => ({
  useSSE: () => mockUseSSE(),
}));

vi.mock("@/hooks/useExport", () => ({
  exportEntry: vi.fn(),
}));

vi.mock("@/hooks/useEntries", () => ({
  useMarkRead: () => ({ mutate: vi.fn() }),
}));

const mockUIState = {
  sidebarCollapsed: false,
  readerOpen: false,
  selectedEntryId: null as string | null,
  activePanel: "entries" as string,
  setActivePanel: vi.fn(),
  setSelectedEntry: vi.fn(),
  setReaderOpen: vi.fn(),
  toggleSidebar: vi.fn(),
  sidebarWidth: 280,
  setSidebarWidth: vi.fn(),
  entryListWidth: 400,
  setEntryListWidth: vi.fn(),
  entryListCollapsed: false,
  setEntryListCollapsed: vi.fn(),
  markReadOnScroll: false,
  setSidebarCollapsed: vi.fn(),
  activeReaderPanel: null as string | null,
  setActiveReaderPanel: vi.fn(),
};

vi.mock("@/stores/uiStore", () => ({
  useUIStore: Object.assign(
    (selector: (s: typeof mockUIState) => unknown) => selector(mockUIState),
    { getState: () => mockUIState }
  ),
}));

vi.mock("@/stores/playerStore", () => ({
  usePlayerStore: (selector: (s: { currentTrack: null; mode: string; speechTrack: null; isPlaying: boolean }) => unknown) =>
    selector({ currentTrack: null, mode: "audio", speechTrack: null, isPlaying: false }),
}));

import { MainLayout } from "../MainLayout";

describe("MainLayout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUIState.sidebarCollapsed = false;
    mockUIState.readerOpen = false;
    mockUIState.selectedEntryId = null;
    mockUIState.activePanel = "entries";
  });

  it("renders sidebar and entry list", () => {
    render(<MainLayout />);

    expect(screen.getByTestId("sidebar")).toBeInTheDocument();
    expect(screen.getByTestId("entry-list")).toBeInTheDocument();
  });

  it("does not own the live-events connection", () => {
    render(<MainLayout />);

    // `useSSE` moved to App. Mounted here, every trip to a SidebarLayout route
    // (search, settings, workbench) tore the connection down and rebuilt it —
    // and the rebuild races its own unmount, leaking a permanently-CONNECTING
    // EventSource each time until the browser's per-origin connection pool is
    // exhausted and every request in the app hangs.
    expect(mockUseSSE).not.toHaveBeenCalled();
  });

  it("does not show reader when closed", () => {
    mockUIState.readerOpen = false;
    mockUIState.selectedEntryId = null;

    render(<MainLayout />);

    expect(screen.queryByTestId("entry-reader")).not.toBeInTheDocument();
  });

  it("shows reader when open with a selected entry", () => {
    mockUIState.readerOpen = true;
    mockUIState.selectedEntryId = "entry-123";

    render(<MainLayout />);

    const reader = screen.getByTestId("entry-reader");
    expect(reader).toBeInTheDocument();
    expect(reader).toHaveTextContent("EntryReader: entry-123");
  });

  it("does not show reader when readerOpen is true but no entry selected", () => {
    mockUIState.readerOpen = true;
    mockUIState.selectedEntryId = null;

    render(<MainLayout />);

    expect(screen.queryByTestId("entry-reader")).not.toBeInTheDocument();
  });

  it("shows notes panel when activePanel is notes", () => {
    mockUIState.activePanel = "notes";
    render(<MainLayout />);

    expect(screen.getByTestId("note-browser")).toBeInTheDocument();
    expect(screen.queryByTestId("entry-list")).not.toBeInTheDocument();
  });
});
