/**
 * Tests for `CommandPalette` (⌘K) — a *command* launcher only.
 *
 * The palette used to also search entities and entries against
 * /search/unified. That half is gone: looking things up belongs to the /search
 * route, and the palette only fuzzy-matches the static vocabulary in
 * `components/search/commands.ts`.
 *
 * Keyboard model pinned here: arrows CLAMP at 0 / len-1 (no wrap, no -1
 * deselect), the selection defaults to 0 so Enter always does something, Tab is
 * unhandled, and Escape is a single rung straight to onClose.
 */
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { User } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";
import { QUICK_ACTIONS } from "@/components/search/commands";
import { CommandPalette } from "@/components/CommandPalette";

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

// Kept mocked purely as a tripwire: nothing in the palette may reach for the
// server search again.
const unifiedSearchMock = vi.fn();
vi.mock("@/hooks/useUnifiedSearch", () => ({
  useUnifiedSearch: (...args: unknown[]) => unifiedSearchMock(...args),
}));

const RECENT_PAGES_KEY = "intelfeed-recent-pages";

const onClose = vi.fn();

function setRole(role: "admin" | "user") {
  useAuthStore.setState({
    user: {
      id: "u1",
      username: "tester",
      role,
      is_active: true,
      settings: {},
      theme_id: null,
      custom_css: null,
      last_login: null,
      created_at: "2026-01-01T00:00:00Z",
    } satisfies User,
  });
}

function renderPalette(open = true) {
  return render(
    <MemoryRouter initialEntries={["/feeds"]}>
      <CommandPalette open={open} onClose={onClose} />
    </MemoryRouter>,
  );
}

function typeQuery(value: string) {
  const input = screen.getByPlaceholderText(/Search commands/i);
  fireEvent.change(input, { target: { value } });
  return input;
}

/** Index of each string inside the rendered text, for order assertions. */
function orderOf(container: HTMLElement, texts: string[]): number[] {
  const all = container.textContent ?? "";
  return texts.map((t) => all.indexOf(t));
}

beforeEach(() => {
  navigateMock.mockReset();
  unifiedSearchMock.mockReset();
  onClose.mockReset();
  localStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
  useIntelStore.setState({ recentPivots: [], recentSearches: [], activeSection: "threat_actors" });
  useUIStore.setState({
    copilotOpen: false,
    addFeedOpen: false,
    ingestOpen: false,
    shortcutsHelpOpen: false,
  });
  setRole("admin");
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Mount / lifecycle
// ---------------------------------------------------------------------------

describe("CommandPalette lifecycle", () => {
  it("renders nothing while closed", () => {
    const { container } = renderPalette(false);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders a dialog with the command input when open", () => {
    renderPalette();
    expect(screen.getByRole("dialog", { name: "Command palette" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search commands/i)).toBeInTheDocument();
  });

  it("closes when the backdrop is clicked but not when the dialog is", () => {
    renderPalette();
    const dialog = screen.getByRole("dialog");

    fireEvent.click(dialog);
    expect(onClose).not.toHaveBeenCalled();

    fireEvent.click(dialog.parentElement!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("tracks the visited page in localStorage even though the palette is a modal", () => {
    renderPalette(false);
    // Known wart: the recently-visited tracker lives inside a component that is
    // usually closed, and writes on every route change regardless of `open`.
    const stored = JSON.parse(localStorage.getItem(RECENT_PAGES_KEY) || "[]");
    expect(stored[0]).toMatchObject({ path: "/feeds", label: "All Feeds" });
  });
});

// ---------------------------------------------------------------------------
// Commands only — no server search
// ---------------------------------------------------------------------------

describe("CommandPalette is command-only", () => {
  it("never queries the unified search endpoint, however much is typed", () => {
    renderPalette();

    typeQuery("a");
    typeQuery("apt");
    typeQuery("APT29");

    expect(unifiedSearchMock).not.toHaveBeenCalled();
  });

  it("points at the search page when nothing in the vocabulary matches", () => {
    renderPalette();
    typeQuery("qzxjv");

    expect(screen.getByText(/No command matches/i)).toBeInTheDocument();
    expect(screen.getByText(/Search page/i)).toBeInTheDocument();
  });

  it("offers the /search route as a command instead of searching in place", () => {
    renderPalette();
    typeQuery("search");

    fireEvent.click(screen.getByText("Search").closest("button")!);
    expect(navigateMock).toHaveBeenCalledWith("/search");
  });
});

// ---------------------------------------------------------------------------
// Result grouping / ordering
// ---------------------------------------------------------------------------

describe("CommandPalette empty-query composition", () => {
  it("orders sections: recent entities, recently visited, then commands by category", () => {
    useIntelStore.setState({
      recentPivots: [{ type: "threat_actor", id: "a1", label: "APT29", timestamp: Date.now() }],
    });
    localStorage.setItem(
      RECENT_PAGES_KEY,
      JSON.stringify([{ path: "/settings", label: "Settings", timestamp: Date.now() }]),
    );

    const { container } = renderPalette();
    const positions = orderOf(container, [
      "RECENT ENTITIES",
      "RECENTLY VISITED",
      "RUN",
      "CREATE",
      "GO TO",
      "BROWSE",
      "MANAGE",
    ]);
    expect(positions.every((p) => p >= 0)).toBe(true);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it("filters UUID-labelled recent pivots out of the recent-entities section", () => {
    useIntelStore.setState({
      recentPivots: [
        { type: "malware", id: "m1", label: "123e4567-e89b-12d3-a456-426614174000", timestamp: 1 },
        { type: "malware", id: "m2", label: "Emotet", timestamp: 2 },
      ],
    });
    renderPalette();

    expect(screen.getByText("Emotet")).toBeInTheDocument();
    expect(screen.queryByText("123e4567-e89b-12d3-a456-426614174000")).not.toBeInTheDocument();
  });

  it("puts 'Ask Copilot' above the navigation commands", () => {
    const { container } = renderPalette();
    const [copilot, settings] = orderOf(container, ["Ask Copilot", "Settings"]);
    expect(copilot).toBeLessThan(settings);
  });
});

describe("CommandPalette filter mode", () => {
  it("breaks score ties with the category order", () => {
    const { container } = renderPalette();
    typeQuery("campaign");

    // Both label-substring hits (score 100), so CREATE wins over GO TO.
    const [create, goTo] = orderOf(container, ["Create campaign", "Campaigns"]);
    expect(create).toBeGreaterThanOrEqual(0);
    expect(goTo).toBeGreaterThan(create);
  });

  it("ranks a label hit above a keyword-only hit", () => {
    const { container } = renderPalette();
    typeQuery("priority");

    const [label, keyword] = orderOf(container, ["Priority queue", "Intelligence requirements"]);
    expect(label).toBeGreaterThanOrEqual(0);
    expect(keyword).toBeGreaterThan(label);
  });

  it("drops the recents sections while filtering", () => {
    useIntelStore.setState({
      recentPivots: [{ type: "malware", id: "m2", label: "Emotet", timestamp: 2 }],
    });
    renderPalette();
    typeQuery("rule");

    expect(screen.queryByText("RECENT ENTITIES")).not.toBeInTheDocument();
    expect(screen.queryByText("Emotet")).not.toBeInTheDocument();
    expect(screen.getByText("Create detection rule")).toBeInTheDocument();
  });

  it("matches on keywords the label never mentions", () => {
    renderPalette();
    typeQuery("opml");

    expect(screen.getByText("Feeds & export (OPML)")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Admin gating
// ---------------------------------------------------------------------------

describe("CommandPalette admin gating", () => {
  it("hides admin-only commands from ordinary users", () => {
    setRole("user");
    renderPalette();

    expect(screen.queryByText("Engine console")).not.toBeInTheDocument();
    expect(screen.queryByText("System settings")).not.toBeInTheDocument();
    // Non-admin surfaces are untouched.
    expect(screen.getByText("Appearance & themes")).toBeInTheDocument();
  });

  it("shows them to admins", () => {
    renderPalette();

    expect(screen.getByText("Engine console")).toBeInTheDocument();
    expect(screen.getByText("System settings")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Keyboard model
// ---------------------------------------------------------------------------

describe("CommandPalette keyboard model", () => {
  /** "yara" matches exactly two commands, tied on score and so ordered by
   *  category: the create command, then the browse one. */
  function twoResults() {
    return typeQuery("yara");
  }

  it("Enter without arrowing selects the first result (index defaults to 0)", () => {
    renderPalette();
    const input = twoResults();

    fireEvent.keyDown(input, { key: "Enter" });
    expect(navigateMock).toHaveBeenCalledWith("/workbench/rule/new");
  });

  it("ArrowDown clamps at the last result — no wrap", () => {
    renderPalette();
    const input = twoResults();

    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(navigateMock).toHaveBeenCalledWith("/workbench/explore?section=rules");
  });

  it("ArrowUp clamps at 0 — there is no deselected state", () => {
    renderPalette();
    const input = twoResults();

    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "ArrowUp" });
    fireEvent.keyDown(input, { key: "ArrowUp" });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(navigateMock).toHaveBeenCalledWith("/workbench/rule/new");
  });

  it("Tab is unhandled — it neither selects nor closes", () => {
    renderPalette();
    const input = twoResults();

    fireEvent.keyDown(input, { key: "Tab" });
    expect(navigateMock).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("Escape closes the palette in one rung, without first clearing the query", () => {
    renderPalette();
    const input = twoResults();

    fireEvent.keyDown(input, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect((input as HTMLInputElement).value).toBe("yara");
  });

  it("hovering a row moves the selection", () => {
    renderPalette();
    const input = twoResults();

    fireEvent.mouseEnter(screen.getByText("Rules library").closest("button")!);
    fireEvent.keyDown(input, { key: "Enter" });
    expect(navigateMock).toHaveBeenCalledWith("/workbench/explore?section=rules");
  });
});

// ---------------------------------------------------------------------------
// Selection -> action
// ---------------------------------------------------------------------------

describe("CommandPalette selection routing", () => {
  it("routes a recent entity pivot to its profile", () => {
    useIntelStore.setState({
      recentPivots: [{ type: "country", id: "co1", label: "Iran", timestamp: Date.now() }],
    });
    renderPalette();

    fireEvent.click(screen.getByText("Iran").closest("button")!);
    expect(navigateMock).toHaveBeenCalledWith("/workbench/country/co1");
    expect(onClose).toHaveBeenCalled();
  });

  it("navigates to a recently visited page", () => {
    localStorage.setItem(
      RECENT_PAGES_KEY,
      JSON.stringify([{ path: "/automation", label: "Automation Rules", timestamp: Date.now() }]),
    );
    renderPalette();

    fireEvent.click(screen.getByText("Automation Rules").closest("button")!);
    expect(navigateMock).toHaveBeenCalledWith("/automation");
  });

  it("sets the workbench section before navigating for section-scoped commands", () => {
    renderPalette();
    fireEvent.click(screen.getByText("CVEs").closest("button")!);

    expect(useIntelStore.getState().activeSection).toBe("cves");
    expect(navigateMock).toHaveBeenCalledWith("/workbench/explore?section=cves");
  });

  it.each([
    ["Ask Copilot", () => useUIStore.getState().copilotOpen],
    ["Add feed", () => useUIStore.getState().addFeedOpen],
    ["Ingest a URL or PDF", () => useUIStore.getState().ingestOpen],
    ["Keyboard shortcuts", () => useUIStore.getState().shortcutsHelpOpen],
  ])("opens %s as a modal instead of navigating", (label, isOpen) => {
    renderPalette();
    fireEvent.click(screen.getByText(label).closest("button")!);

    expect(isOpen()).toBe(true);
    expect(navigateMock).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Vocabulary hygiene
// ---------------------------------------------------------------------------

describe("command vocabulary", () => {
  it("gives every command either a route or a special action, never both", () => {
    for (const action of QUICK_ACTIONS) {
      if (action.special) expect(action.path).toBe("");
      else expect(action.path.startsWith("/")).toBe(true);
    }
  });

  it("has no duplicate labels", () => {
    const labels = QUICK_ACTIONS.map((a) => a.label);
    expect(new Set(labels).size).toBe(labels.length);
  });
});
