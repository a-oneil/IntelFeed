import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { createRef } from "react";
import { HeaderSearch } from "@/components/HeaderSearch";
import type { AutocompleteSuggestion } from "@/hooks/useSearchAutocomplete";
import { useUIStore } from "@/stores/uiStore";

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => vi.fn(),
    useLocation: () => ({ pathname: "/", search: "", hash: "", state: null, key: "default" }),
  };
});

const mockAutocomplete = vi.fn();
vi.mock("@/hooks/useSearchAutocomplete", () => ({
  useSearchAutocomplete: (...args: unknown[]) => mockAutocomplete(...args),
}));

function renderSearch() {
  const inputRef = createRef<HTMLInputElement>();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const utils = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <HeaderSearch inputRef={inputRef as React.RefObject<HTMLInputElement>} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, input: screen.getByPlaceholderText(/^Search /i) };
}

describe("HeaderSearch autocomplete", () => {
  beforeEach(() => {
    mockAutocomplete.mockReset();
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders field and value suggestions from the endpoint", () => {
    const suggestions: AutocompleteSuggestion[] = [
      { type: "field", text: "tool:", insert: "tool:", description: "Search tool names", category: "entity" },
      { type: "value", text: "Mimikatz", insert: "tool:Mimikatz", field: "tool" },
    ];
    mockAutocomplete.mockReturnValue({ data: suggestions });

    const { input } = renderSearch();
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: "tool" } });

    expect(screen.getByText("tool:")).toBeInTheDocument();
    expect(screen.getByText("Mimikatz")).toBeInTheDocument();
    expect(screen.getByText("Search tool names")).toBeInTheDocument();
  });

  it("replaces the token at the cursor when a value is accepted", () => {
    mockAutocomplete.mockReturnValue({
      data: [{ type: "value", text: "Mimikatz", insert: "tool:Mimikatz", field: "tool" }],
    });

    const { input } = renderSearch();
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: "ransomware tool:Mim" } });
    fireEvent.mouseDown(screen.getByText("Mimikatz"));

    // Only the trailing token is replaced; earlier text survives.
    expect((input as HTMLInputElement).value).toBe("ransomware tool:Mimikatz ");
  });
});


describe("HeaderSearch scope placeholder", () => {
  beforeEach(() => {
    mockAutocomplete.mockReset();
    mockAutocomplete.mockReturnValue({ data: [], isLoading: false });
    localStorage.clear();
    useUIStore.setState({ headerSearchQuery: "", searchScope: "everything" });
  });

  afterEach(() => {
    useUIStore.setState({ searchScope: "everything" });
  });

  it("names both halves when the scope is everything", () => {
    useUIStore.setState({ searchScope: "everything" });
    renderSearch();
    expect(screen.getByPlaceholderText(/entries & intelligence/i)).toBeInTheDocument();
  });

  it("names only articles when the scope is feeds", () => {
    // A field reading "entries & intelligence" under an `in: feeds` chip
    // describes a search the user is not running.
    useUIStore.setState({ searchScope: "feeds" });
    renderSearch();
    const input = screen.getByPlaceholderText(/^Search /i);
    expect(input.getAttribute("placeholder")).toMatch(/entries/i);
    expect(input.getAttribute("placeholder")).not.toMatch(/intelligence/i);
  });

  it("names only entities when the scope is workbench", () => {
    useUIStore.setState({ searchScope: "workbench" });
    renderSearch();
    const input = screen.getByPlaceholderText(/^Search /i);
    expect(input.getAttribute("placeholder")).toMatch(/intelligence/i);
    expect(input.getAttribute("placeholder")).not.toMatch(/^Search entries/i);
  });

  it("keeps the slash hint in every scope", () => {
    for (const scope of ["everything", "workbench", "feeds"] as const) {
      useUIStore.setState({ searchScope: scope });
      const { unmount } = renderSearch();
      expect(screen.getByPlaceholderText(/\( \/ \)/)).toBeInTheDocument();
      unmount();
    }
  });
});
