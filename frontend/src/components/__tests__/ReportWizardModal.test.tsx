import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Use vi.hoisted so these are available in vi.mock factories
const { mockNavigate, mockToast, mockMutate, mockTemplates, mockCloseWizard, getMockWizardState, setMockWizardState } = vi.hoisted(() => {
  let _wizardState: Record<string, unknown> | null = null;
  return {
    mockNavigate: vi.fn(),
    mockToast: { success: vi.fn(), error: vi.fn() },
    mockMutate: vi.fn(),
    mockTemplates: [
      {
        type: "flash_alert",
        name: "Flash Alert",
        description: "Rapid notification of emerging threats",
        sections: [
          { name: "summary" },
          { name: "key_findings" },
          { name: "iocs" },
          { name: "recommended_actions" },
          { name: "references" },
        ],
      },
      {
        type: "ioc_bulletin",
        name: "IOC Bulletin",
        description: "Structured list of indicators",
        sections: [
          { name: "summary" },
          { name: "ioc_table" },
          { name: "context" },
          { name: "detection_guidance" },
          { name: "references" },
        ],
      },
    ],
    mockCloseWizard: vi.fn(),
    getMockWizardState: () => _wizardState,
    setMockWizardState: (s: Record<string, unknown> | null) => { _wizardState = s; },
  };
});

vi.mock("react-router-dom", () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock("sonner", () => ({
  toast: mockToast,
}));

vi.mock("@/hooks/useIntelReports", () => ({
  useReportTemplates: () => ({ data: mockTemplates }),
  useGenerateFullReport: () => ({
    mutate: mockMutate,
    isPending: false,
  }),
}));

vi.mock("@/components/SimpleTagEditor", () => ({
  default: ({ tags }: { tags: string[]; onChange: (t: string[]) => void }) => (
    <div data-testid="tag-editor">
      {tags.map((t: string) => (
        <span key={t}>{t}</span>
      ))}
    </div>
  ),
}));

vi.mock("../ReportWizardModal.module.css", () => ({
  default: new Proxy(
    {},
    {
      get: (_target: unknown, prop: string) => String(prop),
    },
  ),
}));

vi.mock("@/hooks/useSearch", () => ({
  useSavedSearches: () => ({ data: [] }),
}));

vi.mock("@/stores/uiStore", () => ({
  useUIStore: (selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      reportWizardState: getMockWizardState(),
      closeReportWizard: mockCloseWizard,
    }),
}));

import { ReportWizardModal } from "../ReportWizardModal";

describe("ReportWizardModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setMockWizardState(null);
  });

  it("renders nothing when wizardState is null", () => {
    setMockWizardState(null);
    const { container } = render(<ReportWizardModal />);
    expect(container.innerHTML).toBe("");
  });

  it("renders nothing when wizardState.isOpen is false", () => {
    setMockWizardState({ isOpen: false, sourceType: "entry" });
    const { container } = render(<ReportWizardModal />);
    expect(container.innerHTML).toBe("");
  });

  it("renders wizard with entry source type", () => {
    setMockWizardState({
      isOpen: true,
      sourceType: "entry",
      entryId: "entry-1",
      entryTitle: "Critical RCE in Apache",
    });
    render(<ReportWizardModal />);
    expect(screen.getByText("Generate AI Report")).toBeDefined();
    expect(screen.getByText("Step 1 of 3: Source")).toBeDefined();
    expect(screen.getByText("Critical RCE in Apache")).toBeDefined();
    expect(screen.getByText("entry")).toBeDefined();
  });

  it("renders wizard with entries source type", () => {
    setMockWizardState({
      isOpen: true,
      sourceType: "entries",
      entryIds: ["e1", "e2", "e3"],
    });
    render(<ReportWizardModal />);
    expect(screen.getByText("3 selected articles")).toBeDefined();
  });

  it("renders wizard with search source type and editable input", () => {
    setMockWizardState({
      isOpen: true,
      sourceType: "search",
      searchQuery: "ransomware",
      searchResultCount: 42,
    });
    render(<ReportWizardModal />);
    // Editable source step shows tabs and search input
    expect(screen.getByText("Search Query")).toBeDefined();
    expect(screen.getByText("Saved Search")).toBeDefined();
    expect(screen.getByPlaceholderText(/ransomware, APT29/)).toBeDefined();
    expect(screen.getByText("Max articles:")).toBeDefined();
  });

  it("renders wizard with saved_search source type and tab UI", () => {
    setMockWizardState({
      isOpen: true,
      sourceType: "saved_search",
      savedSearchId: "ss-1",
      savedSearchName: "My APT Searches",
    });
    render(<ReportWizardModal />);
    // Editable source step shows tabs; saved search tab active
    expect(screen.getByText("Search Query")).toBeDefined();
    expect(screen.getByText("Saved Search")).toBeDefined();
    // No saved searches mocked, so shows empty message
    expect(screen.getByText("No saved searches found.")).toBeDefined();
  });

  it("navigates steps forward and back", async () => {
    const user = userEvent.setup();
    setMockWizardState({
      isOpen: true,
      sourceType: "entry",
      entryId: "entry-1",
      entryTitle: "Test",
    });
    render(<ReportWizardModal />);

    // Step 1 → Step 2
    expect(screen.getByText("Step 1 of 3: Source")).toBeDefined();
    await user.click(screen.getByText("Next"));
    expect(screen.getByText("Step 2 of 3: Template")).toBeDefined();

    // Template grid should be visible
    expect(screen.getByText("Flash Alert")).toBeDefined();
    expect(screen.getByText("IOC Bulletin")).toBeDefined();

    // Select a template
    await user.click(screen.getByText("Flash Alert"));

    // Step 2 → Step 3
    await user.click(screen.getByText("Next"));
    expect(screen.getByText("Step 3 of 3: Configuration")).toBeDefined();

    // Config fields visible
    expect(screen.getByText("Title")).toBeDefined();
    expect(screen.getByText("TLP Marking")).toBeDefined();
    expect(screen.getByText(/Focus/)).toBeDefined();
    expect(screen.getByText(/Audience/)).toBeDefined();

    // Back button works
    await user.click(screen.getByText("Back"));
    expect(screen.getByText("Step 2 of 3: Template")).toBeDefined();
  });

  it("disables Next on step 2 when no template selected", async () => {
    const user = userEvent.setup();
    setMockWizardState({
      isOpen: true,
      sourceType: "entry",
      entryId: "entry-1",
      entryTitle: "Test",
    });
    render(<ReportWizardModal />);

    // Go to step 2
    await user.click(screen.getByText("Next"));

    // Next should be disabled (no template selected)
    const nextBtn = screen.getByText("Next");
    expect((nextBtn as HTMLButtonElement).disabled).toBe(true);
  });

  it("calls generate mutation with correct payload on Generate click", async () => {
    const user = userEvent.setup();
    setMockWizardState({
      isOpen: true,
      sourceType: "entry",
      entryId: "entry-1",
      entryTitle: "Test Article",
    });

    mockMutate.mockImplementation((_body: unknown, opts: { onSuccess: (data: unknown) => void }) => {
      opts.onSuccess({ report: { id: "report-123" }, task_id: "task-abc" });
    });

    render(<ReportWizardModal />);

    // Step 1 → 2
    await user.click(screen.getByText("Next"));
    // Select template
    await user.click(screen.getByText("Flash Alert"));
    // Step 2 → 3
    await user.click(screen.getByText("Next"));

    // Fill in focus
    const focusTextarea = screen.getByPlaceholderText(/Detection opportunities/);
    await user.type(focusTextarea, "lateral movement");

    // Click Generate
    await user.click(screen.getByText("Generate"));

    expect(mockMutate).toHaveBeenCalledTimes(1);
    const callArgs = mockMutate.mock.calls[0][0];
    expect(callArgs.source_type).toBe("entry");
    expect(callArgs.entry_id).toBe("entry-1");
    expect(callArgs.template_type).toBe("flash_alert");
    expect(callArgs.focus).toBe("lateral movement");
    expect(callArgs.tlp_marking).toBe("TLP:GREEN");
  });

  it("navigates to report and closes on success", async () => {
    const user = userEvent.setup();
    setMockWizardState({
      isOpen: true,
      sourceType: "entry",
      entryId: "entry-1",
      entryTitle: "Test",
    });

    mockMutate.mockImplementation((_body: unknown, opts: { onSuccess: (data: unknown) => void }) => {
      opts.onSuccess({ report: { id: "report-999" }, task_id: "t1" });
    });

    render(<ReportWizardModal />);

    // Navigate through wizard
    await user.click(screen.getByText("Next"));
    await user.click(screen.getByText("Flash Alert"));
    await user.click(screen.getByText("Next"));
    await user.click(screen.getByText("Generate"));

    expect(mockNavigate).toHaveBeenCalledWith("/workbench/report/report-999");
    expect(mockCloseWizard).toHaveBeenCalled();
    expect(mockToast.success).toHaveBeenCalledWith(
      "Report created. Generating sections with AI..."
    );
  });

  it("closes when overlay is clicked", () => {
    setMockWizardState({
      isOpen: true,
      sourceType: "entry",
      entryId: "entry-1",
      entryTitle: "Test",
    });
    const { container } = render(<ReportWizardModal />);

    // Click the overlay (first child element)
    const overlay = container.firstChild as HTMLElement;
    overlay.click();
    expect(mockCloseWizard).toHaveBeenCalled();
  });

  it("closes when X button is clicked", async () => {
    const user = userEvent.setup();
    setMockWizardState({
      isOpen: true,
      sourceType: "entry",
      entryId: "entry-1",
      entryTitle: "Test",
    });
    render(<ReportWizardModal />);

    await user.click(screen.getByText("×"));
    expect(mockCloseWizard).toHaveBeenCalled();
  });
});
