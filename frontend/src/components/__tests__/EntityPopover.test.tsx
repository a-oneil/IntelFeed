import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { EntityPopover } from "../EntityPopover";
import type { HighlightEntity } from "../InlineEntityHighlighter";

// The popover re-clamps itself with a ResizeObserver; jsdom has none.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", ResizeObserverStub);

vi.mock("react-router-dom", () => ({
  useNavigate: () => vi.fn(),
}));

const reportMutate = vi.fn();
vi.mock("@/hooks/useFalsePositives", () => ({
  useReportFalsePositive: () => ({ mutate: reportMutate, isPending: false }),
}));

const convertMutate = vi.fn();
const unlinkAllMutate = vi.fn();
const deleteEntityMock = vi.fn(() => Promise.resolve());
vi.mock("@/hooks/useEntityProfile", () => ({
  useConvertEntity: () => ({ mutate: convertMutate, isPending: false }),
  useDeleteEntity: () => deleteEntityMock,
  useUnlinkAllEntries: () => ({ mutate: unlinkAllMutate, isPending: false }),
  MERGEABLE_ENTITY_TYPES: ["threat_actor", "malware", "country", "tool", "vendor", "product"],
}));

const enrichMutate = vi.fn();
vi.mock("@/hooks/useEnrichment", () => ({
  useEnrichEntity: () => ({ mutate: enrichMutate, isPending: false }),
}));

// The glance a test hands the popover; undefined is "not loaded / failed".
let glanceData: unknown = undefined;
vi.mock("@/hooks/useEntityGlance", () => ({
  useEntityGlance: () => ({ data: glanceData }),
}));

// Observable rungs: unlink-this-sighting and the deny tombstone.
const unlinkSightingMutate = vi.fn();
const denyObservableMutate = vi.fn();
vi.mock("@/hooks/useIntelligence", () => ({
  useUnlinkEntity: () => ({ mutate: unlinkSightingMutate, isPending: false }),
  useDenyObservable: () => ({ mutate: denyObservableMutate, isPending: false }),
}));

// Convert / merge / unlink-all are admin-only actions; tests default to an
// admin and one flips the role to check the gate.
const authState = { user: { id: "u1", role: "admin" } };

vi.mock("@/stores/authStore", () => {
  const useAuthStore = (selector: (s: typeof authState) => unknown) => selector(authState);
  useAuthStore.getState = () => authState;
  return { useAuthStore, useIsVisitor: () => false };
});

// The app's own confirm replaced window.confirm here, so the stub moves with
// it. It is async, which is why the assertions below have to wait.
const confirmDialogMock = vi.fn<(opts: unknown) => Promise<boolean>>(() => Promise.resolve(true));
vi.mock("@/utils/dialog", () => ({
  confirmDialog: (opts: unknown) => confirmDialogMock(opts),
  promptDialog: () => Promise.resolve(null),
  alertDialog: () => Promise.resolve(),
}));

// The undo window runs its delete straight away here.
vi.mock("@/hooks/useUndoableDelete", () => ({
  useUndoableDelete: () => (opts: { onDelete: () => void; onInitiate?: () => void }) => {
    opts.onInitiate?.();
    opts.onDelete();
  },
}));

vi.mock("../EntityMergeIntoModal", () => ({
  EntityMergeIntoModal: ({ keeperName }: { keeperName: string }) => (
    <div data-testid="merge-modal">merge {keeperName}</div>
  ),
}));

const vendorEntity: HighlightEntity = {
  id: "vendor-1",
  type: "vendor",
  value: "Sprocket",
  name: "Sprocket Security",
  meta: { article_count: 12 },
};

function openWrongMenu(entity: HighlightEntity = vendorEntity, props: Record<string, unknown> = {}) {
  const onClose = vi.fn();
  render(
    <EntityPopover
      entity={entity}
      x={100}
      y={100}
      onClose={onClose}
      onNavigate={vi.fn()}
      entryId="entry-1"
      {...props}
    />,
  );
  fireEvent.click(screen.getByText("Wrong?"));
  return { onClose };
}

describe("EntityPopover — wrong-match menu", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    confirmDialogMock.mockResolvedValue(true);
    authState.user = { id: "u1", role: "admin" };
    glanceData = undefined;
  });

  it("reports the article-scoped fix and closes", () => {
    const { onClose } = openWrongMenu();
    fireEvent.click(screen.getByText("Wrong for this article"));

    expect(reportMutate).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "entry", entity_id: "vendor-1", source_entry_id: "entry-1" }),
      expect.anything(),
    );
    expect(onClose).toHaveBeenCalled();
  });

  it("offers the alias fix when the matched text isn't the entity's name", () => {
    openWrongMenu();
    fireEvent.click(screen.getByText("Not a name for Sprocket Security"));

    expect(reportMutate).toHaveBeenCalledWith(expect.objectContaining({ scope: "alias" }), expect.anything());
  });

  it("hides the alias fix when the matched text is the entity's own name", () => {
    openWrongMenu({ ...vendorEntity, name: "Sprocket" });
    expect(screen.queryByText(/Not a name for/)).toBeNull();
  });

  it("confirms before blocking a word everywhere", async () => {
    openWrongMenu();
    fireEvent.click(screen.getByText(/Never match/));

    expect(confirmDialogMock).toHaveBeenCalled();
    await waitFor(() =>
      expect(reportMutate).toHaveBeenCalledWith(expect.objectContaining({ scope: "global" }), expect.anything()),
    );
  });

  it("does not report when the block confirmation is declined", async () => {
    confirmDialogMock.mockResolvedValue(false);
    openWrongMenu();
    fireEvent.click(screen.getByText(/Never match/));

    await waitFor(() => expect(confirmDialogMock).toHaveBeenCalled());
    expect(reportMutate).not.toHaveBeenCalled();
  });

  it("lists convert targets except the entity's current type", () => {
    openWrongMenu();
    fireEvent.click(screen.getByText(/Wrong type — convert/));

    expect(screen.getByRole("button", { name: "Threat Actor" })).toBeDefined();
    expect(screen.getByRole("button", { name: "Malware Family" })).toBeDefined();
    // "Vendor" is still on screen as the type badge — just not as a target.
    expect(screen.queryByRole("button", { name: "Vendor" })).toBeNull();
  });

  it("converts through the shared convert action", async () => {
    openWrongMenu();
    fireEvent.click(screen.getByText(/Wrong type — convert/));
    fireEvent.click(screen.getByText("Product"));

    await waitFor(() =>
      expect(convertMutate).toHaveBeenCalledWith(
        expect.objectContaining({ entityId: "vendor-1", targetType: "product" }),
        expect.anything(),
      ),
    );
  });

  it("opens the merge picker for mergeable types", () => {
    openWrongMenu();
    fireEvent.click(screen.getByText("Duplicate — merge into…"));

    expect(screen.getByTestId("merge-modal").textContent).toContain("Sprocket Security");
  });

  it("unlinks from every article after confirmation", async () => {
    openWrongMenu();
    fireEvent.click(screen.getByText("Unlink from every article"));

    expect(confirmDialogMock).toHaveBeenCalled();
    await waitFor(() =>
      expect(unlinkAllMutate).toHaveBeenCalledWith(
        { entityType: "vendor", entityId: "vendor-1" },
        expect.anything(),
      ),
    );
  });

  it("hides the admin-only fixes from a regular analyst", () => {
    authState.user = { id: "u2", role: "user" };
    openWrongMenu();

    // The analyst-scoped fixes stay available...
    expect(screen.getByText(/Never match/)).toBeDefined();
    // ...but the instance-wide ones are gone rather than 403-ing on click.
    expect(screen.queryByText(/Wrong type — convert/)).toBeNull();
    expect(screen.queryByText("Duplicate — merge into…")).toBeNull();
    expect(screen.queryByText("Unlink from every article")).toBeNull();
  });

  it("gives observables their own ladder: unlink sighting + deny tombstone", () => {
    const observable: HighlightEntity = {
      id: "obs-1",
      type: "observable",
      value: "91.92.240.37",
      name: "91.92.240.37",
      meta: {},
    };
    const { onClose } = openWrongMenu(observable);

    // The autolinker rungs never appear on a ledger value.
    expect(screen.queryByText(/Never match/)).toBeNull();
    expect(screen.queryByText(/Wrong type — convert/)).toBeNull();

    fireEvent.click(screen.getByText(/remove sighting/));
    expect(unlinkSightingMutate).toHaveBeenCalledWith(
      { entryId: "entry-1", entityId: "obs-1", entityType: "observable" },
      expect.anything(),
    );
    expect(reportMutate).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("tombstones an observable behind an admin confirm", async () => {
    const observable: HighlightEntity = {
      id: "obs-1",
      type: "observable",
      value: "91.92.240.37",
      name: "91.92.240.37",
      meta: {},
    };
    openWrongMenu(observable);
    fireEvent.click(screen.getByText(/Never capture/));

    expect(confirmDialogMock).toHaveBeenCalled();
    await waitFor(() => expect(denyObservableMutate).toHaveBeenCalledWith("obs-1", expect.anything()));
  });

  it("hides the tombstone rung from a regular analyst on observables", () => {
    authState.user = { id: "u2", role: "user" };
    const observable: HighlightEntity = {
      id: "obs-1",
      type: "observable",
      value: "91.92.240.37",
      name: "91.92.240.37",
      meta: {},
    };
    openWrongMenu(observable);
    expect(screen.queryByText(/Never capture/)).toBeNull();
    expect(screen.getByText(/needs an admin/)).toBeDefined();
  });

  it("shows no wrong-match actions on public shared pages", () => {
    render(
      <EntityPopover
        entity={vendorEntity}
        x={0}
        y={0}
        onClose={vi.fn()}
        onNavigate={vi.fn()}
        readOnly
        entryId="entry-1"
      />,
    );
    expect(screen.queryByText("Wrong?")).toBeNull();
  });
});


const observable: HighlightEntity = {
  id: "obs-1",
  type: "observable",
  value: "71.6.135.131",
  meta: { facts: [{ label: "Kind", value: "ipv4" }] },
};

function renderPopover(entity: HighlightEntity = observable) {
  render(<EntityPopover entity={entity} x={100} y={100} onClose={vi.fn()} onNavigate={vi.fn()} entryId="entry-1" />);
}

describe("EntityPopover — enrichment glance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authState.user = { id: "u1", role: "admin" };
    glanceData = {
      chips: [{ text: "Benign scanner", tone: "warn", source: "GreyNoise Community", observed_at: "2026-10-28T00:00:00Z" }],
      facts: [
        { text: "AS10439 CariNet · US", tone: null, source: "Team Cymru", observed_at: null },
        { text: "VPN", tone: null, source: "Shodan InternetDB", observed_at: null },
      ],
      lookup_sources: [
        { source_type: "greynoise", label: "GreyNoise Community" },
        { source_type: "shodan", label: "Shodan InternetDB" },
      ],
      needs_key: [{ source_type: "virustotal", label: "VirusTotal v3", key: "virustotal" }],
      looked_up: true,
    };
  });

  it("shows verdict chips and a Context row, each naming its source", () => {
    renderPopover();
    expect(screen.getByText("Benign scanner")).toHaveAttribute("title", expect.stringMatching(/^GreyNoise Community · /));
    expect(screen.getByText("Context")).toBeInTheDocument();
    expect(screen.getByText("AS10439 CariNet · US")).toHaveAttribute("title", "Team Cymru");
    expect(screen.getByText("VPN")).toBeInTheDocument();
  });

  it("looks exactly as before when there is no glance", () => {
    glanceData = undefined;
    renderPopover();
    expect(screen.queryByText("Context")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Look up" })).toBeDisabled();
  });

  it("refreshes every applicable source and says what waited or failed", () => {
    enrichMutate.mockImplementation((_vars, opts) =>
      opts?.onSuccess?.({
        results: [
          { source_type: "greynoise", status: "budget_exhausted" },
          { source_type: "shodan", status: "error" },
        ],
      }),
    );
    renderPopover();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(enrichMutate).toHaveBeenCalledWith(
      { entityType: "observable", entityId: "obs-1", sourceTypes: ["greynoise", "shodan"], refresh: true },
      expect.anything(),
    );
    expect(screen.getByText(/GreyNoise Community is at its daily cap/)).toBeInTheDocument();
    expect(screen.getByText(/Shodan InternetDB didn't answer/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(enrichMutate).toHaveBeenLastCalledWith(
      expect.objectContaining({ sourceTypes: ["shodan"] }),
      expect.anything(),
    );
  });

  it("tells an admin which source needs a key, and nobody else", () => {
    renderPopover();
    expect(screen.getByText(/VirusTotal v3 needs a key/)).toBeInTheDocument();
  });

  it("hides the key note from a regular analyst", () => {
    authState.user = { id: "u2", role: "analyst" };
    renderPopover();
    expect(screen.queryByText(/needs a key/)).not.toBeInTheDocument();
  });
});


describe("EntityPopover — delete from the Wrong? menu", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    confirmDialogMock.mockResolvedValue(true);
    authState.user = { id: "u1", role: "admin" };
    glanceData = undefined;
  });

  it("deletes the entity after a confirm and closes", async () => {
    const { onClose } = openWrongMenu();
    fireEvent.click(screen.getByText("Delete Sprocket Security…"));
    await waitFor(() => expect(deleteEntityMock).toHaveBeenCalledWith("vendor", "vendor-1"));
    expect(confirmDialogMock).toHaveBeenCalledWith(expect.objectContaining({ destructive: true }));
    expect(onClose).toHaveBeenCalled();
  });

  it("deletes nothing when the confirm is declined", async () => {
    confirmDialogMock.mockResolvedValue(false);
    openWrongMenu();
    fireEvent.click(screen.getByText("Delete Sprocket Security…"));
    await waitFor(() => expect(confirmDialogMock).toHaveBeenCalled());
    expect(deleteEntityMock).not.toHaveBeenCalled();
  });

  it("offers delete on an observable too", async () => {
    openWrongMenu({ id: "obs-9", type: "observable", value: "203.0.113.5", meta: {} });
    fireEvent.click(screen.getByText("Delete this observable…"));
    await waitFor(() => expect(deleteEntityMock).toHaveBeenCalledWith("observable", "obs-9"));
  });

  it("has no delete for a type the shared delete doesn't handle", () => {
    openWrongMenu({ id: "cwe-1", type: "cwe", value: "CWE-79", meta: {} });
    expect(screen.queryByText(/^Delete /)).not.toBeInTheDocument();
  });
});
