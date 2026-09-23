import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { EntityMergeSelectionModal } from "@/components/EntityMergeSelectionModal";

const mutateAsync = vi.fn();

vi.mock("@/hooks/useEntityProfile", () => ({
  useMergeEntities: () => ({ mutateAsync, isPending: false, isError: false, error: null }),
}));

const ENTITIES = [
  { id: "a", name: "Lazarus", aliases: ["Hidden Cobra"], article_count: 12 },
  { id: "b", name: "LAZARUS GROUP", aliases: [], article_count: 140 },
  { id: "c", name: "lazarus", aliases: null, article_count: 3 },
];

function renderModal(onMerged = vi.fn(), onClose = vi.fn()) {
  render(
    <EntityMergeSelectionModal
      entityType="threat_actor"
      entities={ENTITIES}
      onClose={onClose}
      onMerged={onMerged}
    />
  );
  return { onMerged, onClose };
}

describe("EntityMergeSelectionModal", () => {
  beforeEach(() => {
    mutateAsync.mockReset();
    mutateAsync.mockResolvedValue({});
  });

  it("keeps the profile with the most articles by default", () => {
    renderModal();
    expect(screen.getByRole("button", { name: /Merge 2 into "LAZARUS GROUP"/ })).toBeTruthy();
  });

  it("merges every other selected row into the chosen keeper", async () => {
    const { onMerged, onClose } = renderModal();

    fireEvent.click(screen.getByRole("button", { name: /Merge 2 into/ }));

    await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
    expect(mutateAsync).toHaveBeenCalledWith({
      entityType: "threat_actor",
      keeperId: "b",
      mergeIds: ["a", "c"],
    });
    await waitFor(() => expect(onMerged).toHaveBeenCalled());
    expect(onClose).toHaveBeenCalled();
  });

  it("follows the keeper radio", async () => {
    renderModal();
    fireEvent.click(screen.getAllByRole("radio")[2]);

    expect(screen.getByRole("button", { name: /Merge 2 into "lazarus"/ })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Merge 2 into/ }));
    await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
    expect(mutateAsync.mock.calls[0][0]).toMatchObject({ keeperId: "c", mergeIds: ["a", "b"] });
  });

  it("names the profiles that will be deleted", () => {
    renderModal();
    // Default keeper is "b", so the warning must name the other two.
    expect(screen.getByText(/Lazarus, lazarus/)).toBeTruthy();
  });
});
