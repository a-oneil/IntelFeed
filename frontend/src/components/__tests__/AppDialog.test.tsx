import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, beforeEach } from "vitest";
import { DialogHost } from "../DialogHost";
import { useDialogStore } from "@/stores/dialogStore";
import { alertDialog, confirmDialog, promptDialog } from "@/utils/dialog";

/** The host has to be mounted for the imperative API to raise anything. */
function mountHost() {
  return render(<DialogHost />);
}

const accept = () => fireEvent.click(screen.getByTestId("app-dialog-accept"));
const cancel = (name = "Cancel") => fireEvent.click(screen.getByRole("button", { name }));

describe("app dialogs", () => {
  beforeEach(() => {
    useDialogStore.setState({ queue: [] });
  });

  it("resolves true when a confirm is accepted", async () => {
    mountHost();
    const answer = confirmDialog("Delete the thing?");
    await screen.findByText("Delete the thing?");
    accept();
    expect(await answer).toBe(true);
  });

  it("resolves false when a confirm is cancelled", async () => {
    mountHost();
    const answer = confirmDialog("Delete the thing?");
    await screen.findByText("Delete the thing?");
    cancel();
    expect(await answer).toBe(false);
  });

  it("resolves false on Escape — the safe answer, not the accepting one", async () => {
    mountHost();
    const answer = confirmDialog("Delete the thing?");
    await screen.findByText("Delete the thing?");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(await answer).toBe(false);
  });

  it("uses the caller's button labels", async () => {
    mountHost();
    const answer = confirmDialog({
      message: "Tombstone or hard-delete?",
      confirmLabel: "Hard-delete",
      cancelLabel: "Tombstone (recommended)",
      destructive: true,
    });
    await screen.findByText("Tombstone or hard-delete?");
    cancel("Tombstone (recommended)");
    expect(await answer).toBe(false);
  });

  it("starts focus on Cancel for a destructive action", async () => {
    mountHost();
    void confirmDialog({ message: "Delete everything?", destructive: true });
    const cancelBtn = await screen.findByRole("button", { name: "Cancel" });
    await waitFor(() => expect(document.activeElement).toBe(cancelBtn));
  });

  it("starts focus on the accept button otherwise", async () => {
    mountHost();
    void confirmDialog({ message: "Publish this rule?" });
    const acceptBtn = await screen.findByTestId("app-dialog-accept");
    await waitFor(() => expect(document.activeElement).toBe(acceptBtn));
  });

  it("returns the trimmed answer from a prompt", async () => {
    mountHost();
    const answer = promptDialog({ message: "Rename to:", defaultValue: "old" });
    const input = await screen.findByRole("textbox");
    fireEvent.change(input, { target: { value: "  new name  " } });
    accept();
    expect(await answer).toBe("new name");
  });

  it("returns null when a prompt is cancelled", async () => {
    mountHost();
    const answer = promptDialog({ message: "Rename to:", defaultValue: "old" });
    await screen.findByRole("textbox");
    cancel();
    expect(await answer).toBeNull();
  });

  it("blocks an empty prompt answer by default", async () => {
    mountHost();
    void promptDialog({ message: "Label name:" });
    const acceptBtn = await screen.findByTestId("app-dialog-accept");
    expect(acceptBtn).toHaveProperty("disabled", true);
  });

  it("allows an empty answer when the caller clears `required`", async () => {
    mountHost();
    // The saved-search rename uses this: blank means "fall back to the query".
    const answer = promptDialog({ message: "Display name:", defaultValue: "x", required: false });
    const input = await screen.findByRole("textbox");
    fireEvent.change(input, { target: { value: "" } });
    accept();
    expect(await answer).toBe("");
  });

  it("submits a prompt on Enter", async () => {
    mountHost();
    const answer = promptDialog({ message: "Alias:" });
    const input = await screen.findByRole("textbox");
    fireEvent.change(input, { target: { value: "APT99" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await answer).toBe("APT99");
  });

  it("an alert has only an acknowledgement", async () => {
    mountHost();
    const done = alertDialog({ title: "Import finished", message: "Imported: 3, Skipped: 0" });
    await screen.findByText("Imported: 3, Skipped: 0");
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    accept();
    await done;
  });

  it("queues rather than stacks when two are raised at once", async () => {
    mountHost();
    const first = confirmDialog("First question?");
    const second = confirmDialog("Second question?");

    await screen.findByText("First question?");
    expect(screen.queryByText("Second question?")).toBeNull();

    accept();
    expect(await first).toBe(true);

    await screen.findByText("Second question?");
    cancel();
    expect(await second).toBe(false);
  });

  it("denies instead of hanging when no host is mounted", async () => {
    // A component rendered in isolation in a unit test has no DialogHost, and a
    // promise that never settles would wedge the caller.
    expect(await confirmDialog("Anything?")).toBe(false);
    expect(await promptDialog("Anything?")).toBeNull();
  });
});
