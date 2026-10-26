import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import { UploadByline } from "../EntryUploadInfo";
import { formatBytes, originalState, uploadMeta } from "@/utils/ingest";

describe("UploadByline", () => {
  beforeEach(() => {
    useAuthStore.setState({ accessToken: "tok-123" });
    useUIStore.setState({ selectedFeedId: null, viewMode: "compact" });
  });

  it("renders nothing for an ordinary polled entry", () => {
    const { container } = render(<UploadByline metadata={{ some: "thing" }} feedId="f1" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("offers a signed download for a kept original", () => {
    render(
      <UploadByline
        metadata={{
          source: "file_upload",
          batch_id: "b1",
          ingest_file_id: "file-1",
          filename: "M-Trends.pdf",
          file_content_type: "application/pdf",
          size_bytes: 8_600_000,
          original_retained: true,
        }}
        feedId="manual"
      />,
    );
    const original = screen.getByTestId("upload-original");
    expect(original).toHaveTextContent("M-Trends.pdf");
    expect(original).toHaveTextContent("PDF");
    expect(original).toHaveTextContent("8.2 MB");
    const link = screen.getByRole("link", { name: "Download" });
    expect(link.getAttribute("href")).toBe("/api/ingest-files/file-1?token=tok-123");
    // The batch chip opens the uploads feed as a file table.
    screen.getByRole("button", { name: /Batch/ }).click();
    expect(useUIStore.getState().selectedFeedId).toBe("manual");
    expect(useUIStore.getState().viewMode).toBe("table");
  });

  it("says so when the sweep removed the file, and for a pre-batch PDF", () => {
    const { rerender } = render(
      <UploadByline
        metadata={{ source: "file_upload", ingest_file_id: "file-1", filename: "old.pdf", original_retained: false }}
        feedId="manual"
      />,
    );
    expect(screen.getByTestId("upload-original")).toHaveTextContent("removed by retention");
    expect(screen.queryByRole("link", { name: "Download" })).toBeNull();

    rerender(<UploadByline metadata={{ source: "pdf_upload", filename: "legacy.pdf" }} feedId="manual" />);
    expect(screen.getByTestId("upload-original")).toHaveTextContent("not kept");
    expect(screen.queryByRole("button", { name: /Batch/ })).toBeNull();
  });

  it("shows only the batch chip for a fetched URL", () => {
    render(<UploadByline metadata={{ source: "url_ingest", batch_id: "b1" }} feedId="manual" />);
    expect(screen.queryByTestId("upload-original")).toBeNull();
    expect(screen.getByRole("button", { name: /Batch/ })).toBeInTheDocument();
  });
});

describe("ingest helpers", () => {
  it("classifies original state and formats sizes", () => {
    expect(originalState(uploadMeta({ source: "pdf_upload" }))).toBe("not_kept");
    expect(originalState(uploadMeta({ ingest_file_id: "x", original_retained: false }))).toBe("evicted");
    expect(originalState(uploadMeta({ ingest_file_id: "x" }))).toBe("available");
    expect(originalState(uploadMeta({ source: "url_ingest", batch_id: "b" }))).toBe("none");
    expect(uploadMeta(null)).toBeNull();
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(45_056)).toBe("44 KB");
    expect(formatBytes(12 * 1024 * 1024)).toBe("12 MB");
  });
});
