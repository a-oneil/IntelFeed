import { render } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { YouTubePlayer } from "@/components/YouTubePlayer";

describe("YouTubePlayer", () => {
  it("renders iframe with correct src", () => {
    render(<YouTubePlayer videoId="dQw4w9WgXcQ" title="Test Video" />);
    const iframe = document.querySelector("iframe");
    expect(iframe).toBeTruthy();
    expect(iframe?.src).toContain("youtube.com/embed/dQw4w9WgXcQ");
  });

  it("sets iframe title", () => {
    render(<YouTubePlayer videoId="abc123" title="My Video" />);
    const iframe = document.querySelector("iframe");
    expect(iframe?.title).toBe("My Video");
  });

  it("sets allowFullScreen", () => {
    render(<YouTubePlayer videoId="abc123" />);
    const iframe = document.querySelector("iframe");
    expect(iframe?.allowFullscreen).toBe(true);
  });

  it("uses default title when none provided", () => {
    render(<YouTubePlayer videoId="abc123" />);
    const iframe = document.querySelector("iframe");
    expect(iframe?.title).toBe("YouTube video");
  });
});
