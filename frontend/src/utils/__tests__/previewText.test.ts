import { describe, expect, it } from "vitest";
import { previewSnippet, stripBannerLines } from "../previewText";

describe("stripBannerLines", () => {
  it("drops full-width punctuation banner lines (AusCERT/ESB style)", () => {
    const text = [
      "===========================================================================",
      "AUSCERT External Security Bulletin Redistribution",
      "---------------------------------------------------------------------------",
      "ESB-2026.1234 — Security update for product",
    ].join("\n");
    expect(stripBannerLines(text)).toBe(
      "AUSCERT External Security Bulletin Redistribution\nESB-2026.1234 — Security update for product",
    );
  });

  it("drops space-separated and mixed-length banners of 4+ repeats", () => {
    expect(stripBannerLines("- - - - -\nreal text\n####")).toBe("real text");
    expect(stripBannerLines("****\nkeep")).toBe("keep");
  });

  it("keeps short punctuation runs and normal prose", () => {
    expect(stripBannerLines("a --- b")).toBe("a --- b");
    expect(stripBannerLines("state-of-the-art C2")).toBe("state-of-the-art C2");
    expect(stripBannerLines("x == y")).toBe("x == y");
  });

  it("strips inline banner runs when line structure was flattened", () => {
    expect(stripBannerLines("========== Bulletin ========== details")).toBe(" Bulletin  details");
  });

  it("does not eat PGP armor headers embedded in words", () => {
    expect(stripBannerLines("-----BEGIN PGP SIGNED MESSAGE-----")).toBe(
      "-----BEGIN PGP SIGNED MESSAGE-----",
    );
  });
});

describe("previewSnippet", () => {
  it("collapses whitespace and slices after stripping banners", () => {
    const text = "==========\n\n  AusCERT   bulletin\n----------\nbody text";
    expect(previewSnippet(text, 200)).toBe("AusCERT bulletin body text");
    expect(previewSnippet(text, 7)).toBe("AusCERT");
  });

  it("returns plain text unchanged apart from trimming", () => {
    expect(previewSnippet("  hello world  ", 200)).toBe("hello world");
  });
});
