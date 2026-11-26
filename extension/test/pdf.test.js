import assert from "node:assert/strict";
import { test } from "node:test";

import { isPdfType, isPdfUrl, pdfFileName } from "../src/lib/pdf.js";

test("isPdfUrl looks at the path only", () => {
  assert.equal(isPdfUrl("https://cisa.example/aa24-038a.pdf"), true);
  assert.equal(isPdfUrl("https://cisa.example/AA24.PDF?download=1#page=2"), true);
  assert.equal(isPdfUrl("https://cisa.example/view?file=a.pdf"), false);
  assert.equal(isPdfUrl("not a url"), false);
});

test("isPdfType", () => {
  assert.equal(isPdfType("application/pdf"), true);
  assert.equal(isPdfType("application/pdf; charset=binary"), true);
  assert.equal(isPdfType("text/html"), false);
  assert.equal(isPdfType(null), false);
});

test("pdfFileName prefers the address, else the title", () => {
  assert.equal(pdfFileName("https://x.example/docs/Report%202024.pdf", "t"), "Report 2024.pdf");
  assert.equal(pdfFileName("https://x.example/download?id=1", "Q3: threat/report"), "Q3 threat report.pdf");
});
