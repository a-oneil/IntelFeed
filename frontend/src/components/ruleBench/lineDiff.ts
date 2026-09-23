export type DiffOp = "same" | "add" | "remove";
export interface DiffLine { op: DiffOp; text: string }

/**
 * Line diff between two rule bodies, computed client-side.
 *
 * The near-duplicate comparison has no endpoint and does not need one — rules
 * are tens of lines, so a full LCS table is cheap. Guarded anyway, because an
 * imported YARA blob can be long and a 2,000×2,000 table is not worth it.
 */
export function lineDiff(a: string, b: string, maxLines = 600): DiffLine[] {
  const left = a.split("\n");
  const right = b.split("\n");
  if (left.length > maxLines || right.length > maxLines) {
    return [
      ...left.map((text): DiffLine => ({ op: "remove", text })),
      ...right.map((text): DiffLine => ({ op: "add", text })),
    ];
  }

  const lcs: number[][] = Array.from({ length: left.length + 1 }, () =>
    new Array<number>(right.length + 1).fill(0),
  );
  for (let i = left.length - 1; i >= 0; i--) {
    for (let j = right.length - 1; j >= 0; j--) {
      lcs[i][j] = left[i] === right[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) {
      out.push({ op: "same", text: left[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ op: "remove", text: left[i++] });
    } else {
      out.push({ op: "add", text: right[j++] });
    }
  }
  while (i < left.length) out.push({ op: "remove", text: left[i++] });
  while (j < right.length) out.push({ op: "add", text: right[j++] });
  return out;
}
