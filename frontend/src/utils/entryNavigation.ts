/**
 * Where "previous"/"next" lands when moving between articles.
 *
 * List order is the primary answer, but it isn't always enough: with auto-read
 * on, a Hide-Read list drops each article the moment you move off it, so the
 * one you just came from is no longer in the list and plain index math has
 * nothing to step back to. The visit trail — the order entries were actually
 * opened in — covers that gap, so j/k and the reader's prev/next keep working
 * after an article has been read out from under them.
 */
export function adjacentEntryId(
  direction: "prev" | "next",
  currentId: string | null,
  navIds: string[],
  trail: string[],
  trailIndex: number,
): string | null {
  if (!currentId) return null;

  const listIdx = navIds.indexOf(currentId);
  if (listIdx !== -1) {
    const fromList = navIds[direction === "next" ? listIdx + 1 : listIdx - 1];
    if (fromList) return fromList;
  }

  const trailIdx = trail[trailIndex] === currentId ? trailIndex : trail.lastIndexOf(currentId);
  if (trailIdx === -1) return null;
  return trail[direction === "next" ? trailIdx + 1 : trailIdx - 1] ?? null;
}
