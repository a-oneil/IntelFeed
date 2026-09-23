import type { CampaignSuggestion } from "@/api/types";

/** Suggestions grouped the way they'll be acted on: a story at a time. */
export type SuggestionGroup =
  | { kind: "story"; slug: string; title: string; held: number; total: number; items: CampaignSuggestion[] }
  | { kind: "entry"; item: CampaignSuggestion };

/**
 * A campaign holding two articles of a nine-article story should be offered the
 * other seven as one row, not seven rows that happen to share entities. Stories
 * the campaign is already part of come first — that is the surest match there
 * is — and a story contributing a single article is just that article.
 */
export function groupSuggestions(suggestions: CampaignSuggestion[]): SuggestionGroup[] {
  const stories = new Map<string, Extract<SuggestionGroup, { kind: "story" }>>();
  const groups: SuggestionGroup[] = [];

  for (const item of suggestions) {
    if (!item.thread_slug) {
      groups.push({ kind: "entry", item });
      continue;
    }
    let story = stories.get(item.thread_slug);
    if (!story) {
      story = {
        kind: "story",
        slug: item.thread_slug,
        title: item.thread_title || item.title,
        held: item.thread_in_campaign ?? 0,
        total: item.thread_article_count ?? 0,
        items: [],
      };
      stories.set(item.thread_slug, story);
      groups.push(story);
    }
    story.items.push(item);
  }

  return groups.flatMap<SuggestionGroup>((group) =>
    group.kind === "story" && group.items.length < 2
      ? group.items.map((item) => ({ kind: "entry" as const, item }))
      : [group]
  );
}
