# Story Threads

For operators and contributors. It explains how story threads are built, how each thread's timeline is written, where threads appear, and which settings tune them. For the user view, read the user guide page [Story threads](guide/story-threads.md).

One news story often arrives twenty times from different outlets. A **story thread** groups those articles into one object: a timeline of what changed in each wave of coverage, the outlet that reported it first, and the re-reports grouped under the article they repeat. The same vectors that build threads also answer "find articles like this one".

Two other mechanisms handle repeats: the `feed_echo` signal lowers their score (`_feed_echo` in `backend/app/intelligence/signals.py:761`), and `temporal_clusters()` groups them on the fly by shared entities (`backend/app/intelligence/correlation.py:3155`). Neither produces an object that can be named, read or opened later.

- [Vector substrate](#vector-substrate)
- [How a thread is built](#how-a-thread-is-built)
- [The spine](#the-spine)
- [Where threads appear](#where-threads-appear)
- [Settings](#settings)
- [Operations](#operations)

---

## Vector substrate

An **embedding** is a list of numbers that places a text in "meaning space"; two articles about the same thing get vectors that point the same way (high cosine similarity).

- **Storage.** `entry_embeddings` holds one `halfvec(768)` per entry, with an HNSW cosine index (migration `s4t6u8w0x2y4`). `halfvec` uses 2 bytes per number instead of 4, which halves the index's memory at almost no loss of accuracy.
- **Database image.** pgvector is compiled into the database image from `db/Dockerfile`, on the same `postgres:16-alpine` base. The image must stay on Alpine (musl): moving an existing data directory to a glibc image changes text sorting and breaks every index on a text column until a full `REINDEX`.
- **The model.** `backend/app/services/embeddings.py` calls Ollama's `/api/embed`. The embedder does not use AI task assignments: it is bulk, non-generative work that must keep running even when every chat provider is paused. It has its own settings and borrows only the Ollama provider row's base URL and token.

**What gets embedded.** The title, a blank line, then the first 1,500 characters of the best body: the summary if it is a real lede (300 characters or more), otherwise the article text. Many feeds ship a summary of a few dozen characters, so preferring the summary every time would embed little more than the headline. No task prefix is added. nomic-embed-text documents `search_document:` and `clustering:` prefixes, but measured on real headline pairs the clustering prefix raised unrelated pairs much more than matched ones, which halves the gap the thresholds rely on.

**The sweeper** (`app.workers.embedding_tasks.embed_pending_entries`, job `embed-entries`, every 15 minutes, newest first) works three queues in order:

1. Entries with no vector.
2. Entries embedded with a different model.
3. Only when both are empty: the least-recently-checked stored vectors, re-hashed against the entry's current text. A re-fetched body, a re-sanitized article or a change to the embedded text above is picked up without a manual backfill. `verified_at` records how far the rotation has reached.

It does nothing while `embeddings_enabled` is off. It runs on the **default** queue: the `ai` worker runs one task at a time to pace a single GPU, and a backfill of thousands of entries there would block everything else.

## How a thread is built

`assign_entries()` (`backend/app/intelligence/story_threads.py:833`) runs every two hours (job `story-threads`). For each article it checks whether the article continues an existing story.

| Step | Rule |
|---|---|
| **Candidates** | Embedded, not yet threaded, inside `thread_window_days`, with at least `thread_min_body_chars` of body. Articles never checked before go first; within each group, **oldest first**, because a story's first article must exist before later waves can join it, and it identifies which outlet published first. Advisory bulletins are left out by the body floor and by title (`BULLETIN_TITLE_RE`); their vectors encode the template, not a subject, so they look similar to everything. |
| **Retrieve** | The nearest open threads by centroid, limited to threads whose latest article is within `thread_gap_days` of this one. An article three weeks later is a new story, not a continuation. |
| **Join** | All must hold: cosine to the thread's **closest single article** clears `thread_join_similarity` (if they share an entity) or `thread_join_similarity_no_entity` (if not); cosine to the centroid clears the same bar minus `CENTROID_MARGIN` (0.08); the pair is not two unrelated catalogs (guard 5); the outlet has fewer than `SAME_SOURCE_LIMIT` (3) articles in the thread. A thread with `ENTITY_REQUIRED_ABOVE` (12) or more articles also requires a shared entity. |
| **Echo** | A joining article at or above `thread_duplicate_similarity` that brings no entity the thread lacks is a re-report. It is kept, linked to the article it repeats, and grouped under it. |
| **Seed** | If no thread fits, look at unthreaded neighbors within `thread_gap_days` either side. A new thread starts when at least `thread_min_entries` articles clear `thread_seed_similarity`, from at least `thread_min_sources` distinct outlets, with no outlet over `DOMINANT_SOURCE_SHARE` (two thirds) or past `SAME_SOURCE_LIMIT`, and they are not a set of catalogs. |
| **Merge** | Open threads whose centroids reach `thread_merge_similarity` and whose time ranges overlap, or come within `thread_gap_days` of each other, become one. A thread under `ENTITY_REQUIRED_ABOVE` articles that shares `MERGE_SHARED_ENTITIES` (2) key actors, malware families or CVEs with a bigger one needs only `thread_merge_similarity_shared_entity`, in the same way a shared entity lowers the join bar. This covers a common case: a story's next chapter narrowly misses the join bar and starts a thread beside the existing one, the next outlets join the nearer thread, and the two centroids sit at 0.87 with the same actors on both sides. Products and tools never count as shared (one AI-abuse thread would otherwise absorb unrelated stories through "Microsoft 365"). One shared CVE is a mention, not a chapter. Two threads both past that size are two stories, however close their centroids are. Incremental grouping splits a story when two outlets break it hours apart, and the join rules split it again when a large thread turns away an entity-less wave; the plain merge bar sits a little under the no-entity join bar so that second split heals. A thread seeded during a pass gets its centroid at once, so later candidates in the same pass can join it and the merge step can see it. |
| **Prune** | Threads whose stored counts differ from their rows in `story_thread_entries` are corrected, and a thread left with fewer than two articles is deleted. Feed retention and feed deletion remove rows from `story_thread_entries`; without this step the thread would keep stale counts and a timeline about articles that are gone. |

A thread that has had no new article for `thread_dormancy_days` becomes `dormant`: it stops accepting articles but keeps its history.

Six guards:

1. **Closest article, not centroid.** A centroid is an average. The average of a twenty-article thread drifts toward "vulnerability news" and then attracts every vulnerability article, so joining on the centroid alone chains unrelated articles into one long thread.
2. **Background entities are not identity.** "Linux" and "Windows" each sit on about 15% of a three-week window. Any entity on more than `AMBIENT_ENTITY_SHARE` (2%) of the window's articles is ignored in the shared-entity test. This is measured per window, and skipped when the window has fewer than `AMBIENT_MIN_WINDOW` (200) articles, where the numbers are noise.
3. **One outlet is not corroboration.** After `SAME_SOURCE_LIMIT` articles from one source domain, that outlet adds no more articles to the thread, in any role. Two unrelated Red Hat errata look like "0.9 cosine and no new entity" to an embedding, so echoes get no exemption.
4. **Body floor, and a title test.** A large share of a typical window is template bulletin rows. The ones long enough to clear the floor (AusCERT's "package: CVSS (Max): 7.5" bulletins, Red Hat RHSA errata, NVD "CVE-YYYY-NNNNN: …" rows, ZDI and Siemens SSA advisories) are caught by `BULLETIN_TITLE_RE`. NVD needs this rule most: it mirrors every vendor's own advisory page, so a vendor's monthly release would otherwise arrive as "two outlets" agreeing on thirty bugs and seed a thread per CWE family.
5. **A catalog is not a story.** "CISA adds ownCloud, Linux Kernel and JFrog flaws to KEV" names many entities, and each installment names different ones. One chance overlap clears a shared-entity bar, so such roundups would chain into a fake story. When both sides name at least `ROUNDUP_MIN_ENTITIES` (4) entities and share less than `ROUNDUP_MIN_OVERLAP` (25%) of them, it is a catalog. An article that names no entities is never caught by this test.
6. **Never-checked articles go first.** Articles inside the gap window are offered again on every pass, in case their story has not broken yet. Once there are more of them than `thread_sweep_limit`, a plain oldest-first order would spend the whole pass re-checking old articles and never reach today's.

An outlet is the article's host name, not its feed row, using `_source_key()` from `backend/app/intelligence/signals.py`; one outlet publishing through four feeds is one outlet. Every article the sweep considers is stamped `threaded_checked_at`, and stays eligible for re-checking only while it is inside its own gap window.

## The spine

`backend/app/services/thread_narrative.py` writes one update per wave of coverage, in one of two ways:

- **Heuristic** (no AI, the fallback). Updates are grouped by day. The day's highest-scoring article is the headline. The first day is marked `first_disclosure` and the day with the most coverage `peak`. Echoes are counted, not listed. Every thread has a readable timeline, even when no AI provider answers.
- **Written** (`story_thread_spine` prompt, `narrate-story-threads` job at 06:10 on the `ai` queue). A title, a one-line summary and an update per wave, under the same rules as the threat-board brief: only the supplied articles, no invented counts, hedges kept. Updates point at articles by their index in the prompt, which is mapped back to entry IDs.

Both are keyed by a hash of the member list, so an unchanged thread costs nothing. The sweeper fills a heuristic timeline only where there is none, and never replaces a written timeline with a heuristic one.

`narrated_at` is set only when a model wrote the thread's current timeline: not by the heuristic fill, and not by an AI call that failed or timed out. The nightly job picks threads with no written timeline, or whose members changed after it was written (up to `thread_narrate_limit`), and skips only threads a model has already narrated. The reader reads this column to show its note that the timeline is grouped by day and not yet written. A failed call leaves the thread in the next night's queue.

Feed summaries vary in format (raw `<p>` markup, a Google News link wrapped around a long tracking token), so `clean_body()` strips tags and drops anything that is not prose.

## Where threads appear

**Priority Queue.** `GET /api/entries/priority-queue` (`build_priority_queue`, `backend/app/api/entries.py:1452`) returns entries and threads as one ranked list; `ThreadRow` draws the thread rows. A thread ranks by the score of its best *non-echo* article, read or not, so reading one doesn't change it, and its articles are left out of the list as single rows: the thread row stands for them. A thread with nothing unread does not appear, because the queue lists what to read next.

Leaving members out is safe because a thread always scores at least as high as each article it folds, so its row comes before them. With infinite scroll, a thread that outranks nothing on the current page waits for a later page instead of being added at the end. Otherwise the next page would insert it mid-list and shift every row under the reader's cursor. Threads still waiting when the last page loads go at the end. The reader, the CLI and agents all get the same order from this one endpoint.

**Reader pane.** `ThreadReader` shows the timeline, the coverage list with the first outlet tagged, grouped echoes behind a toggle, what the thread produced (techniques, CVEs, products, rules) and the nearest other threads, which open in the same pane.

**Threats board** (`/workbench/threats`, `backend/app/services/threat_board.py`). The ranking counts *stories*, not outlets. A row's `stories` is one per thread holding its coverage in the window, plus one per source domain no thread claimed. Without embeddings this is the number of distinct outlets; with them, a wave of re-reports counts once. `echoes_folded` shows the hidden count in the caption. Also:

- **The row's lead article** is its earliest article inside its main story, when one thread holds at least `THREAD_LEAD_SHARE` (half) of the row's articles. Within the story, an article that names the row's threat is preferred over one that does not.
- **Two rows merge into one** when a single thread holds `THREAD_MERGE_SHARE` (three quarters) of each and at least two of its articles, such as an operator and the payload it drops. Only open rows merge, and the absorbed rows are listed in `merged_from`. Two spellings of one threat also merge by name.
- **Stories with no entity get a row.** A thread whose articles name no actor, malware or CVE cannot key an entity row, so `build_story_rows` gives it one: keyed by the thread's slug, with `is_story` set and `collect` as its action. Opening it opens the thread (in the Workbench's docked reader from the board; `/priority-queue?thread=<slug>` is its shareable address). It must carry at least one technique, observable, or tracked product; otherwise any news story would qualify. Its unit count is its number of updates, and its technique count is capped at `STORY_TECHNIQUE_CAP` (6).
- **`GET /api/threat-board/precedent?thread=<slug>`** finds earlier threads similar to this one, from thread centroids, above the same 0.7 floor that "more like this" uses. The drawer shows the top match.
- The nightly `threat_brief` reduces its input to one article per story before prompting (`collect_brief_entries`, `backend/app/services/threat_brief.py:226`).

**"More like this".** `GET /api/entries/{id}/similar` answers from the embedding index, and falls back to Meilisearch term overlap for entries that have no vector yet.

**Briefings.** The daily briefing (read by the Morning Briefing rule and the day-divider summaries) and batch `run_ai_task` actions reduce their input to one article per story (`fold_by_thread()`) and tell the model how many outlets carried each. Eight outlets reporting one zero-day count as one development. See [automation-ai-enrichment.md](automation-ai-enrichment.md#one-article-per-story).

**Scores.** With `thread_signals_enabled` on, the `feed_echo` and `source_convergence` signals read thread membership instead of counting shared entities in a 72-hour window. An article the thread grouped as an echo is the re-report, whatever its entity overlap; an article kept as an update is not, however many entities it shares; and the thread's outlet count is the corroboration. Articles are scored before they are threaded, so after each sweep `rescore_entries_for_threads` (`backend/app/workers/signal_tasks.py:412`) re-scores every article in each thread that changed: one more outlet on a story is one more point of corroboration for every article already in it. See [engine.md](engine.md#signal-catalog).

A thread has **no page of its own**. The queue is the index of current stories, and a second list of the same objects would duplicate it. `/priority-queue?thread=<slug>` opens one directly for bookmarks and links.

API: `GET /api/threads`, `GET /api/threads/{slug}`, `POST /api/threads/{id}/open` (records when you last saw the thread, which the "N new" count measures from).

## Settings

All under **Settings → Engine → Score stage → Story threads**, and inline on the `embed-entries`, `story-threads` and `narrate-story-threads` job rows in Engine → Jobs. They sit under Score because a thread is read in the queue that stage ranks.

| Setting | Default | What it does |
|---|---|---|
| `embeddings_enabled` | `true` | Master switch for the embedding sweeper |
| `embedding_model` | `nomic-embed-text` | Must output 768 dimensions |
| `embedding_base_url` | *(blank)* | Blank uses the Ollama provider row's URL |
| `embedding_batch_size` | `32` | Texts per `/api/embed` call |
| `embedding_backfill_limit` | `2000` | Entries embedded per run |
| `thread_window_days` | `21` | How far back an article can still be threaded |
| `thread_dormancy_days` | `14` | Days of silence before a thread stops accepting articles |
| `thread_gap_days` | `7` | Most quiet days between an article and the thread it joins |
| `thread_min_body_chars` | `400` | Below this an entry is treated as a bulletin row |
| `thread_join_similarity` | `0.84` | Bar to the closest article, with a shared entity |
| `thread_join_similarity_no_entity` | `0.90` | Bar without a shared entity |
| `thread_seed_similarity` | `0.84` | Bar between unthreaded articles to start a thread |
| `thread_duplicate_similarity` | `0.90` | At or above this, an article is an echo |
| `thread_merge_similarity` | `0.90` | Two overlapping threads this close become one |
| `thread_merge_similarity_shared_entity` | `0.85` | The merge bar for a chapter-sized thread sharing two key actors, malware or CVEs with a bigger one |
| `thread_sweep_limit` | `1500` | Articles examined per sweep; keep it above the number published inside the gap window |
| `thread_min_entries` | `3` | Articles needed to start a thread |
| `thread_min_sources` | `2` | Distinct outlets needed to start a thread |
| `thread_narrate_limit` | `10` | Threads given a written timeline per nightly run |
| `thread_signals_enabled` | `true` | Let thread membership answer the echo and convergence signals |

The constants in capitals above (`SAME_SOURCE_LIMIT`, `CENTROID_MARGIN`, …) are in `backend/app/intelligence/story_threads.py` and are not settings.

## Operations

**Prerequisite: the embedding model on the Ollama host.**

```bash
# on the Ollama host
ollama pull nomic-embed-text   # about 274 MB
```

Without it every sweep logs a failed batch and embeds nothing.

**Keep models loaded.** If the Ollama server unloads a model after each request, every AI call pays the full load time before its first token, and each embedding batch can push the chat model out of memory. A per-request `keep_alive` (the `story_thread_spine` assignment sends `30m`) has no effect if the server pins its own default, so set it on the server:

```bash
# in the Ollama service environment
OLLAMA_KEEP_ALIVE=30m   # or -1 to never unload
```

nomic-embed-text is small, so it and a 9B chat model fit in memory together on an 8 GB card, but only if the server keeps both loaded.

**The output schema controls timeline quality.** The timeline prompt sets `maxLength` on every string and an `enum` on `kind`. Without those limits a small local model can write a long summary, hit the token ceiling and never close its JSON. With them, a valid timeline takes about 300 tokens. Local models need the schema to enforce brevity; asking in the prompt is not enough. The assignment's output ceiling is 2,000 tokens. Narration is optional: threads show their heuristic timeline whether or not a model answers, and `ensure_spine` falls back instead of failing.

**First run on an existing archive.**

1. The `db` service is built from `db/Dockerfile`. On a host that has never built it, build it once by hand before the automatic update does, so a failed build (no network, no disk) is seen at once:
   ```bash
   # on the production host
   docker compose -f docker-compose.prod.yml build db
   docker compose -f docker-compose.prod.yml up -d db   # about 30 s of downtime; the data volume is untouched
   ```
2. Migrations run automatically when the API container starts.
3. Make sure **Entry Embeddings** is on (Settings → Engine → Score stage → Story threads, or the `embed-entries` job row).
4. Let `embed-entries` work through the archive. At the default limit it embeds about 8,000 entries an hour, newest first, so threads form on recent news within the first hour. Raising `embedding_backfill_limit` finishes sooner but loads the Ollama host more.
5. `story-threads` runs every two hours with no intervention. Keep `thread_sweep_limit` above the number of articles published inside `thread_gap_days`, or re-checks crowd out new arrivals (guard 6).

**Expect one round of tuning.** The right thresholds depend on the feed mix, so they are settings. A bar set too low gives threads whose articles share only a topic. A bar set too high splits one story across several threads; try lowering `thread_merge_similarity` before lowering the join bars.

**Related docs:** [engine.md](engine.md) (signal scoring and the Radar queue), [data-model.md](data-model.md) (tables), [entries.md](entries.md) (where an entry meets its thread).
