# Story Threads

For operators and contributors: how threads are built, how the spine is written, where they surface, and the settings that tune them. If you only want to *use* threads, read the user-guide page [Story threads](guide/story-threads.md).

*Last verified: 2026-09-13*

Search is keyword-only, so one story arrives twenty-three times. Before this
feature the platform could only *penalise* the repeats: `feed_echo`
(`backend/app/intelligence/signals.py:578`) subtracts score from an entry that
shares entities with an earlier one, and `temporal_clusters()`
(`backend/app/intelligence/correlation.py:2345`) recomputes a throwaway
entity-overlap cluster on every request. Neither leaves anything you can read,
name or come back to.

A **story thread** is that missing object: one unfolding story, with a spine of
what actually changed in each wave, the outlet that got there first, and the
re-reports folded underneath the article they echo. The same vectors that build
threads also answer "find articles like this one".

- [Vector substrate](#vector-substrate)
- [How a thread is built](#how-a-thread-is-built)
- [The spine](#the-spine)
- [Where threads appear](#where-threads-appear)
- [Settings](#settings)
- [Operations](#operations)

---

## Vector substrate

`entry_embeddings` holds one `halfvec(768)` per entry with an HNSW cosine index
(migration `s4t6u8w0x2y4`). `halfvec` rather than `vector` because at 134k rows
the 2-bytes-per-dimension form saves ~200MB of resident index on a host that has
OOM-flapped before, and recall loss at 768 dimensions is negligible.

pgvector is compiled into the database image from `db/Dockerfile` — the same
`postgres:16-alpine` the stack has always run, *not* the Debian-based
`pgvector/pgvector` image. The data directory was `initdb`'d under musl; moving
it to glibc changes text collation and silently corrupts every btree index on a
text column until a full `REINDEX`. Same base, same libc, no data migration.

Embeddings are produced by `backend/app/services/embeddings.py` calling Ollama's
`/api/embed` through `AIProvider.embed()`. The sweeper is deliberately *not*
routed through the AI task/assignment machinery: embedding is bulk,
non-generative, promptless work that must keep running when every generative
provider is paused or inactive. It reads its own settings and borrows only the
Ollama provider row's base URL and bearer token.

The text embedded is `title + "\n\n"` and then the first 1500 characters of the
best available body — the entry's summary when it is a real lede (300 characters
or more), the article text when it is not. 70% of the corpus ships a summary
under 200 characters (130 entries ship a three-character stub) while averaging
4,381 characters of body, so preferring the summary unconditionally embedded the
headline with noise attached. No task prefix: nomic-embed-text documents `search_document:` / `clustering:`
prefixes, and both were measured against real headline pairs — the clustering
prefix lifts an unrelated pair from 0.45 to 0.68 cosine while lifting a matched
pair from 0.96 to 0.98, costing roughly half the separation the thresholds
depend on.

The sweeper works three queues in order of cost: entries with no vector, then
entries embedded under a different model, then — only when both are empty — the
least-recently-verified slice of what is already stored, re-hashed against the
entry's current text. That third pass is what makes `content_hash` mean
something: a re-sanitized article, a re-fetched body, or a change to the text
recipe above is picked up on the next rotation instead of needing a hand-run
backfill. `verified_at` is the rotation marker; a confirmed row is stamped and
moves to the back.

`app.workers.embedding_tasks.embed_pending_entries` runs on the **default**
queue every 15 minutes, newest entries first, and does nothing at all until
`embeddings_enabled` is on. It is on the default queue on purpose: the `ai`
worker is a concurrency-1 serializer for one GPU and the CLI credentials volume,
and a multi-thousand-entry backfill parked behind a nightly enrichment run would
starve both.

## How a thread is built

`backend/app/intelligence/story_threads.py::assign_entries` walks unthreaded,
embedded entries in the window — never-looked-at ones first, **oldest first**
within each half (a story's first article has to exist before the later waves can
join it, and it is also the "who published first" answer) — and asks one question
per entry: *does this continue a story we already have?*

| Step | Rule |
|---|---|
| **Candidates** | Embedded, unthreaded, inside `thread_window_days`, with at least `thread_min_body_chars` of body, **never-looked-at ones first**. Bulletin rows are excluded twice over: by the body floor ("kubernetes: CVSS (Max): None") and by title, which is the only thing that catches a 20,000-character Red Hat erratum. Their embeddings encode the template, not a subject, so they sit at 0.8 cosine to everything. |
| **Retrieve** | Nearest open threads by centroid distance, restricted to threads whose last article is within `thread_gap_days` of this one. A story is bursty; three weeks later is a sequel. |
| **Join** | Cosine to the thread's **nearest individual member** clears `thread_join_similarity` (with a shared entity) or `thread_join_similarity_no_entity` (without), *and* centroid similarity clears the same bar less `CENTROID_MARGIN`, *and* the two sides are not a pair of catalogues that merely intersect (see guard 5), *and* the outlet is under `SAME_SOURCE_LIMIT`. |
| **Echo** | A joining article at or above `thread_duplicate_similarity` that introduces no entity the thread lacks is a re-report: kept, attributed to the article it echoes, folded out of the way. |
| **Seed** | No thread fits: look at the article's unthreaded neighbours, within `thread_gap_days` **either side**. `thread_min_entries` of them above `thread_seed_similarity`, from `thread_min_sources` distinct outlets, with no single outlet over `DOMINANT_SOURCE_SHARE` or past `SAME_SOURCE_LIMIT`, and not a set of disjoint catalogues, is a story breaking. |
| **Merge** | After assignment, open threads whose centroids sit at `thread_merge_similarity` with overlapping time ranges are folded into one — incremental clustering splits when two outlets break the same story hours apart. |
| **Prune** | Finally, threads whose membership no longer matches what they claim are reconciled, and a thread left holding fewer than two articles is deleted. Feed retention and feed deletion cascade through `story_thread_entries`; the thread itself would otherwise keep its counts, its centroid and a spine describing articles that no longer exist. |

Six guards exist because the corpus taught them, and each is load-bearing:

1. **Nearest member, not centroid.** A centroid is an average, and the average
   of a twenty-article thread is a vector for "vulnerability news" that then
   attracts every vulnerability article there is. The first pass over the live
   corpus produced one thread with 103 articles across three weeks this way.
2. **Ambient entities are not identity.** "Linux" sits on 16% of a three-week
   window and "Windows" on 15%. Any entity above `AMBIENT_ENTITY_SHARE` of the
   window is discarded before the shared-entity test — measured per window
   rather than hardcoded, and skipped entirely below `AMBIENT_MIN_WINDOW`
   articles, where prevalence is noise.
3. **One outlet is not corroboration.** Past `SAME_SOURCE_LIMIT` articles from
   the same source domain, that outlet contributes nothing further to the
   thread — in any role. The cap once exempted echoes, on the reasoning that a
   re-report should still be folded rather than left loose; but "0.9 cosine and
   no new entity" is precisely what two *unrelated* Red Hat errata look like to
   an embedding, and six of them chained themselves into one "story" through
   that exemption.
4. **Body length floor, and a title test.** 41% of a live window is template
   bulletin rows. The ones that clear the floor anyway — AusCERT's
   "package: CVSS (Max): 7.5" bulletins and Red Hat's RHSA errata, 16% of a
   three-week window between them — are caught by `BULLETIN_TITLE_RE`.
5. **A catalogue is not a story.** "CISA adds ownCloud, Linux Kernel and JFrog
   flaws to KEV" is entity-dense and entity-disjoint: each instalment names half
   a dozen CVEs and products, almost none of them last week's. One incidental
   overlap clears a shared-entity bar, so the format assembled itself into a
   ten-article "story" that was really ownCloud, PaperCut, Cisco, Citrix,
   Fortinet and RouterOS at once. When both sides carry `ROUNDUP_MIN_ENTITIES`
   or more and agree on less than `ROUNDUP_MIN_OVERLAP` of them, it is a
   catalogue. Density is what keeps the test safe: a breach story that names
   nothing extractable has no entities to disagree about and never trips it.
6. **Never-looked-at articles go first.** Everything inside the gap window is
   re-offered on every pass, and once that set outgrows `thread_sweep_limit` a
   plain oldest-first ordering spends the entire budget re-examining the same
   five-day-old articles. Measured on the live corpus before the fix: 494 of 500
   candidates had already been checked, and the newest article the sweep could
   reach was three days older than the newest unthreaded one — today's pile, the
   only part of the window the queue is about, was never looked at until it was
   too old to fold.

Source identity is the article's host, not its feed row, reusing `_source_key()`
from `signals.py` — one outlet publishing through four feeds is one outlet.

Every entry the sweeper considers is stamped with `threaded_checked_at`, and
stays re-checkable only while it is inside its own gap window. Without that
marker each pass re-offered the same oldest unthreaded articles and never
reached the rest of the window.

## The spine

`backend/app/services/thread_narrative.py` writes one beat per *wave* of
coverage, in one of two ways:

- **Heuristic** (the default path, no AI): beats grouped by day, the day's
  highest-scoring article as the headline, first day marked `first_disclosure`,
  loudest marked `peak`, echoes counted rather than listed. Dev runs with every
  AI provider inactive and prod runs on one Ollama box — a thread page that only
  works when a model answers is a page that mostly does not work.
- **Written** (`story_thread_spine` prompt, nightly, `ai` queue): title, one-line
  summary, and a beat per wave under the same contract as the threat-board
  brief — supplied articles only, no counts, hedges preserved. Beats reference
  articles by their index in the prompt, which is mapped back to entry ids.

Both are keyed by a hash of the member set, so an unchanged thread costs
nothing. The sweeper only fills a heuristic spine where there is none; it never
demotes a written spine back to headlines.

The hash is not the whole cache key, though, and the difference matters: the
sweeper stamps it when it fills a *heuristic* spine, so treating a hash match as
"done" meant a thread that never gained another article was permanently ineligible
for a written one. Measured before the fix: 350 heuristic beats to 2 written ones,
with 134 of 136 threads reporting "cached" to the nightly pass. The AI pass now
skips only what a model actually wrote, and the nightly job selects threads that
*need* narration rather than the ten most recent — otherwise a run could spend
its whole budget on threads that immediately returned "cached".

`narrated_at` means "the spine on this thread right now was written by a model",
and nothing else sets it — not the heuristic fill, and not an AI call that failed
or timed out. The reader shows its "grouped by day — not yet written" note off
that column, and a failed call leaves the thread in tomorrow night's queue rather
than marking it done.

Entry summaries arrive as whatever the feed shipped — raw `<p>` markup, or a
Google News anchor wrapped around a 400-character tracking token — so
`clean_body()` strips tags and drops anything that does not come out as prose.

## Where threads appear

- **Priority Queue** — `GET /api/entries/priority-queue`
  (`build_priority_queue` in `backend/app/api/entries.py`) returns entries and
  thread rows as one ranked list, and `ThreadRow` renders the thread ones. A
  thread ranks by the score of its best *unread, non-echo* member, and every
  member is withheld from the entry stream — the
  row stands for them. A thread with nothing unread does not appear at all: the
  queue answers "read this next". This replaced the convergence-cluster rows,
  which were the same idea without persistence, a name, or a spine.

  Withholding members unconditionally is safe because a thread scores at or above
  every member it folds, so the row is always reached before the articles it
  stands for — the story is folded, never missing.

  Placement still has to survive an infinite scroll. A thread that outranks
  nothing on the current page has no knowable position yet, so it waits for a
  later page rather than being parked at the end — otherwise the next page would
  drop it into the middle and shove every row under the reader's cursor, once per
  page, all the way down. Whatever is still waiting when the last page of entries
  lands is flushed to the tail.

  This ordering lived in the client until it became an endpoint; the reader, the
  CLI and an agent now read the same queue in the same order.
- **Reader pane** — `ThreadReader` shows the spine, the coverage list with the
  first outlet tagged, folded echoes behind a disclosure, thread yield
  (techniques / CVEs / products / rules), and the nearest threads (which open in
  the same pane).

- **The Threats board** (`/workbench/threats`) — the ranking counts *stories*,
  not outlets. A row's `stories` is one per thread holding its window coverage
  plus one per source domain no thread claimed, so an un-embedded corpus scores
  exactly as it did before and a threaded one collapses a wave of re-reports
  into the one story it is; `echoes_folded` keeps what that hid visible in the
  caption. Four more consequences, all in
  `backend/app/services/threat_board.py`:

  - **The row's lede** is its own earliest article inside its story, not the
    most technique-dense one — but only where one thread holds at least
    `THREAD_LEAD_SHARE` (half) of the row's window articles. Inside the story,
    an article naming the row beats one that doesn't, or a single write-up that
    introduces three threats becomes the lede on all three rows.
  - **Two rows fold into one** when a single thread holds `THREAD_MERGE_SHARE`
    (three quarters) of each and at least two of its articles — an operator and
    the payload it drops are one job. Only open rows fold, and the absorbed
    rows are named in `merged_from`. The pre-existing name path (two spellings
    of one threat) is unchanged.
  - **Stories with no entity get a row.** A thread whose articles resolved to no
    actor, malware or CVE cannot key an entity row at all, which is why the
    board has never been able to show it. `build_story_rows` gives it one, keyed
    by thread slug, with `is_story` set and `collect` as its action, and opening
    it opens the thread (in the Workbench's docked reader when opened from the board;
    `/priority-queue?thread=<slug>` is its shareable address). It has to carry something
    extractable — a technique, an observable, or a product in your stack — or a
    funding round and a webinar qualify for the same reason a zero-day does.
    Its unit count is its beats, and its tradecraft term is its technique count
    capped at `STORY_TECHNIQUE_CAP`, since a story has no entity to have seen
    those techniques before.
  - **`GET /api/threat-board/precedent?thread=<slug>`** answers "have we seen
    this shape before" from the thread centroids, above the same 0.7 floor
    `similar_entries` uses. The drawer renders the top one.

  The nightly `threat_brief` also folds its input to one article per story
  before prompting (`collect_brief_entries`), the same treatment the daily
  briefing gives its batch.
- **`GET /api/entries/{id}/similar`** — "More like this" in the reader now
  answers from the embedding index, falling back to Meilisearch term overlap for
  entries that have not been embedded yet.

- **Every briefing** — the daily briefing (which the Morning Briefing rule and
  the in-app day-divider summaries both read) and batch `run_ai_task` actions
  fold their input to one article per story before prompting, and tell the model
  how many outlets carried each. A day where eight outlets covered one zero-day
  is one development, not eight. Measured on a live day: 60 articles became 49
  items, with the two loudest stories folding three re-reports each. See
  [automation-ai-enrichment.md](automation-ai-enrichment.md#one-article-per-story).
- **The score of every member** — `feed_echo` and `source_convergence` read
  thread membership rather than counting shared entities in a 72-hour window.
  An article the thread folded as an echo *is* the re-report, whatever its
  entity overlap says; an article the thread kept as a beat is explicitly not
  one, no matter how many entities it shares with earlier coverage; and the
  thread's outlet count is the corroboration. Because threading runs up to 30
  minutes behind ingest, this arrives as a rescore: the sweeper hands every
  thread whose membership changed to `rescore_entries_for_threads`, which
  re-scores the *whole* thread — one more outlet on a story is one more point of
  corroboration for every article already in it. Governed by
  `thread_signals_enabled`; off, and the entity probes answer as before. See
  [engine.md](engine.md#signal-catalog).

A thread has **no page of its own on purpose**. The queue is already the index of
what is unfolding, ranked by what is worth reading next; a second address listing
the same objects is the duplication threads exist to remove.
`/priority-queue?thread=<slug>` opens one directly, which is what a bookmark or an
external link uses.

API: `GET /api/threads`, `GET /api/threads/{slug}`, `POST /api/threads/{id}/open`
(stamps what "N new" is measured from).

## Settings

All under **Settings → Engine → Score stage → Story threads**, and inline on the
`embed-entries` / `story-threads` / `narrate-story-threads` job rows in Engine →
Jobs. They sit under Score because a thread is read in the queue that stage
ranks — it takes the score of its best unread beat.

| Setting | Default | What it does |
|---|---|---|
| `embeddings_enabled` | `false` | Master switch for the sweeper |
| `embedding_model` | `nomic-embed-text` | Must output 768 dimensions |
| `embedding_base_url` | *(blank)* | Blank uses the configured Ollama provider |
| `embedding_batch_size` | `32` | Texts per `/api/embed` call |
| `embedding_backfill_limit` | `2000` | Entries embedded per sweeper run |
| `thread_window_days` | `21` | How far back an article can still be threaded |
| `thread_dormancy_days` | `14` | Silence after which a thread stops accepting |
| `thread_gap_days` | `5` | Max quiet days between an article and the thread it joins |
| `thread_min_body_chars` | `400` | Below this an entry is a bulletin row |
| `thread_join_similarity` | `0.84` | Bar to the nearest member, with a shared entity |
| `thread_join_similarity_no_entity` | `0.90` | Bar without one |
| `thread_seed_similarity` | `0.84` | Bar between unthreaded articles to start a thread |
| `thread_duplicate_similarity` | `0.90` | At/above this an article is an echo |
| `thread_merge_similarity` | `0.92` | Two overlapping threads this close are one story |
| `thread_sweep_limit` | `1500` | Entries examined per sweep — keep it above the number published inside the gap window |
| `thread_min_entries` | `3` | Articles required to seed |
| `thread_min_sources` | `2` | Distinct outlets required to seed |
| `thread_narrate_limit` | `10` | Threads given a written spine per nightly run |
| `thread_signals_enabled` | `true` | Let thread membership answer the echo and convergence signals |

## Operations

**Prerequisite:** the embedding model must exist on the Ollama host —
`ollama pull nomic-embed-text` (274MB). Without it every sweep logs a failed
batch and embeds nothing.

### Which model writes the spine

`story_thread_spine` runs on whatever the Ollama provider serves —
`qwen3.5:9b` today, the same model as `threat_brief` and `cve_brief`, and the
right choice: measured on a self-hosted Ollama host (RTX 2070 Super) it
generates at **69 tokens/second**
and produces a valid, well-shaped spine in ~300 tokens. Model choice is not the
lever here. Two other things are:

1. **The output schema is the quality control.** With unbounded string fields,
   qwen3.5:9b wrote a six-sentence "summary", ran to the 4096-token ceiling and
   never closed the JSON — 224 seconds of GPU time for a parse error. With
   `maxLength` on every string and an `enum` on `kind`, the same prompt returns
   valid JSON in 306 tokens. Local models need the grammar to enforce brevity;
   asking politely in the prompt is not enough.
2. **`keep_alive` on the Ollama host dominates everything else.** That host
   currently unloads the model after each request and reloads 5.9GB from slow
   storage at ~38MB/s, so **every** AI call — spines, threat briefs, entry
   analysis — pays ~155 seconds before its first token. A request-level
   `keep_alive` does not override it (`/api/ps` reports no resident model
   seconds after a call), so it has to be fixed on the box:
   `OLLAMA_KEEP_ALIVE=30m` (or `-1`) in the Ollama service environment. With
   ten threads narrated per nightly run, that reload alone is ~26 minutes of
   the run.

Narration is optional either way: threads render their heuristic spine whether
or not a model ever answers, and `ensure_spine` falls back rather than failing.

**Before the first deploy — build the database image by hand.** The `db` service
now has a `build:` stanza, and production updates itself from a ~2-minute cron
(`update.sh`), so the first tick after this merges compiles pgvector on the
production host unattended. `update.sh` builds every image *before* it recreates
anything, precisely so a failed build means "not updated yet" rather than "no
database" — it logs the failure and retries on the next tick. Still, do the first
build deliberately rather than discovering that the host cannot reach GitHub or
has no disk left after the BuildKit cache cap:

```bash
ssh "$INTELFEED_PROD_HOST" 'cd intelfeed && docker compose -f docker-compose.prod.yml build db'
```

**Then, enabling on an existing install:**

1. Recreate the database container on the new image:
   `docker compose -f docker-compose.prod.yml up -d db` (~30s of downtime; the
   data volume is untouched, same base image and libc).
2. `alembic upgrade head` runs automatically on the API container.
3. Turn on **Entry Embeddings** in Settings → Engine → Score stage → Story
   threads (or on the `embed-entries` job row).
4. Let `embed-entries` walk the corpus. At the default limit it embeds ~8k
   entries/hour, so a 134k-entry archive is ~17 hours unattended, newest first —
   threads start forming on the recent window within the first run. Raising
   `embedding_backfill_limit` shortens that at the cost of more load on the
   Ollama host.
5. `story-threads` runs every 30 minutes and needs no intervention. Keep
   `thread_sweep_limit` above the number of articles published inside
   `thread_gap_days`, or re-checks crowd out the newest arrivals (guard 6).

**Check `OLLAMA_KEEP_ALIVE` on the model host before starting the backfill.** The
embedding sweep runs every 15 minutes against the same Ollama instance that
serves `qwen3.5:9b`. On a host that unloads between requests, each embed batch
evicts the chat model, and every generative call for the next 17 hours pays the
~155-second reload described above. `nomic-embed-text` is 274MB against the chat
model's 5.9GB, so both fit resident on an 8GB card — but only if the server is
told to keep them.

**Expect one round of tuning.** Every threshold above is a registered setting
precisely because the right values depend on the feed mix. The symptom of a bar
set too low is a thread whose articles are only related by topic; the symptom of
one set too high is the same story split across three threads (raise
`thread_merge_similarity`'s neighbours before lowering the join bars).

**Related docs:** [engine.md](engine.md) (signal scoring and the Radar queue this
folds into), [data-model.md](data-model.md) (table definitions),
[entries.md](entries.md) (where an entry meets its thread).
