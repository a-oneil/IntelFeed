# Story threads

How IntelFeed folds one unfolding story — covered by twenty outlets over three days — into a single row you can read, and how to read it. Read this when a row in the [Priority Queue](priority-queue.md) says "11 outlets · 23 articles · 6 new" and you want to know what it's telling you.

Search is keyword-only, so one story arrives over and over: the original report, the follow-up with a new indicator, then a dozen outlets re-reporting the first one. A **story thread** is the object that holds all of that together — the story, its articles, and a short **spine** of what actually changed in each wave.

## Check that threading is on

Threads are built from article embeddings, and the embedding sweeper is **off by default**. If you never see a thread row, the usual reason is that nobody turned it on.

An admin enables it under **Settings → Engine → Score stage → Story threads** (`embeddings_enabled`). It embeds with Ollama, using the **Embedding base URL** setting if you've set one, otherwise the base URL of your first Ollama provider, otherwise Ollama's default local address. So a provider row isn't required, but a reachable Ollama with the embedding model (`embedding_model`, default `nomic-embed-text`) is. It works through the backlog newest-first, so threads appear over the first few runs rather than all at once. The settings and how they're tuned are in [story-threads.md](../story-threads.md) in the developer docs.

Threading also trails ingest — it runs on a sweep, up to about half an hour behind — so a story that broke a few minutes ago may show as loose articles first and fold into a thread shortly after.

## Where you'll see one

- **The Priority Queue.** A thread is one row, in place of its articles. It ranks as its best *unread* article plus a small bump for every extra outlet carrying it, and the articles inside are withheld from the list so the story appears once. A thread you've finished reading drops out of the queue entirely — the queue answers "what should I read next", not "what exists".
- **The reader pane.** Open a thread row and the reader shows the thread itself (below).
- **The Threats board.** Rows are counted in *stories*, not outlets, so a wave of re-reports counts once. A story that resolved to no actor, malware family or CVE still gets a row if it carries something extractable — a technique, an observable, or a product in your stack — and opening it shows that thread in the Workbench's docked reader. See [The Threats board](threats-board.md).
- **More like this.** In the reader, similar articles come from the same embeddings, falling back to keyword overlap for anything not yet embedded.
- **Briefings and scoring.** Daily briefings fold their input to one article per story before summarising, so a day where eight outlets covered one zero-day reads as one development. An article a thread folded as a re-report is also scored as one — the *feed echo* signal described in [Priority Queue and watching](priority-queue.md).

A thread has no page of its own, on purpose: the queue is already the index of what's unfolding. A thread's address, `/priority-queue?thread=<slug>`, opens it directly, which is what a bookmark or a link in a note uses.

## Reading a thread

**The header** gives the date range, the outlet count, which outlet got there **first**, and the **yield**: how many techniques, CVEs and detection rules the thread's articles produced, and how many near-duplicate re-reports were folded. Key entities sit underneath and link to their profiles.

**The spine** is the point. It's one line per *wave* of coverage rather than one per article, each tagged with what kind of wave it was:

| Tag | Meaning |
| --- | --- |
| **First disclosure** | The first article on the story |
| **New tradecraft** | A technique, tooling or payload not previously reported in the thread. Only a *written* spine (below) uses this tag — a bigger victim count isn't new tradecraft |
| **Peak coverage** | The loudest day |
| **Update** | A later development |

Re-reports aren't listed on the spine; each wave just says how many near-duplicates it folded.

You may see the note **"Spine grouped by day — not yet written."** Every thread starts with a spine built mechanically — beats grouped by day, with the highest-scoring article as each headline — which needs no AI. If an AI provider is configured, a nightly pass replaces it with a written title, one-line summary and a beat per wave. The mechanical spine is accurate, just terser; the note disappears once a model has written it.

**Coverage** lists the thread's articles, with the one that got there first tagged **first**. The re-reports sit behind a disclosure ("*N* re-reports folded") — kept, attributed to the article they echo, and out of your way.

**Nearest threads** at the bottom are other stories close to this one; they open in the same pane.

**Mark as read** in the pane's top bar clears every article in the thread at once, which is also how a thread leaves the queue.

## "N new"

A collapsed thread row shows how much of the story is new since you last opened it. Opening a thread stamps that moment, so the count means "since I last looked", not "since it started".

## Why an article isn't in a thread

- It hasn't been embedded or swept yet (see the delay above).
- It's too short, or it's a templated bulletin — security-advisory feeds that publish hundreds of near-identical rows, such as distro errata and CVSS bulletins. Their embeddings describe the template rather than a subject, so they're deliberately kept out.
- It's a roundup. "CISA adds three flaws to KEV" names a different set of products every time, and chaining those together would invent a story that isn't one.
- It's the only article on its story so far. Starting a thread takes at least three similar articles from at least two distinct outlets (by default), and one outlet publishing four times is still one outlet.

If threads fold things that don't belong together, or miss ones that do, that's tuning, and it's an admin's job: the knobs and what each does are in the developer docs' [Story Threads](../story-threads.md) page.
