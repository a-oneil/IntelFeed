# Feed Ingestion Pipeline

What happens when a feed is due: the poller locks it, `fetch_feed` downloads and parses it, new entries are stored and indexed, and each one starts the entry pipeline.

```mermaid
flowchart TD
    beat["Celery Beat: poll_due_feeds()<br/>(every 60 seconds)"] --> lock["Redis NX locks<br/>feed_fetch:{feed_id} (10-min TTL)"]
    lock --> fetch["fetch_feed(feed_id)<br/>Per-domain rate limiting<br/>Conditional GET (If-None-Match, If-Modified-Since)<br/>Auto-detect feed type (RSS/Atom/YouTube/Podcast)<br/>RSS autodiscovery after 3 straight 404s"]
    fetch --> base["BaseAdapter<br/>parse_entries()"]
    fetch --> ext["ExtendedAdapter<br/>fetch_entries()"]
    base --> parsed["[ParsedEntry]"]
    ext --> parsed
    parsed --> dedup["Entry deduplication (GUID, content_hash)<br/>HTML sanitization (nh3)<br/>Full-text extraction (RSS articles)<br/>Lead image extraction / og:image fetch"]
    dedup --> entry["Create Entry"]
    dedup --> media["Create EntryMedia<br/>Fetch transcript; Telegram image OCR"]
    entry --> meili["Index in Meilisearch"]
    entry --> errev["Breakage tracking:<br/>error_count, feed_error events"]
    meili --> pipeline["Dispatch entry pipeline (Celery chord):<br/>translate? → autolink ∥ observables ∥ telegram_links ∥ extract<br/>→ cooccurrence ∥ correlation ∥ requirements<br/>→ signal scoring"]
    entry --> side["Side effects:<br/>SSE feed_fetched event<br/>Automation rules (run_entry_automations)"]
```
