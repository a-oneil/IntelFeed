# Production Service Topology

Docker Compose service graph for `docker-compose.prod.yml`. Only Caddy is exposed to the internet; the `frontend` and `backend` Docker networks isolate the reverse-proxy path from the data services.

```mermaid
graph TD
    subgraph internet [Internet]
        U[Browser]
    end

    subgraph fe [frontend network]
        Caddy["Caddy<br/>:80 / :443 (TLS)"]
        FE["Frontend (nginx)<br/>:80 — SPA + /api proxy"]
    end

    subgraph be [backend network]
        API["API (gunicorn ×4)<br/>:8000"]
        DB[("PostgreSQL 16")]
        R[("Redis 7<br/>1 GB, volatile-lru")]
        MS["Meilisearch v1.6<br/>:7700"]
        LT["LibreTranslate v1.9.6<br/>:5000 (profile: translate)"]
        P["Piper TTS<br/>:5000"]
        W["celery-worker<br/>queue: celery ×4"]
        WC["celery-worker-ai<br/>queue: ai ×1"]
        B["celery-beat"]
        TG["telegram-listener"]
    end

    U --> Caddy --> FE
    FE -- "/api/*" --> API
    API --> DB
    API --> R
    API --> MS
    API --> P
    W --> DB
    W --> R
    W --> MS
    W --> LT
    W --> P
    WC --> R
    WC -- "IntelFeed skill (HTTP)" --> API
    B --> R
    TG --> API
    TG --> R
```

Notes:

- The API never runs the Claude CLI itself — global copilot turns are enqueued on the `ai` queue and executed by `celery-worker-ai`, which is the sole owner of the OAuth credentials volume. The service is behind the `claude_code` compose profile — a plain `up -d` / `update.sh` does not start it.
- LibreTranslate is called by the Celery translation tasks. It is behind the `translate` compose profile (on-demand); while it's down, the `retry_untranslated_entries` beat task backfills once it returns.
- Piper (text-to-speech) is called over HTTP by both the API (on-demand read-aloud) and the Celery TTS tasks (pre-generation + caching).
- Healthcheck ordering: db + redis must be healthy before the API starts; the API must be healthy before frontend, telegram-listener, and (transitively) Caddy start.
