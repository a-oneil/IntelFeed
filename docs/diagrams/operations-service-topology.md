# Production Service Topology

The services in `docker-compose.prod.yml` and how they connect. Only Caddy is reachable from the internet; the `frontend` and `backend` Docker networks keep the proxy path apart from the data services.

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
        API["API (gunicorn ×3)<br/>:8000"]
        DB[("PostgreSQL 16 + pgvector")]
        R[("Redis 7<br/>1 GB, volatile-lru")]
        MS["Meilisearch v1.6<br/>:7700"]
        LT["LibreTranslate v1.9.6<br/>:5000 (profile: translate)"]
        P["Piper TTS<br/>:5000"]
        W["celery-worker<br/>queue: celery ×2"]
        WC["celery-worker-ai<br/>queue: ai ×1"]
        WE["celery-worker-enrichment<br/>queue: enrichment ×1"]
        B["celery-beat"]
        TG["telegram-listener"]
    end

    U --> Caddy --> FE
    FE -- "/api/*" --> API
    API --> DB
    API --> R
    API --> MS
    W --> DB
    W --> R
    W --> MS
    W --> LT
    W --> P
    WC --> DB
    WC --> R
    WE --> DB
    WE --> R
    WC -- "IntelFeed MCP (HTTP, read-only token)" --> API
    B --> R
    TG --> DB
    TG --> R
```

Notes:

- The API never runs the Claude CLI itself. Copilot turns and every other AI task go on the `ai` queue, which only `celery-worker-ai` serves, one task at a time. That worker is the only one that mounts the CLI credentials volume.
- LibreTranslate is behind the `translate` compose profile, so a plain `up -d` does not start it. Celery translation tasks call it; the `retry-untranslated-entries` job catches up on missed entries once it is back.
- Piper (text-to-speech) is called only by the Celery TTS task. The API queues the synthesis and serves the cached MP3.
- Start order: db and redis must be healthy before the API and workers start; the API must be healthy before the frontend and telegram-listener; the frontend must be healthy before Caddy.
