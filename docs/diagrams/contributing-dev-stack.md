# Dev Stack Services (docker-compose.dev.yml)

Service topology for local development. Arrows follow `depends_on`; dashed lines are runtime connections configured via env URLs. Host port → container port shown where they differ.

```mermaid
flowchart TD
    frontend["frontend — Vite dev server<br/>host 3001 → 3000"] --> api
    api["api — uvicorn --reload<br/>:8000 (runs migrations on start)"] --> db
    api --> redis
    api -.-> meili["meilisearch v1.6<br/>:7700"]
    api -.-> lt["libretranslate<br/>host 5050 → 5000"]
    api -.-> piper["piper TTS<br/>host 5060 → 5000"]

    worker["celery-worker<br/>default queue"] --> db
    worker --> redis
    cli["celery-worker-ai<br/>ai queue (copilot)"] --> db
    cli --> redis
    beat["celery-beat<br/>scheduler"] --> db
    beat --> redis
    tg["telegram-listener"] --> api
    tg --> redis

    db[("db — PostgreSQL 16<br/>host 5433 → 5432")]
    redis[("redis — Redis 7<br/>host 6380 → 6379")]
```

The celery services also `depends_on` the api (service_started) — those arrows are omitted to keep the graph readable. `./docs` is mounted read-only into the api container to serve the in-app documentation.
