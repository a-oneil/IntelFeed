# Dev Stack Services (docker-compose.dev.yml)

The services `docker-compose.dev.yml` starts for local development. Solid arrows follow `depends_on`; dashed arrows are runtime connections set by env URLs. Ports read host → container where they differ.

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
    cli["celery-worker-ai<br/>ai queue (all AI calls, one at a time)"] --> db
    cli --> redis
    beat["celery-beat<br/>scheduler"] --> db
    beat --> redis
    tg["telegram-listener"] --> api
    tg --> redis

    db[("db — PostgreSQL 16 + pgvector<br/>host 5433 → 5432")]
    redis[("redis — Redis 7<br/>host 6380 → 6379")]
```

The celery services also `depends_on` the api (service_started); those arrows are left out to keep the graph readable. `./docs` is mounted read-only into the api container for the in-app documentation, and `./scripts` is mounted so the utility scripts can run there.
