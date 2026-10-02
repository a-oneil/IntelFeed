FROM python:3.15.0rc2-slim-bookworm AS base

WORKDIR /app
ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    curl \
    ca-certificates \
    gnupg \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libcairo2 \
    libffi-dev \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*
# postgresql-client-16 provides pg_dump/pg_restore matching the PostgreSQL 16 server.
# Must match the server major version — pg_dump refuses to dump a newer server.
# Used by scripts/backup.sh, scripts/restore.sh, and the backup_database Celery task.

# Install Node.js (for Claude CLI) and Claude Code CLI
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g @anthropic-ai/claude-code \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and install dependencies
# Create minimal package structure so setuptools can resolve deps
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && mkdir -p app && touch app/__init__.py \
    && pip install --no-cache-dir ".[dev]" \
    && rm -rf app

COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

# Development target — deps already in base, volume mount keeps code fresh
FROM base AS development
RUN useradd -m -u 1000 appuser \
    && mkdir -p /home/appuser/.claude \
    && chown -R appuser:appuser /home/appuser/.claude
COPY --chown=appuser:appuser . .
# Build stamp, injected by compose from scripts/ops/version.sh. Deliberately
# below the COPY: these change on every commit, and an ARG any earlier would
# invalidate the apt/pip layers and turn each deploy into a full rebuild.
ARG APP_VERSION=dev
ARG GIT_SHA=""
ARG BUILD_TIME=""
ENV APP_VERSION=${APP_VERSION} GIT_SHA=${GIT_SHA} BUILD_TIME=${BUILD_TIME}

USER appuser
ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Production target
FROM base AS production
RUN useradd -m -u 1000 appuser \
    && mkdir -p /home/appuser/.claude \
    && chown -R appuser:appuser /home/appuser/.claude
COPY --chown=appuser:appuser . .
# Build stamp, injected by compose from scripts/ops/version.sh. Deliberately
# below the COPY: these change on every commit, and an ARG any earlier would
# invalidate the apt/pip layers and turn each deploy into a full rebuild.
ARG APP_VERSION=dev
ARG GIT_SHA=""
ARG BUILD_TIME=""
ENV APP_VERSION=${APP_VERSION} GIT_SHA=${GIT_SHA} BUILD_TIME=${BUILD_TIME}

USER appuser
ENTRYPOINT ["./entrypoint.sh"]
# --timeout 180: AI-generation endpoints (e.g. /entries/daily-summary) can run
# 30-90s for a busy day; gunicorn's default 30s kills them mid-flight.
CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--timeout", "180"]
