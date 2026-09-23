# EC2 Deployment

End-to-end walkthrough for deploying IntelFeed to a single EC2 host with Docker Compose and Caddy-managed TLS.

## 1. EC2 instance

- **AMI:** Ubuntu 24.04 LTS (or Amazon Linux 2023)
- **Instance type:** t3.large
- **Storage:** 30 GB+ gp3 EBS
- **Security group inbound rules:**
  - `22/tcp` → your IP
  - `80/tcp` → `0.0.0.0/0`
  - `443/tcp` → `0.0.0.0/0`

Note: AWS can be expensive... OVH offers a decent VPS with 8GB of ram for $60 a year.

## 2. DNS

Point `intelfeed.example.com` A record → your EC2 public IP. Do this **before** step 5 — Caddy needs DNS to resolve to the instance for Let's Encrypt verification.

## 3. Install Docker

```bash
ssh -i your-key.pem ubuntu@<ec2-ip>

curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

## 4. Deploy the code

```bash
git clone <your-repo-url> ~/intelfeed
cd ~/intelfeed
```

## 5. Create `.env`

```bash
cp .env.example .env
```

Generate real secrets and edit `.env`:

```bash
openssl rand -hex 32                                                           # SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # ENCRYPTION_KEY
openssl rand -base64 24                                                        # POSTGRES_PASSWORD, REDIS_PASSWORD, MEILI_MASTER_KEY
```

Minimum production `.env`:

```bash
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_DB=intelfeed
POSTGRES_USER=intelfeed
POSTGRES_PASSWORD=<generated>

REDIS_PASSWORD=<generated>
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0

MEILI_URL=http://meilisearch:7700
MEILI_MASTER_KEY=<generated>

SECRET_KEY=<generated>
CORS_ORIGINS=["https://intelfeed.example.com"]

# Domain Caddy serves and requests a TLS cert for (see Caddyfile)
SITE_DOMAIN=intelfeed.example.com

ENCRYPTION_KEY=<generated>

VITE_API_URL=/api
```

## 6. Build and start

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

First build takes several minutes. Watch progress:

```bash
docker compose -f docker-compose.prod.yml logs -f
```

## 7. Create your user account

Open `https://intelfeed.example.com` and register the first account via the web UI — the first account registered becomes the admin. Registration can then be disabled or invite-gated under Settings > System.

## 8. Verify

- Visit `https://intelfeed.example.com` — should load with a valid TLS cert.
- If Caddy can't obtain a cert, confirm DNS: `dig intelfeed.example.com` should return your EC2 IP.

## 9. (Optional) Migrate local data

To bring your existing database over:

```bash
# On your local machine
docker compose -f docker-compose.dev.yml exec db pg_dump -U intelfeed intelfeed | gzip > intelfeed_dump.gz
scp -i your-key.pem intelfeed_dump.gz ubuntu@<ec2-ip>:~/intelfeed/
```

```bash
# On EC2 — stop writers first to avoid conflicts
docker compose -f docker-compose.prod.yml stop api celery-worker celery-beat
gunzip -c intelfeed_dump.gz | docker compose -f docker-compose.prod.yml exec -T db psql -U intelfeed intelfeed
docker compose -f docker-compose.prod.yml up -d
```

> **Important:** if migrating data, reuse the **same `ENCRYPTION_KEY`** you had locally — otherwise encrypted feed credentials won't decrypt.

## 10. (Optional) Set up Telegram channel ingestion

Telegram is a high-signal source for threat intel — ransomware leak sites publish victim listings there, hacktivist groups (Killnet, NoName057, Anonymous Sudan) coordinate operations there, and eCrime brokers run announcement channels there. IntelFeed can ingest public (and pre-joined private) Telegram channels alongside RSS, Reddit, etc.

> **Warning.** Telegram ingestion requires a real Telegram **user** account (bots can't read channels they aren't admin of). Aggressive use can permanently ban the account. Treat the resulting session file as a credential equivalent to the account password. Recommend a dedicated burner SIM / Telegram identity, not your personal account. Monitoring some channels (e.g. those banned in your jurisdiction) may have legal implications — operator's responsibility.

Steps:

1. Visit https://my.telegram.org → "API development tools" → create an application. Save the `api_id` and `api_hash`.
2. Set the values in `.env` and restart the api + celery-worker services:

   ```
   TELEGRAM_API_ID=12345
   TELEGRAM_API_HASH=abc123...
   ```

   ```bash
   docker compose -f docker-compose.prod.yml up -d --build api celery-worker
   ```

3. Run the bootstrap script interactively (the `-it` flags are critical — Telethon prompts on stdin):

   ```bash
   docker compose -f docker-compose.prod.yml exec -it api python scripts/telegram/telegram_login.py
   ```

   You'll be prompted for: phone number → SMS code Telegram sends → optional 2FA password. On success the script prints `Logged in as <name> @<username>, id <id>` and exits.

4. The session file lives at `./telegram_data/telegram.session` on the host. **Back this file up with the database.** Restrict permissions (`chmod 600`).

Operational notes:

- If the IntelFeed Telegram account is logged out from another device or banned, fetches will fail with `Telegram session revoked` until you re-run `scripts/telegram/telegram_login.py`.
- Default poll interval is 30 minutes per channel. Lower intervals risk flood waits and bans.
- Media (photos, videos, voice notes, documents) is downloaded to `./telegram_media/` and served from `/api/telegram-media/...` (auth-required). Default max media size is 25 MB — set `TELEGRAM_MAX_MEDIA_SIZE_MB` to change.
- For private channels: join through the Telegram client app, **or** use `scripts/telegram/telegram_join.py "https://t.me/+HASH"` to join from inside the IntelFeed container. There is no "join channel" button in the web UI by design.
- Multi-session: pass `--session NAME` to `telegram_login.py` to bootstrap a second identity (e.g. one for OSINT, one for darker channels). Reference the same `session_name` in each feed's `adapter_config`.
- **Discovery**: the Add Feed modal has a "Discover from my Telegram account" button that lists every channel the bootstrap account is joined to, with a flag for which ones are already wired up. The CLI equivalent is `discover_telegram_channels`.
- **Realtime ingest** (optional): the `telegram-listener` container holds a long-lived MTProto connection and pushes new messages as they arrive. Opt in per-feed by setting the "Realtime ingest" checkbox in Edit Feed (or `adapter_config.realtime: true`). Polling stays as a safety net — if the listener dies, entries still arrive on the normal cadence.
- Ensure the host clock is in sync (`chronyd` / `systemd-timesyncd`); MTProto rejects requests that drift more than ~5 minutes.

## 11. CLI access

On whatever machine runs the CLI:

```bash
export INTELFEED_API_URL=https://intelfeed.example.com
export INTELFEED_USERNAME=your-username
export INTELFEED_PASSWORD=your-password
```

## 12. (Optional) Claude Code CLI authentication

The scheduled entity-link validator (`validate-entity-links` job, runs daily at 04:00 by default) uses the Claude Code CLI shipped inside the backend image. It runs in the dedicated `celery-worker-ai` service which mounts a named volume (`claude_cli`) at `/home/appuser/.claude` to persist OAuth tokens across container rebuilds.

Until you bootstrap auth, the job will run and log failures (each `claude -p` call will exit with an auth-required error). Validation tasks simply no-op; nothing else is affected.

**Prod (Ubuntu, SSH-only, no browser on the box)** — use the long-lived token flow:

1. On any local machine with a browser, generate a long-lived OAuth token:

   ```bash
   claude setup-token        # opens browser, returns sk-ant-oat01-... — copy the full token
   ```

2. SSH to the prod host and paste the token into the container:

   ```bash
   ssh ubuntu@<your-host>
   cd ~/intelfeed
   docker compose -f docker-compose.prod.yml exec -it celery-worker-ai claude setup-token
   # paste the sk-ant-oat01-... token when prompted; writes to /home/appuser/.claude
   ```

3. Sanity-check:

   ```bash
   docker compose -f docker-compose.prod.yml exec celery-worker-ai claude --version
   docker compose -f docker-compose.prod.yml exec celery-worker-ai claude -p "say ok" --output-format json
   # should print {"result":"ok",...}
   ```

**Dev (Mac with browser)** — interactive login works:

```bash
docker compose -f docker-compose.dev.yml exec -it celery-worker-ai claude /login
```

**Notes:**

- The `claude_cli` named volume persists across rebuilds. Only `docker compose down -v` wipes it.
- Tokens revoked at claude.ai will require re-running setup-token.
- Emergency fallback: set `ANTHROPIC_API_KEY` in `.env` to switch to pay-per-token billing if the OAuth token lapses. The provider auto-uses the env var when present.
- Validator runs in **shadow mode** on first deploy — it logs would-be removals to `entity_link_validation_log` without touching junction rows. Review the log via the admin API for 1–2 weeks before flipping `link_validation_mode` to `"apply"`.
