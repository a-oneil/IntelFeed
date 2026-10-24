# Production Deployment

Walkthrough for running IntelFeed on a single Linux host with Docker Compose and Caddy-managed TLS. AWS EC2 is the worked example, but nothing here is AWS-specific: any VPS or bare-metal box with Docker, ports 80 and 443 reachable, and a DNS record pointing at it will do. When you're done you'll have a seeded instance, behind HTTPS, polling feeds.

Each code block says where it runs: **on the server** (over SSH), **in your browser**, or **on your own machine**.

## 1. The host

| | |
| --- | --- |
| **OS** | Ubuntu 24.04 LTS or Amazon Linux 2023. Anything else current that runs Docker Engine with Compose v2 should behave the same, because everything runs in containers. |
| **Memory** | **8 GB** is the smallest we'd run it on, with swap — see [Memory](#memory-and-swap) below. 16 GB if you'll also run local translation. |
| **Disk** | 30 GB or more. |
| **Network** | `80/tcp` and `443/tcp` open to the internet (Caddy needs both to issue and renew the certificate); `22/tcp` for SSH from your own IP only. |
| **DNS** | An `A` record for the hostname you'll serve, pointing at the host (step 2). |

**On AWS:** a `t3.large` (8 GB) with a 30 GB+ gp3 volume and a security group allowing `22/tcp` from your IP and `80/tcp`, `443/tcp` from `0.0.0.0/0`.

Note: AWS can be expensive... OVH offers a decent VPS with 8GB of ram for $60 a year.

### Memory and swap

`docker-compose.prod.yml` caps each container's memory. The caps add up to about **11.4 GiB** for the default stack and about **13.4 GiB** with local translation (`libretranslate`, 2 GiB, behind the `translate` compose profile). They are ceilings, not what an idle stack uses, but a cold image build plus a busy ingest on an 8 GB host can run it out of memory.

On an 8 GB host:

- **Add swap before the first build.** On the server:

  ```bash
  sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab   # keep it across reboots
  ```

- **Leave translation off.** `libretranslate` is not started by `up -d`; start it only when you want auto-translate feeds (`docker compose -f docker-compose.prod.yml --profile translate up -d libretranslate`). Translate-enabled feeds degrade gracefully while it's down and catch up once it's running.

## 2. DNS

Point your hostname's `A` record (this guide uses `intelfeed.example.com`) at the host's public IP. Do this **before** step 6 — Caddy needs DNS to resolve to the host to get a Let's Encrypt certificate when it starts.

## 3. Install Docker

On your own machine, log in:

```bash
ssh <user>@<server-ip>
```

Then, on the server:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

## 4. Deploy the code

On the server:

```bash
git clone https://github.com/a-oneil/IntelFeed.git ~/intelfeed
cd ~/intelfeed
```

## 5. Create `.env`

On the server:

```bash
cp .env.example .env
```

Generate real secrets and put them in `.env`:

```bash
openssl rand -hex 32                                                           # SECRET_KEY
openssl rand -base64 32 | tr '+/' '-_'                                         # ENCRYPTION_KEY (a Fernet key; needs no Python on the host)
openssl rand -base64 24                                                        # POSTGRES_PASSWORD, REDIS_PASSWORD, MEILI_MASTER_KEY
```

If you'd rather generate the Fernet key with the library (it needs `pip install cryptography` on the host): `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

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

That is everything the stack needs to boot. These are optional:

| Variable | Set it when |
| --- | --- |
| `TELEGRAM_API_ID`, `TELEGRAM_API_HASH` | You want Telegram channel ingestion (step 12). Leave `TELEGRAM_API_ID=0` to keep it off. |
| `PUBLIC_BASE_URL` | You post to Discord or Slack from automation rules and want in-app links in those posts to be absolute. Empty means relative links only. |
| `INTELFEED_USERNAME`, `INTELFEED_PASSWORD` | You run the skill CLIs or the MCP server from your own shell against this instance. The containers do not use them. |
| `ANTHROPIC_API_KEY` | Emergency fallback for the Claude Code provider if its OAuth token lapses (step 14). |

Everything else is editable in the web UI and needs no `.env` entry, in the section for the thing it controls:

| What | Where |
| --- | --- |
| AI providers, models and prompts | **Settings → AI Configuration** |
| Pipeline thresholds, enrichment and the NVD and GitHub API keys, feed fetching, rate limits, the image proxy | **Settings → Engine** |
| Registration and the invite code | **Settings → Users** |
| Monitoring and backups | **Settings → System** |

A few settings are env-only (database and Redis connections, secrets, build stamps). [docs/engine-settings.md](docs/engine-settings.md) lists which is which.

## 6. Build and start

On the server:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

First build takes several minutes. Watch progress:

```bash
docker compose -f docker-compose.prod.yml logs -f
```

## 7. Create your user account

In your browser: open `https://intelfeed.example.com` and register the first account — the first account registered becomes the admin, and registration closes behind a generated invite code at that moment. The code (and the switch to disable registration altogether) is under **Settings → Users** (see [Users and access](docs/guide/users-and-access.md)).

## 8. Seed the reference data

**Don't skip this.** A fresh install isn't empty — its migrations load 191 countries and a baseline of 703 ATT&CK Enterprise techniques — but it has no CWE catalog, vendors, products, CPE curation or actor attribution. Most of what the autolinker matches against is missing, so vendors and products never link and CVEs can't resolve their weaknesses. The onboarding wizard detects the gap and shows the same command; running it now saves you the surprise.

On the server:

```bash
docker compose -f docker-compose.prod.yml exec api python scripts/seed/seed_all.py --dry-run   # preview, writes nothing (~15 s)
docker compose -f docker-compose.prod.yml exec api python scripts/seed/seed_all.py             # seed everything
```

It runs ten seeders in dependency order; four of them (MITRE ATT&CK, the CWE catalog, vendors, vendor descriptions) download from MITRE and Wikipedia and take a few minutes each. Every seeder is idempotent, so re-running only fills gaps. If one fails, the remaining steps are skipped and the run prints an `--only` command naming the failed and skipped steps; fix the cause and run that, or simply re-run the whole command. Useful flags:

| Flag | Effect |
| --- | --- |
| `--offline` | Skip the four steps that download — handy on a locked-down host; run them later. |
| `--only a,b` / `--skip a,b` | Run or skip named steps (`--list` shows the names). |

The full seeder reference is in [scripts/README.md](scripts/README.md#seed--reference-data-for-a-fresh-install).

## 9. Add feeds

The onboarding wizard opens on the **Start With Recommended Feeds** step. IntelFeed ships an audited
list of security sources as selectable packs, so a fresh install doesn't sit empty while you go
hunting for URLs:

| Pack | Feeds | What's in it |
| --- | --- | --- |
| **Core** (pre-selected) | 37 | Security news, government/CERT advisories, NVD and vendor CVE bulletins, marquee vendor research, detection engineering |
| More news & government | 16 | Second-tier press, regional CERTs, breach and leak-site trackers |
| Vendor advisories | 13 | Distro, network and OSS product bulletins — high volume, CVE-shaped |
| Vendor research | 62 | The long tail of vendor and lab research: campaigns, malware analysis, attribution |
| Detection engineering | 12 | Building, testing and tuning detections |
| Detection rule repositories | 20 | Sigma, Elastic, Splunk, YARA, Nuclei, Atomic Red Team. **Needs a GitHub token** |
| Practitioner blogs | 39 | Independent researchers and responders |
| Reddit | 10 | Security subreddits |
| YouTube | 26 | Conference talks and technical channels |
| Podcasts | 5 | Playable in the reader |

Nothing is created until you choose — it's your instance. Everything shipped polls hourly at most,
because every install polls the same sources. Two things are deliberately **not** in any pack:

- **Telegram channels**, which need `TELEGRAM_API_ID`/`TELEGRAM_API_HASH` and the interactive login
  in step 12 below. Imported without that, they'd be permanently failing feeds.
- **The GitHub repo pack, unless you set a token.** Unauthenticated GitHub API calls are capped at
  60/hour and those 20 repositories will exhaust it. Set `github_token` under **Settings → Engine** (the Enrich stage).

Headless installs get the same thing from the CLI (on the server):

```bash
docker compose -f docker-compose.prod.yml exec api python scripts/seed/seed_feeds.py --list
docker compose -f docker-compose.prod.yml exec api python scripts/seed/seed_feeds.py --packs core
```

A committed list rots, so before each release re-audit it and prune what has died:

```bash
GITHUB_TOKEN=$(gh auth token) python scripts/maintenance/audit_feed_packs.py   # on your own machine
```

One caveat on that audit: it runs from wherever you run it. CISA's advisory feeds answer a
datacenter IP with HTTP 403 while serving a residential one fine, so a source that passes on your
laptop can still fail on the box.

## 10. Verify

In your browser, `https://intelfeed.example.com` should load with a valid TLS certificate. If Caddy can't obtain one, confirm DNS from your own machine: `dig intelfeed.example.com` should return the host's IP.

Then on the server:

```bash
docker compose -f docker-compose.prod.yml ps
# every service Up; the ones with healthchecks (db, redis, meilisearch, piper, api, frontend) show "healthy"

docker compose -f docker-compose.prod.yml exec api curl -fsS http://localhost:8000/api/health
# the API answers

docker compose -f docker-compose.prod.yml logs --tail=50 celery-worker
# once you've added feeds: app.workers.feed_tasks.fetch_feed tasks succeeding
```

**If something's off on day one:**

| You see | Likely cause |
| --- | --- |
| Articles arrive but entity pages are empty and nothing is highlighted | The reference data isn't seeded — run step 8. |
| Caddy never gets a certificate | DNS doesn't resolve to this host yet, or `80`/`443` are blocked by a firewall or security group. |
| The build is killed, or the host stops responding during it | Out of memory — add swap (see [Memory and swap](#memory-and-swap)) and re-run step 6. |
| A feed fails with HTTP 403 but opens fine in your browser | The source blocks datacenter IPs (CISA's advisory feeds do). Nothing to fix on your side; see the caveat in step 9. |

**AI is optional.** The stack runs, polls feeds, links entities and searches without any AI provider. The onboarding wizard has an explicit "run without AI" choice, and the Claude Code CLI step below is only needed if you want that provider. What an AI provider adds is covered in [Automation and AI](docs/guide/automation-and-ai.md).

## 11. (Optional) Migrate local data

To bring your existing database over:

```bash
# On your own machine
docker compose -f docker-compose.dev.yml exec db pg_dump -U intelfeed intelfeed | gzip > intelfeed_dump.gz
scp intelfeed_dump.gz <user>@<server-ip>:~/intelfeed/
```

```bash
# On the server — stop writers first to avoid conflicts
docker compose -f docker-compose.prod.yml stop api celery-worker celery-beat
gunzip -c intelfeed_dump.gz | docker compose -f docker-compose.prod.yml exec -T db psql -U intelfeed intelfeed
docker compose -f docker-compose.prod.yml up -d
```

> **Important:** if migrating data, reuse the **same `ENCRYPTION_KEY`** you had locally — otherwise encrypted feed credentials won't decrypt.

## 12. (Optional) Set up Telegram channel ingestion

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

## 13. CLI access

On whatever machine runs the CLI:

```bash
export INTELFEED_API_URL=https://intelfeed.example.com
export INTELFEED_USERNAME=your-username
export INTELFEED_PASSWORD=your-password
```

## 14. (Optional) Claude Code CLI authentication

The `claude_code` AI provider runs the Claude Code CLI shipped inside the backend image. It is the default provider assignment for the **copilot** task (the global streaming assistant — see [docs/copilot.md](docs/copilot.md)), and any other AI task an operator assigns to it under Settings → AI Configuration runs through it too. CLI turns execute on the dedicated `celery-worker-ai` service, which mounts a named volume (`claude_cli`) at `/home/appuser/.claude` to persist OAuth tokens across container rebuilds. Skip this section if every task is assigned to Ollama or an API-key provider.

Until you bootstrap auth, each `claude -p` call exits with an auth-required error and the task that invoked it fails; nothing else is affected.

**Prod (Ubuntu, SSH-only, no browser on the box)** — use the long-lived token flow:

1. On any local machine with a browser, generate a long-lived OAuth token:

   ```bash
   claude setup-token        # opens browser, returns sk-ant-oat01-... — copy the full token
   ```

2. SSH to the prod host and paste the token into the container:

   ```bash
   ssh <user>@<your-host>
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
- Tokens revoked at claude.ai require re-running setup-token. Credential health is checked every 30 minutes (`refresh_claude_auth_status`) and shown on the provider card at Settings → AI Configuration, which also offers in-app re-auth.
- Emergency fallback: set `ANTHROPIC_API_KEY` in `.env` to switch to pay-per-token billing if the OAuth token lapses. The provider auto-uses the env var when present.
