# Integration Cookbook

Recipes for chat alerts, SIEM and firewall feeds, API pulls, AI providers and enrichment.

**Contents**

- [Prerequisites for All Recipes](#prerequisites-for-all-recipes)
  - [Obtain an API Token](#obtain-an-api-token)
- [Outbound Integrations: IntelFeed → External Systems](#outbound-integrations-intelfeed--external-systems)
  - [1. Slack Notifications](#1-slack-notifications)
  - [2. Discord Notifications](#2-discord-notifications)
  - [3. Custom HTTP Webhook (Generic JSON)](#3-custom-http-webhook-generic-json)
  - [4. Microsoft Teams](#4-microsoft-teams)
  - [5. Email Digest (via Webhook to Email Service)](#5-email-digest-via-webhook-to-email-service)
  - [6. SIEM Ingestion](#6-siem-ingestion)
  - [7. MISP and Other Threat Intel Platforms](#7-misp-and-other-threat-intel-platforms)
  - [8. Detection Rule Export to GitHub / GitLab](#8-detection-rule-export-to-github--gitlab)
  - [9. Exports (Markdown, CSV, ATT&CK Layer)](#9-exports-markdown-csv-attck-layer)
- [Inbound Integrations: External Systems → IntelFeed](#inbound-integrations-external-systems--intelfeed)
  - [10. OPML Import (Bulk Feed Onboarding)](#10-opml-import-bulk-feed-onboarding)
  - [11. Manual URL/PDF Ingestion via REST API](#11-manual-urlpdf-ingestion-via-rest-api)
  - [12. Polling IntelFeed via REST API](#12-polling-intelfeed-via-rest-api)
  - [13. IntelFeed CLI Integration](#13-intelfeed-cli-integration)
- [Configuration Recipes](#configuration-recipes)
  - [14. Configure Claude as AI Provider](#14-configure-claude-as-ai-provider)
  - [15. Configure OpenAI as AI Provider](#15-configure-openai-as-ai-provider)
  - [16. Configure Local Ollama](#16-configure-local-ollama)
  - [17. Configure an OpenAI-Compatible Endpoint](#17-configure-an-openai-compatible-endpoint-lm-studio-vllm-llamacpp-openrouter-litellm-groq)
  - [18. Configure Enrichment Sources](#18-configure-enrichment-sources)
  - [19. Image Proxy Configuration](#19-image-proxy-configuration)
- [Authoring Complex Automation Patterns](#authoring-complex-automation-patterns)
  - [20. Multi-Step Automation: Extract → Rules → Slack](#20-multi-step-automation-extract--rules--slack)
  - [21. Morning Briefing: Scheduled Digest](#21-morning-briefing-scheduled-digest)
  - [22. Watched-Entity Alerts](#22-watched-entity-alerts)
- [Summary Table: Integration Methods](#summary-table-integration-methods)
- [Troubleshooting](#troubleshooting)
  - [Webhook not firing](#webhook-not-firing)
  - [API authentication fails](#api-authentication-fails)
  - [Enrichment sources not running](#enrichment-sources-not-running)
  - [Image proxy issues](#image-proxy-issues)
- [Related Documentation](#related-documentation)

## Prerequisites for All Recipes

An account, your instance URL (such as `https://intelfeed.example.com` or `http://localhost:8000`), and network access between IntelFeed and the other system.

### Obtain an API Token

```bash
curl -X POST https://intelfeed.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}'
```

Response:

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer"
}
```

- Send `Authorization: Bearer <access_token>` on every request.
- Access tokens last 2 hours (`access_token_expire_minutes`, default 120); refresh tokens 7 days (`refresh_token_expire_days`).
- `POST /api/auth/refresh` with `{"refresh_token": "..."}` returns a new pair; each refresh token works once.

---

## Outbound Integrations: IntelFeed → External Systems

**Automation rules** (sidebar → **Automation**: trigger, optional conditions, actions) send data out with two actions:

- **Send Notification** posts a formatted message (`slack`, `discord`, `custom`).
- **Run Webhook** POSTs JSON to any URL, optionally with headers and a custom payload.

URLs can be saved as presets in the rule builder.

**Template variables** (single braces, in message templates and custom payloads):

| Variable | Value |
|----------|-------|
| `{title}`, `{url}`, `{author}`, `{feed_name}` | Article title, link, author, feed name |
| `{app_url}` | Link to the article in IntelFeed (absolute when `PUBLIC_BASE_URL` is set) |
| `{summary}` | Earlier AI summary, else article summary (up to 500 characters) |
| `{ai_summary}` | Output of an earlier **Run AI Task** or **Use Daily Summary** |
| `{published_at}` | Publication time |
| `{observables_count}`, `{observables}` | Captured indicators (notification templates only) |

Custom payload values are JSON-escaped; other fields (such as article ID) are only in the default payload. **Run AI Task** prompts use `{{ entry.* }}` variables; the rule builder lists both (`GET /api/automation/variable-contexts`).

**Per-entry and batch mode.** Actions run once per article, except that a **Schedule (Cron)** rule can use **Batch** mode: AI tasks see all matched articles at once, a notification sends one digest, and templates fill from the first article.

**Network safety.** Webhook URLs are checked and the connection pinned to the checked address, so DNS changes can't redirect it; redirects aren't followed.

- Webhooks may reach private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) unless `WEBHOOK_ALLOW_PRIVATE_NETWORKS=false` in `.env`.
- Loopback (127.0.0.0/8, `::1`, `localhost`) and link-local (169.254.0.0/16 — cloud metadata — plus `fe80::/10` and `fd00:ec2::254`) are always refused.
- Feeds, linked articles, transcripts, manual ingest, feed discovery and the image proxy share the guard (`backend/app/core/safe_http.py`) but refuse private ranges unless `OUTBOUND_ALLOW_PRIVATE_NETWORKS=true`.

### 1. Slack Notifications

1. At api.slack.com/apps, open an app, turn on **Incoming Webhooks**, **Add New Webhook to Workspace**, pick the channel, copy the URL.
2. In IntelFeed, **Automation → + New Rule** with a trigger (such as **CVE Detected**) and optional condition (such as **Severity Above**).
3. Add **Send Notification**:
   - Platform: `slack`
   - Webhook URL: from step 1
   - Channel, username: optional (app webhooks usually post to the step-1 channel)
   - Message template: optional, such as `New critical alert: {title}\n{url}\n{ai_summary}`

**Payload** (per-entry, no template):

```json
{
  "text": "**Entry Title**\nhttps://example.com/article\n\nSummary text...",
  "username": "IntelFeed",
  "icon_emoji": ":shield:",
  "unfurl_links": false,
  "unfurl_media": false,
  "channel": "#threat-intel",
  "blocks": [
    {"type": "section", "text": {"type": "mrkdwn", "text": "*<https://example.com/article|Entry Title>*"}},
    {"type": "section", "text": {"type": "mrkdwn", "text": "Summary text..."}},
    {"type": "section", "fields": [
      {"type": "mrkdwn", "text": "*Author:* Security Researcher"},
      {"type": "mrkdwn", "text": "*Source:* IntelFeed"}
    ]}
  ]
}
```

`channel` is sent only if set; long AI summaries split across blocks.

Batch mode sends the AI summary or your template, else a list of matched articles under "IntelFeed Digest — N entries", split if long.

---

### 2. Discord Notifications

In Discord, **Server Settings → Integrations → Webhooks → New Webhook**, pick the channel, copy the URL. Add **Send Notification** with platform `discord` and that URL. Username is optional (default `IntelFeed`); embeds are on by default.

**Payload** (per-entry, no template):

```json
{
  "content": "**Zero-Day RCE in Product X**\nhttps://example.com/article\n\nSummary text...",
  "username": "IntelFeed",
  "embeds": [
    {
      "title": "Zero-Day RCE in Product X",
      "url": "https://example.com/article",
      "description": "Summary text...",
      "fields": [
        {"name": "Author", "value": "Security Researcher", "inline": true},
        {"name": "Source", "value": "IntelFeed Automation", "inline": true}
      ],
      "color": 16220518
    }
  ]
}
```

Embed color: always `0xF78166`. Earlier AI output is added as `ai_results`. Batch messages over Discord's limits split into several.

---

### 3. Custom HTTP Webhook (Generic JSON)

**Run Webhook** POSTs JSON to n8n, Zapier or your own service. Set:

- URL: `https://your-service.example.com/webhook`
- Headers (optional): `{"Authorization": "Bearer YOUR_TOKEN"}`
- Payload (optional): a JSON template, such as:

     ```json
     {
       "event_type": "entry_ingested",
       "title": "{title}",
       "url": "{url}",
       "summary": "{summary}",
       "ai_analysis": "{ai_summary}",
       "timestamp": "{published_at}"
     }
     ```

**Default payload** (empty payload field):

```json
{
  "entry_id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "Critical CVE in OpenSSL",
  "url": "https://example.com/cve",
  "author": "Security Team",
  "content_text": "First 5,000 characters of the article...",
  "published_at": "2026-05-03 12:00:00+00:00",
  "ai_results": {"article_summary": {"summary": "..."}}
}
```

`ai_summary` and `ai_results` (keyed by task name) appear only if an earlier action made them.

Batch: `{"entry_count", "ai_summary", "ai_results", "entries": [...]}`, each entry with `entry_id`, `title`, `url`, `author`, `content_text` (first 2,000 characters) and `published_at`.

Platform `custom` **Send Notification** sends `{"message", "entry_id", "title", "url", "author", "published_at"}`, plus `channel`, `ai_summary` and `ai_results` when set.

---

### 4. Microsoft Teams

Use **Run Webhook** with the URL of a Teams channel incoming webhook, and a payload in the MessageCard format of the classic **Incoming Webhook** connector (Teams **Workflows** webhooks expect an Adaptive Card instead):

   ```json
   {
     "@type": "MessageCard",
     "@context": "https://schema.org/extensions",
     "summary": "{title}",
     "themeColor": "E74C3C",
     "sections": [
       {
         "activityTitle": "{title}",
         "activitySubtitle": "Source: {feed_name}",
         "facts": [
           {"name": "Author", "value": "{author}"},
           {"name": "Published", "value": "{published_at}"}
         ],
         "text": "{summary}"
       }
     ],
     "potentialAction": [
       {"@type": "OpenUri", "name": "View Full Article", "targets": [{"os": "default", "uri": "{url}"}]}
     ]
   }
   ```

---

### 5. Email Digest (via Webhook to Email Service)

IntelFeed doesn't send email; webhook a service that does (Zapier, n8n, AWS SES, SendGrid). With Zapier, create a Zap **Webhooks by Zapier (Catch Raw Hook) → Send Email**, copy the hook URL, and make a **Schedule (Cron)** rule in **Batch** mode ([recipe 21](#21-morning-briefing-scheduled-digest)) with **Send Notification** (platform `custom`) to that URL, or **Run Webhook** with a payload like:

```json
{
  "to": "security-team@example.com",
  "subject": "IntelFeed Alert: {title}",
  "html": "<h2>{title}</h2><p>{summary}</p><p><a href='{url}'>View article</a></p>"
}
```

---

### 6. SIEM Ingestion

Push articles with **Run Webhook** (6a–6c) or pull indicator files (6d).

#### 6a. Splunk HTTP Event Collector (HEC)

In Splunk, create a token under **Settings → Data Inputs → HTTP Event Collector**. Add a **Run Webhook** action:

- URL: the HEC URL, such as `https://splunk.example.com:8088/services/collector`
- Headers: `{"Authorization": "Splunk YOUR_HEC_TOKEN"}`
- Payload:

```json
{
  "event": {
    "title": "{title}",
    "url": "{url}",
    "content": "{summary}",
    "source": "intelfeed"
  },
  "sourcetype": "_json",
  "source": "intelfeed"
}
```

There's no `{entry_id}` variable; for the article ID, send the default payload (recipe 3) to a HEC raw endpoint or a relay.

Test HEC by hand:

```bash
curl -X POST https://splunk.example.com:8088/services/collector \
  -H "Authorization: Splunk YOUR_HEC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event": {"title": "Critical CVE", "url": "https://example.com", "source": "intelfeed"}}'
```

#### 6b. Elastic / Logstash

Logstash HTTP input:

```text
input {
  http {
    port => 8080
    codec => json
  }
}
```

IntelFeed **Run Webhook**:

- URL: `http://logstash.example.com:8080`
- Payload:

  ```json
  {
    "timestamp": "{published_at}",
    "type": "intelfeed",
    "title": "{title}",
    "url": "{url}",
    "summary": "{summary}"
  }
  ```

#### 6c. Microsoft Sentinel (Azure Log Analytics)

The legacy Data Collector API needs requests signed with the workspace's shared key, which a webhook can't do. Send the default payload to a relay (Logic App, Azure Function, n8n) that signs and forwards it:

```bash
curl -X POST "https://YOUR_WORKSPACE.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" \
  -H "Authorization: SharedKey WORKSPACE_ID:SIGNATURE" \
  -H "Content-Type: application/json" \
  -H "Log-Type: IntelFeedAlert" \
  -d '[{"Title": "Critical CVE", "URL": "https://example.com", "Author": "Security Researcher"}]'
```

#### 6d. Indicator Feeds (EDL, Lookup CSV, TAXII 2.1)

Firewalls, SIEMs and TIPs can pull the indicator (observable) ledger: active, recently seen indicators above a confidence floor, minus shared infrastructure (CDNs, VPN exits). Off by default; enable in **Settings → Engine → Publishing**:

| Setting | Default | Meaning |
|---------|---------|---------|
| `observables_publish_enabled` | `false` | Publishing on |
| `observables_publish_token` | empty | Comma-separated `name:secret` pairs, one per consumer |
| `observables_publish_min_confidence` | `0.6` | Minimum confidence |
| `observables_publish_max_age_days` | `90` | Drop if unseen this many days |
| `observables_publish_never_suffixes` | empty | Never-publish domains (such as yours) |

Requests need a publish token, not a login token: `Authorization: Bearer <secret>`, or `?token=<secret>` where headers can't be set.

| URL | Format | Contents |
|-----|--------|----------|
| `/api/publish/edl/ipv4.txt` | One per line | IPv4 and IPv6 |
| `/api/publish/edl/domains.txt` | One per line | Domains |
| `/api/publish/edl/urls.txt` | One per line | URLs |
| `/api/publish/lookup/hashes.csv` | CSV: kind, value, label, role, confidence, last_seen | MD5, SHA-1, SHA-256 |
| `/api/publish/lookup/host_artifacts.csv` | Same CSV | Host artifacts: command lines, registry keys, paths, mutexes, pipes, services, tasks, user agents, HTTP headers |
| `/api/taxii2/` | TAXII 2.1, read-only | Collection `observables` of STIX 2.1 indicators |

```bash
curl -H "Authorization: Bearer <publish-secret>" \
  https://intelfeed.example.com/api/publish/edl/domains.txt
```

TAXII objects are at `/api/taxii2/api/collections/observables/objects/`, with `added_after`, `next` and `limit` (default 500, max 5,000). `valid_until` follows confidence decay. Scoring: [observables.md](observables.md).

---

### 7. MISP and Other Threat Intel Platforms

- **TAXII 2.1 readers** (OpenCTI and others) pull the collection in [6d](#6d-indicator-feeds-edl-lookup-csv-taxii-21).
- **MISP** has no connector; script it from anywhere that reaches both:

```python
import requests

INTELFEED_URL = "https://intelfeed.example.com"
MISP_URL = "https://misp.example.com"
MISP_KEY = "YOUR_MISP_API_KEY"

headers = {"Authorization": "Bearer YOUR_INTELFEED_TOKEN"}

# The 10 newest articles that mention ransomware
resp = requests.get(
    f"{INTELFEED_URL}/api/search",
    headers=headers,
    params={"q": "ransomware", "limit": 10, "sort": "newest"},
)
entries = resp.json()["hits"]

for entry in entries:
    event = {
        "Event": {
            "info": entry["title"],
            "distribution": 2,
            "threat_level_id": 2,
            "analysis": 1,
            "Attribute": [{"type": "link", "value": entry["url"], "distribution": 2}],
        }
    }
    misp_resp = requests.post(
        f"{MISP_URL}/events",
        headers={"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"},
        json=event,
    )
    print("Created MISP event:", misp_resp.json()["Event"]["id"])
```

---

### 8. Detection Rule Export to GitHub / GitLab

To keep generated rules in Git, pull the export on a schedule:

```text
GET /api/detection-rules/export?format=zip                     # one file per rule
GET /api/detection-rules/export?format=yaml                    # all rules in one file, joined with ---
GET /api/detection-rules/export?format=zip&rule_ids=ID1,ID2    # only these rules
```

ZIP files are named by rule title, extension by type (`.yml` Sigma, `.spl` Splunk, `.kql` KQL, `.eql` Elastic, `.cql` CrowdStrike, `.rules` Snort/Suricata, `.yar` YARA).

**To generate rules automatically**, use an automation rule with **Extract TTPs** then **Generate Detection Rules** (types such as `sigma`); articles without techniques are skipped.

**GitHub Actions** (`.github/workflows/sync-intelfeed-rules.yml` in your rules repo), with `INTELFEED_URL`, `INTELFEED_USERNAME` and `INTELFEED_PASSWORD` as repository secrets:

```yaml
on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:

jobs:
  sync:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - name: Download rules from IntelFeed
        env:
          URL: ${{ secrets.INTELFEED_URL }}
          USER: ${{ secrets.INTELFEED_USERNAME }}
          PASS: ${{ secrets.INTELFEED_PASSWORD }}
        run: |
          TOKEN=$(curl -sf -X POST "$URL/api/auth/login" -H "Content-Type: application/json" \
            -d "{\"username\": \"$USER\", \"password\": \"$PASS\"}" | jq -r .access_token)
          curl -sf -H "Authorization: Bearer $TOKEN" \
            "$URL/api/detection-rules/export?format=zip" -o rules.zip
          rm -rf rules && mkdir rules && unzip -o rules.zip -d rules
      - name: Commit changes
        run: |
          git config user.name "IntelFeed Bot"
          git config user.email "bot@example.com"
          git add rules/
          git diff --cached --quiet || git commit -m "Sync rules from IntelFeed"
          git push
```

---

### 9. Exports (Markdown, CSV, ATT&CK Layer)

| Endpoint | Returns |
|----------|---------|
| `GET /api/export/entries/{entry_id}` | Article as Markdown |
| `GET /api/export/notes/{note_id}` | Note as Markdown |
| `POST /api/export/bulk` | ZIP of article and note Markdown files |
| `GET /api/export/entities/{entity_type}/{entity_id}` | Entity profile as Markdown |
| `POST /api/export/entities/bulk` | ZIP of entity profiles of one type |
| `POST /api/export/research-bundle` | ZIP: article Markdown, `entities.md`, `iocs.csv`, ATT&CK Navigator layer |
| `GET /api/export/campaigns/{campaign_id}/bundle` | That bundle for a campaign's articles |

Research bundle:

```bash
curl -X POST https://intelfeed.example.com/api/export/research-bundle \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entry_ids": ["550e8400-e29b-41d4-a716-446655440000"], "name": "Q3 ransomware"}' \
  -o bundle.zip
```

**CSV of search results** via the [IntelFeed CLI](#13-intelfeed-cli-integration) (from the repo root):

```bash
export INTELFEED_API_URL=https://intelfeed.example.com
export INTELFEED_USERNAME=your_user
export INTELFEED_PASSWORD=your_pass

python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "cve.cvss:>=9.0", "limit": 100}' | \
  python3 -c "
import sys, json, csv
data = json.load(sys.stdin)['result']
writer = csv.DictWriter(sys.stdout, fieldnames=['title', 'url', 'feed_title', 'published_at'])
writer.writeheader()
for e in data.get('entries', []):
    writer.writerow({k: e.get(k) for k in writer.fieldnames})
" > entries.csv
```

---

## Inbound Integrations: External Systems → IntelFeed

### 10. OPML Import (Bulk Feed Onboarding)

Export OPML from another reader (Feedly, Inoreader, …) and import it via **Add Feed** or onboarding, or the API:

```bash
curl -X POST https://intelfeed.example.com/api/opml/import \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@subscriptions.opml"
```

Folders become categories; existing feed URLs are skipped; new feeds get a first fetch. The response counts `feeds_added`, `feeds_skipped`, `categories_created`, `errors`. Max 10 MB. With per-user subscriptions off, only admins can import.

Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<opml version="1.0">
  <head><title>My Subscriptions</title></head>
  <body>
    <outline text="Security" title="Security">
      <outline text="Krebs on Security" type="rss" xmlUrl="https://krebsonsecurity.com/feed/" />
    </outline>
  </body>
</opml>
```

---

### 11. Manual URL/PDF Ingestion via REST API

**A URL:**

```bash
curl -X POST https://intelfeed.example.com/api/entries/ingest/url \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/article"}'
```

Response:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "Article Title",
  "url": "https://example.com/article",
  "word_count": 1200,
  "feed_id": "550e8400-e29b-41d4-a716-446655440001",
  "content_hash": "abc123...",
  "message": "Entry created"
}
```

**A PDF:**

```bash
curl -X POST https://intelfeed.example.com/api/entries/ingest/pdf \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@report.pdf" \
  -F "title=Security Report 2026"
```

Errors: 409 duplicate, 413 too large, 422 textless scan, 400 bad file.

**Many files or URLs:** create a batch (`POST /api/entries/ingest/batches`), add `.../batches/{batch_id}/files` (one per request: PDF, DOCX, TXT, MD, HTML, CSV, EML, ZIP and more), `.../urls` (up to 500) or `.../text`. Processing is in the background; status at `GET /api/entries/ingest/batches/{batch_id}`.

---

### 12. Polling IntelFeed via REST API

**Plain-text search** (`GET /api/search`; `q` is not the query language):

```bash
curl "https://intelfeed.example.com/api/search?q=ransomware&limit=20&sort=newest" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Parameters: `date_from` / `date_to` (ISO timestamps), `feed_type`, `tags`, `limit` (up to 500), `offset`, `sort` (`relevance`, `newest`, `oldest`, `title_asc`, `title_desc`).

Response:

```json
{
  "hits": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Critical Vulnerability Disclosure",
      "url": "https://example.com",
      "author": "Security Team",
      "summary": "...",
      "published_at": 1746358800,
      "feed_id": "550e8400-e29b-41d4-a716-446655440001",
      "feed_title": "Security Feed",
      "tags": ["critical", "cve"]
    }
  ],
  "query": "ransomware",
  "estimatedTotalHits": 125,
  "processingTimeMs": 42
}
```

**Query-language search** (`POST /api/search/unified`) for filters like `cve.cvss:>=9.0` ([query-language.md](query-language.md)):

```bash
curl -X POST https://intelfeed.example.com/api/search/unified \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"q": "cve.kev:true date:>=2026-10-01 sort:newest", "limit": 50}'
```

Articles return in `entries.hits`, intelligence records in `entities.items`.

**Entity search** (`GET /api/search/entities`): `q` and `entity_type` (`cve`, `ttp`, `threat_actor`, `malware`):

```bash
curl "https://intelfeed.example.com/api/search/entities?q=APT29&entity_type=threat_actor&limit=10" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Incremental polling** (Python):

```python
import json
from datetime import datetime, timezone

import requests

API_URL = "https://intelfeed.example.com"
headers = {"Authorization": "Bearer YOUR_TOKEN"}
STATE_FILE = "last_sync.json"

try:
    with open(STATE_FILE) as f:
        last_sync = json.load(f)["last_sync"]
except FileNotFoundError:
    last_sync = None

now = datetime.now(timezone.utc).isoformat()
params = {"q": "", "limit": 100, "sort": "newest"}
if last_sync:
    params["date_from"] = last_sync

for entry in requests.get(f"{API_URL}/api/search", headers=headers, params=params).json()["hits"]:
    print("New entry:", entry["title"])  # send to your system here

with open(STATE_FILE, "w") as f:
    json.dump({"last_sync": now}, f)
```

`date_from` filters on publication date, so late articles with older dates can be missed; overlap windows if that matters.

**Saved searches:** `GET /api/saved-searches` returns their `query` strings for `POST /api/search/unified`.

---

### 13. IntelFeed CLI Integration

`intelfeed-skill/scripts/intelfeed_cli.py` is a dependency-free Python 3 script that calls the tool registry over the API.

```bash
export INTELFEED_API_URL=https://intelfeed.example.com
export INTELFEED_USERNAME=your_user
export INTELFEED_PASSWORD=your_pass

python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'
python3 intelfeed-skill/scripts/intelfeed_cli.py --list-tools          # every tool
python3 intelfeed-skill/scripts/intelfeed_cli.py --help-tool get_cve   # one tool's parameters
```

- `INTELFEED_API_URL` must be `https://` or `http://` localhost; `INTELFEED_ALLOW_INSECURE_HTTP=1` allows plain HTTP on trusted networks.
- `INTELFEED_READ_ONLY=1` refuses every write tool.
- Output: JSON `{"tool": ..., "result": ...}` per call on stdout, a list for several.

Common tools: `search_entries` (full query language), `search_entities`, `get_entry`, `get_threat_actor`, `get_malware`, `get_cve`, `get_ttp`, `get_dashboard_stats`, `get_feeds`, `list_saved_searches`.

Several calls at once:

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py \
  search_entries '{"query": "Log4j", "limit": 5}' \
  get_feeds '{"limit": 10}'
```

**CI example** (GitHub Actions step, CLI checked out):

```yaml
- name: Check for new critical CVEs
  run: |
    python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "cve.cvss:>=9.0 date:>=2026-10-01", "limit": 20}' \
      | python3 -c "import sys, json; r = json.load(sys.stdin)['result']; print(f\"Found {r['total']} articles\")"
```

Full tool list: [cli-reference.md](cli-reference.md).

---

## Configuration Recipes

AI providers live in **Settings → AI Configuration → Providers** (**+ Add**). A provider does nothing until tasks are assigned to it, with a model, in the **Prompts** tab. The article extraction model is set in **Settings → Engine → Pipeline → extract stage**.

| Provider type | Use for | Tool calling (copilot) |
|---------------|---------|------------------------|
| Claude (Anthropic API) | Hosted Claude with an API key | No |
| Claude Code CLI | Claude via subscription sign-in | Yes |
| Ollama (self-hosted) | Local models | Yes |
| OpenAI-compatible | OpenAI, LM Studio, vLLM, llama.cpp, OpenRouter, LiteLLM, Groq | No |

Copilot needs tool calling ([copilot.md](copilot.md)).

### 14. Configure Claude as AI Provider

With an Anthropic API key (console.anthropic.com): **+ Add** a provider of type **Claude (Anthropic API)** with a name and the key, **Save**, **Test**, then assign tasks and models in **Prompts**.

Models: `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001` (Haiku cheapest and fastest, Opus strongest). Spend: **Settings → AI Configuration → Cost Dashboard**.

**Claude Code CLI** is created by IntelFeed at startup, signs in with a Claude account (admins redo expired sign-ins in **Settings → AI Configuration**), and runs only on `celery-worker-ai`. See [copilot.md](copilot.md).

---

### 15. Configure OpenAI as AI Provider

With an OpenAI API key that has credit:

1. **+ Add** a provider of type **OpenAI-compatible**, base URL `https://api.openai.com/v1`, your key, **Save**.
2. **Configure** → **Default model**: a chat model id (such as `gpt-4o-mini`).
3. For reasoning models (o1, o3, gpt-5) also set **Max tokens param** `max_completion_tokens`, **Send temperature** off, **System role** `developer`.
4. **Test**, then assign tasks in **Prompts**.

**Cost tracking:** set **Input $/1M tok** and **Output $/1M tok** in **Configure**, or usage counts as free.

---

### 16. Configure Local Ollama

**Pick a model.** A ~9B tool-calling model is a good start, such as `qwen3.5:9b` on an 8 GB GPU. Model plus context must fit in GPU memory, or Ollama spills to CPU and slows sharply.

```bash
# On the Ollama host
ollama pull qwen3.5:9b
ollama ps            # while a request runs: PROCESSOR should say 100% GPU
```

**Keep the context small.** Context is sized per prompt, up to 32,768 tokens by default — too much for 9B on 8 GB. Either:

- set **Context cap** `16384` in **Configure**, or
- start Ollama with `OLLAMA_FLASH_ATTENTION=1` and `OLLAMA_KV_CACHE_TYPE=q8_0`, roughly halving context memory.

**Reaching Ollama.** In Docker, `localhost` is the container.

- Same machine: set `OLLAMA_HOST=0.0.0.0`; with the dev compose file use `http://host.docker.internal:11434` (mapped to the host for `api`, `celery-worker` and `celery-worker-ai`). The prod compose file has no such mapping; use the host's LAN address.
- Another machine: its address (such as `http://gpu-box:11434`) or an HTTPS reverse proxy.

**Add the provider:** **+ Add**, type **Ollama (self-hosted)**, base URL from above with no `/v1` (IntelFeed uses Ollama's own `/api/chat`), API key empty unless a proxy wants a bearer token. **Save**, **Test** (also loads pulled models), assign tasks in **Prompts**.

**Defaults** (editable in **Configure**, per provider or model):

- **Thinking** off, else reasoning models spend the output budget thinking and return nothing.
- Temperature never below 0.2; at 0, local models can loop forever on structured output.
- Request timeout 900 seconds.
- **Keep alive**: how long the model stays loaded (such as `30m`; Ollama default 5 minutes).

---

### 17. Configure an OpenAI-Compatible Endpoint (LM Studio, vLLM, llama.cpp, OpenRouter, LiteLLM, Groq)

**OpenAI-compatible** covers any server speaking `/v1/chat/completions`. Start your server, **+ Add** that provider type with a base URL from the table (API key for hosted services like OpenRouter and Groq; usually empty locally), **Save**, then set **Configure** → **Default model** to an id the server lists (**Test** shows them).

| Server | Base URL |
|---|---|
| LM Studio | `http://localhost:1234/v1` |
| llama.cpp server | `http://localhost:8080/v1` |
| vLLM | `http://vllm-server:8000/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| LiteLLM proxy | your proxy's `/v1` URL |

As with Ollama, `localhost` is the IntelFeed container; use `host.docker.internal` (dev) or the host's address.

**LM Studio:** load a model, start the local server; no key. 

**llama.cpp** (model host):

```bash
llama-server -m ./your-model.gguf --jinja -c 8192
```

`--jinja` enables the chat templates most GGUF models need.

**vLLM** (model host):

```bash
python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen2.5-7B-Instruct
```

Model: `Qwen/Qwen2.5-7B-Instruct`.

**Configure settings:**

- **Min temperature**: `0.2` locally if a task hangs or returns cut-off JSON.
- **Structured output**: `json_schema` by default, `json_object` without schema support; a rejected format is retried once simpler.
- **Input / Output $/1M tok**: for paid services (OpenRouter, Groq), or **Use provider-reported cost** for OpenRouter and LiteLLM. Local defaults to $0.
- **Extra body**: JSON merged into every request, such as `{"chat_template_kwargs": {"enable_thinking": false}}`.

**Rate limits:** a `429` pauses the provider until `Retry-After` (or 60 seconds); queued work then resumes. OpenAI's `insufficient_quota` pauses it for an hour.

**Not supported:** tool calling; the copilot and agentic tasks need Ollama or the Claude Code CLI.

OpenRouter's health check doesn't validate the key, so a bad key passes **Test**.

---

### 18. Configure Enrichment Sources

Enrichment adds outside data to CVEs, techniques, malware and indicators. Each source declares itself in its class (`backend/app/enrichment/adapters/`, `backend/app/enrichment/catalogs.py`), listed in `backend/app/enrichment/registry.py`:

| Source | Key | Default trigger | Default rate limit | Scheduled jobs | Adds |
|--------|---------|-----------------|--------------------|----------------|------|
| FIRST EPSS | No | Manual | 100/min | Daily score sync | CVE exploit probability |
| NVD API 2.0 | No | Auto | 50 per 30 s | Backfill, refresh, re-enrich | CVE details, CVSS |
| CISA KEV | No | Manual | 100/min | Catalog sync every 6 h | Known exploited CVEs |
| MITRE ATT&CK | No | Manual | 10/hour | Weekly bundle sync | Technique data |
| VulnCheck KEV | Yes | Manual | 1,000/min | | KEV, EPSS, exploit data |
| OSV | No | Auto | 100/min | | Open-source vulnerabilities |
| Malpedia | No | Manual | 30/min | Weekly family sync | Malware families |
| GitHub PoC | No (optional token) | Manual | 10/min, 30/min with a token | Daily PoC scan | Public PoC repos |
| CVEDetails | Yes | Auto | 60/min | | CVE context |
| Wikipedia | No | Auto | 20/min | Weekly sync | Background articles |
| VirusTotal v3 | Yes | Manual | 4/min | | Indicator reputation |
| GreyNoise Community | No (optional) | Manual | 10/hour | | IP noise, reputation |
| Shodan InternetDB | No | Auto | 30/min | | IP open ports and tags |
| MISP Galaxy | No | — | 10/hour | Weekly | Reference actor aliases |
| Metasploit modules | No | — | 10/hour | Weekly | CVEs with Metasploit modules |
| MITRE CWE | No | — | 10/hour | Weekly | The CWE catalog |
| ransomware.live | No | — | 2/min | Every 30 min | Leak-site victims |
| Cybergeist | No | — | 10/hour | Daily | Threat actors and malware |

Auto = looked up when a new entity appears; Manual = on request from an entity or indicator. The last five are catalog sources: they only run their jobs. Turning a source off also stops its jobs. A rate above what a source documents it allows is refused.

**To configure:** **Settings → Engine → Pipeline** → **enrich** stage: turn on sources, paste keys, optionally change rate limit and confidence threshold, save.

**Personal keys:** **Set My Key** on a source card stores your own key for your requests.

---

### 19. Image Proxy Configuration

Article images are rewritten to `/api/proxy/image?url=...` so outside sites don't see users' IPs; they're cached on disk.

In **Settings → Engine → Feeds** (fetch settings):

| Setting | Default |
|---------|---------|
| `image_proxy_enabled` | `true` |
| `image_proxy_cache_ttl_days` | `30` |
| `image_proxy_max_size_bytes` | 10 MB |

Markdown exports and the public RSS feed restore the original image URLs.

---

## Authoring Complex Automation Patterns

Conditions are fixed types (**Content Contains**, **Severity Above**, **Has Signal Type**, **Watched Entity Mentioned**, …) joined with AND or OR, not the query language. Automation **Templates** creates editable ready-made rules.

### 20. Multi-Step Automation: Extract → Rules → Slack

**Goal:** when an article mentions a CVE, extract techniques, generate Sigma rules, and tell a Slack review channel.

- **Trigger:** **CVE Detected**.
- **Actions:**
  1. **Extract TTPs**: links ATT&CK techniques.
  2. **Branch** on **Severity Above** (minimum CVSS 8.0):
     - **Then:**
       - **Generate Detection Rules**, types `sigma` (skipped with no techniques).
       - **Send Notification**: platform `slack`, template `Rules drafted from {title}: {url}`.
     - **Else:** nothing.

[Recipe 8](#8-detection-rule-export-to-github--gitlab) moves the rules to Git.

---

### 21. Morning Briefing: Scheduled Digest

**Goal:** an AI briefing of the last 24 hours, posted to Slack at 08:00 UTC each weekday.

- **Trigger:** **Schedule (Cron)**
  - Cron: `0 8 * * 1-5` (UTC)
  - Entry filter: **Last 24 hours** (optionally some feeds or categories)
  - Execution mode: **Batch**
- **Actions:**
  1. **Run AI Task** `intelligence_briefing` writes one briefing into `{ai_summary}` (or **Use Daily Summary** reuses the existing daily summary).
  2. **Send Notification**: platform `slack`, channel `#daily-briefing`, template `{ai_summary}`.

Trigger **Max entries** caps articles per run (1–500).

For email, add a **Run Webhook** to an email relay (recipe 5):

```json
{
  "to": "security-team@example.com",
  "subject": "Morning Threat Brief",
  "body": "{ai_summary}"
}
```

---

### 22. Watched-Entity Alerts

**Goal:** a message as soon as an article mentions a watched entity.

1. Watch the entities from their profiles.
2. In Automation **Templates**, pick **Alert on Watched Entities** (creates a disabled rule):
   - Trigger: **New Entry**
   - Condition: **Watched Entity Mentioned**
   - Action: **Send Notification**, platform `custom`
3. Set platform (such as `discord`) and webhook URL; optionally **Add Tags** `watchlist-hit` to find hits with `tag:watchlist-hit`.
4. Enable the rule.

---

## Summary Table: Integration Methods

| Target | Method | Format | When |
|---|---|---|---|
| Slack | Send Notification | Block Kit JSON | Live or scheduled |
| Discord | Send Notification | Embed JSON | Live or scheduled |
| Teams | Run Webhook | MessageCard or Adaptive Card | Live |
| Splunk | Webhook to HEC, or pull lookup CSVs | JSON / CSV | Push or scheduled pull |
| Elastic | Webhook to Logstash | JSON | Live |
| Firewalls | Pull EDL files | Plain text | Scheduled pull |
| TIPs (TAXII 2.1) | Pull TAXII collection | STIX 2.1 | Scheduled pull |
| MISP | Script against the REST API | MISP JSON | Scheduled |
| Git | Pull rule export | ZIP / YAML | Scheduled |
| Email | Webhook to an email service | JSON | Live or scheduled |
| Any tool | REST API | JSON | Polling |
| Other RSS readers | OPML import / export | XML | One-off |

---

## Troubleshooting

### Webhook not firing

- Is the rule enabled, and do trigger and conditions match the article?
- **Settings → Logs → Automation** shows each action's result: errors like `Webhook returned 400` come from the receiver; refused URLs show why.
- Test the URL with `curl` from the IntelFeed host.

### API authentication fails

- Access tokens expire after 2 hours: log in again or `/api/auth/refresh` (each refresh token works once).
- Header format: `Authorization: Bearer <token>`.

### Enrichment sources not running

- Is it on (**Settings → Engine → Enrichment**), with a working key? A status of **failing** or **needs key** says which; expand the row for the last job error. A disabled source's jobs report `skipped: source disabled`.
- Errors are in **Settings → Logs** (Tasks).
- Lower the rate limit if throttled.

### Image proxy issues

- Is `image_proxy_enabled` on (**Settings → Engine → Feeds**)?
- Images over the size limit (default 10 MB) aren't proxied.
- Private-network hosts are refused unless `OUTBOUND_ALLOW_PRIVATE_NETWORKS=true`.

---

## Related Documentation

- [automation-ai-enrichment.md](automation-ai-enrichment.md): AI tasks, prompts and enrichment in depth.
- [api-reference.md](api-reference.md): all endpoints.
- [query-language.md](query-language.md): search syntax for `search_entries` and `/api/search/unified`.
- [observables.md](observables.md): the indicator ledger behind published feeds.
- [guide/automation-and-ai.md](guide/automation-and-ai.md): building automation rules.
- [guide/searching.md](guide/searching.md): searching.
