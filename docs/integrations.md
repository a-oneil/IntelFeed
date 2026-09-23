# Integration Cookbook

Recipes for hooking IntelFeed into other systems. Each recipe is a self-contained guide with prerequisites, steps, and copy-paste payloads.

## Prerequisites for All Recipes

All recipes require:
- **IntelFeed API credentials**: Username and password (or API token after login)
- **API endpoint**: Your IntelFeed instance URL (e.g., `https://intelfeed.example.com` or `http://localhost:8000`)
- **Network access**: From the external system to IntelFeed (or webhook target)

### Obtain an API Token

```bash
curl -X POST https://intelfeed.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Token lifecycle**:
- Access tokens expire after 2 hours (`access_token_expire_minutes`, default 120); refresh tokens last 7 days
- Use the refresh token to obtain new access tokens (endpoint: `/api/auth/refresh`)
- Include access token in all API requests: `Authorization: Bearer <access_token>`

---

## Outbound Integrations: IntelFeed → External Systems

> **Note:** All outbound webhooks and notifications are configured inside automation rules — there is no separate webhook configuration in Settings. Saved webhooks appear as reusable presets in the rule builder's action node.

### 1. Slack Notifications

**Summary**: Automation rule sends critical CVEs to a Slack channel using Block Kit formatting.

**Prerequisites**:
- A Slack workspace and channel
- A Slack Incoming Webhook URL (create at workspace.slack.com/apps/A0F7XDUAZ)
- IntelFeed automation rule enabled

**Steps**:
1. Create or open a Slack app and go to **Incoming Webhooks**
2. Click **Add New Webhook to Workspace** and select your channel
3. Copy the Webhook URL
4. In IntelFeed, navigate to **Sidebar > Automation > New Rule**
5. Set trigger: e.g., `contains("critical CVE")`
6. Add action: **Send Notification**
7. Configure:
   - Platform: `slack`
   - Webhook URL: Paste from step 3
   - Channel: `#threat-intel` (or omit to use channel from webhook)
   - Username: `IntelFeed`
   - Message template (optional): `New critical alert: {title}\n{url}\n{ai_summary}`

**Payload sent**:
```json
{
  "text": "**New Entry Alert**\n...",
  "username": "IntelFeed",
  "icon_emoji": ":shield:",
  "channel": "#threat-intel",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*<https://example.com|Entry Title>*"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "Entry summary or AI-generated text here..."
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Author:* Security Researcher"
        },
        {
          "type": "mrkdwn",
          "text": "*Source:* IntelFeed"
        }
      ]
    }
  ]
}
```

**Variants**:
- **Digest mode** (batch): Create a scheduled rule that aggregates N entries and posts one summary message per N entries
- **Per-entry mode**: Trigger on individual entries (default)
- **Threaded replies**: Use `thread_ts` header for follow-ups (supported in custom webhook mode)

---

### 2. Discord Notifications

**Summary**: Post rich embeds with color-coded severity to Discord.

**Prerequisites**:
- A Discord server and channel
- Discord Webhook URL (Server Settings > Webhooks > New Webhook)
- IntelFeed automation rule

**Steps**:
1. In Discord server, go to **Server Settings > Webhooks**
2. Click **New Webhook**, select channel, copy URL
3. In IntelFeed, **Sidebar > Automation > New Rule**
4. Configure action:
   - Platform: `discord`
   - Webhook URL: Paste from step 2
   - Username: `IntelFeed`
   - Include embeds: `true`

**Payload sent**:
```json
{
  "content": "**New Critical Alert**\n<https://example.com|View Article>",
  "username": "IntelFeed",
  "embeds": [
    {
      "title": "Zero-Day Remote Code Execution in Product X",
      "url": "https://example.com/article",
      "description": "A critical vulnerability was discovered in Product X v1.0 allowing remote code execution...",
      "fields": [
        {
          "name": "Author",
          "value": "Security Researcher Name",
          "inline": true
        },
        {
          "name": "Source",
          "value": "IntelFeed Automation",
          "inline": true
        }
      ],
      "color": 16731398
    }
  ]
}
```

**Color codes**:
- Critical: `0xF78166` (red)
- High: `0xFB8500` (orange)
- Medium: `0xFFBF69` (yellow)
- Low: `0x52B788` (green)

---

### 3. Custom HTTP Webhook (Generic JSON)

**Summary**: POST arbitrary JSON to a custom endpoint (n8n, Zapier, custom service).

**Prerequisites**:
- An HTTP endpoint that accepts POST requests
- IntelFeed automation rule

**Steps**:
1. Prepare your endpoint (test with curl if needed)
2. In IntelFeed, **Sidebar > Automation > New Rule**
3. Add action: **Run Webhook**
4. Configure:
   - URL: `https://your-service.example.com/webhook`
   - Headers: `{"Authorization": "Bearer YOUR_TOKEN"}` (if needed)
   - Custom payload (optional):
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

**Default payload** (if no custom payload specified):
```json
{
  "entry_id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "Critical CVE in OpenSSL",
  "url": "https://example.com/cve",
  "author": "Security Team",
  "content_text": "...",
  "published_at": "2026-05-03T12:00:00Z",
  "ai_summary": "AI-generated summary text",
  "ai_results": {
    "summarization": {"summary": "..."}
  }
}
```

**Security notes**:
- IntelFeed validates webhook URLs against SSRF attacks (scheme and host checks)
- Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are **allowed by default** (`webhook_allow_private_networks: true`), since self-hosted deployments commonly target internal endpoints
- To block private-network webhooks, set `webhook_allow_private_networks: false` in backend config

**Variable substitution** in custom payload:
- `{title}`, `{url}`, `{author}`, `{summary}`, `{ai_summary}`, `{published_at}`, `{feed_name}`
- All variables are JSON-escaped for safe string embedding
- This single-brace set is fixed — other fields (e.g. the entry UUID) are only available via the default payload. Distinct from the Jinja `{{ entry.* }}` variables used by **Run AI Task** prompts, which additionally expose `entry.id` and `entry.app_url` (in-app deep link). The rule builder shows the live catalog for both systems (`GET /api/automation/variable-contexts`).

---

### 4. Microsoft Teams (Adaptive Card via Webhook)

**Summary**: Post Adaptive Cards to Teams for rich formatting.

**Prerequisites**:
- A Microsoft Teams channel
- Incoming Webhook connector (Channel Settings > Connectors > Incoming Webhook)

**Steps**:
1. In Teams, go to **Channel Settings > Connectors > Configure "Incoming Webhook"**
2. Name the webhook and (optionally) upload an image
3. Copy the webhook URL
4. In IntelFeed, create automation rule with **Run Webhook** action
5. URL: Webhook URL from step 3
6. Custom payload:
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
           {"name": "Published", "value": "{published_at}"},
           {"name": "Feed", "value": "{feed_name}"}
         ],
         "text": "{summary}"
       },
       {
         "text": "**AI Analysis:**\n{ai_summary}"
       }
     ],
     "potentialAction": [
       {
         "@type": "OpenUri",
         "name": "View Full Article",
         "targets": [{"os": "default", "uri": "{url}"}]
       }
     ]
   }
   ```

---

### 5. Email Digest (via Webhook to Email Service)

**Summary**: Send digested intelligence via email (using Zapier, n8n, or SES webhook).

**Current state**: IntelFeed does **not** send email directly. Instead, use:
- **Zapier/n8n integration**: Route webhooks to email
- **AWS SES**: Raw email service
- **SendGrid**: Email delivery API

**Recipe using Zapier**:
1. Create a Zap: **Webhook (Catch raw request) → Send Email**
2. Get Zap webhook URL
3. In IntelFeed, create scheduled automation rule
4. Action: **Send Notification** (batch mode)
   - Platform: `custom`
   - Webhook URL: Zap URL
5. Or use **Run Webhook** with custom payload containing email fields

**Example payload for email service**:
```json
{
  "to": "security-team@company.com",
  "subject": "IntelFeed Alert: {title}",
  "html": "<h2>{title}</h2><p>{summary}</p><p><a href='{url}'>View article</a></p>"
}
```

---

### 6. SIEM Ingestion

#### 6a. Splunk HTTP Event Collector (HEC)

**Prerequisites**:
- Splunk instance with HEC enabled
- HEC token

**Steps**:
1. In Splunk, go to **Settings > Data Inputs > HTTP Event Collector**
2. Create a new token, note the token value
3. Copy the HEC URL (e.g., `https://splunk.example.com:8088/services/collector`)
4. In IntelFeed, create automation rule with **Run Webhook** action

**Payload**:
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

> Custom payloads only support the single-brace variables listed in recipe 3 — `{entry_id}` is not one of them. If you need the entry UUID, leave the payload empty: the default webhook payload includes `entry_id`, `title`, `url`, `author`, `content_text`, `published_at`, and any `ai_summary` / `ai_results` produced by earlier actions.

**Request**:
```bash
curl -X POST https://splunk.example.com:8088/services/collector \
  -H "Authorization: Splunk YOUR_HEC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "entry_id": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Critical CVE",
      "url": "https://example.com",
      "content": "...",
      "source": "intelfeed"
    }
  }'
```

#### 6b. Elastic / Logstash

**Recipe**: POST JSON to Logstash HTTP input plugin or Elasticsearch bulk endpoint.

**Logstash input config**:
```
input {
  http {
    port => 8080
    codec => json
  }
}
```

**IntelFeed webhook**:
- URL: `http://logstash.example.com:8080`
- Custom payload:
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

**Prerequisites**:
- Azure subscription with Log Analytics workspace
- Custom Logs API endpoint and shared key

**Recipe**:
```bash
curl -X POST "https://YOUR_WORKSPACE.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" \
  -H "Authorization: SharedKey WORKSPACE_ID:SIGNATURE" \
  -H "Content-Type: application/json" \
  -H "Log-Type: IntelFeedAlert" \
  -d '[{
    "Title": "Critical CVE",
    "URL": "https://example.com",
    "Author": "Security Researcher",
    "TimeGenerated": "2026-05-03T12:00:00Z"
  }]'
```

---

### 7. MISP Push Integration

**Summary**: Export IntelFeed intelligence to MISP as events.

**Prerequisites**:
- MISP instance running
- MISP API key
- IntelFeed Python script or custom automation

**Current support**: IntelFeed does not have direct MISP export, but you can:
1. Use the **Export API** to get Markdown/JSON of intelligence
2. Write a script that polls IntelFeed and pushes to MISP via MISP API

**Recipe script** (Python):
```python
import requests
import json

INTELFEED_URL = "https://intelfeed.example.com"
MISP_URL = "https://misp.example.com"
MISP_KEY = "YOUR_MISP_API_KEY"

# Fetch recent entries from IntelFeed
headers = {"Authorization": "Bearer YOUR_INTELFEED_TOKEN"}
response = requests.get(f"{INTELFEED_URL}/api/search?limit=10&sort=newest", headers=headers)
entries = response.json()["hits"]

# For each entry, create a MISP event
for entry in entries:
  event = {
    "Event": {
      "info": entry["title"],
      "distribution": 2,
      "threat_level_id": 2,
      "analysis": 1,
      "Attribute": [
        {
          "type": "url",
          "value": entry["url"],
          "distribution": 2
        }
      ]
    }
  }
  
  misp_resp = requests.post(
    f"{MISP_URL}/events",
    headers={"Authorization": MISP_KEY, "Content-Type": "application/json"},
    json=event
  )
  print(f"Created MISP event: {misp_resp.json()['Event']['id']}")
```

---

### 8. Detection Rule Export to GitHub / GitLab

**Summary**: Automation rule that commits generated detection rules to a Git repository.

**Prerequisites**:
- GitHub/GitLab account with a rules repository
- Personal access token (GitHub: Settings > Developer Settings > Tokens)
- IntelFeed automation rule with rule generation

**Steps**:
1. Create automation rule:
   - Trigger: `contains("malware")` or custom
   - Actions:
     - **Extract TTPs** (if not already extracted)
     - **Generate Detection Rules** (rule_types: `["sigma"]`)
     - **Run Webhook** (to a custom endpoint or n8n flow that commits to Git)

2. Leave the webhook payload **empty** to send the default payload — it includes `entry_id`, `title`, `url`, and the `ai_results` object (which carries the generated rules from the earlier action). Custom single-brace payload templates cannot reference `{entry_id}` or nested `ai_results` fields; your receiving endpoint (or n8n flow) extracts the rules from the default payload and forwards them to GitHub.

3. GitHub Actions workflow (`.github/workflows/ingest-rules.yml`):
   ```yaml
   on:
     repository_dispatch:
       types: [intelfeed_rules]
   
   jobs:
     add_rules:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Add rule from IntelFeed
           run: |
             mkdir -p rules/sigma
             echo "${{ github.event.client_payload.rules }}" > rules/sigma/${{ github.event.client_payload.entry_id }}.yml
         - name: Commit and push
           run: |
             git config user.name "IntelFeed Bot"
             git config user.email "bot@intelfeed.local"
             git add rules/
             git commit -m "Add rules from IntelFeed: ${{ github.event.client_payload.title }}"
             git push
   ```

---

### 9. CSV Export for Analysis

**Summary**: Export entries, entities, or rules as CSV for spreadsheet analysis.

**Currently supported via API**: Export endpoints return Markdown or JSON.

**CSV generation**: Use IntelFeed CLI or custom script.

**Recipe using CLI**:
```bash
# Set credentials
export INTELFEED_USERNAME=your_user
export INTELFEED_PASSWORD=your_pass
export INTELFEED_API_URL=https://intelfeed.example.com

# Search and export
python intelfeed_cli.py search_entries '{"query": "CVE:>9.0", "limit": 100}' | \
  python -c "
import sys, json, csv
data = json.load(sys.stdin)
writer = csv.DictWriter(sys.stdout, fieldnames=['title', 'url', 'author', 'published_at'])
writer.writeheader()
for hit in data.get('hits', []):
  writer.writerow({
    'title': hit.get('title'),
    'url': hit.get('url'),
    'author': hit.get('author'),
    'published_at': hit.get('published_at')
  })
" > entries.csv
```

---

## Inbound Integrations: External Systems → IntelFeed

### 10. OPML Import (Bulk Feed Onboarding)

**Summary**: Import RSS/Atom feeds from another reader (Feedly, Inoreader, etc.).

**Prerequisites**:
- OPML file exported from your previous reader

**Steps**:
1. Export OPML from source reader (usually **Settings > Export**)
2. Save the `.opml` file locally
3. In IntelFeed, go to **Settings > Feeds & Import > Import OPML**
4. Select the OPML file and upload

**OPML structure** (for reference):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<opml version="1.0">
  <head>
    <title>My Subscriptions</title>
  </head>
  <body>
    <outline text="Security" title="Security">
      <outline text="Krebs on Security" title="Krebs on Security" type="rss" xmlUrl="https://krebsonsecurity.com/feed/" />
      <outline text="CIS Alerts" title="CIS Alerts" type="rss" xmlUrl="https://www.cisecurity.org/advisories/feed/" />
    </outline>
    <outline text="Security Newsletter" type="rss" xmlUrl="https://newsletter.example.com/feed.xml" />
  </body>
</opml>
```

**Result**: IntelFeed creates feeds grouped by category and queues initial fetches.

---

### 11. Manual URL/PDF Ingestion via REST API

**Summary**: Programmatically push articles or PDFs into IntelFeed.

**Prerequisites**:
- IntelFeed API token
- URLs to ingest or PDF files

**Ingest URL**:
```bash
curl -X POST https://intelfeed.example.com/api/entries/ingest/url \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/article"
  }'
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

**Ingest PDF**:
```bash
curl -X POST https://intelfeed.example.com/api/entries/ingest/pdf \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@report.pdf" \
  -F "title=Security Report 2026"
```

**Use cases**:
- Slack command that ingests pinned articles
- Email webhook that forwards threat intel from security mailing lists
- Custom script that monitors a directory and pushes new PDFs

---

### 12. Polling IntelFeed via REST API

**Summary**: External tool queries IntelFeed for new intelligence since last sync.

**Prerequisites**:
- IntelFeed API token
- Saved search or query string

**API endpoints**:

**Search entries**:
```bash
curl -X GET "https://intelfeed.example.com/api/search?query=CVE:>9.0&limit=20&sort=newest" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

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
  "estimatedTotalHits": 125,
  "processingTimeMs": 42
}
```

**Search entities** (CVEs, TTPs, threat actors):
```bash
curl -X GET "https://intelfeed.example.com/api/search/entities?query=APT29&limit=10" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Polling pattern** (incremental sync):
```python
import requests
import json
import time
from datetime import datetime, timezone

API_URL = "https://intelfeed.example.com"
TOKEN = "YOUR_TOKEN"
LAST_SYNC_FILE = "last_sync.json"

headers = {"Authorization": f"Bearer {TOKEN}"}

# Load last sync timestamp
try:
  with open(LAST_SYNC_FILE) as f:
    state = json.load(f)
  last_sync = state.get("last_sync")
except FileNotFoundError:
  last_sync = None

# Query for new entries
query = f"date:>{last_sync}" if last_sync else ""
response = requests.get(
  f"{API_URL}/api/search",
  headers=headers,
  params={"query": query, "limit": 100, "sort": "newest"}
)

entries = response.json()["hits"]

# Process entries
for entry in entries:
  print(f"New entry: {entry['title']}")
  # ... send to external system, update SIEM, etc.

# Save new sync timestamp
with open(LAST_SYNC_FILE, "w") as f:
  json.dump({"last_sync": datetime.now(timezone.utc).isoformat()}, f)
```

**Saved searches for polling**:
- Create a saved search in IntelFeed UI: **Sidebar > Searches > New Saved Search**
- Query: e.g., `cve.cvss:>9.0 type:rss`
- Name: "Critical CVEs"
- API polls this search: `GET /api/saved-searches/{search_id}`

---

### 13. IntelFeed CLI Integration

**Summary**: Use the standalone Python CLI to interact with IntelFeed from scripts or CI/CD.

**Prerequisites**:
- Python 3.8+
- CLI script: `intelfeed_cli.py` (located in `intelfeed-skill/scripts/`)
- Environment variables set

**Setup**:
```bash
# Export credentials
export INTELFEED_API_URL=https://intelfeed.example.com
export INTELFEED_USERNAME=your_user
export INTELFEED_PASSWORD=your_pass

# Run a tool
python intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'
```

**Available tools** (170 total):
- `search_entries` — Full-text search across entries
- `search_entities` — Search CVEs, TTPs, threat actors, malware
- `get_entry` — Fetch single entry by ID
- `get_threat_actor` — Get actor profile with aliases and TTPs
- `get_malware` — Get malware family details
- `get_cve` — Get CVE with CVSS and EPSS scores
- `get_ttp` — Get MITRE ATT&CK technique
- `get_dashboard_stats` — System overview
- `get_feeds` — Feed list with pagination
- `list_saved_searches` — This user's saved searches
- ... (and 160 more — run `--list-tools` for the full catalog)

**Example: Multi-tool call**:
```bash
python intelfeed_cli.py \
  search_entries '{"query": "Log4j", "limit": 5}' \
  get_threat_actor '{"actor_id": "ACTOR-001"}' \
  get_feeds '{"limit": 10}'
```

**Output**: JSON printed to stdout (one result per tool call).

**CI/CD example** (GitHub Actions):
```yaml
- name: Check for new critical CVEs
  run: |
    python intelfeed_cli.py search_entries '{"query": "cve.cvss:>9.0", "limit": 20}' \
      | python -c "import sys, json; data = json.load(sys.stdin); print(f'Found {len(data[\"hits\"])} critical CVEs')"
```

---

## Configuration Recipes

### 14. Configure Claude as AI Provider

**Summary**: Wire Anthropic Claude for intelligence analysis tasks (summarization, rule generation, etc.).

**Prerequisites**:
- Anthropic API key (get from console.anthropic.com)

**Steps**:
1. In IntelFeed, go to **Settings > AI Configuration** (Providers tab)
2. Click **Add Provider**
3. Configuration:
   - **Provider**: Claude (Anthropic)
   - **API Key**: Paste your Anthropic key
   - **Model**: Select from available (e.g., `claude-opus-4-1`, `claude-sonnet-4`, `claude-haiku-4`)
   - **Base URL**: (leave default or use proxy)
   - **Timeout**: 120 seconds
4. Click **Test Connection** to verify
5. Assign tasks: still in **Settings > AI Configuration**, select Claude + model for each AI task

**Supported tasks**:
- Summarization
- Report section generation
- TTP extraction
- Threat actor identification
- Detection rule generation (Sigma, Splunk SPL, KQL, etc.)

**Model recommendations**:
- **Summarization**: Claude Haiku (fast, cheap)
- **Report generation**: Claude Sonnet (balanced)
- **Complex analysis**: Claude Opus (highest quality)

**Related**:
- **Cost Dashboard**: token usage and spend per provider/task live in **Settings > AI Configuration > Cost Dashboard**
- **Global AI copilot**: the in-app copilot is backed by the Claude Code CLI running on the dedicated `ai` Celery queue (`celery-worker-ai` service). Its OAuth session can be re-authenticated in-app at **Settings > AI Configuration** when it expires — no shell access needed.

---

### 15. Configure OpenAI as AI Provider

**Prerequisites**:
- OpenAI API key (api.openai.com)
- Sufficient account credits

**Steps**:
1. **Settings > AI Configuration > Add Provider**
2. Configuration:
   - **Provider**: OpenAI
   - **API Key**: Your OpenAI API key
   - **Model**: `gpt-4-turbo`, `gpt-4o`, `gpt-3.5-turbo`, etc.
   - **Base URL**: `https://api.openai.com/v1` (default)
3. Test and assign tasks

---

### 16. Configure Local Ollama

**Prerequisites**:
- Ollama running locally: `ollama serve` (listens on `http://localhost:11434`)
- Model downloaded: `ollama pull mistral` (or your chosen model)

**Steps**:
1. **Settings > AI Configuration > Add Provider**
2. Configuration:
   - **Provider**: OpenAI-compatible (Ollama uses OpenAI API format)
   - **API Key**: (leave empty; Ollama doesn't require auth)
   - **Base URL**: `http://localhost:11434/v1`
   - **Model**: Name of pulled model (e.g., `mistral`, `neural-chat`)
3. Test connection

**Note**: For remote Ollama, use full URL (e.g., `http://your-host:11434/v1`) and update config to allow private networks.

---

### 17. Configure Custom OpenAI-Compatible Endpoint

**Examples**: vLLM, LM Studio, llama.cpp server, custom inference API.

**Steps**:
1. Ensure your endpoint is running and accepts OpenAI API format
2. **Settings > AI Configuration > Add Provider**
3. Configuration:
   - **Provider**: OpenAI-compatible
   - **API Key**: If required by your endpoint
   - **Base URL**: Full URL of your endpoint (e.g., `http://vllm-server:8000/v1`)
   - **Model**: Model name your endpoint serves
4. Test

**Example: vLLM**:
```bash
python -m vllm.entrypoints.openai.api_server --model meta-llama/Llama-2-7b-chat-hf
```

Then configure IntelFeed:
- Base URL: `http://vllm-server:8000/v1`
- Model: `meta-llama/Llama-2-7b-chat-hf`

---

### 18. Configure Enrichment Sources

**Summary**: Enable and configure 10 enrichment adapters for automatic intelligence enhancement.

**Available sources** (from `enrichment/registry.py`):

| Source | Requires API Key | Trigger Mode | Rate Limit | Purpose |
|--------|---|---|---|---|
| **EPSS** (FIRST) | No | Scheduled | 100/min | CVE exploitability scoring |
| **NVD 2.0** | No | Auto | 50/30s | CVE details + CVSS |
| **CISA KEV** | No | Scheduled | 100/min | Known exploited vulnerabilities |
| **MITRE ATT&CK** | No | Scheduled | 10/hour | TTP / technique context |
| **VulnCheck KEV** | Yes | Scheduled | 1000/min | KEV + EPSS + exploit data |
| **OSV** | No | Auto | 100/min | Open vulnerability database |
| **Malpedia** | No | Scheduled | 30/min | Malware families + hashes |
| **GitHub PoC** | No | Scheduled | 10/min | Public proof-of-concept repos |
| **CVEDetails** | Yes | Auto | 60/min | Additional CVE context |
| **Wikipedia** | No | Auto | 10/min | General reference articles |

> **Note:** IntelFeed ships no IOC-lookup adapters (Shodan, ThreatFox, URLhaus, MalwareBazaar, GreyNoise, AbuseIPDB, VirusTotal, AlienVault OTX, urlscan). Indicator reputation lookups are handled by external tooling; any config that references such a source is inert.

**Steps to configure**:
1. **Settings > Engine > Pipeline** and select the **enrich** stage
2. For each source, click **Enable**
3. If the source requires an API key:
   - Paste your key
   - (Optional) Override rate limit
   - (Optional) Set confidence threshold (low/medium/high)
4. Save

**Example: VulnCheck**:
- Get API key from vulncheck.com (enterprise account)
- Enable in IntelFeed
- Paste key
- Rate limit: 1000 requests/min (default)
- Confidence threshold: medium
- Result: Entries mentioning CVEs automatically enriched with VulnCheck exploit data

**Per-user API keys**:
- Key-requiring sources (VulnCheck, CVEDetails) support a per-user override
- On the source's card in the enrichment panel, use **Set My Key** to store a personal key
- IntelFeed uses your key instead of the team key for that source

---

### 19. Image Proxy Configuration

**Summary**: Understand how IntelFeed proxies external images for privacy + caching.

**How it works**:
- IntelFeed extracts image URLs from feed entries
- When sharing or exporting, images are re-sanitized via a proxy URL
- External clients receive: `https://intelfeed.example.com/proxy/image?url=...` (encoded)
- Proxy fetches and streams the original image

**Configuration**:
- **Settings > Engine > Pipeline** (sanitize stage): Toggle enabled/disabled
- Proxy image caching: 30 days (default, `image_proxy_cache_ttl_days`)
- Max proxied image size: 10 MB (`image_proxy_max_size_bytes`)

**Use case**: When sharing IntelFeed findings externally, image URLs don't expose your users' IPs to external sites.

---

## Authoring Complex Automation Patterns

### 20. Multi-Step Automation: AI → Rule Generation → Slack

**Scenario**: New article → AI-summarize → If mentions a KEV CVE, generate Sigma rule → Post to Slack review channel.

**Automation rule config**:

**Trigger**: `contains("CVE") AND contains("exploit")`

**Actions** (in order):
1. **Run AI Task**: `summarization` task
   - Produces `{ai_summary}` for downstream use

2. **Extract CVEs**: Auto-extract CVE IDs
   - Stores CVE entities in database
   - Available in later actions as `{extraction_results.cves}`

3. **Branch**: Conditional split
   - **Condition**: `extraction_results.cves.length > 0`
   - **Then-branch**: 
     - **Generate Detection Rules**: `rule_types: ["sigma"]`
       - Creates Sigma rules from entry + extracted CVEs
     - **Run Webhook**: POST to n8n / custom rule-storage endpoint
       - Payload: Generated rules + entry details
     - **Send Notification**: Slack (batch mode)
       - Message: "Rule generated from {title} — review at [link]"
   - **Else-branch**: Silent (no rules generated)

**Result**: Automated triage pipeline that only alerts when actionable rules are generated.

---

### 21. Morning Briefing: Scheduled Digest

**Scenario**: Every morning at 8 AM, digest last 24h of starred entries + AI briefing → email + Slack.

**Automation rule config**:

**Trigger**: **Scheduled** (Daily, 08:00 UTC)

**Condition**: `is:starred date:>-1d`

**Actions**:
1. **Run AI Task** (batch mode): `detection_engineering_summary`
   - Input: All matched entries
   - Output: Single briefing text (not per-entry)
   - Produces `{ai_summary}` = morning briefing prose

2. **Send Notification** (batch mode): Slack
   - Platform: `slack`
   - Channel: `#daily-briefing`
   - Username: `📋 Morning Threat Brief`
   - Message template: `Morning briefing for {entry_count} starred items:\n\n{ai_summary}`

3. **Send Notification** (batch mode): Custom webhook
   - URL: Zapier webhook → Email
   - Payload:
     ```json
     {
       "to": "security-team@company.com",
       "subject": "Morning Threat Brief — {entry_count} items",
       "body": "{ai_summary}"
     }
     ```

**Result**: Every morning, your team receives a curated briefing of yesterday's top threats.

---

### 22. Watchlist Alerts with Real-Time Toast

**Scenario**: Monitor for mentions of specific threat actors; alert immediately in UI.

**Automation rule config**:

**Trigger**: `is:watchlist` AND (`threat_actor:APT29` OR `threat_actor:Lazarus`)

**Actions**:
1. **Add Tags**: `["watchlist-hit"]`
2. **Send Notification**: Discord
   - Webhook to security-alerts channel
   - Include AI summary if available
3. (Optional) **Run Webhook**: Custom endpoint that triggers UI toast via Server-Sent Events (SSE)
   - Backend broadcasts: `event: watchlist_hit` with entry details
   - Frontend shows: "🚨 Watchlist hit: APT29 activity detected"

**Frontend integration** (real-time):
```javascript
// src/hooks/useWatchlistAlerts.ts
const eventSource = new EventSource('/api/events?watch=watchlist_hit');
eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  toast({
    title: '🚨 Watchlist Hit',
    description: data.entry.title,
    action: <a href={data.entry.url}>View</a>,
  });
};
```

---

## Summary Table: Integration Methods

| Target System | Method | Complexity | Payload Format | Real-Time |
|---|---|---|---|---|
| **Slack** | Automation → Send Notification | Low | JSON (Block Kit) | Yes |
| **Discord** | Automation → Send Notification | Low | JSON (Embed) | Yes |
| **Splunk** | Automation → Run Webhook | Medium | JSON (HEC format) | Yes |
| **Elasticsearch** | Automation → Run Webhook | Medium | JSON (bulk API) | Yes |
| **Zapier/n8n** | Webhook + custom payload | Medium | JSON | Yes |
| **MISP** | Python script (polling) | High | MISP JSON | No (polling) |
| **GitHub** | Automation → Webhook → GitHub Actions | Medium | Dispatch event | No (workflow) |
| **Email** | Webhook → Email service | Low | JSON (SendGrid/SES) | Yes |
| **External tool** (polling) | REST API + saved search | Low | JSON (Meilisearch format) | No |
| **RSS readers** | OPML export/import | Low | XML (OPML) | N/A |

---

## Troubleshooting

### Webhook not firing
- Check automation rule is **enabled**
- Verify trigger condition matches test entries
- Check **Automation > Logs** for execution details
- Test webhook URL independently with curl

### API authentication fails
- Verify token is not expired (obtain fresh one)
- Check `Authorization: Bearer <token>` header format
- Confirm credentials in refresh endpoint if rotating tokens

### Enrichment sources not running
- Verify source is **enabled** in **Settings > Engine > Pipeline** (enrich stage)
- Check API key (if required) is valid and the source health status is not degraded
- Review **Settings > Logs** (Tasks tab) for source-specific errors
- Adjust rate limit if hitting throttle

### Image proxy issues
- Enable proxy in **Settings > Engine > Pipeline** (sanitize stage)
- Check external image URL is accessible and under the 10 MB size cap

---

## Related Documentation

- **Automation & AI**: See `automation-ai-enrichment.md` for advanced AI task setup, custom prompts, and extraction tuning
- **API Reference**: See `api-reference.md` for full endpoint documentation and schema details
- **User Guide**: See `guide/automation-and-ai.md` for UI-based automation, and `guide/searching.md` for search

---

*Last updated: July 2026*
