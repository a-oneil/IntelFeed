"""Shared Wikipedia fetch and parse logic for enrichment, API endpoints, and scripts."""

from __future__ import annotations

import logging
import re

import httpx

from app.enrichment.gateway import GatewayError, SourceGateway, client_for, user_agent

logger = logging.getLogger(__name__)

# Sections filtered out of Wikipedia content
SKIP_SECTIONS: set[str] = {
    "See also",
    "References",
    "External links",
    "Further reading",
    "Notes",
    "Bibliography",
    "Sources",
    "Footnotes",
    "Citations",
}

MAX_CONTENT_CHARS = 12_000

# Map entity names to their best Wikipedia search query.
# Handles disambiguation and names that don't resolve cleanly.
WIKI_OVERRIDES: dict[str, str] = {
    # Vendors
    "CrowdStrike": "CrowdStrike",
    "Palo Alto Networks": "Palo Alto Networks",
    "Fortinet": "Fortinet",
    "Check Point": "Check Point Software Technologies",
    "Sophos": "Sophos",
    "Trend Micro": "Trend Micro",
    "Rapid7": "Rapid7",
    "Qualys": "Qualys",
    "Tenable": "Tenable (company)",
    "CyberArk": "CyberArk",
    "BeyondTrust": "BeyondTrust",
    "Proofpoint": "Proofpoint (company)",
    "Barracuda": "Barracuda Networks",
    "Darktrace": "Darktrace",
    "Wiz": "Wiz (company)",
    "Snyk": "Snyk",
    "Recorded Future": "Recorded Future",
    "Mandiant": "Mandiant",
    "ESET": "ESET",
    "Bitdefender": "Bitdefender",
    "Malwarebytes": "Malwarebytes",
    "KnowBe4": "KnowBe4",
    "Splunk": "Splunk",
    "Elastic": "Elastic NV",
    "IBM": "IBM",
    "Microsoft": "Microsoft",
    "Google": "Google",
    "Amazon": "Amazon (company)",
    "Oracle": "Oracle Corporation",
    "Salesforce": "Salesforce",
    "Cisco": "Cisco",
    "Juniper Networks": "Juniper Networks",
    "F5 Networks": "F5 Networks",
    "Cloudflare": "Cloudflare",
    "Akamai": "Akamai Technologies",
    "Zscaler": "Zscaler",
    "Canonical": "Canonical (company)",
    "Red Hat": "Red Hat",
    "Apple": "Apple Inc.",
    "VMware": "VMware",
    "Citrix": "Citrix Systems",
    "Docker": "Docker (software)",
    "HashiCorp": "HashiCorp",
    "Okta": "Okta",
    "MongoDB": "MongoDB Inc.",
    "Snowflake": "Snowflake Inc.",
    "Atlassian": "Atlassian",
    "Zoom": "Zoom (software)",
    "ServiceNow": "ServiceNow",
    "Mozilla": "Mozilla",
    "Apache Software Foundation": "Apache Software Foundation",
    "Intel": "Intel",
    "AMD": "AMD",
    "NVIDIA": "Nvidia",
    "Broadcom": "Broadcom Inc.",
    "Huawei": "Huawei",
    "Samsung": "Samsung Electronics",
    "Linux Foundation": "Linux Foundation",
    # Products
    "CrowdStrike Falcon": "CrowdStrike",
    "Metasploit": "Metasploit",
    "Tenable Nessus": "Nessus (software)",
    "Microsoft Azure": "Microsoft Azure",
    "Microsoft 365": "Microsoft 365",
    "Microsoft Sentinel": "Microsoft Sentinel",
    "Microsoft Exchange": "Microsoft Exchange Server",
    "Windows": "Microsoft Windows",
    "Windows Server": "Windows Server",
    "Active Directory": "Active Directory",
    "Microsoft SQL Server": "Microsoft SQL Server",
    "PowerShell": "PowerShell",
    "GitHub": "GitHub",
    "Google Cloud Platform": "Google Cloud Platform",
    "Android": "Android (operating system)",
    "Chrome": "Google Chrome",
    "Gmail": "Gmail",
    "Amazon Web Services": "Amazon Web Services",
    "Amazon S3": "Amazon S3",
    "Oracle Database": "Oracle Database",
    "Java": "Java (programming language)",
    "Slack": "Slack (software)",
    "Cisco IOS": "Cisco IOS",
    "Cisco ASA": "Cisco ASA",
    "Cisco Duo": "Duo Security",
    "Junos OS": "Junos OS",
    "F5 BIG-IP": "F5 BIG-IP",
    "Ubuntu": "Ubuntu",
    "Red Hat Enterprise Linux": "Red Hat Enterprise Linux",
    "Ansible": "Ansible (software)",
    "macOS": "macOS",
    "iOS": "iOS",
    "Safari": "Safari (web browser)",
    "VMware vSphere": "VMware vSphere",
    "Docker Engine": "Docker (software)",
    "Terraform": "Terraform (software)",
    "PostgreSQL": "PostgreSQL",
    "Elasticsearch": "Elasticsearch",
    "Kubernetes": "Kubernetes",
    "Firefox": "Firefox",
    "Apache HTTP Server": "Apache HTTP Server",
    "Apache Log4j": "Log4j",
    "Apache Kafka": "Apache Kafka",
    "Apache Tomcat": "Apache Tomcat",
    "OpenSSL": "OpenSSL",
    "Linux": "Linux",
    "Jira": "Jira (software)",
    "WireGuard": "WireGuard",
    "OpenVPN": "OpenVPN",
    "Tailscale": "Tailscale",
    "Symantec Endpoint Protection": "Symantec Endpoint Protection",
    "FortiGate": "FortiGate",
    "ESET NOD32": "ESET NOD32 Antivirus",
    "HarmonyOS": "HarmonyOS",
    "NVIDIA CUDA": "CUDA",
    "GitLab CI/CD": "GitLab",
}


def get_search_queries(entity_name: str, entity_type: str) -> list[str]:
    """Build an ordered list of Wikipedia search queries for a given entity.

    Checks WIKI_OVERRIDES first, then applies entity-type-specific suffixes.
    """
    # If there's a known override, use it first, then fall back to the raw name
    override = WIKI_OVERRIDES.get(entity_name)
    if override:
        queries = [override]
        if override != entity_name:
            queries.append(entity_name)
        return queries

    queries = [entity_name]

    if entity_type == "threat_actor":
        queries.append(f"{entity_name} hacker group")
        queries.append(f"{entity_name} APT")
    elif entity_type == "malware":
        queries.append(f"{entity_name} malware")
        queries.append(f"{entity_name} ransomware")
    elif entity_type == "tool":
        queries.append(f"{entity_name} (software)")
        queries.append(f"{entity_name} security tool")
    elif entity_type == "vendor":
        queries.append(f"{entity_name} (company)")
    elif entity_type == "product":
        queries.append(f"{entity_name} (software)")
        queries.append(f"{entity_name} (service)")

    return queries


def _normalize_title(value: str) -> str:
    """Normalize a title/name for comparison: strip parenthetical qualifiers,
    underscores, punctuation, and collapse whitespace."""
    value = re.sub(r"\s*\([^)]*\)\s*$", "", value)
    value = value.replace("_", " ")
    value = re.sub(r"[^\w\s]", "", value.lower())
    return re.sub(r"\s+", " ", value).strip()


def title_matches_entity(
    title: str,
    entity_name: str,
    aliases: list[str] | None = None,
    extra_titles: list[str] | None = None,
) -> bool:
    """Guardrail: check that a fetched Wikipedia article title reasonably matches
    the entity name, one of its aliases, or an explicitly expected title.

    Case-insensitive; parenthetical qualifiers are ignored (e.g. "Iran (country)"
    matches "Iran") and redirect targets that extend the name on a word boundary
    are accepted (e.g. "WannaCry ransomware attack" matches "WannaCry").
    Prevents storing wrong articles (e.g. "Iran" -> "ISBN").
    """
    if not title:
        return False
    normalized = _normalize_title(title)
    if not normalized:
        return False
    for candidate in [entity_name, *(aliases or []), *(extra_titles or [])]:
        cand = _normalize_title(candidate) if candidate else ""
        if not cand:
            continue
        if normalized == cand or normalized.startswith(f"{cand} "):
            return True
    return False


def _reconstruct_wiki_text(summary: str, sections) -> str:
    """Reconstruct raw text with == Section == markers from structured sections.

    This produces output compatible with format_wiki_content(), which expects
    the == Header == format from the old wikipedia package.
    """
    parts = [summary] if summary else []

    def _add_sections(section_list, level=2):
        for section in section_list:
            marker = "=" * level
            parts.append(f"{marker} {section.title} {marker}")
            if section.text:
                parts.append(section.text)
            if section.sections:
                _add_sections(section.sections, level + 1)

    _add_sections(sections)
    return "\n".join(parts)


def format_wiki_content(raw_content: str, url: str, max_chars: int = MAX_CONTENT_CHARS) -> str:
    """Convert raw Wikipedia page content to formatted markdown.

    Filters boilerplate sections, converts wiki-style headers to markdown,
    and truncates at max_chars with a read-more link.
    """
    lines = raw_content.split("\n")
    md_lines: list[str] = []
    in_skip = False
    char_count = 0

    for line in lines:
        # Check h3 before h2 — the h2 regex also matches === lines
        h3 = re.match(r"^===\s*(.+?)\s*===$", line)
        h2 = re.match(r"^==\s*(.+?)\s*==$", line) if not h3 else None

        if h3 and not in_skip:
            md_lines.append(f"\n### {h3.group(1).strip()}\n")
            continue

        if h2:
            section = h2.group(1).strip()
            if section in SKIP_SECTIONS:
                in_skip = True
                continue
            in_skip = False
            md_lines.append(f"\n## {section}\n")
            continue

        if in_skip:
            continue

        stripped = line.strip()
        if not stripped:
            if md_lines and md_lines[-1] != "":
                md_lines.append("")
            continue

        char_count += len(stripped)
        if char_count > max_chars:
            md_lines.append("")
            md_lines.append(f"*[Read more on Wikipedia]({url})*")
            break

        md_lines.append(stripped)

    content = "\n".join(md_lines).strip()

    if url and f"Wikipedia]({url})" not in content:
        content += f"\n\n*Source: [Wikipedia]({url})*"

    return content


def extract_first_paragraph(content: str) -> str | None:
    """Extract the first substantive paragraph from formatted Wikipedia content.

    Skips headings and italic attribution lines. Returns None if nothing suitable found.
    """
    for chunk in content.split("\n\n"):
        chunk = chunk.strip()
        if chunk.startswith("#") or (chunk.startswith("*") and chunk.endswith("*")):
            continue
        if len(chunk) >= 30:
            return chunk
    return None


WIKI_API_URL = "https://en.wikipedia.org/w/api.php"


async def _fetch_page_image_async(
    title: str, thumb_size: int = 300, *, transport: httpx.AsyncBaseTransport
) -> str | None:
    """The lead/infobox image URL for a Wikipedia page, from the MediaWiki API."""
    try:
        async with client_for(transport, timeout=10) as client:
            resp = await client.get(
                WIKI_API_URL,
                params={
                    "action": "query",
                    "titles": title,
                    "prop": "pageimages",
                    "format": "json",
                    "pithumbsize": thumb_size,
                },
            )
            if resp.status_code != 200:
                return None
            pages = resp.json().get("query", {}).get("pages", {})
            for page_data in pages.values():
                thumb = page_data.get("thumbnail", {}).get("source")
                if thumb:
                    return thumb
    except GatewayError:
        raise
    except Exception:
        pass
    return None


async def fetch_wikipedia(
    entity_name: str,
    entity_type: str,
    aliases: list[str] | None = None,
    *,
    transport: httpx.AsyncBaseTransport,
) -> dict | None:
    """Async Wikipedia fetch using wikipediaapi's native async support.

    ``transport`` routes every call through an enrichment SourceGateway:
    wikipediaapi hands it to the httpx client it builds, and its own retries
    are turned off so the gateway's breaker owns backoff. A gateway refusal
    propagates; any other failure means no article.
    """
    try:
        import wikipediaapi
    except ImportError:
        logger.warning("wikipedia-api package not installed")
        return None

    wiki = wikipediaapi.AsyncWikipedia(
        user_agent=user_agent("wikipedia"), language="en", transport=transport, max_retries=0
    )
    queries = get_search_queries(entity_name, entity_type)

    for q in queries:
        try:
            page = wiki.page(q)
            if not await page.exists():
                continue
            # CVE-id pages only exist as redirects to the vuln's common-name article
            # (e.g. CVE-2021-44228 -> Log4Shell), so an exact-id lookup is trusted.
            trusted_redirect = entity_type == "cve" and q == entity_name
            ok = trusted_redirect or title_matches_entity(page.title, entity_name, aliases, extra_titles=queries)
            if not ok:
                logger.warning(
                    "Wikipedia title mismatch for %s/%s: got %r — skipping", entity_type, entity_name, page.title
                )
                continue
            summary = await page.summary
            sections = await page.sections
            fullurl = await page.fullurl
            raw_text = _reconstruct_wiki_text(summary, sections)
            content = format_wiki_content(raw_text, fullurl)
            image_url = await _fetch_page_image_async(page.title, transport=transport)
            return {"content": content, "url": fullurl, "title": page.title, "image_url": image_url}
        except GatewayError:
            raise
        except Exception:
            continue

    return None


async def fetch_wikipedia_by_title(title: str, *, transport: httpx.AsyncBaseTransport) -> dict | None:
    """Fetch a specific Wikipedia article by exact title (user-selected — no guardrail).
    ``transport`` works as in fetch_wikipedia."""
    try:
        import wikipediaapi
    except ImportError:
        logger.warning("wikipedia-api package not installed")
        return None

    wiki = wikipediaapi.AsyncWikipedia(
        user_agent=user_agent("wikipedia"), language="en", transport=transport, max_retries=0
    )
    try:
        page = wiki.page(title)
        if not await page.exists():
            return None
        summary = await page.summary
        sections = await page.sections
        fullurl = await page.fullurl
        raw_text = _reconstruct_wiki_text(summary, sections)
        content = format_wiki_content(raw_text, fullurl)
        image_url = await _fetch_page_image_async(page.title, transport=transport)
        return {"content": content, "url": fullurl, "title": page.title, "image_url": image_url}
    except GatewayError:
        raise
    except Exception:
        logger.exception("Wikipedia fetch by title failed for %r", title)
        return None


_TAG_RE = re.compile(r"<[^>]+>")


async def search_wikipedia(query: str, gateway: SourceGateway, limit: int = 8) -> list[dict]:
    """Search Wikipedia article titles. Returns [{"title", "snippet", "url"}, ...]."""
    async with gateway.client(timeout=10) as client:
        resp = await client.get(
            WIKI_API_URL,
            params={
                "action": "query",
                "list": "search",
                "srsearch": query,
                "srlimit": limit,
                "format": "json",
            },
        )
        resp.raise_for_status()
        results = resp.json().get("query", {}).get("search", [])

    return [
        {
            "title": r["title"],
            "snippet": _TAG_RE.sub("", r.get("snippet") or ""),
            "url": f"https://en.wikipedia.org/wiki/{r['title'].replace(' ', '_')}",
        }
        for r in results
        if r.get("title")
    ]
