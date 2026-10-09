package com.example.intelfeed.data

import com.example.intelfeed.data.model.AuthTokens
import com.example.intelfeed.data.model.CursorPage
import com.example.intelfeed.data.model.EntryDetail
import com.example.intelfeed.data.model.EntryItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntelFeedSerializationTest {

    private val json = com.example.intelfeed.data.network.ApiJson.json

    @Test
    fun testAuthTokensDeserialization() {
        val payload = """
            {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh"
            }
        """.trimIndent()

        val tokens = json.decodeFromString<AuthTokens>(payload)
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", tokens.accessToken)
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh", tokens.refreshToken)
    }

    @Test
    fun testCursorPageEntriesDeserialization() {
        val payload = """
            {
                "items": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "title": "CISA Adds Known Exploited Vulnerability to Catalog",
                        "summary": "CISA has added one new vulnerability to its Known Exploited Vulnerabilities catalog.",
                        "url": "https://www.cisa.gov/news-events/alerts/2024/01/20",
                        "published_at": "2024-01-20T10:00:00Z",
                        "feed_id": "cisa-kev",
                        "feed_title": "CISA Alerts",
                        "author": "CISA Cyber Division",
                        "content_type": "article",
                        "is_read": false,
                        "is_starred": true,
                        "is_bookmarked": false,
                        "created_at": "2024-01-20T11:00:00Z",
                        "priority_score": 8.5
                    }
                ],
                "next_cursor": "eyJvZmZzZXQiOiA1MH0=",
                "has_more": true
            }
        """.trimIndent()

        val page = json.decodeFromString<CursorPage<EntryItem>>(payload)
        assertEquals(1, page.items.size)
        assertTrue(page.hasMore)
        assertEquals("eyJvZmZzZXQiOiA1MH0=", page.nextCursor)

        val item = page.items[0]
        assertEquals("550e8400-e29b-41d4-a716-446655440000", item.id)
        assertEquals("CISA Adds Known Exploited Vulnerability to Catalog", item.title)
        assertFalse(item.isRead)
        assertTrue(item.isStarred)
        assertEquals(8.5, item.priorityScore!!, 0.01)
    }

    /** Shape of GET /api/entries/{id} on the live server (2026-09-22): no entity lists, signals + echo instead. */
    @Test
    fun testEntryDetailMatchesLiveServer() {
        val payload = """
            {
                "id": "17bdf8b3",
                "title": "Weekly Recap",
                "url": "https://thehackernews.com/2026/09/weekly-recap.html",
                "published_at": "2026-09-07T14:36:07Z",
                "feed_title": "The Hacker News",
                "feed_type": "rss",
                "word_count": 2555,
                "content_html": "<p>Body</p>",
                "is_read": true,
                "tags": [ { "name": "hidden-by-automation", "color": "#6B7280" } ],
                "priority_score": 8.7816,
                "top_signals": [ { "type": "novel_entity", "explanation": "First mention of CVE 'CVE-2026-84124'" } ],
                "priority_signals": [
                    { "type": "novel_entity", "family": "novelty", "score": 1.0, "weighted": 0.184, "explanation": "First mention" },
                    { "type": "kev_added", "family": "severity", "score": 1.0, "weighted": 0.9, "explanation": "Added to KEV" }
                ],
                "is_echo": false,
                "echo_of": null,
                "metadata": { "article_intel": { "report_type": "news" } },
                "exposure": null,
                "personal": null
            }
        """.trimIndent()

        val detail = json.decodeFromString<EntryDetail>(payload)
        assertEquals("Weekly Recap", detail.title)
        assertEquals(2555, detail.wordCount)
        assertEquals(8.7816, detail.priorityScore!!, 0.0001)
        assertEquals(2, detail.prioritySignals.size)
        assertEquals("severity", detail.prioritySignals[1].family)
        assertEquals(0.9, detail.prioritySignals[1].weighted!!, 0.0001)
        assertEquals("hidden-by-automation", detail.tags.single().name)
        assertEquals(null, detail.echoOf)
    }

    @Test
    fun testEchoEntryDetail() {
        val payload = """
            { "id": "e1", "title": "Re-report", "is_echo": true,
              "echo_of": { "entry_id": "orig", "title": "Original", "feed_title": "BleepingComputer",
                           "published_at": "2026-09-22T16:32:47Z", "shared": 3, "total": 4 } }
        """.trimIndent()
        val detail = json.decodeFromString<EntryDetail>(payload)
        assertTrue(detail.isEcho)
        assertEquals("orig", detail.echoOf!!.entryId)
        assertEquals(3, detail.echoOf!!.shared)
    }

    @Test
    fun testCategoryAndFeedDeserialization() {
        val catPayload = """
            [
                {
                    "id": "cat-1",
                    "name": "Security Advisories",
                    "parent_id": null,
                    "position": 0,
                    "feed_count": 42
                }
            ]
        """.trimIndent()
        val categories = json.decodeFromString<List<com.example.intelfeed.data.model.Category>>(catPayload)
        assertEquals(1, categories.size)
        assertEquals("Security Advisories", categories[0].name)
        assertEquals(42, categories[0].feedCount)

        val feedPayload = """
            {
                "items": [
                    {
                        "id": "feed-1",
                        "title": "Palo Alto Security Bulletins",
                        "url": "https://security.paloaltonetworks.com/rss.xml",
                        "feed_type": "rss",
                        "unread_count": 5,
                        "is_active": true
                    }
                ],
                "total": 1
            }
        """.trimIndent()
        val feedPage = json.decodeFromString<CursorPage<com.example.intelfeed.data.model.FeedSource>>(feedPayload)
        assertEquals(1, feedPage.items.size)
        assertEquals("Palo Alto Security Bulletins", feedPage.items[0].displayTitle)
        assertEquals(5, feedPage.items[0].unreadCount)
    }

    @Test
    fun testThreatActorAndCveDeserialization() {
        val actorPayload = """
            {
                "id": "actor-1",
                "name": "Qilin",
                "aliases": ["Agenda", "Qilin RaaS"],
                "country": "RU",
                "description": "Ransomware group active since 2022",
                "article_count": 4577,
                "targeted_sectors": ["Healthcare", "Finance"],
                "ttps": [
                    { "technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "impact", "count": 12 }
                ]
            }
        """.trimIndent()
        val actor = json.decodeFromString<com.example.intelfeed.data.model.ThreatActor>(actorPayload)
        assertEquals("Qilin", actor.name)
        assertEquals(2, actor.aliases.size)
        assertEquals(4577, actor.articleCount)
        assertEquals(1, actor.ttps.size)
        assertEquals("T1486", actor.ttps[0].techniqueId)

        val cvePayload = """
            {
                "id": "cve-1",
                "cve_id": "CVE-2024-38812",
                "cvss_score": "9.8",
                "severity": "CRITICAL",
                "is_kev": true,
                "epss_score": 0.89,
                "description": "VMware vCenter Server heap-based buffer overflow."
            }
        """.trimIndent()
        val cve = json.decodeFromString<com.example.intelfeed.data.model.Cve>(cvePayload)
        assertEquals("CVE-2024-38812", cve.cveId)
        assertTrue(cve.isKev)
        assertEquals("9.8", cve.cvssScore)
        assertEquals(0.89, cve.epssScore!!, 0.001)
    }

    @Test
    fun testUnifiedSearchResponseDeserialization() {
        val searchPayload = """
            {
                "query": "cisco",
                "entries": {
                    "hits": [
                        {
                            "id": "entry-1",
                            "title": "Cisco Security Advisory"
                        }
                    ],
                    "estimatedTotalHits": 1
                },
                "entities": {
                    "items": [
                        {
                            "id": "ent-1",
                            "name": "Cisco",
                            "type": "threat_actor",
                            "description": "Networking hardware vendor"
                        }
                    ],
                    "counts": { "threat_actor": 1 }
                }
            }
        """.trimIndent()
        val res = json.decodeFromString<com.example.intelfeed.data.model.UnifiedSearchResponse>(searchPayload)
        assertEquals("cisco", res.query)
        assertEquals(1, res.entries.hits.size)
        assertEquals("Cisco Security Advisory", res.entries.hits[0].title)
        assertEquals(1, res.entities.items.size)
        assertEquals("threat_actor", res.entities.items[0].displayType)
    }

    @Test
    fun testCweDeserialization() {
        val payload = """
            {
                "id": "cwe-79",
                "cwe_id": "CWE-79",
                "name": "Improper Neutralization of Input During Web Page Generation",
                "description": "Cross-site scripting vulnerability",
                "likelihood_of_exploit": "High",
                "article_count": 42
            }
        """.trimIndent()
        val cwe = json.decodeFromString<com.example.intelfeed.data.model.Cwe>(payload)
        assertEquals("CWE-79", cwe.cweId)
        assertEquals("Cross-site scripting vulnerability", cwe.description)
        assertEquals(42, cwe.articleCount)
        assertEquals("CWE-79: Improper Neutralization of Input During Web Page Generation", cwe.displayTitle)
    }

    @Test
    fun unifiedSearchAsksForEveryEntityOfAType() {
        // Same as the web's search page: 200 entities in all, no practical cap per type. With the
        // old 25 per type, "Showing 25 of 200" was the most a search could list for one type.
        val body = json.parseToJsonElement(
            json.encodeToString(com.example.intelfeed.data.model.UnifiedSearchRequest.serializer(),
                com.example.intelfeed.data.model.UnifiedSearchRequest(q = "cve.kev:true"))
        ) as kotlinx.serialization.json.JsonObject
        assertEquals("200", body["entity_limit"].toString())
        assertEquals("500", body["entity_group_limit"].toString())
    }

    @Test
    fun testObservableDeserialization() {
        val payload = """
            {
                "id": "obs-1",
                "value": "198.51.100.42",
                "kind": "ipv4",
                "role": "c2",
                "current_confidence": 0.8,
                "article_count": 5
            }
        """.trimIndent()
        // The ledger's identity is (kind, value) (docs/data-model.md); there is no `type` field.
        val obs = json.decodeFromString<com.example.intelfeed.data.model.ObservableItem>(payload)
        assertEquals("198.51.100.42", obs.value)
        assertEquals("ipv4", obs.kind)
        assertEquals("c2", obs.role)
        assertEquals(0.8, obs.currentConfidence!!, 0.0)
        assertEquals(5, obs.articleCount)
    }

    @Test
    fun testCreateFeedRequestSerialization() {
        val req = com.example.intelfeed.data.model.CreateFeedRequest(
            url = "https://example.com/rss.xml",
            categoryId = "cat-1",
            title = "Custom Title"
        )
        val encoded = json.encodeToString(com.example.intelfeed.data.model.CreateFeedRequest.serializer(), req)
        assertTrue(encoded.contains("https://example.com/rss.xml"))
        assertTrue(encoded.contains("category_id"))
    }
}

