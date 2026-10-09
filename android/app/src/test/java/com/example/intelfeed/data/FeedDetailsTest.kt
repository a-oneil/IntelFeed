package com.example.intelfeed.data

import com.example.intelfeed.data.model.CursorPage
import com.example.intelfeed.data.model.FeedSource
import com.example.intelfeed.data.network.ApiJson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Feed health and curation, shown for a selected feed like the web's single-feed view. */
class FeedDetailsTest {

    private fun feed(mode: String?, auto: Boolean) = FeedSource(id = "f", title = "t", url = "u", intelExtractionMode = mode, autoExtractOnIngest = auto)

    @Test
    fun curationLabelsFollowTheWebRules() {
        assertEquals("Full — extract all intelligence automatically", feed("full", true).curationLabel)
        assertEquals("Selective — security-relevant articles only", feed("selective", true).curationLabel)
        assertEquals("Known entities only — match against existing database", feed("full", false).curationLabel)
        assertEquals("Known entities only — match against existing database", feed("selective", false).curationLabel)
        // No mode counts as selective, as on the web.
        assertEquals("Known entities only — match against existing database", feed(null, false).curationLabel)
        assertEquals("Selective — security-relevant articles only", feed(null, true).curationLabel)
        assertEquals("Manual — only when triggered", feed("manual", true).curationLabel)
        assertNull(feed("none", true).curationLabel)
    }

    @Test
    fun decodesTheLiveFeedPayload() {
        // GET /api/feeds?limit=2 on the live server, 2026-09-22 (trimmed).
        val json = """{"items":[{"id":"00651c7d","title":"Palo Alto Networks Security Advisories","url":"https://security.paloaltonetworks.com/rss.xml",
            "feed_type":"rss","last_fetched_at":"2026-09-22T19:51:14.465190Z","fetch_interval_minutes":30,"error_count":0,"last_error":null,
            "is_active":true,"intel_extraction_mode":"full","auto_extract_on_ingest":true,"category_id":"ff037255","custom_title":null,
            "is_muted":false,"unread_count":0,"per_user":true}],"total":306,"limit":2,"offset":0,"has_more":true}"""
        val page = ApiJson.json.decodeFromString(CursorPage.serializer(FeedSource.serializer()), json)
        val f = page.items.single()
        assertEquals(30, f.fetchIntervalMinutes)
        assertEquals("RSS", f.typeLabel)
        assertEquals("Full — extract all intelligence automatically", f.curationLabel)
        assertEquals(306, page.total)
    }

    @Test
    fun typeLabels() {
        assertEquals("GitHub repo", FeedSource(id = "f", title = "t", url = "u", feedType = "github_repo").typeLabel)
        assertEquals("Telegram", FeedSource(id = "f", title = "t", url = "u", feedType = "telegram").typeLabel)
        assertNull(FeedSource(id = "f", title = "t", url = "u").typeLabel)
    }
}
