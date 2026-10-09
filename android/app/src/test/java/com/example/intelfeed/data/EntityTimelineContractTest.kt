package com.example.intelfeed.data

import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.MentionPoint
import com.example.intelfeed.data.model.MentionsTimeseries
import com.example.intelfeed.data.model.TimelineEvent
import com.example.intelfeed.data.model.TimelineNavContext
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.data.network.IntelFeedApi
import com.example.intelfeed.ui.entity.TimelinePresentation
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/** Profile Timeline tab: live response shapes (checked read-only on the server) and how they're listed. */
class EntityTimelineContractTest {

    private lateinit var server: MockWebServer
    private lateinit var api: IntelFeedApi

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        api = Retrofit.Builder()
            .baseUrl(server.url("/"))
            .addConverterFactory(ApiJson.json.asConverterFactory("application/json".toMediaType()))
            .build()
            .create(IntelFeedApi::class.java)
    }

    @After
    fun tearDown() = server.shutdown()

    private fun ok(body: String) = server.enqueue(MockResponse().setBody(body).setHeader("Content-Type", "application/json"))

    @Test
    fun mentionsTimeseries() = runTest {
        ok(
            """{"entity_type":"threat_actor","entity_id":"a1","window":"90d","bucket":"day","total_feeds":70,"previous_total":20,"top_feed_share":0.091,
               "points":[{"date":"2026-06-26","count":4,"feeds":4},{"date":"2026-06-27","count":0,"feeds":0},{"date":"2026-06-28","count":21,"feeds":9}]}"""
        )
        val m = api.getMentionsTimeseries("threat_actor", "a1", "90d")
        assertEquals("/api/entities/threat_actor/a1/mentions-timeseries?window=90d", server.takeRequest().path)
        assertEquals(25, m.total)
        assertEquals(70, m.totalFeeds)
        assertEquals(25, TimelinePresentation.trendPercent(m)) // 25 vs 20
    }

    @Test
    fun timelineEvents() = runTest {
        ok(
            """{"entity":{"id":"a1","type":"threat_actor","name":"ShinyHunters"},"events":[
               {"entry_id":"e1","title":"An article","url":"https://example.com/a","date":"2026-09-23T07:13:49+00:00","event_type":"article","severity":null,"event_subtype":null,"nav_context":null},
               {"entry_id":null,"title":"Uses malware “Click2Shell”","url":null,"date":"2026-09-23T06:45:01.713712+00:00","event_type":"relationship","severity":null,"event_subtype":"uses","nav_context":{"entity_type":"malware","entity_id":"m1"}},
               {"entry_id":"e2","title":"Known actor ShinyHunters linked to known malware Shai-Hulud in new article","url":null,"date":"2026-09-22T17:53:08+00:00","event_type":"correlation","severity":"low","event_subtype":"actor_malware_cooccurrence","nav_context":{"entity_type":"malware","entity_id":"m2"}},
               {"entry_id":"e3","title":"Old article with no date","url":null,"date":null,"event_type":"article","severity":null,"event_subtype":null,"nav_context":null}]}"""
        )
        val events = api.getEntityTimeline("threat_actor", "a1").events
        assertEquals("/api/intelligence/timeline/threat_actor/a1", server.takeRequest().path)
        assertEquals(4, events.size)
        val key = TimelinePresentation.keyEvents(events)
        assertEquals(listOf("relationship", "correlation"), key.map { it.eventType })
        assertEquals("Uses", TimelinePresentation.eventLabel(key[0]))
        assertEquals("Correlation", TimelinePresentation.eventLabel(key[1]))
        val target = TimelinePresentation.eventTarget(key[0])!!
        assertEquals(EntityType.MALWARE, target.type)
        assertEquals("m1", target.id)
        assertEquals("Click2Shell", target.name)
    }

    @Test
    fun whatsNewAndStories() = runTest {
        ok(
            """{"items":[{"entry_id":"e9","entry_title":"Clop Hack: ShinyHunters Hijacks Data Leak Site","published_at":"2026-09-21T13:28:13+00:00",
               "signal_type":"new_pairing","explanation":"First-ever observed pairing","subject":null}]}"""
        )
        val items = api.getWhatsNew("threat_actor", "a1").items
        assertEquals("/api/engine/entities/threat_actor/a1/whats-new?scoped=true", server.takeRequest().path)
        assertEquals("New pairing", TimelinePresentation.signalLabel(items.single().signalType))

        ok(
            """{"items":[{"slug":"s1","title":"ShinyHunters Claims FBI Data Theft","summary":"…","status":"open","entry_count":8,"source_count":8,
               "first_seen":"2026-09-22T17:24:13+00:00","last_seen":"2026-09-23T07:13:49+00:00","entity_entry_count":8,
               "latest_beat":{"headline":"FBI investigates","occurred_at":"2026-09-23T02:43:07+00:00"}}]}"""
        )
        val stories = api.getEntityStories("threat_actor", "a1").items
        assertEquals("/api/entities/threat_actor/a1/story-threads?limit=10&status=any", server.takeRequest().path)
        assertEquals("s1", stories.single().slug)
        assertEquals("FBI investigates", stories.single().latestBeat?.headline)
    }

    @Test
    fun keyEventsAreNewestFirstAndSkipRelatedTo() {
        val events = listOf(
            TimelineEvent(title = "Targets sector “Retail”", date = "2026-09-01T00:00:00Z", eventType = "relationship", eventSubtype = "targets"),
            TimelineEvent(title = "Related to campaign “X”", date = "2026-09-20T00:00:00Z", eventType = "relationship", eventSubtype = "related_to"),
            TimelineEvent(title = "Exploits “CVE-2026-1”", date = "2026-09-10T00:00:00Z", eventType = "relationship", eventSubtype = "exploits",
                navContext = TimelineNavContext("cve", "c1"))
        )
        val key = TimelinePresentation.keyEvents(events)
        assertEquals(listOf("Exploits", "Targets"), key.map { TimelinePresentation.eventLabel(it) })
        // A relationship without a known type or id isn't tappable as a profile.
        assertNull(TimelinePresentation.eventTarget(key[1]))
        assertEquals("CVE-2026-1", TimelinePresentation.eventTarget(key[0])!!.name)
    }

    @Test
    fun trendNeedsAPreviousWindow() {
        assertNull(TimelinePresentation.trendPercent(MentionsTimeseries(previousTotal = null, points = listOf(MentionPoint("2026-01-01", 5)))))
        assertNull(TimelinePresentation.trendPercent(MentionsTimeseries(previousTotal = 0, points = listOf(MentionPoint("2026-01-01", 5)))))
        assertEquals(-50, TimelinePresentation.trendPercent(MentionsTimeseries(previousTotal = 10, points = listOf(MentionPoint("2026-01-01", 5)))))
    }

    @Test
    fun trendLineMatchesTheWebWording() {
        fun line(previous: Int?, now: Int) =
            TimelinePresentation.trendLine(MentionsTimeseries(previousTotal = previous, points = listOf(MentionPoint("2026-01-01", now))), "90 days")
        // No change was shown as "→ 0% vs the previous 90 days"; the web shows nothing.
        assertNull(line(1, 1))
        assertNull(line(null, 3))
        assertNull(line(0, 0))
        assertEquals(TimelinePresentation.Trend(true, "↑ New: none in the previous 90 days"), line(0, 2))
        assertEquals(TimelinePresentation.Trend(false, "↓ 50% vs the previous 90 days"), line(10, 5))
        assertEquals(TimelinePresentation.Trend(true, "↑ >999% vs the previous 90 days"), line(1, 20))
    }

    @Test
    fun weaknessesUseTheWebsitePathName() {
        assertEquals("cwe", EntityType.WEAKNESS.timelinePath)
        assertEquals("threat_actor", EntityType.THREAT_ACTOR.timelinePath)
        assertNull(EntityType.RULE.timelinePath)
    }
}
