package com.example.intelfeed.data

import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.data.network.IntelFeedApi
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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

/** The day divider requests carry the same filters as the web client's (feed/folder/starred/bookmarked, dedup). */
class DayIntelContractTest {

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

    @Test
    fun dayIntelSendsBoundsAndFilters() = runTest {
        server.enqueue(MockResponse().setBody("""{"signals":{"actively_exploited":0}}""").setHeader("Content-Type", "application/json"))
        api.getDayIntel("2026-09-21T04:00:00.000Z", "2026-09-22T03:59:59.999Z", feedId = "f1", isStarred = true)
        val url = server.takeRequest().requestUrl!!
        assertEquals("/api/entries/day-intel", url.encodedPath)
        assertEquals("2026-09-21T04:00:00.000Z", url.queryParameter("since"))
        assertEquals("2026-09-22T03:59:59.999Z", url.queryParameter("before"))
        assertEquals("f1", url.queryParameter("feed_id"))
        assertEquals("true", url.queryParameter("is_starred"))
        assertEquals("true", url.queryParameter("dedup"))
        assertNull(url.queryParameter("category_id"))
        assertNull(url.queryParameter("is_bookmarked"))
    }

    @Test
    fun markDayReadSendsTheDayBoundsAndMarkAllDoesNot() = runTest {
        server.enqueue(MockResponse().setBody("{}"))
        server.enqueue(MockResponse().setBody("{}"))
        api.markAllRead(com.example.intelfeed.data.model.MarkAllReadRequest(feedId = "f1", since = "2026-09-21T04:00:00.000Z", before = "2026-09-22T03:59:59.999Z"))
        val day = ApiJson.json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
        assertEquals("2026-09-21T04:00:00.000Z", day["since"]!!.jsonPrimitive.content)
        assertEquals("2026-09-22T03:59:59.999Z", day["before"]!!.jsonPrimitive.content)
        assertEquals("f1", day["feed_id"]!!.jsonPrimitive.content)
        api.markAllRead(com.example.intelfeed.data.model.MarkAllReadRequest())
        val all = ApiJson.json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
        // Unchanged: plain "mark all read" never sends a time window.
        assertEquals(false, "since" in all || "before" in all)
        // ...nor the Priority Queue limit.
        assertEquals(false, "radar_only" in all)
    }

    @Test
    fun priorityQueueMarkAllSendsRadarOnly() = runTest {
        // The web's Priority Queue sends {radar_only: true}; without it the server marks every unread article read.
        server.enqueue(MockResponse().setBody("{}"))
        api.markAllRead(com.example.intelfeed.data.model.MarkAllReadRequest(radarOnly = true))
        val body = ApiJson.json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
        assertEquals("true", body["radar_only"]!!.jsonPrimitive.content)
        assertEquals(false, "since" in body || "before" in body)
    }

    @Test
    fun dailySummaryIsARead() = runTest {
        server.enqueue(MockResponse().setBody("null").setHeader("Content-Type", "application/json"))
        api.getDailySummary("2026-09-21", categoryId = "c1")
        val req = server.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("2026-09-21", req.requestUrl!!.queryParameter("day_key"))
        assertEquals("c1", req.requestUrl!!.queryParameter("category_id"))
        assertNull(req.requestUrl!!.queryParameter("force"))
    }
}
