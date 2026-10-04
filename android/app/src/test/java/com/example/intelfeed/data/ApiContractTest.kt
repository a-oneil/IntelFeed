package com.example.intelfeed.data

import com.example.intelfeed.data.model.BulkActionRequest
import com.example.intelfeed.data.model.CreateEntityNoteRequest
import com.example.intelfeed.data.model.NoteRequest
import com.example.intelfeed.data.model.RadarFeedbackRequest
import com.example.intelfeed.data.model.TagIdsRequest
import com.example.intelfeed.data.model.UnifiedSearchRequest
import com.example.intelfeed.data.model.WatchlistRequest
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.data.network.IntelFeedApi
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/**
 * Checks the requests the app sends (method, path, JSON body) against the shapes the web client
 * sends, which were read from the live web bundle on 2026-09-22. Write endpoints were not exercised
 * against the live server, so these tests are the main guard on their contract.
 */
class ApiContractTest {

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

    private fun ok(body: String = "{}") = server.enqueue(MockResponse().setBody(body).setHeader("Content-Type", "application/json"))

    private fun bodyOf(request: okhttp3.mockwebserver.RecordedRequest) =
        ApiJson.json.parseToJsonElement(request.body.readUtf8()).jsonObject

    @Test
    fun createNotePostsTitleAndMarkdownToEntryRoute() = runTest {
        ok("""{ "id": "n1", "title": "t", "content_markdown": "body" }""")
        val note = api.createEntryNote("e1", NoteRequest(title = "t", contentMarkdown = "body", isPinned = true))
        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/notes/entry/e1", req.path)
        val body = bodyOf(req)
        assertEquals("t", body["title"]!!.jsonPrimitive.content)
        assertEquals("body", body["content_markdown"]!!.jsonPrimitive.content)
        assertEquals("true", body["is_pinned"]!!.jsonPrimitive.content)
        assertEquals("n1", note.id)
    }

    @Test
    fun updateNoteUsesPut() = runTest {
        ok("""{ "id": "n1" }""")
        api.updateNote("n1", NoteRequest("t", "b", false))
        val req = server.takeRequest()
        assertEquals("PUT", req.method)
        assertEquals("/api/notes/n1", req.path)
    }

    @Test
    fun addTagSendsTagIds() = runTest {
        ok()
        api.addEntryTags("e1", TagIdsRequest(listOf("t1")))
        val req = server.takeRequest()
        assertEquals("/api/tags/entries/e1", req.path)
        assertEquals("t1", bodyOf(req)["tag_ids"].toString().trim('[', ']', '"'))
    }

    @Test
    fun removeTagUsesDeleteWithBothIds() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        api.removeEntryTag("e1", "t1")
        val req = server.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/api/tags/entries/e1/t1", req.path)
    }

    @Test
    fun deleteTagUsesDeleteWithPath() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        api.deleteTag("t1")
        val req = server.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/api/tags/t1", req.path)
    }

    @Test
    fun watchAndUnwatch() = runTest {
        ok("{}")
        api.setWatchlistEntry(WatchlistRequest("threat_actor", "a1", "watch"))
        val put = server.takeRequest()
        assertEquals("PUT", put.method)
        assertEquals("/api/intelligence/watchlist", put.path)
        val body = bodyOf(put)
        assertEquals("threat_actor", body["entity_type"]!!.jsonPrimitive.content)
        assertEquals("a1", body["entity_id"]!!.jsonPrimitive.content)
        assertEquals("watch", body["mode"]!!.jsonPrimitive.content)

        server.enqueue(MockResponse().setResponseCode(204))
        api.removeWatchlistEntry("threat_actor", "a1")
        val del = server.takeRequest()
        assertEquals("DELETE", del.method)
        assertEquals("/api/intelligence/watchlist/threat_actor/a1", del.path)
    }

    @Test
    fun radarFeedback() = runTest {
        ok()
        api.sendRadarFeedback(RadarFeedbackRequest("e1", -1))
        val req = server.takeRequest()
        assertEquals("PUT", req.method)
        assertEquals("/api/engine/radar-feedback", req.path)
        assertEquals("-1", bodyOf(req)["verdict"]!!.jsonPrimitive.content)
    }

    @Test
    fun bulkActionBody() = runTest {
        ok("""{ "updated": 2 }""")
        api.bulkAction(BulkActionRequest(listOf("a", "b"), "read"))
        val body = bodyOf(server.takeRequest())
        assertEquals("read", body["action"]!!.jsonPrimitive.content)
        assertTrue(body["entry_ids"].toString().contains("\"b\""))
    }

    @Test
    fun entityNoteBody() = runTest {
        ok("""{ "id": "n", "content": "c" }""")
        api.createEntityNote(CreateEntityNoteRequest("cve", "c1", null, "c"))
        val body = bodyOf(server.takeRequest())
        assertEquals("cve", body["entity_type"]!!.jsonPrimitive.content)
        assertEquals("c", body["content"]!!.jsonPrimitive.content)
    }

    @Test
    fun ttpDetailIsLookedUpByTechniqueId() = runTest {
        ok("""{ "id": "x", "technique_id": "T1190" }""")
        api.getTtpByTechnique("T1190")
        assertEquals("/api/ttps/by-technique/T1190", server.takeRequest().path)
    }

    @Test
    fun dailySummaryCanBeNull() = runTest {
        ok("null")
        val element = api.getDailySummary("2026-09-21")
        assertEquals(JsonNull, element)
        // dedup=true like the web client, which sends its list filters (incl. dedup) with the briefing.
        assertEquals("/api/entries/daily-summary?day_key=2026-09-21&dedup=true", server.takeRequest().path)
    }

    @Test
    fun unifiedSearchBody() = runTest {
        ok("""{ "entries": { "hits": [], "estimatedTotalHits": 0 }, "entities": { "items": [], "counts": {} } }""")
        api.searchUnified(UnifiedSearchRequest(q = "threat_actor:\"Qilin\"", limit = 20, offset = 40))
        val body = bodyOf(server.takeRequest())
        assertEquals("threat_actor:\"Qilin\"", body["q"]!!.jsonPrimitive.content)
        assertEquals("40", body["offset"]!!.jsonPrimitive.content)
    }

    @Test
    fun feedsRequestAllFeeds() = runTest {
        ok("""{ "items": [], "total": 0 }""")
        api.getFeeds()
        assertTrue(server.takeRequest().path!!.contains("limit=1000"))
    }
}
