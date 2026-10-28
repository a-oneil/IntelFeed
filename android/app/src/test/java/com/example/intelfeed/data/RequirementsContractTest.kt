package com.example.intelfeed.data

import com.example.intelfeed.data.model.Requirement
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.data.network.IntelFeedApi
import com.example.intelfeed.ui.screens.RequirementsViewModel
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/** Intelligence requirements: shapes from the live server (GET) and the web's create form (POST). */
class RequirementsContractTest {

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
    fun listParsesTheLiveShape() = runTest {
        ok(
            """{"items":[{"id":"r1","created_by":"u1","title":"Edge devices","description":"VPN and firewall exploitation",
               "priority":"high","status":"active","category":"operational","keywords":["BIG-IP","FortiGate"],
               "linked_feed_ids":[],"linked_entities":[],"min_relevance":"medium","auto_match":true,"match_count":42,
               "last_matched_at":"2026-09-22T10:00:00Z","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-09-22T10:00:00Z",
               "expires_at":null,"fulfilled_by_report_id":null}]}"""
        )
        val page = api.getRequirements()
        assertEquals("/api/requirements?limit=200&offset=0", server.takeRequest().path)
        val r = page.items.single()
        assertEquals("Edge devices", r.title)
        assertEquals(listOf("BIG-IP", "FortiGate"), r.keywords)
        assertEquals(42, r.matchCount)
        assertEquals("2026-09-22T10:00:00Z", r.lastMatchedAt)
    }

    @Test
    fun matchesParseTheLiveShape() = runTest {
        ok(
            """{"items":[{"requirement_id":"r1","entry_id":"e9","match_type":"keyword","matched_on":"BIG-IP",
               "matched_at":"2026-09-22T10:00:00Z","relevance":"high","entry_title":"F5 BIG-IP exploited",
               "entry_url":"https://example.com/a","entry_published_at":"2026-09-22T09:00:00Z"}]}"""
        )
        val page = api.getRequirementMatches("r1", offset = 20)
        assertEquals("/api/requirements/r1/matches?limit=20&offset=20", server.takeRequest().path)
        val m = page.items.single()
        assertEquals("e9", m.entryId)
        assertEquals("BIG-IP", m.matchedOn)
        assertEquals("F5 BIG-IP exploited", m.entryTitle)
    }

    @Test
    fun activeRequirementsComeFirstThenByPriority() {
        fun req(id: String, priority: String?, status: String = "active") = Requirement(id = id, title = id, priority = priority, status = status)
        val sorted = RequirementsViewModel.sortRequirements(
            listOf(req("low", "low"), req("paused", "critical", "paused"), req("crit", "critical"), req("none", null), req("high", "high"))
        )
        assertEquals(listOf("crit", "high", "low", "none", "paused"), sorted.map { it.id })
    }
}
