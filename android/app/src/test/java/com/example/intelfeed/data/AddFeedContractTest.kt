package com.example.intelfeed.data

import com.example.intelfeed.data.model.CreateFeedRequest
import com.example.intelfeed.data.model.IngestUrlRequest
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.data.network.IntelFeedApi
import com.example.intelfeed.data.repository.parseDiscoveredFeeds
import com.example.intelfeed.util.WebUrl
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/** Add Feed: discover, then subscribe (shapes from the live web client's Add Feed dialog). */
class AddFeedContractTest {

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
    fun subscribeLeavesOutUnsetFields() = runTest {
        ok("""{ "id": "f1", "title": "Feed", "url": "https://example.com/feed" }""")
        api.createFeed(CreateFeedRequest(url = "https://example.com/feed"))
        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/feeds", req.path)
        val body = ApiJson.json.parseToJsonElement(req.body.readUtf8()).jsonObject
        // The web omits category and interval when they're not chosen; explicit nulls could fail validation.
        assertEquals(setOf("url"), body.keys)
    }

    @Test
    fun subscribeSendsFolderAndInterval() = runTest {
        ok("""{ "id": "f1", "title": "Feed", "url": "https://example.com/feed" }""")
        api.createFeed(CreateFeedRequest(url = "https://example.com/feed", categoryId = "c1", fetchIntervalMinutes = 60))
        val body = ApiJson.json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
        assertEquals("c1", body["category_id"]!!.jsonPrimitive.content)
        assertEquals("60", body["fetch_interval_minutes"]!!.jsonPrimitive.content)
    }

    @Test
    fun discoverPostsTheAddress() = runTest {
        ok("""{ "url": "https://example.com/feed.xml", "title": "Example", "description": "d", "feed_type": "rss" }""")
        val element = api.discoverFeed(IngestUrlRequest("https://example.com"))
        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/feeds/discover", req.path)
        assertEquals("""{"url":"https://example.com"}""", req.body.readUtf8())
        val feeds = parseDiscoveredFeeds(element, ApiJson.json)
        assertEquals(1, feeds.size)
        assertEquals("https://example.com/feed.xml", feeds[0].url)
        assertEquals("RSS", feeds[0].typeLabel)
    }

    @Test
    fun discoverAcceptsTheDocumentedListShape() {
        val element = ApiJson.json.parseToJsonElement(
            """{ "feeds": [ { "url": "https://e.com/feed.xml", "title": "Main", "type": "rss" },
                            { "url": "https://e.com/blog/feed", "title": "Blog", "type": "atom" },
                            { "title": "no url" } ] }"""
        )
        val feeds = parseDiscoveredFeeds(element, ApiJson.json)
        assertEquals(listOf("https://e.com/feed.xml", "https://e.com/blog/feed"), feeds.map { it.url })
        assertEquals("ATOM", feeds[1].typeLabel)
    }

    @Test
    fun discoverWithNothingFoundIsEmpty() {
        assertTrue(parseDiscoveredFeeds(ApiJson.json.parseToJsonElement("""{ "feeds": [] }"""), ApiJson.json).isEmpty())
        assertTrue(parseDiscoveredFeeds(ApiJson.json.parseToJsonElement("""{ "detail": "not a feed" }"""), ApiJson.json).isEmpty())
        assertTrue(parseDiscoveredFeeds(ApiJson.json.parseToJsonElement("null"), ApiJson.json).isEmpty())
    }

    @Test
    fun webUrlKeepsPathAndQueryAndAddsScheme() {
        assertEquals("https://example.com/feed?format=rss", WebUrl.normalize("  example.com/feed?format=rss "))
        assertEquals("http://example.com/rss", WebUrl.normalize("http://example.com/rss"))
        assertNull(WebUrl.normalize("feed"))
        assertNull(WebUrl.normalize("https:/example.com"))
        assertNull(WebUrl.normalize("ftp://example.com/feed"))
        assertNull(WebUrl.normalize("two words.com"))
        assertFalse(WebUrl.normalize("javascript:alert(1)") != null)
    }
}
