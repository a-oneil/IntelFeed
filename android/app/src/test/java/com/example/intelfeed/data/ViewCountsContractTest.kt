package com.example.intelfeed.data

import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.data.network.IntelFeedApi
import com.example.intelfeed.data.repository.FeedFilter
import com.example.intelfeed.data.repository.ViewCounts
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

/** Quick-view counts and the Watched view, with the parameters the web sidebar sends. */
class ViewCountsContractTest {

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
    fun countSendsUnreadDedupAndFilters() = runTest {
        ok("""{"total": 35}""")
        val count = api.countEntries(isRead = false, watched = true)
        val url = server.takeRequest().requestUrl!!
        assertEquals("/api/entries/count", url.encodedPath)
        assertEquals("false", url.queryParameter("is_read"))
        assertEquals("true", url.queryParameter("watched"))
        assertEquals("true", url.queryParameter("dedup"))
        assertNull(url.queryParameter("is_starred"))
        assertEquals(35, count.total)
    }

    @Test
    fun priorityUnreadCountShape() = runTest {
        ok("""{"unread_count": 7}""")
        assertEquals(7, api.getPriorityUnreadCount().unreadCount)
        assertEquals("/api/entries/priority-unread-count", server.takeRequest().path)
    }

    @Test
    fun watchedViewAsksForWatchedEntries() = runTest {
        ok("""{"items": [], "has_more": false}""")
        api.getEntries(watched = true, limit = 30)
        val url = server.takeRequest().requestUrl!!
        assertEquals("true", url.queryParameter("watched"))
        assertNull(url.queryParameter("is_read"))
    }

    @Test
    fun savedSearchesDecodeWithTheirScope() {
        // GET /api/saved-searches on the live server, 2026-09-22.
        val json = """[{"id":"d66db5ae","name":"\"device code phishing\"","display_name":null,"query":"\"device code phishing\"","filters":{},"unread_count":2,"total_count":189},
            {"id":"ce69fc78","name":"Warp Panda","display_name":null,"query":"warp panda","filters":{"scope":"everything","entity_type":null,"match_kinds":["direct","mention"]},"unread_count":0,"total_count":46}]"""
        val list = ApiJson.json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(com.example.intelfeed.data.model.SavedSearch.serializer()), json)
        assertEquals(2, list[0].unreadCount)
        assertEquals(189, list[0].totalCount)
        assertNull(list[0].filters?.scope)
        assertEquals("everything", list[1].filters?.scope)
        assertEquals("Warp Panda", list[1].label)
    }

    @Test
    fun countsMapToViews() {
        val counts = ViewCounts(priority = 3, unread = 35, watched = 2)
        assertEquals(3, counts.forFilter(FeedFilter.PRIORITY_QUEUE))
        assertEquals(35, counts.forFilter(FeedFilter.UNREAD))
        assertEquals(2, counts.forFilter(FeedFilter.WATCHED))
        assertNull(counts.forFilter(FeedFilter.ALL))
        assertNull(counts.forFilter(FeedFilter.STARRED))
    }
}
