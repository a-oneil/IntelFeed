package com.example.intelfeed.data

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.example.intelfeed.data.local.AuthPreferences
import com.example.intelfeed.data.local.TokenCipher
import com.example.intelfeed.data.repository.BulkAction
import com.example.intelfeed.data.repository.EntryFlagUpdate
import com.example.intelfeed.data.repository.IntelFeedRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.TimeUnit

@OptIn(ExperimentalCoroutinesApi::class)
class ReadStatusUpdateTest {
    @get:Rule val temp = TemporaryFolder()
    private lateinit var scope: CoroutineScope
    private lateinit var auth: AuthPreferences
    private lateinit var server: MockWebServer

    @Before fun setUp() {
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val store = PreferenceDataStoreFactory.create(scope = scope) {
            temp.root.resolve("auth.preferences_pb")
        }
        auth = AuthPreferences(store, TokenCipher { null })
        server = MockWebServer().also { it.start() }
    }

    @After fun tearDown() {
        server.shutdown()
        scope.cancel()
    }

    @Test fun failedReadReversesOptimisticUpdateWithoutConfirmingIt() = runTest {
        auth.setServerUrl(server.url("/").toString())
        server.enqueue(MockResponse().setResponseCode(500))
        val repository = IntelFeedRepository(auth)
        val updates = async(UnconfinedTestDispatcher(testScheduler)) {
            repository.entryUpdates.take(2).toList()
        }

        assertTrue(repository.setRead("article-1", true).isFailure)
        assertEquals(
            listOf(
                EntryFlagUpdate("article-1", isRead = true),
                EntryFlagUpdate("article-1", isRead = false)
            ),
            updates.await()
        )
        assertEquals("/api/entries/article-1/read", server.takeRequest().path)
    }

    @Test fun successfulReadConfirmsUpdateAfterServerAcceptsIt() = runTest {
        auth.setServerUrl(server.url("/").toString())
        server.enqueue(MockResponse().setResponseCode(204))
        val repository = IntelFeedRepository(auth)
        val updates = async(UnconfinedTestDispatcher(testScheduler)) {
            repository.entryUpdates.take(2).toList()
        }

        assertTrue(repository.setRead("article-1", true).isSuccess)
        val events = updates.await()
        assertFalse(events[0].confirmed)
        assertEquals(EntryFlagUpdate("article-1", isRead = true, confirmed = true), events[1])
    }

    @Test fun bulkUpdateOfManyArticlesDeliversEveryUpdate() = runTest {
        auth.setServerUrl(server.url("/").toString())
        server.enqueue(MockResponse().setResponseCode(204))
        val repository = IntelFeedRepository(auth)
        val ids = (1..300).map { "article-$it" }
        // Collects on the test thread, so it only runs when the emitter suspends (like the UI's
        // collectors on the main thread). More than the 256-update buffer is sent at once.
        val updates = async { repository.entryUpdates.take(ids.size * 2).toList() }
        runCurrent()

        assertTrue(repository.bulkSet(BulkAction.READ, ids.associateWith { false }).isSuccess)
        val events = updates.await()
        assertEquals(ids, events.filter { !it.confirmed }.map { it.id })
        assertEquals(ids, events.filter { it.confirmed }.map { it.id })
    }

    @Test fun rapidReadThenUnreadKeepsServerAndUiUpdatesInOrder() = runTest {
        auth.setServerUrl(server.url("/").toString())
        server.enqueue(MockResponse().setResponseCode(204).setHeadersDelay(500, TimeUnit.MILLISECONDS))
        server.enqueue(MockResponse().setResponseCode(204))
        val repository = IntelFeedRepository(auth)
        val updates = async(UnconfinedTestDispatcher(testScheduler)) {
            repository.entryUpdates.take(4).toList()
        }

        val read = async(Dispatchers.Default) { repository.setRead("article-1", true) }
        val firstRequest = server.takeRequest()
        val unread = async(Dispatchers.Default) { repository.setRead("article-1", false) }

        assertTrue(read.await().isSuccess)
        assertTrue(unread.await().isSuccess)
        assertEquals("/api/entries/article-1/read", firstRequest.path)
        assertEquals("/api/entries/article-1/unread", server.takeRequest().path)
        assertEquals(
            listOf(
                EntryFlagUpdate("article-1", isRead = true),
                EntryFlagUpdate("article-1", isRead = true, confirmed = true),
                EntryFlagUpdate("article-1", isRead = false),
                EntryFlagUpdate("article-1", isRead = false, confirmed = true)
            ),
            updates.await()
        )
    }
}
