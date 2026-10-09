package com.example.intelfeed.ui

import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.StoryThread
import com.example.intelfeed.data.model.TagEntity
import com.example.intelfeed.data.repository.FeedFilter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReadUnreadPurgeTest {

    private fun testShouldHideRead(filter: FeedFilter, feedHideRead: Boolean): Boolean {
        val state = IntelFeedUiState(
            selectedFilter = filter,
            feedHideRead = feedHideRead
        )
        return state.selectedFilter == FeedFilter.UNREAD ||
            state.selectedFilter == FeedFilter.PRIORITY_QUEUE ||
            (state.feedHideRead && state.selectedFilter != FeedFilter.PRIORITY_QUEUE)
    }

    private fun purgeReadEntries(entries: List<EntryItem>, shouldHide: Boolean): List<EntryItem> {
        return if (shouldHide) {
            entries.filterNot { it.isRead && !it.isThread }
        } else {
            entries
        }
    }

    @Test
    fun shouldHideReadForUnreadFilter() {
        assertTrue(testShouldHideRead(FeedFilter.UNREAD, feedHideRead = false))
        assertTrue(testShouldHideRead(FeedFilter.UNREAD, feedHideRead = true))
    }

    @Test
    fun shouldHideReadForPriorityQueue() {
        assertTrue(testShouldHideRead(FeedFilter.PRIORITY_QUEUE, feedHideRead = false))
        assertTrue(testShouldHideRead(FeedFilter.PRIORITY_QUEUE, feedHideRead = true))
    }

    @Test
    fun shouldHideReadForAllFilterOnlyWhenHideReadEnabled() {
        assertFalse(testShouldHideRead(FeedFilter.ALL, feedHideRead = false))
        assertTrue(testShouldHideRead(FeedFilter.ALL, feedHideRead = true))
    }

    @Test
    fun shouldHideReadForStarredFilterOnlyWhenHideReadEnabled() {
        assertFalse(testShouldHideRead(FeedFilter.STARRED, feedHideRead = false))
        assertTrue(testShouldHideRead(FeedFilter.STARRED, feedHideRead = true))
    }

    @Test
    fun purgeRemovesOnlyReadNonThreadArticlesWhenHiding() {
        val unreadArticle = EntryItem(id = "1", title = "Unread", isRead = false)
        val readArticle = EntryItem(id = "2", title = "Read", isRead = true)
        val readThread = EntryItem(
            id = "thread:sample",
            title = "Thread row",
            isRead = true,
            thread = StoryThread(slug = "sample", title = "Thread")
        )

        val entries = listOf(unreadArticle, readArticle, readThread)
        val remaining = purgeReadEntries(entries, shouldHide = true)

        assertEquals(2, remaining.size)
        assertEquals("1", remaining[0].id)
        assertEquals("thread:sample", remaining[1].id)
    }

    @Test
    fun purgePreservesAllArticlesWhenNotHiding() {
        val unreadArticle = EntryItem(id = "1", title = "Unread", isRead = false)
        val readArticle = EntryItem(id = "2", title = "Read", isRead = true)

        val entries = listOf(unreadArticle, readArticle)
        val remaining = purgeReadEntries(entries, shouldHide = false)

        assertEquals(2, remaining.size)
    }

    @Test
    fun tagEntitySupportsEntryCountAndColor() {
        val tag = TagEntity(id = "tag1", name = "malware", color = "#ff0000", entryCount = 42)
        assertEquals("tag1", tag.id)
        assertEquals("malware", tag.name)
        assertEquals("#ff0000", tag.color)
        assertEquals(42, tag.entryCount)
    }
}
