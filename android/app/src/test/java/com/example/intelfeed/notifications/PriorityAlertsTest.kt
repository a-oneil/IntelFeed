package com.example.intelfeed.notifications

import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.StoryThread
import org.junit.Assert.assertEquals
import org.junit.Test

class PriorityAlertsTest {
    private fun article(id: String, score: Double, read: Boolean = false) =
        EntryItem(id = id, title = id, priorityScore = score, isRead = read)

    private fun story(slug: String, score: Double, members: List<String>) =
        EntryItem(id = "thread:$slug", title = slug, priorityScore = score, thread = StoryThread(slug = slug, entryIds = members))

    @Test fun everyUnreadRowAtOrAboveTheCutOffAlerts() {
        val rows = (1..8).map { article("a$it", 9.0) } + article("read", 9.9, read = true) + article("low", 8.9)
        val outcome = PriorityAlerts.plan(rows, cutoff = 9.0, notified = emptySet())
        assertEquals((1..8).map { "a$it" }, outcome.alerts.map { it.id })
        assertEquals((1..8).map { "e:a$it" }, outcome.record)
    }

    @Test fun anArticleAlertsOnlyOnce() {
        val outcome = PriorityAlerts.plan(listOf(article("a", 10.0), article("a", 10.0)), 9.5, notified = setOf("e:b"))
        assertEquals(listOf("a"), outcome.alerts.map { it.id })
        assertEquals(emptyList<EntryItem>(), PriorityAlerts.plan(listOf(article("a", 10.0)), 9.5, setOf("e:a")).alerts)
    }

    @Test fun aStoryAlertsOnceHoweverMuchItGrows() {
        val first = PriorityAlerts.plan(listOf(story("s", 9.8, listOf("m1"))), 9.5, emptySet())
        assertEquals(listOf("thread:s"), first.alerts.map { it.id })
        assertEquals(listOf("t:s", "e:m1"), first.record)

        val grown = PriorityAlerts.plan(listOf(story("s", 10.0, listOf("m1", "m2"))), 9.5, first.record.toSet())
        assertEquals(emptyList<EntryItem>(), grown.alerts)
        assertEquals(listOf("e:m2"), grown.record)
    }

    @Test fun aStoryDoesNotRepeatAnArticleThatAlreadyAlerted() {
        val outcome = PriorityAlerts.plan(listOf(story("s", 9.8, listOf("m1", "m2"))), 9.5, setOf("e:m1"))
        assertEquals(emptyList<EntryItem>(), outcome.alerts)
        assertEquals(listOf("t:s", "e:m2"), outcome.record)
    }

    @Test fun anArticleOfAnAlertedStoryDoesNotAlertOnItsOwn() {
        val outcome = PriorityAlerts.plan(listOf(article("m1", 9.9)), 9.5, setOf("t:s", "e:m1"))
        assertEquals(emptyList<EntryItem>(), outcome.alerts)
    }

    @Test fun aBaselineRecordsWithoutAlerting() {
        val outcome = PriorityAlerts.plan(listOf(article("a", 9.6), story("s", 9.7, listOf("m1"))), 9.5, emptySet(), baseline = true)
        assertEquals(emptyList<EntryItem>(), outcome.alerts)
        assertEquals(listOf("e:a", "t:s", "e:m1"), outcome.record)
    }

    @Test fun cutOffIsClampedToTheSettingsRangeAndStep() {
        assertEquals(7.0, PriorityAlerts.clampCutoff(3.0), 0.0)
        assertEquals(10.0, PriorityAlerts.clampCutoff(12.0), 0.0)
        assertEquals(8.5, PriorityAlerts.clampCutoff(8.6), 0.0)
    }
}
