package com.example.intelfeed.util

import com.example.intelfeed.notifications.KeywordAlerts
import org.junit.Assert.assertEquals
import org.junit.Test

class KeywordAlertsTest {

    @Test
    fun aNewKeywordRecordsWithoutNotifying() {
        assertEquals(emptyList<String>(), KeywordAlerts.newIds(listOf("a", "b"), seen = null))
    }

    @Test
    fun onlyUnseenIdsAreNew() {
        assertEquals(listOf("c"), KeywordAlerts.newIds(listOf("c", "a", "b"), seen = listOf("a", "b")))
        assertEquals(emptyList<String>(), KeywordAlerts.newIds(listOf("a"), seen = listOf("a")))
        assertEquals(listOf("x"), KeywordAlerts.newIds(listOf("x", "x"), seen = emptyList()))
    }

    @Test
    fun firstCheckRecordsAMatchesBaselineWithoutAlerting() {
        val outcome = KeywordAlerts.evaluate(listOf("a", "b"), seen = null, readState = emptyMap())
        assertEquals(listOf("a", "b"), outcome.seen)
        assertEquals(emptyList<String>(), outcome.alert)
        assertEquals(emptyList<String>(), KeywordAlerts.toLookUp(listOf("a", "b"), seen = null))
        // A keyword with no matches yet still gets a baseline, so its first match alerts.
        assertEquals(emptyList<String>(), KeywordAlerts.evaluate(emptyList(), seen = null, readState = emptyMap()).seen)
        assertEquals(listOf("c"), KeywordAlerts.evaluate(listOf("c"), seen = emptyList(), readState = mapOf("c" to false)).alert)
    }

    @Test
    fun newUnreadMatchAlertsAndReadOneIsOnlyRecorded() {
        val outcome = KeywordAlerts.evaluate(
            current = listOf("new1", "new2", "old"),
            seen = listOf("old"),
            readState = mapOf("new1" to false, "new2" to true)
        )
        assertEquals(listOf("new1"), outcome.alert)
        assertEquals(listOf("old", "new1", "new2"), outcome.seen)
    }

    @Test
    fun failedLookupStaysUnseenSoTheNextCheckRetriesIt() {
        val outcome = KeywordAlerts.evaluate(listOf("x", "old"), seen = listOf("old"), readState = mapOf("x" to null))
        assertEquals(emptyList<String>(), outcome.alert)
        assertEquals(listOf("old"), outcome.seen)
        assertEquals(listOf("x"), KeywordAlerts.toLookUp(listOf("x", "old"), outcome.seen))
    }

    @Test
    fun matchesBeyondTheLookupCapWaitForTheNextCheck() {
        val current = (1..15).map { "n$it" }
        val first = KeywordAlerts.toLookUp(current, seen = emptyList())
        assertEquals(current.take(KeywordAlerts.MAX_LOOKUPS), first)
        val outcome = KeywordAlerts.evaluate(current, emptyList(), first.associateWith { false })
        assertEquals(first, outcome.alert)
        assertEquals(current.drop(KeywordAlerts.MAX_LOOKUPS), KeywordAlerts.toLookUp(current, outcome.seen))
    }

    @Test
    fun articleAnotherAlertCoveredIsRecordedWithoutAlertingAgain() {
        val outcome = KeywordAlerts.evaluate(listOf("a"), seen = emptyList(), readState = mapOf("a" to false), alreadyAlerted = setOf("a"))
        assertEquals(emptyList<String>(), outcome.alert)
        assertEquals(listOf("a"), outcome.seen)
    }

    @Test
    fun queryIsAQuotedPhraseAmongRecentArticles() {
        assertEquals("\"donkey\" date:>=2026-09-21 sort:newest", KeywordAlerts.query("donkey", "2026-09-21"))
        assertEquals("\"bad name\" date:>=2026-09-21 sort:newest", KeywordAlerts.query("bad \"name\"", "2026-09-21"))
    }
}
