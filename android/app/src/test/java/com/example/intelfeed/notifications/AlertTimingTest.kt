package com.example.intelfeed.notifications

import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.util.DateUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AlertTimingTest {
    private val lastCheck = DateUtils.parseIsoMillis("2026-09-23T12:00:00Z")

    @Test fun articleIngestedAfterTheLastCheckIsNewEvenIfPublishedBefore() {
        // Published an hour before the check, fetched from its feed five minutes after it.
        val entry = EntryItem(id = "a", publishedAt = "2026-09-23T11:00:00Z", createdAt = "2026-09-23T12:05:00Z")
        assertTrue(AlertTiming.arrivedAtMs(entry) > lastCheck)
    }

    @Test fun missingIngestTimeFallsBackToPublishTime() {
        val entry = EntryItem(id = "a", publishedAt = "2026-09-23T11:00:00Z")
        assertEquals(DateUtils.parseIsoMillis("2026-09-23T11:00:00Z"), AlertTiming.arrivedAtMs(entry))
    }
}
