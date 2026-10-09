package com.example.intelfeed.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.TimeZone

class DateUtilsExtraTest {
    private val utc = TimeZone.getTimeZone("UTC")
    // 2026-09-22T12:00:00Z
    private val now = 1_790_078_400_000L

    @Test
    fun decimalEpochSecondsFromSearchHitsParse() {
        // One hour before "now", sent as a decimal the way search hits do.
        assertEquals("1h ago", DateUtils.formatRelativeTime("1790074800.0", now))
    }

    @Test
    fun dayLabels() {
        assertEquals("Today", DateUtils.dayLabel("2026-09-22T01:00:00Z", now, utc))
        assertEquals("Yesterday", DateUtils.dayLabel("2026-09-21T23:00:00Z", now, utc))
        assertEquals("Friday, Sep 18", DateUtils.dayLabel("2026-09-18T10:00:00Z", now, utc))
        assertEquals("Sep 1", DateUtils.dayLabel("2026-09-01T10:00:00Z", now, utc))
        assertEquals("Dec 30, 2025", DateUtils.dayLabel("2025-12-30T10:00:00Z", now, utc))
        assertEquals("", DateUtils.dayLabel(null, now, utc))
    }

    @Test
    fun readingTime() {
        assertNull(DateUtils.readingMinutes(100))
        assertEquals(1, DateUtils.readingMinutes(200))
        assertEquals(12, DateUtils.readingMinutes(2555))
    }

    @Test
    fun olderTimestampShowsItsLocalDayButABareDateDoesNotMove() {
        val march29 = 1711713600000L // 2024-03-29T12:00Z
        val newYork = TimeZone.getTimeZone("America/New_York")
        // 03:00 UTC on Mar 10 is still the evening of Mar 9 in New York.
        assertEquals("Mar 9", DateUtils.formatRelativeTime("2024-03-10T03:00:00Z", march29, newYork))
        assertEquals("Mar 10", DateUtils.formatRelativeTime("2024-03-10T03:00:00Z", march29, TimeZone.getTimeZone("UTC")))
        assertEquals("Mar 10", DateUtils.formatRelativeTime("2024-03-10", march29, newYork))
    }
}
