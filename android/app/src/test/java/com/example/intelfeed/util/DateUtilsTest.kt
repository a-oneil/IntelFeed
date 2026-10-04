package com.example.intelfeed.util

import org.junit.Assert.assertEquals
import org.junit.Test
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class DateUtilsTest {

    @Test
    fun testRelativeTimeJustNow() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC
        val result = DateUtils.formatRelativeTime("2024-03-29T11:59:45Z", now = now)
        assertEquals("Just now", result)
    }

    @Test
    fun testRelativeTimeMinutesAgo() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC
        val result = DateUtils.formatRelativeTime("2024-03-29T11:45:00Z", now = now)
        assertEquals("15m ago", result)
    }

    @Test
    fun testRelativeTimeHoursAgo() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC
        val result = DateUtils.formatRelativeTime("2024-03-29T08:00:00Z", now = now)
        assertEquals("4h ago", result)
    }

    @Test
    fun testRelativeTimeYesterday() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC
        val result = DateUtils.formatRelativeTime("2024-03-28T12:00:00Z", now = now)
        assertEquals("Yesterday", result)
    }

    @Test
    fun testRelativeTimeDaysAgo() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC
        val result = DateUtils.formatRelativeTime("2024-03-25T12:00:00Z", now = now)
        assertEquals("4d ago", result)
    }

    @Test
    fun testRelativeTimeFallback() {
        assertEquals("", DateUtils.formatRelativeTime(null))
        assertEquals("", DateUtils.formatRelativeTime(""))
        assertEquals("invalid-date", DateUtils.formatRelativeTime("invalid-date"))
        val now = 1711713600000L // 2024-03-29
        assertEquals("Jan 1", DateUtils.formatRelativeTime("2024-01-01", now = now))
        assertEquals("Jan 1, 2023", DateUtils.formatRelativeTime("2023-01-01", now = now))
    }

    @Test
    fun testRelativeTimeEpochTimestamp() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC (1711713600s)
        // 15m ago (1711712700s)
        assertEquals("15m ago", DateUtils.formatRelativeTime("1711712700", now = now))
        // Milliseconds
        assertEquals("15m ago", DateUtils.formatRelativeTime("1711712700000", now = now))
    }

    @Test
    fun testRelativeTimeMicrosecondPrecision() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC
        // Microseconds used to be read as milliseconds (500000 ms = 8m20s), giving "7m ago".
        assertEquals("15m ago", DateUtils.formatRelativeTime("2024-03-29T11:44:00.500000Z", now = now))
    }

    @Test
    fun testRelativeTimeFractionWithOffset() {
        val now = 1711713600000L // 2024-03-29 12:00:00 UTC
        // 13:44 at +02:00 is 11:44 UTC. This used to fall through to the unzoned pattern and read
        // the time as UTC, which is in the future ("Just now").
        assertEquals("15m ago", DateUtils.formatRelativeTime("2024-03-29T13:44:00.123456+02:00", now = now))
    }
}
