package com.example.intelfeed.util

import java.text.ParsePosition
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object DateUtils {

    // Zoned patterns come before unzoned ones: SimpleDateFormat.parse accepts a matching prefix,
    // so "yyyy-MM-dd'T'HH:mm:ss" would otherwise read "…+02:00" timestamps as UTC.
    private val isoFormats = listOf(
        "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
        "yyyy-MM-dd'T'HH:mm:ssXXX",
        "yyyy-MM-dd'T'HH:mm:ss.SSS",
        "yyyy-MM-dd'T'HH:mm:ss",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd"
    )

    private val fractionalSeconds = Regex("\\.(\\d+)")

    private val dateOnly = Regex("^\\d{4}-\\d{2}-\\d{2}$")

    fun formatRelativeTime(dateString: String?, now: Long = System.currentTimeMillis(), zone: TimeZone = TimeZone.getDefault()): String {
        if (dateString.isNullOrBlank()) return ""

        val parsedDate = parseDate(dateString) ?: run {
            return if (dateString.length >= 10 && dateString[4] == '-' && dateString[7] == '-') {
                dateString.take(10)
            } else {
                dateString
            }
        }

        val diff = now - parsedDate.time
        if (diff < 0) {
            // Future date or slight clock skew
            return "Just now"
        }

        val seconds = diff / 1000
        val minutes = seconds / 60
        val hours = minutes / 60
        val days = hours / 24

        return when {
            minutes < 1 -> "Just now"
            minutes < 60 -> "${minutes}m ago"
            hours < 24 -> "${hours}h ago"
            days == 1L -> "Yesterday"
            days < 7 -> "${days}d ago"
            else -> {
                // A timestamp shows its local day, like the day dividers (it used to be the UTC
                // day, which differs for part of every day). A date without a time is a calendar
                // day read as UTC midnight, so it stays in UTC rather than moving to the day before.
                val tz = if (dateOnly.matches(dateString.trim())) TimeZone.getTimeZone("UTC") else zone
                val cal = Calendar.getInstance(tz).apply { time = parsedDate }
                val currentYear = Calendar.getInstance(tz).apply { timeInMillis = now }.get(Calendar.YEAR)
                val pattern = if (cal.get(Calendar.YEAR) == currentYear) "MMM d" else "MMM d, yyyy"
                SimpleDateFormat(pattern, Locale.US).apply { timeZone = tz }.format(parsedDate)
            }
        }
    }

    /**
     * Day divider label in the device's time zone: "Today", "Yesterday", "Monday, Sep 21" within
     * the week, otherwise "Sep 3" or "Sep 3, 2025". Empty when the date can't be read.
     */
    fun dayLabel(dateString: String?, now: Long = System.currentTimeMillis(), zone: TimeZone = TimeZone.getDefault()): String {
        val date = dateString?.let { parseDate(it) } ?: return ""
        val dayIndex = { millis: Long -> Calendar.getInstance(zone).apply { timeInMillis = millis }.let { it.get(Calendar.YEAR) * 1000 + it.get(Calendar.DAY_OF_YEAR) } }
        val today = Calendar.getInstance(zone).apply { timeInMillis = now }
        val then = Calendar.getInstance(zone).apply { time = date }
        val daysAgo = daysBetween(then, today)
        return when {
            dayIndex(date.time) == dayIndex(now) -> "Today"
            daysAgo == 1 -> "Yesterday"
            daysAgo in 2..6 -> SimpleDateFormat("EEEE, MMM d", Locale.US).apply { timeZone = zone }.format(date)
            then.get(Calendar.YEAR) == today.get(Calendar.YEAR) -> SimpleDateFormat("MMM d", Locale.US).apply { timeZone = zone }.format(date)
            else -> SimpleDateFormat("MMM d, yyyy", Locale.US).apply { timeZone = zone }.format(date)
        }
    }

    /** Whole calendar days from [from] to [to] (both already in the same zone). */
    private fun daysBetween(from: Calendar, to: Calendar): Int {
        val a = (from.clone() as Calendar).apply { set(Calendar.HOUR_OF_DAY, 12); set(Calendar.MINUTE, 0); set(Calendar.SECOND, 0); set(Calendar.MILLISECOND, 0) }
        val b = (to.clone() as Calendar).apply { set(Calendar.HOUR_OF_DAY, 12); set(Calendar.MINUTE, 0); set(Calendar.SECOND, 0); set(Calendar.MILLISECOND, 0) }
        return Math.round((b.timeInMillis - a.timeInMillis) / 86_400_000.0).toInt()
    }

    /** Estimated reading time at ~230 words a minute, or null for very short or unknown lengths. */
    fun readingMinutes(wordCount: Int?): Int? = wordCount?.takeIf { it >= 150 }?.let { (it + 229) / 230 }

    /** Returns ISO day key "yyyy-MM-dd" in UTC for querying /api/entries/daily-summary. */
    fun isoDayKey(dateString: String?): String? {
        val date = dateString?.let { parseDate(it) } ?: return null
        return SimpleDateFormat("yyyy-MM-dd", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(date)
    }

    /**
     * The calendar day ("yyyy-MM-dd") the timestamp falls on in [zone], the device's time zone by
     * default. This is the key the website uses for a day divider's chips and AI briefing, and it
     * matches dayLabel ("Today" is today's local date; isoDayKey used the UTC date, which is a
     * different day for part of every day outside UTC).
     */
    fun localDayKey(dateString: String?, zone: TimeZone = TimeZone.getDefault()): String? {
        val date = dateString?.let { parseDate(it) } ?: return null
        return dayKeyFormat.get()!!.apply { timeZone = zone }.format(date)
    }

    // The feed builds a day key for every card each time the list changes (every read or star),
    // on the main thread; a new SimpleDateFormat per card made that noticeably slow.
    private val dayKeyFormat = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue(): SimpleDateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.US)
    }

    /**
     * Local midnight and 23:59:59.999 of [dayKey] in [zone], as UTC ISO timestamps
     * ("2026-09-21T04:00:00.000Z"), the since/before pair the website sends for a day. Null if
     * [dayKey] isn't yyyy-MM-dd.
     */
    fun dayBounds(dayKey: String, zone: TimeZone = TimeZone.getDefault()): Pair<String, String>? {
        val match = Regex("^(\\d{4})-(\\d{2})-(\\d{2})$").matchEntire(dayKey) ?: return null
        val (y, m, d) = match.destructured
        val start = Calendar.getInstance(zone).apply {
            clear()
            set(y.toInt(), m.toInt() - 1, d.toInt(), 0, 0, 0)
        }
        val end = (start.clone() as Calendar).apply {
            add(Calendar.DAY_OF_MONTH, 1)
            add(Calendar.MILLISECOND, -1)
        }
        val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        return iso.format(start.time) to iso.format(end.time)
    }

    fun parseIsoMillis(dateString: String?): Long = dateString?.let { parseDate(it)?.time } ?: 0L

    /**
     * Parses the server's timestamps (ISO forms or epoch seconds). Called for every card on every
     * redraw, so results are cached and each thread reuses its formatters (it used to build up to
     * eight SimpleDateFormats per call and throw a ParseException for each pattern that missed).
     */
    fun parseDate(dateString: String): Date? {
        val trimmed = dateString.trim()
        synchronized(parsedCache) { parsedCache[trimmed] }?.let { return if (it == UNPARSEABLE) null else Date(it) }
        val millis = parseUncached(trimmed)
        synchronized(parsedCache) { parsedCache[trimmed] = millis ?: UNPARSEABLE }
        return millis?.let(::Date)
    }

    private const val UNPARSEABLE = Long.MIN_VALUE

    // Most recently used timestamps (a list page holds 30–60).
    private val parsedCache = object : LinkedHashMap<String, Long>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > 1024
    }

    // SimpleDateFormat isn't thread-safe, so one set per thread. (ThreadLocal.withInitial needs API 26.)
    private val formatters = object : ThreadLocal<List<SimpleDateFormat>>() {
        override fun initialValue(): List<SimpleDateFormat> =
            isoFormats.map { pattern -> SimpleDateFormat(pattern, Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") } }
    }

    private fun parseUncached(trimmed: String): Long? {
        // Epoch seconds or millis. Search hits send seconds as a decimal ("1790094767.0").
        val numeric = trimmed.toLongOrNull() ?: trimmed.toDoubleOrNull()?.toLong()
        if (numeric != null && numeric > 0) {
            return if (numeric < 100_000_000_000L) numeric * 1000L else numeric
        }

        // SimpleDateFormat reads "S" as a count of milliseconds, so microseconds (".123456") were
        // parsed as 123,456 ms, up to ~16 minutes off. Normalize the fraction to exactly 3 digits.
        val normalized = fractionalSeconds.replace(trimmed) { "." + it.groupValues[1].take(3).padEnd(3, '0') }

        // parse(text, position) returns null instead of throwing; like parse(text), it accepts a
        // matching prefix, which is why zoned patterns come first in isoFormats.
        for (formatter in formatters.get()!!) {
            formatter.parse(normalized, ParsePosition(0))?.let { return it.time }
        }
        return null
    }
}
