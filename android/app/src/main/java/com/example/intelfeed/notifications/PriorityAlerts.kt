package com.example.intelfeed.notifications

import com.example.intelfeed.data.model.EntryItem

/** Decides which Priority Queue rows notify. Plain Kotlin, unit-tested. */
object PriorityAlerts {

    /** The default cut-off: the red score band, the same as the red badge (EntryCards.scoreColor). */
    const val DEFAULT_CUTOFF = 9.5
    // The queue only holds items that clear the Radar threshold (around 8), so a lower cut-off
    // would change nothing.
    const val MIN_CUTOFF = 7.0
    const val MAX_CUTOFF = 10.0
    const val CUTOFF_STEP = 0.5

    /** Queue rows per request. */
    const val PAGE_SIZE = 50

    /** The most pages one check reads. The scan normally stops at the first row below the cut-off. */
    const val MAX_PAGES = 10

    /** [cutoff] clamped to the settings range and rounded to a [CUTOFF_STEP]. */
    fun clampCutoff(cutoff: Double): Double =
        Math.round(cutoff.coerceIn(MIN_CUTOFF, MAX_CUTOFF) / CUTOFF_STEP) * CUTOFF_STEP

    /** A check's result: the rows to notify about, and the alert keys to remember as done. */
    data class Outcome(val alerts: List<EntryItem>, val record: List<String>)

    /**
     * Picks the unread [rows] scoring at least [cutoff] that haven't alerted yet. [notified] holds
     * the keys of alerts already posted ("e:<entry id>", "t:<story slug>").
     *
     * A story alerts once, keyed by its slug, however much it grows. It doesn't alert when one of
     * its articles already did, and its articles are recorded with it, so none of them alerts on
     * its own later. With [baseline] (the first check, or after the cut-off was lowered) everything
     * is recorded and nothing alerts, so the items already waiting in the queue don't flood in.
     */
    fun plan(rows: List<EntryItem>, cutoff: Double, notified: Set<String>, baseline: Boolean = false): Outcome {
        val seen = notified.toHashSet()
        val alerts = mutableListOf<EntryItem>()
        val record = mutableListOf<String>()
        fun remember(keys: List<String>) = keys.forEach { if (seen.add(it)) record += it }

        for (row in rows) {
            if (row.isRead || (row.priorityScore ?: 0.0) < cutoff) continue
            val thread = row.thread
            if (thread != null) {
                val slug = thread.slug ?: continue
                val keys = listOf("t:$slug") + thread.entryIds.map { "e:$it" }
                val covered = keys.any { it in seen }
                remember(keys)
                if (!covered && !baseline) alerts += row
            } else {
                val key = "e:${row.id}"
                if (key in seen) continue
                remember(listOf(key))
                if (!baseline) alerts += row
            }
        }
        return Outcome(alerts, record)
    }
}
