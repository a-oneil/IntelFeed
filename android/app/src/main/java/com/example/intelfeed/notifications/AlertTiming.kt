package com.example.intelfeed.notifications

import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.util.DateUtils

/** Decides whether an entry is new since the last background check. Plain Kotlin, unit-tested. */
object AlertTiming {

    /**
     * When [entry] reached the server: the later of its publish and ingest times. Feeds are polled,
     * so most articles arrive well after their publish time; comparing the publish time alone with
     * the last 15-minute check skipped them.
     */
    fun arrivedAtMs(entry: EntryItem): Long =
        maxOf(DateUtils.parseIsoMillis(entry.publishedAt), DateUtils.parseIsoMillis(entry.createdAt))
}
