package com.example.intelfeed.notifications

/** Decides which keyword matches are new enough to notify about. Plain Kotlin, unit-tested. */
object KeywordAlerts {

    /**
     * Newest matches looked at per keyword and check. A common word can have more than 20
     * new matches in two days, and with 20 an article further down was never seen (found while
     * testing with "vulnerabilities").
     */
    const val RESULTS_PER_CHECK = 50

    /** New matches whose read state is looked up per keyword and check; the rest wait for the next check. */
    const val MAX_LOOKUPS = 10

    /**
     * Ids in [current] that aren't in [seen]. A null [seen] means the keyword was never checked
     * (just added): its current matches are recorded without notifying, so adding "ransomware"
     * doesn't produce an alert for every existing article.
     */
    fun newIds(current: List<String>, seen: List<String>?): List<String> {
        if (seen == null) return emptyList()
        val known = seen.toHashSet()
        return current.filterNot { it in known }.distinct()
    }

    /** The new matches to look up this check, newest first (search order). */
    fun toLookUp(current: List<String>, seen: List<String>?): List<String> = newIds(current, seen).take(MAX_LOOKUPS)

    /** One keyword check's result: the ids to remember as seen, and the ids to alert about (search order). */
    data class Outcome(val seen: List<String>, val alert: List<String>)

    /**
     * Folds one check into a keyword's state. [readState] holds each looked-up id's current read
     * flag, or null when its lookup failed. A first check (null [seen]) records [current] without
     * alerting. A new unread match alerts unless [alreadyAlerted] (another alert covered it). A
     * failed lookup, or a new match beyond this check's lookup cap, stays unseen so the next check
     * tries it again.
     */
    fun evaluate(
        current: List<String>,
        seen: List<String>?,
        readState: Map<String, Boolean?>,
        alreadyAlerted: Set<String> = emptySet()
    ): Outcome {
        if (seen == null) return Outcome(current.distinct(), emptyList())
        val candidates = newIds(current, seen)
        val lookedUp = candidates.filter { readState[it] != null }
        val alert = lookedUp.filter { readState[it] == false && it !in alreadyAlerted }
        return Outcome((seen + lookedUp).distinct(), alert)
    }

    /** Search recent matches; the worker checks the current read state from each article detail. */
    fun query(keyword: String, sinceDay: String): String =
        "\"${keyword.replace("\"", "")}\" date:>=$sinceDay sort:newest"
}
