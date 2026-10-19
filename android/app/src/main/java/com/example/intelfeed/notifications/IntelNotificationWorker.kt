package com.example.intelfeed.notifications

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.example.intelfeed.IntelFeedApplication
import com.example.intelfeed.data.model.EntryItem
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Locale
import kotlin.coroutines.cancellation.CancellationException

class IntelNotificationWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    // The periodic check and "Check for updates now" (or a new keyword's first check) can overlap.
    // Both would post the same alerts and overwrite each other's saved state, so one runs at a time.
    override suspend fun doWork(): Result = runLock.withLock { check() }

    private suspend fun check(): Result {
        val app = applicationContext as? IntelFeedApplication ?: return Result.failure()

        // Verify user is logged in
        val token = app.authPreferences.getAccessToken()
        if (token.isNullOrBlank()) return Result.success()

        // Verify notifications are enabled
        val enabled = app.userPreferences.notificationsEnabled.first()
        if (!enabled) return Result.success()

        // Nothing could be shown (Android 13+ permission not granted, or notifications switched off
        // for the app): skip the network work instead of polling the server every 15 minutes.
        if (!IntelNotificationHelper.canPostNotifications(applicationContext)) return Result.success()

        // The saved alert state belongs to one account on one server. After signing in as someone
        // else, the old keyword baselines made every match of the new account look new.
        val owner = app.authPreferences.getServerUrl() + "|" + app.authPreferences.username.first().orEmpty().lowercase(Locale.ROOT)
        app.userPreferences.claimAlertState(owner)

        val lastSyncMs = app.userPreferences.getLastNotificationSyncMs().let {
            if (it == 0L) System.currentTimeMillis() - 3600_000L else it
        }
        val currentSyncMs = System.currentTimeMillis()
        // Each article (or story update) alerts once, whichever source finds it. Without this, a
        // partial failure, which keeps the window below from advancing, re-posted the same alerts
        // every 15 minutes.
        val notified = app.userPreferences.getNotifiedAlertKeys().toHashSet()
        val newlyNotified = mutableListOf<String>()
        fun firstAlert(key: String): Boolean = notified.add(key).also { if (it) newlyNotified += key }
        fun isNew(entry: EntryItem) = AlertTiming.arrivedAtMs(entry) > lastSyncMs

        try {
            var syncComplete = true

            // 1. Tracked keywords (kept on the device) first: the user chose them, and the sources
            // below can take minutes on a slow server (WorkManager stops a run after 10).
            checkKeywords(app, notified) { firstAlert(it) }

            // 2. Poll Active Campaigns
            app.repository.getCampaigns(limit = 10).onSuccess { campaignsPage ->
                for (campaign in campaignsPage.items) {
                    app.repository.getCampaignEntries(
                        campaignId = campaign.id,
                        isRead = false,
                        limit = 5
                    ).onSuccess { entriesPage ->
                        for (entry in entriesPage.items) {
                            if (isNew(entry) && firstAlert("e:${entry.id}")) {
                                IntelNotificationHelper.postNotification(
                                    context = applicationContext,
                                    id = entry.id.hashCode(),
                                    title = "Campaign: ${campaign.name}",
                                    message = entry.title,
                                    entryId = entry.id,
                                    campaignId = campaign.id,
                                    campaignName = campaign.name
                                )
                            }
                        }
                    }.onFailure { syncComplete = false }
                }
            }.onFailure { syncComplete = false }

            // 3. Poll Saved Searches
            app.repository.getSavedSearches().onSuccess { savedSearches ->
                for (saved in savedSearches) {
                    if ((saved.unreadCount ?: 0) > 0) {
                        app.repository.searchEntries(query = saved.query, limit = 5).onSuccess { searchPage ->
                            val newUnread = searchPage.items.filter { entry ->
                                !entry.isRead && isNew(entry) && "e:${entry.id}" !in notified
                            }
                            if (newUnread.isNotEmpty()) {
                                newUnread.forEach { firstAlert("e:${it.id}") }
                                val top = newUnread.first()
                                IntelNotificationHelper.postNotification(
                                    context = applicationContext,
                                    id = saved.id.hashCode(),
                                    title = "Saved search: ${saved.label}",
                                    message = "${newUnread.size} new match${if (newUnread.size > 1) "es" else ""}: ${top.title}",
                                    entryId = top.id
                                )
                            }
                        }.onFailure { syncComplete = false }
                    }
                }
            }.onFailure { syncComplete = false }

            // 4. Poll Priority Queue for Critical Alerts. Scores run 0–10 and everything in the queue
            // already clears the Radar threshold (around 8), so only the red band alerts.
            app.repository.getEntries(
                filter = com.example.intelfeed.data.repository.FeedFilter.PRIORITY_QUEUE,
                limit = 5
            ).onSuccess { page ->
                for (entry in page.items) {
                    if (entry.isRead) continue
                    val score = entry.priorityScore ?: 0.0
                    if (score < PRIORITY_ALERT_SCORE || !isNew(entry)) continue
                    val scoreText = String.format(Locale.US, "%.1f", score)
                    val thread = entry.thread
                    if (thread != null) {
                        // A story row: its id is "thread:<slug>", not an article id, so open the story.
                        // Keyed with its last update, so a story that grows again can alert again.
                        val slug = thread.slug ?: continue
                        if (!firstAlert("t:$slug:${entry.publishedAt}")) continue
                        IntelNotificationHelper.postNotification(
                            context = applicationContext,
                            id = slug.hashCode(),
                            title = "Priority story (score $scoreText)",
                            message = entry.title,
                            threadSlug = slug,
                            threadTitle = entry.title
                        )
                    } else {
                        if (!firstAlert("e:${entry.id}")) continue
                        IntelNotificationHelper.postNotification(
                            context = applicationContext,
                            id = entry.id.hashCode(),
                            title = "Priority intelligence (score $scoreText)",
                            message = entry.title,
                            entryId = entry.id
                        )
                    }
                }
            }.onFailure { syncComplete = false }

            // A partial failure must not move the window past alerts the failed request missed.
            if (syncComplete) app.userPreferences.setLastNotificationSyncMs(currentSyncMs)
        } catch (e: CancellationException) {
            throw e // WorkManager stopped the job; let the coroutine end as cancelled
        } catch (_: Exception) {
            // Background polling failure should not crash; it will retry next interval
        } finally {
            // Also after a failure or cancellation part-way: whatever was posted must not repeat.
            if (newlyNotified.isNotEmpty()) {
                withContext(NonCancellable) { runCatching { app.userPreferences.addNotifiedAlertKeys(newlyNotified) } }
            }
        }

        return Result.success()
    }

    /**
     * Searches each tracked keyword (as a phrase, from the last two days) and notifies about
     * unread matches not seen on an earlier check. A keyword's first check only records what's
     * there. Up to 4 keywords are checked at once: searches take several seconds each on the
     * server and a worker run is limited to 10 minutes. [notified] holds the alerts already posted
     * ("e:<entry id>"), so an article another alert covered doesn't alert again; [firstAlert]
     * records a new one.
     */
    private suspend fun checkKeywords(app: IntelFeedApplication, notified: Set<String>, firstAlert: (String) -> Boolean) {
        val keywords = app.userPreferences.trackedKeywords.first()
        if (keywords.isEmpty()) return
        val seen = app.userPreferences.getKeywordSeenIds()
        val sinceDay = java.text.SimpleDateFormat("yyyy-MM-dd", Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
            .format(java.util.Date(System.currentTimeMillis() - 2 * 24 * 3600_000L))
        val updated = seen.filterKeys { it in keywords }.toMutableMap()
        try {
            for (batch in keywords.chunked(4)) {
                val results = coroutineScope {
                    batch.map { keyword ->
                        async {
                            // The search index's is:unread filter can lag behind a read-state change.
                            // Search the phrase once and check each new hit against its current detail.
                            val matches = app.repository.searchEntries(
                                KeywordAlerts.query(keyword, sinceDay),
                                limit = KeywordAlerts.RESULTS_PER_CHECK
                            ).getOrNull()?.items
                            val readState = matches?.let { m ->
                                KeywordAlerts.toLookUp(m.map { it.id }, seen[keyword])
                                    .associateWith { id -> app.repository.getEntryDetail(id).getOrNull()?.isRead }
                            }.orEmpty()
                            Triple(keyword, matches, readState)
                        }
                    }.awaitAll()
                }
                for ((keyword, matches, readState) in results) {
                    matches ?: continue // failed search: try again next time, without forgetting what was seen
                    val ids = matches.map { it.id }
                    val outcome = KeywordAlerts.evaluate(
                        ids, seen[keyword], readState,
                        alreadyAlerted = ids.filterTo(HashSet()) { "e:$it" in notified }
                    )
                    updated[keyword] = outcome.seen
                    if (outcome.alert.isEmpty()) continue
                    outcome.alert.forEach { firstAlert("e:$it") }
                    postKeywordAlert(keyword, outcome.alert.map { id -> matches.first { it.id == id } })
                }
            }
        } finally {
            // Saved even when the run is stopped part-way (lost network, time limit, a newer run
            // replacing it): alerts already posted must not be posted again next time.
            withContext(NonCancellable) { runCatching { app.userPreferences.setKeywordSeenIds(updated) } }
        }
    }

    /** One notification per keyword; [articles] are the new unread matches, newest first. */
    private fun postKeywordAlert(keyword: String, articles: List<EntryItem>) {
        val id = "keyword:$keyword".hashCode()
        // An earlier alert for this keyword that hasn't been opened is added to rather than replaced
        // with a smaller count, and the tap then opens all the keyword's newest matches.
        val stillShowing = IntelNotificationHelper.isShowing(applicationContext, id)
        val first = articles.first()
        val single = articles.size == 1 && !stillShowing
        val count = articles.size
        val message = when {
            single -> first.displayTitle
            stillShowing -> "$count more new ${if (count == 1) "article mentions" else "articles mention"} \"$keyword\" · ${first.displayTitle}"
            else -> "$count new articles mention \"$keyword\" · ${first.displayTitle}"
        }
        IntelNotificationHelper.postNotification(
            context = applicationContext,
            id = id,
            title = "Keyword: $keyword",
            message = message,
            entryId = if (single) first.id else null,
            keyword = if (single) null else keyword
        )
    }

    companion object {
        /** The "critical" band, the same cut-off as the red score badge (EntryCards.scoreColor). */
        const val PRIORITY_ALERT_SCORE = 9.5

        private val runLock = Mutex()
    }
}
