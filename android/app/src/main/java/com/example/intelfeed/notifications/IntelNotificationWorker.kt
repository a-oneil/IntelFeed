package com.example.intelfeed.notifications

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.example.intelfeed.IntelFeedApplication
import com.example.intelfeed.data.model.EntryItem
import kotlinx.coroutines.NonCancellable
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

    // The periodic check and "Check for new intel now" can overlap.
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

        // The saved alert state belongs to one account on one server, so signing in as someone
        // else starts it fresh.
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

            // 1. Poll Active Campaigns
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

            // 2. Poll Saved Searches
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

            // 3. Poll the Priority Queue: every unread row at or above the user's cut-off. The queue
            // is ranked highest score first, so the scan stops at the first row below it.
            val cutoff = app.userPreferences.priorityAlertScore.first()
            val baselineAt = app.userPreferences.getPriorityAlertBaseline()
            val rows = mutableListOf<EntryItem>()
            var scanned = false
            var cursor: String? = null
            for (pageNo in 1..PriorityAlerts.MAX_PAGES) {
                val page = app.repository.getEntries(
                    filter = com.example.intelfeed.data.repository.FeedFilter.PRIORITY_QUEUE,
                    cursor = cursor,
                    limit = PriorityAlerts.PAGE_SIZE
                ).getOrNull()
                if (page == null) {
                    syncComplete = false
                    break
                }
                rows += page.items.filter { (it.priorityScore ?: 0.0) >= cutoff }
                cursor = page.nextCursor
                if (page.items.any { (it.priorityScore ?: 0.0) < cutoff } || !page.hasMore || cursor == null) {
                    scanned = true
                    break
                }
            }
            // First check, or the cut-off was lowered: record what's already waiting without alerting.
            val baseline = baselineAt == null || cutoff < baselineAt
            val outcome = PriorityAlerts.plan(rows, cutoff, notified, baseline)
            outcome.record.forEach { firstAlert(it) }
            for (entry in outcome.alerts) {
                val scoreText = String.format(Locale.US, "%.1f", entry.priorityScore ?: 0.0)
                val slug = entry.thread?.slug
                if (slug != null) {
                    // A story row: its id is "thread:<slug>", not an article id, so open the story.
                    IntelNotificationHelper.postNotification(
                        context = applicationContext,
                        id = slug.hashCode(),
                        title = "Priority story (score $scoreText)",
                        message = entry.title,
                        threadSlug = slug,
                        threadTitle = entry.title
                    )
                } else {
                    IntelNotificationHelper.postNotification(
                        context = applicationContext,
                        id = entry.id.hashCode(),
                        title = "Priority intelligence (score $scoreText)",
                        message = entry.title,
                        entryId = entry.id
                    )
                }
            }
            if (scanned) app.userPreferences.setPriorityAlertBaseline(cutoff)

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

    companion object {
        private val runLock = Mutex()
    }
}
