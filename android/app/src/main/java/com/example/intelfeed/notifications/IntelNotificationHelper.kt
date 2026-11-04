package com.example.intelfeed.notifications

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.example.intelfeed.R
import java.util.concurrent.TimeUnit

object IntelNotificationHelper {

    const val CHANNEL_ID = "intel_alerts"
    private const val CHANNEL_NAME = "Intel Alerts"
    private const val CHANNEL_DESCRIPTION = "Alerts for tracked campaigns, saved searches, and priority intelligence"
    private const val PERIODIC_WORK_NAME = "intel_periodic_sync"
    private const val IMMEDIATE_WORK_NAME = "intel_immediate_sync"

    // New app releases get their own channel, so they can be silenced apart from intel alerts.
    const val UPDATE_CHANNEL_ID = "app_updates"
    private const val UPDATE_WORK_NAME = "app_update_check"
    private const val UPDATE_NOTIFICATION_ID = 9998

    const val EXTRA_ROUTE_ENTRY_ID = "route_entry_id"
    const val EXTRA_ROUTE_CAMPAIGN_ID = "route_campaign_id"
    const val EXTRA_ROUTE_CAMPAIGN_NAME = "route_campaign_name"
    const val EXTRA_ROUTE_THREAD_SLUG = "route_thread_slug"
    const val EXTRA_ROUTE_THREAD_TITLE = "route_thread_title"

    /** Where a notification tap should go, after validation by the private notification target. */
    sealed interface Route {
        data class Entry(val id: String) : Route
        data class Campaign(val id: String, val name: String?) : Route
        data class Thread(val slug: String, val title: String?) : Route
    }

    private val ID_PATTERN = Regex("^[A-Za-z0-9-]{1,64}$")
    private val SLUG_PATTERN = Regex("^[A-Za-z0-9-]{1,200}$")

    /** The validated destination in a notification's intent, or null. */
    fun routeFrom(intent: Intent?): Route? {
        intent ?: return null
        fun text(key: String) = try {
            intent.getStringExtra(key)?.take(200)?.trim()?.takeIf { it.isNotEmpty() }
        } catch (_: RuntimeException) {
            // Ignore malformed extras rather than crashing when a notification is tapped.
            null
        }
        text(EXTRA_ROUTE_ENTRY_ID)?.takeIf { ID_PATTERN.matches(it) }?.let { return Route.Entry(it) }
        text(EXTRA_ROUTE_THREAD_SLUG)?.takeIf { SLUG_PATTERN.matches(it) }?.let { return Route.Thread(it, text(EXTRA_ROUTE_THREAD_TITLE)) }
        text(EXTRA_ROUTE_CAMPAIGN_ID)?.takeIf { ID_PATTERN.matches(it) }?.let { return Route.Campaign(it, text(EXTRA_ROUTE_CAMPAIGN_NAME)) }
        return null
    }

    /** True when the app may post notifications: the Android 13+ permission and the system switch. */
    fun canPostNotifications(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return false
        return NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_DEFAULT
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = CHANNEL_DESCRIPTION
                enableVibration(true)
            }
            val updates = NotificationChannel(UPDATE_CHANNEL_ID, "App updates", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "A new version of IntelFeed for Android is available"
            }
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
            notificationManager.createNotificationChannel(updates)
        }
    }

    fun schedulePeriodicSync(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val periodicRequest = PeriodicWorkRequestBuilder<IntelNotificationWorker>(15, TimeUnit.MINUTES)
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            periodicRequest
        )
    }

    /** Stops the periodic check (signed out, or alerts switched off in the app). */
    fun cancelPeriodicSync(context: Context) {
        WorkManager.getInstance(context).cancelUniqueWork(PERIODIC_WORK_NAME)
    }

    /** The daily new-release check (AppUpdateWorker). */
    fun scheduleUpdateCheck(context: Context) {
        val request = PeriodicWorkRequestBuilder<AppUpdateWorker>(1, TimeUnit.DAYS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(UPDATE_WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
    }

    fun cancelUpdateCheck(context: Context) {
        WorkManager.getInstance(context).cancelUniqueWork(UPDATE_WORK_NAME)
    }

    /** "IntelFeed <version> is available"; a tap opens the release page ([url]) in the browser. */
    fun postUpdateNotification(context: Context, version: String, url: String?, summary: String?) {
        if (!canPostNotifications(context)) return
        val intent = url?.let { Intent(Intent.ACTION_VIEW, Uri.parse(it)).addCategory(Intent.CATEGORY_BROWSABLE) }
            ?: context.packageManager.getLaunchIntentForPackage(context.packageName)
            ?: return
        val pendingIntent = PendingIntent.getActivity(
            context,
            UPDATE_NOTIFICATION_ID,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, UPDATE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(0xFF8B5CF6.toInt()) // CyberPurple
            .setContentTitle("IntelFeed $version is available")
            .setContentText(summary ?: "Tap to open the release and download the new APK.")
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(UPDATE_NOTIFICATION_ID, notification)
        } catch (_: SecurityException) {
        }
    }

    /** Removes the update notice once the installed app is no longer older than [notifiedVersion]. */
    fun clearStaleUpdateNotification(context: Context, notifiedVersion: String?, currentName: String, currentCode: Int) {
        notifiedVersion ?: return
        if (!AppUpdates.isNewer(AppUpdates.Release(notifiedVersion, null, null), currentName, currentCode)) {
            NotificationManagerCompat.from(context).cancel(UPDATE_NOTIFICATION_ID)
        }
    }

    fun triggerImmediateSync(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val oneTimeRequest = OneTimeWorkRequestBuilder<IntelNotificationWorker>()
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(context).enqueueUniqueWork(
            IMMEDIATE_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            oneTimeRequest
        )
    }

    fun postNotification(
        context: Context,
        id: Int,
        title: String,
        message: String,
        entryId: String? = null,
        campaignId: String? = null,
        campaignName: String? = null,
        threadSlug: String? = null,
        threadTitle: String? = null
    ) {
        if (!canPostNotifications(context)) return

        val intent = Intent(context, NotificationRouteActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            entryId?.let { putExtra(EXTRA_ROUTE_ENTRY_ID, it) }
            campaignId?.let { putExtra(EXTRA_ROUTE_CAMPAIGN_ID, it) }
            campaignName?.let { putExtra(EXTRA_ROUTE_CAMPAIGN_NAME, it) }
            threadSlug?.let { putExtra(EXTRA_ROUTE_THREAD_SLUG, it) }
            threadTitle?.let { putExtra(EXTRA_ROUTE_THREAD_TITLE, it) }
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            id,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(0xFF8B5CF6.toInt()) // CyberPurple
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        // Checked above, but the permission can be revoked at any moment on Android 13+.
        try {
            NotificationManagerCompat.from(context).notify(id, notification)
        } catch (_: SecurityException) {
        }
    }

    fun sendTestNotification(context: Context) {
        postNotification(
            context = context,
            id = 9999,
            title = "IntelFeed Alert System Active",
            message = "Tracking active campaigns, saved searches, and priority intelligence in the background."
        )
    }
}
