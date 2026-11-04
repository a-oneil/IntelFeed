package com.example.intelfeed.notifications

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.example.intelfeed.BuildConfig
import com.example.intelfeed.IntelFeedApplication
import kotlinx.coroutines.flow.first

/** Once a day: asks GitHub for the newest app release and notifies once per new version. */
class AppUpdateWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val app = applicationContext as? IntelFeedApplication ?: return Result.failure()
        if (!app.userPreferences.updateNoticesEnabled.first()) return Result.success()
        if (!IntelNotificationHelper.canPostNotifications(applicationContext)) return Result.success()

        // A failure waits for tomorrow's run rather than retrying: nothing is lost by a day's delay.
        val release = AppUpdates.fetchLatest() ?: return Result.success()
        if (!AppUpdates.isNewer(release, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE)) return Result.success()
        if (app.userPreferences.getNotifiedUpdateVersion() == release.versionName) return Result.success()

        IntelNotificationHelper.postUpdateNotification(applicationContext, release.versionName, release.url, release.summary)
        app.userPreferences.setNotifiedUpdateVersion(release.versionName)
        return Result.success()
    }
}
