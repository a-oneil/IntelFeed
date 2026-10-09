package com.example.intelfeed

import android.app.Application
import coil.ImageLoader
import coil.ImageLoaderFactory
import coil.disk.DiskCache
import coil.memory.MemoryCache
import com.example.intelfeed.data.local.AuthPreferences
import com.example.intelfeed.data.local.UserPreferences
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.notifications.IntelNotificationHelper
import com.example.intelfeed.ui.UiMessenger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

/**
 * Holds the process-wide singletons. There must be one repository per process: it owns the OkHttp
 * client and the token-refresh lock, and the server rotates refresh tokens, so two instances
 * refreshing at once would log the user out. (MainActivity used to build a new one per
 * configuration change.)
 */
class IntelFeedApplication : Application(), ImageLoaderFactory {

    // Set only by the non-exported notification target; MainActivity clears it on the main thread
    // once the route is handled. Untrusted apps can launch MainActivity but cannot supply a route.
    internal var pendingNotificationRoute: IntelNotificationHelper.Route? = null

    val authPreferences: AuthPreferences by lazy { AuthPreferences(this) }
    val userPreferences: UserPreferences by lazy { UserPreferences(this) }
    val repository: IntelFeedRepository by lazy { IntelFeedRepository(authPreferences) }
    val messenger: UiMessenger by lazy { UiMessenger() }

    // Process-wide background work that must not be tied to a screen.
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        // Protect a session saved by an older version (plain-text tokens) without signing out.
        appScope.launch { runCatching { authPreferences.encryptStoredTokens() } }
        IntelNotificationHelper.createNotificationChannel(this)
        // The 15-minute background check runs only while someone is signed in with alerts on.
        // It used to be scheduled always, waking the app every 15 minutes just to find nothing to do.
        appScope.launch {
            combine(authPreferences.isLoggedIn, userPreferences.notificationsEnabled) { signedIn, alertsOn -> signedIn && alertsOn }
                .distinctUntilChanged()
                .collect { needed ->
                    if (needed) IntelNotificationHelper.schedulePeriodicSync(this@IntelFeedApplication)
                    else IntelNotificationHelper.cancelPeriodicSync(this@IntelFeedApplication)
                }
        }
        // A new keyword's first check records what already matches without alerting. Run it now:
        // waiting for the next periodic check (up to 15 minutes, longer in Doze) silently counted
        // every article that arrived in between as already seen.
        appScope.launch {
            var previous: Set<String>? = null
            userPreferences.trackedKeywords.collect { list ->
                val current = list.mapTo(HashSet()) { it.lowercase() }
                if (previous?.containsAll(current) == false) {
                    IntelNotificationHelper.triggerImmediateSync(this@IntelFeedApplication)
                }
                previous = current
            }
        }
    }
    /** Coil's loader for article images; see IntelFeedRepository.imageHttpClient. */
    override fun newImageLoader(): ImageLoader = ImageLoader.Builder(this)
        .okHttpClient { repository.imageHttpClient() }
        .memoryCache {
            MemoryCache.Builder(this)
                .maxSizePercent(0.25)
                .build()
        }
        .diskCache {
            DiskCache.Builder()
                .directory(cacheDir.resolve("image_cache"))
                .maxSizeBytes(50L * 1024 * 1024)
                .build()
        }
        .crossfade(true)
        .build()
}
