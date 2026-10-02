# Codex review and fixes — 2026-09-23

Reviewed `claude_changes.md`, the Android source, manifest, networking, notifications, and the recent feed changes. This project has no Git repository, so this note records Codex's edits separately from the Claude change log.

## Changes

- **Session and server safety:** `AuthPreferences` now loads the saved server and token into its cache before first use, serializes session mutations, and rejects a refresh that completes after logout or a newer sign-in. A new sign-in without a refresh token clears any prior account's token. `IntelFeedRepository` uses the loaded server address. Sign-in never carries a previous session's bearer token. Server URLs with embedded credentials are rejected.
- **Intent security:** Notification taps target a private `NotificationRouteActivity`. It validates the route and hands it to `MainActivity` through process-private application state. The exported `MainActivity` no longer reads route extras supplied by other apps. Malformed share and notification extras are ignored instead of crashing the activity.
- **TLS:** The public `intelfeed.cc` domain trusts system certificate authorities only. User-installed authorities remain available to self-hosted instances through the base configuration.
- **Feed paging:** A failed page load waits for the Retry action instead of automatically repeating while the user is near the end. Switching list/grid uses the current layout for the near-end calculation.
- **Alerts:** A partial polling failure no longer advances the last-sync time past unseen alerts. Keyword matches whose detail lookup failed, or which exceeded the per-run lookup cap, remain eligible for the next check.

## Verification

`./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease` succeeded. 148 unit tests passed with no failures; lint reported zero errors and 24 warnings. Added tests for saved-server initialization, late refresh rejection, stale refresh failure, refresh token replacement, and the absence of a previous bearer token on sign-in. No live server writes or account changes were made. Notification taps and server switching were not exercised on a device in this review.

## Best Practices and Security Alignment Update: exported intent routing

**Priority:** Medium. A foreign app could launch exported `MainActivity` with notification route extras, causing it to open a reader or perform a search in the signed-in account.

**Scope:** `AndroidManifest.xml`, `IntelFeedApplication.kt`, `MainActivity.kt`, `IntelNotificationHelper.kt`, new `NotificationRouteActivity.kt`, and `ShareIntentSanitizer.kt`. No dependency changes.

**Implementation:** Notification PendingIntents are immutable and explicitly target a non-exported activity. That activity validates the route and transfers it through application memory. `MainActivity` consumes the route once. Both incoming share text and route extras tolerate malformed parcels.

```diff
--- a/app/src/main/AndroidManifest.xml
+++ b/app/src/main/AndroidManifest.xml
@@ -36,6 +36,11 @@
                 <data android:mimeType="text/plain" />
             </intent-filter>
         </activity>
+        <activity
+            android:name=".notifications.NotificationRouteActivity"
+            android:exported="false"
+            android:excludeFromRecents="true"
+            android:theme="@android:style/Theme.Translucent.NoTitleBar" />
     </application>
 
 </manifest>
--- a/app/src/main/java/com/example/intelfeed/IntelFeedApplication.kt
+++ b/app/src/main/java/com/example/intelfeed/IntelFeedApplication.kt
@@ -21,6 +21,10 @@
  * configuration change.)
  */
 class IntelFeedApplication : Application(), ImageLoaderFactory {
+
+    // Set only by the non-exported notification target, then consumed by MainActivity on the
+    // main thread. Untrusted apps can launch MainActivity but cannot supply a notification route.
+    internal var pendingNotificationRoute: com.example.intelfeed.notifications.IntelNotificationHelper.Route? = null
 
     val authPreferences: AuthPreferences by lazy { AuthPreferences(this) }
     val userPreferences: UserPreferences by lazy { UserPreferences(this) }
--- a/app/src/main/java/com/example/intelfeed/MainActivity.kt
+++ b/app/src/main/java/com/example/intelfeed/MainActivity.kt
@@ -40,8 +40,8 @@
         // Not after a configuration change or process restore: the same tap would be handled again.
         if (savedInstanceState == null) {
             handleShareIntent(intent)
-            takeNotificationRoute(intent)
         }
+        takeNotificationRoute()
 
         val app = application as IntelFeedApplication
         enableEdgeToEdge()
@@ -101,12 +101,13 @@
         super.onNewIntent(intent)
         setIntent(intent)
         handleShareIntent(intent)
-        takeNotificationRoute(intent)
+        takeNotificationRoute()
     }
 
-    private fun takeNotificationRoute(intent: Intent?) {
-        IntelNotificationHelper.routeFrom(intent)?.let { pendingRoute = it }
-        IntelNotificationHelper.clearRoute(intent)
+    private fun takeNotificationRoute() {
+        val app = application as IntelFeedApplication
+        app.pendingNotificationRoute?.let { pendingRoute = it }
+        app.pendingNotificationRoute = null
     }
 
     /** Picks the first safe http(s) link out of text shared from another app (browsers often add a title). */
--- a/app/src/main/java/com/example/intelfeed/notifications/IntelNotificationHelper.kt
+++ b/app/src/main/java/com/example/intelfeed/notifications/IntelNotificationHelper.kt
@@ -18,7 +18,6 @@
 import androidx.work.OneTimeWorkRequestBuilder
 import androidx.work.PeriodicWorkRequestBuilder
 import androidx.work.WorkManager
-import com.example.intelfeed.MainActivity
 import com.example.intelfeed.R
 import java.util.concurrent.TimeUnit
 
@@ -37,10 +36,7 @@
     const val EXTRA_ROUTE_THREAD_TITLE = "route_thread_title"
     const val EXTRA_ROUTE_KEYWORD = "route_keyword"
 
-    /**
-     * Where a notification tap should go. MainActivity is exported (it's the launcher), so any app
-     * can start it with these extras: ids are checked against the server's id formats before use.
-     */
+    /** Where a notification tap should go, after validation by the private notification target. */
     sealed interface Route {
         data class Entry(val id: String) : Route
         data class Campaign(val id: String, val name: String?) : Route
@@ -55,19 +51,18 @@
     /** The validated destination in a notification's intent, or null. */
     fun routeFrom(intent: Intent?): Route? {
         intent ?: return null
-        fun text(key: String) = intent.getStringExtra(key)?.trim()?.take(200)?.takeIf { it.isNotEmpty() }
+        fun text(key: String) = try {
+            intent.getStringExtra(key)?.take(200)?.trim()?.takeIf { it.isNotEmpty() }
+        } catch (_: RuntimeException) {
+            // Ignore malformed extras rather than crashing when a notification is tapped.
+            null
+        }
         text(EXTRA_ROUTE_ENTRY_ID)?.takeIf { ID_PATTERN.matches(it) }?.let { return Route.Entry(it) }
         text(EXTRA_ROUTE_THREAD_SLUG)?.takeIf { SLUG_PATTERN.matches(it) }?.let { return Route.Thread(it, text(EXTRA_ROUTE_THREAD_TITLE)) }
         text(EXTRA_ROUTE_CAMPAIGN_ID)?.takeIf { ID_PATTERN.matches(it) }?.let { return Route.Campaign(it, text(EXTRA_ROUTE_CAMPAIGN_NAME)) }
         // A keyword only ever becomes a phrase search in the app; no control characters, 100 chars max.
         text(EXTRA_ROUTE_KEYWORD)?.takeIf { k -> k.length <= 100 && k.none { it.isISOControl() } }?.let { return Route.Keyword(it) }
         return null
-    }
-
-    /** Clears the route extras so the same tap isn't handled twice (e.g. after a configuration change). */
-    fun clearRoute(intent: Intent?) {
-        listOf(EXTRA_ROUTE_ENTRY_ID, EXTRA_ROUTE_CAMPAIGN_ID, EXTRA_ROUTE_CAMPAIGN_NAME, EXTRA_ROUTE_THREAD_SLUG, EXTRA_ROUTE_THREAD_TITLE, EXTRA_ROUTE_KEYWORD)
-            .forEach { intent?.removeExtra(it) }
     }
 
     /** True when the app may post notifications: the Android 13+ permission and the system switch. */
@@ -136,7 +131,7 @@
     ) {
         if (!canPostNotifications(context)) return
 
-        val intent = Intent(context, MainActivity::class.java).apply {
+        val intent = Intent(context, NotificationRouteActivity::class.java).apply {
             flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
             entryId?.let { putExtra(EXTRA_ROUTE_ENTRY_ID, it) }
             campaignId?.let { putExtra(EXTRA_ROUTE_CAMPAIGN_ID, it) }
--- /dev/null
+++ b/app/src/main/java/com/example/intelfeed/notifications/NotificationRouteActivity.kt
@@ -0,0 +1,21 @@
+package com.example.intelfeed.notifications
+
+import android.app.Activity
+import android.content.Intent
+import android.os.Bundle
+import com.example.intelfeed.IntelFeedApplication
+import com.example.intelfeed.MainActivity
+
+/** Receives only our notification PendingIntents and hands their validated route to MainActivity. */
+class NotificationRouteActivity : Activity() {
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        IntelNotificationHelper.routeFrom(intent)?.let { route ->
+            (application as IntelFeedApplication).pendingNotificationRoute = route
+            startActivity(Intent(this, MainActivity::class.java).apply {
+                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
+            })
+        }
+        finish()
+    }
+}
--- a/app/src/main/java/com/example/intelfeed/util/ShareIntentSanitizer.kt
+++ b/app/src/main/java/com/example/intelfeed/util/ShareIntentSanitizer.kt
@@ -34,7 +34,12 @@
         }
 
         // 2. Bound incoming text length to avoid regex DoS or memory spikes
-        val rawText = intent.getStringExtra(Intent.EXTRA_TEXT)?.take(MAX_SHARE_TEXT_LENGTH) ?: return null
+        val rawText = try {
+            intent.getStringExtra(Intent.EXTRA_TEXT)?.take(MAX_SHARE_TEXT_LENGTH)
+        } catch (_: RuntimeException) {
+            // Malformed extras from another app must not crash the exported activity.
+            null
+        } ?: return null
         return extractUrlFromText(rawText)
     }
 
```

The application state transfer is the same-process boundary between the private notification target and the exported activity. The notification `PendingIntent` remains `FLAG_IMMUTABLE`. There are no exported services, receivers, or providers in the app manifest.

## Follow-up: read/unread and keyword notification checks

- Fixed a read rollback bug in `IntelFeedViewModel`: an optimistic mark-read update no longer removes an article from Unread before the server confirms it. Failed requests can now restore the same card and count. The repository emits a confirmation event after successful flag changes.
- Serialized read/unread requests per article in `IntelFeedRepository`, so a quick read followed by undo reaches the server in that order. Added three MockWebServer tests covering failed read, confirmed read, and rapid read/undo.
- Fixed `NotificationRouteActivity` so a valid notification with no destination, including the built-in test alert, opens the app. The security patch shown above is a snapshot from the first review; this later correction is in the current source.
- Added an emulator test that posts a controlled keyword notification and waits for Android to deliver it.

**Emulator:** On a signed-in live session, marking an article read removed it from Unread and decremented the badge; marking it unread restored it. Opening the article marked it read, and Undo in the reader restored it to Unread. The built-in test notification opened the app. A controlled keyword notification appeared in the Android shade and tapping it opened the app. The final keyword search destination after a tap could not be verified because the Gradle connected-test task uninstalled the app and cleared its emulator sign-in. The live worker's end-to-end keyword match alert was not observed; a recent read/unread change was absent from server search results during the check. No production keyword or article was created.

**Verification:** `:app:testDebugUnitTest`, `:app:lintDebug`, `:app:assembleDebug`, and `:app:assembleDebugAndroidTest` passed. 151 unit tests had zero failures. The isolated emulator keyword delivery test passed after notification permission was granted. The app currently shows Sign In on the emulator; a new sign-in is needed before any further authenticated live checks.

## Follow-up: keyword alert search reliability

The keyword worker no longer depends on the search index's `is:unread` filter. That filter lagged behind read/unread changes during emulator testing and could omit a current unread match. It now makes one recent phrase search per keyword, then checks up to ten new hits through `GET /api/entries/{id}` before notifying; only articles currently unread can alert. The first check still records a baseline without alerting, and failed detail lookups remain eligible for a later check. This keeps the search request count at one per keyword per poll.

`KeywordAlertsTest` covers the revised query. `:app:testDebugUnitTest :app:assembleDebug :app:lintDebug` passed (151 tests, no failures), and the updated debug APK was installed on the emulator without clearing data. The emulator is signed out, so this change has not yet been verified against a new live keyword match.
