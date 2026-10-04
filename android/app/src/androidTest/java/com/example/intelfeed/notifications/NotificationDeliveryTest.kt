package com.example.intelfeed.notifications

import android.app.NotificationManager
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.intelfeed.IntelFeedApplication
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Posts a real keyword notification for the emulator tap-routing check. */
@RunWith(AndroidJUnit4::class)
class NotificationDeliveryTest {
    @Test fun postsKeywordNotification() {
        val app = ApplicationProvider.getApplicationContext<IntelFeedApplication>()
        val id = 314159
        assertTrue("Notification permission is required for this emulator test", IntelNotificationHelper.canPostNotifications(app))
        IntelNotificationHelper.createNotificationChannel(app)
        IntelNotificationHelper.postNotification(
            context = app,
            id = id,
            title = "Keyword: One Kubernetes YAML",
            message = "Controlled keyword notification routing test",
            keyword = "One Kubernetes YAML"
        )

        val manager = app.getSystemService(NotificationManager::class.java)
        val deadline = SystemClock.uptimeMillis() + 3_000
        while (manager.activeNotifications.none { it.id == id } && SystemClock.uptimeMillis() < deadline) {
            Thread.sleep(50)
        }
        assertTrue(manager.activeNotifications.any { it.id == id })
    }
}
