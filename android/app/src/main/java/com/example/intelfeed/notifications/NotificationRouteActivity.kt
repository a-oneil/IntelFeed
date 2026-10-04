package com.example.intelfeed.notifications

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import com.example.intelfeed.IntelFeedApplication
import com.example.intelfeed.MainActivity

/** Receives only our notification PendingIntents and hands their validated route to MainActivity. */
class NotificationRouteActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        (application as IntelFeedApplication).pendingNotificationRoute = IntelNotificationHelper.routeFrom(intent)
        startActivity(Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        })
        finish()
    }
}
