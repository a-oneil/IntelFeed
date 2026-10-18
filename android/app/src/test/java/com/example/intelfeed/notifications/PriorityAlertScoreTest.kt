package com.example.intelfeed.notifications

import com.example.intelfeed.theme.CyberOrange
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.ui.components.scoreColor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Priority scores run 0–10 and the Radar threshold sits around 8 — every queue entry clears it. */
class PriorityAlertScoreTest {
    @Test fun alertCutOffIsTheRedBand() {
        assertEquals(CyberRed, scoreColor(IntelNotificationWorker.PRIORITY_ALERT_SCORE))
        assertTrue(scoreColor(IntelNotificationWorker.PRIORITY_ALERT_SCORE - 0.1) != CyberRed)
    }

    @Test fun anEntryJustOverTheRadarThresholdNeitherAlertsNorGoesRed() {
        assertTrue(8.0 < IntelNotificationWorker.PRIORITY_ALERT_SCORE)
        assertTrue(scoreColor(8.0) != CyberRed)
    }

    @Test fun bandsMatchTheWebApp() {
        // frontend/src/utils/signalBand.ts: high ≥ 9.5, medium ≥ 8.5
        assertEquals(CyberRed, scoreColor(9.5))
        assertEquals(CyberOrange, scoreColor(8.5))
        assertEquals(CyberOrange, scoreColor(9.4))
    }
}
