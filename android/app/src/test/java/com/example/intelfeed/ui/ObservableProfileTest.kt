package com.example.intelfeed.ui

import com.example.intelfeed.data.model.ObservableItem
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.ui.entity.toProfile
import com.example.intelfeed.ui.entity.toWorkbenchItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ObservableProfileTest {
    // Field names as the website reads them (Workbench columns, profile badges and provenance panel).
    private val json = """
        {"id": "0541b5c2-028f-4485-8583-783697af7d7b", "value": "webhook.site", "kind": "domain",
         "role": "exfil", "current_confidence": 0.42, "status": "active", "infra_tag": "public_service",
         "created_via": "ai_extraction", "first_seen_at": "2026-09-07T10:00:00Z",
         "last_seen_at": "2026-09-23T10:00:00Z", "article_count": 2}
    """.trimIndent()

    @Test
    fun kindIsShownInsteadOfAGenericLabel() {
        val item = ApiJson.json.decodeFromString(ObservableItem.serializer(), json)
        // Before: the app read a `type` field the server doesn't send, so every row said "OBSERVABLE".
        assertEquals("DOMAIN · role: exfil", item.toWorkbenchItem().subtitle)
        val profile = item.toProfile()
        assertEquals("Observable · DOMAIN", profile.subtitle)
        assertTrue(profile.facts.contains("Kind" to "DOMAIN"))
        assertTrue(profile.facts.contains("Captured by" to "ai extraction"))
    }

    @Test
    fun badgesAreTheWebSignalsNotAConstantIoc() {
        val item = ApiJson.json.decodeFromString(ObservableItem.serializer(), json)
        // "active" is the normal state and gets no badge.
        assertEquals(listOf("Confidence 42%", "Dual-use"), item.toWorkbenchItem().badges.map { it.label })
        val bare = ObservableItem(id = "x", value = "1.2.3.4")
        assertEquals("Observable", bare.toWorkbenchItem().subtitle)
        assertTrue(bare.toWorkbenchItem().badges.isEmpty())
    }
}
