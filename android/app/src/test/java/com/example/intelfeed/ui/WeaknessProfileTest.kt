package com.example.intelfeed.ui

import com.example.intelfeed.data.model.Cwe
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.ui.entity.toProfile
import org.junit.Assert.assertEquals
import org.junit.Test

class WeaknessProfileTest {
    private val cwe = Cwe(id = "5f0c7a52-1111-4a8e-9b1a-000000000416", cweId = "CWE-416", name = "Use After Free")

    @Test
    fun timelineAndNotesUseTheRowIdNotTheCweId() {
        val profile = cwe.toProfile()
        assertEquals("CWE-416", profile.ref.id) // how the profile is opened
        assertEquals("5f0c7a52-1111-4a8e-9b1a-000000000416", profile.serverId)
    }

    @Test
    fun articlesSearchUsesTheCweId() {
        val profile = cwe.toProfile()
        assertEquals("cwe:\"CWE-416\"", EntityType.WEAKNESS.articlesQuery(profile.searchName))
    }

    @Test
    fun weaknessUsesTheServersCweTypeName() {
        // Relationships and entity notes send type.key; the server's slug for weaknesses is "cwe".
        assertEquals("cwe", EntityType.WEAKNESS.key)
        assertEquals(EntityType.WEAKNESS, EntityType.fromKey("weakness"))
    }
}
