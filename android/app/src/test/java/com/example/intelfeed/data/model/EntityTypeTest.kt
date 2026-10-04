package com.example.intelfeed.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EntityTypeTest {
    @Test
    fun serverTypeNamesMapToProfiles() {
        assertEquals(EntityType.THREAT_ACTOR, EntityType.fromKey("actor"))
        assertEquals(EntityType.THREAT_ACTOR, EntityType.fromKey("threat-actors"))
        assertEquals(EntityType.RULE, EntityType.fromKey("detection_rule"))
        assertEquals(EntityType.CVE, EntityType.fromKey("CVE"))
        assertNull(EntityType.fromKey("note"))
        assertNull(EntityType.fromKey(null))
    }

    @Test
    fun articlesQueryQuotesTheNameAndStripsQuotes() {
        assertEquals("threat_actor:\"Volt Typhoon\"", EntityType.THREAT_ACTOR.articlesQuery("Volt Typhoon"))
        assertEquals("malware:\"Bad Name\"", EntityType.MALWARE.articlesQuery("Bad \"Name\""))
        assertNull(EntityType.RULE.articlesQuery("x"))
    }
}
