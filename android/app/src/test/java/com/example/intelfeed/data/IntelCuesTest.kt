package com.example.intelfeed.data

import com.example.intelfeed.data.model.EntryIntelCounts
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.data.network.IntelFeedApi
import com.example.intelfeed.ui.components.intelCues
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/** The list cards' intel cues (POST /api/entries/intel-counts). */
class IntelCuesTest {

    // One entry from the live server's response, 2026-09-23.
    private val live = "{\"5f8ea946-e742-4b71-b970-d4716c973023\": {\"ttps\": 0, \"cves\": 2, \"rules\": 0, \"notes\": 0, \"ai_results\": 0, \"total\": 2, \"has_detection_gap\": true, \"detection_opportunity\": \"actionable_gap\", \"has_high_risk_cve\": true, \"has_kev_cve\": true, \"high_value\": false, \"pir_matches\": [{\"id\": \"38ae4159-fc01-4438-933b-4ffc7443cbdb\", \"title\": \"Vulnerability Exploitation & Weaponization\", \"priority\": \"critical\", \"category\": \"tactical\", \"match_type\": \"keyword\", \"matched_on\": \"zero-day\", \"relevance\": \"high\"}, {\"id\": \"aa5b3000-6ee8-4129-b619-b4426acec085\", \"title\": \"Edge Device & Network Infrastructure Exploitation\", \"priority\": \"critical\", \"category\": \"tactical\", \"match_type\": \"keyword\", \"matched_on\": \"zyxel\", \"relevance\": \"low\"}], \"actors\": [\"Nightmare Eclipse\"], \"actor_count\": 1, \"malware\": [\"Click2Shell\"], \"malware_count\": 1, \"cve_max_severity\": \"critical\"}}"

    @Test
    fun decodesTheLivePayload() {
        val obj = ApiJson.json.parseToJsonElement(live).jsonObject
        val counts = ApiJson.json.decodeFromJsonElement(EntryIntelCounts.serializer(), obj.values.single())
        assertEquals(2, counts.cves)
        assertEquals("critical", counts.cveMaxSeverity)
        assertTrue(counts.hasKevCve)
        assertEquals(listOf("Nightmare Eclipse"), counts.actors)
        assertEquals(2, counts.pirMatches.size)
        assertEquals("Vulnerability Exploitation & Weaponization", counts.pirMatches[0].title)
        assertEquals("actionable_gap", counts.detectionOpportunity)
    }

    @Test
    fun cuesFollowTheWebBadges() {
        val obj = ApiJson.json.parseToJsonElement(live).jsonObject
        val counts = ApiJson.json.decodeFromJsonElement(EntryIntelCounts.serializer(), obj.values.single())
        // The web's IntelBadges order and wording (EntryReader-*.js, 2026-09-24).
        assertEquals(listOf("Nightmare Eclipse +1", "2 PIR", "2 CVEs", "KEV opportunity"), intelCues(counts).map { it.text })
        assertEquals(2, intelCues(counts)[1].pirs.size)
        assertTrue(intelCues(EntryIntelCounts()).isEmpty())
        assertEquals(listOf("1 note", "3 TTPs", "1 CVE", "2 Rules"),
            intelCues(EntryIntelCounts(cves = 1, ttps = 3, rules = 2, notes = 1)).map { it.text })
        assertEquals(listOf("Qilin"), intelCues(EntryIntelCounts(malware = listOf("Qilin"), malwareCount = 1)).map { it.text })
        assertEquals(listOf("1 CVE", "high-risk opportunity"),
            intelCues(EntryIntelCounts(cves = 1, hasDetectionGap = true, hasHighRiskCve = true)).map { it.text })
        assertEquals(listOf("2 TTPs", "detection opportunity"),
            intelCues(EntryIntelCounts(ttps = 2, hasDetectionGap = true)).map { it.text })
        assertEquals(listOf("2 TTPs", "telemetry gap"),
            intelCues(EntryIntelCounts(ttps = 2, detectionOpportunity = "telemetry_gap")).map { it.text })
    }

    @Test
    fun requestBodyIsABareIdArray() = runTest {
        val server = MockWebServer()
        server.start()
        try {
            val api = Retrofit.Builder().baseUrl(server.url("/"))
                .addConverterFactory(ApiJson.json.asConverterFactory("application/json".toMediaType()))
                .build().create(IntelFeedApi::class.java)
            server.enqueue(MockResponse().setBody("{}").setHeader("Content-Type", "application/json"))
            api.getIntelCounts(listOf("a", "b"))
            val req = server.takeRequest()
            assertEquals("POST", req.method)
            assertEquals("/api/entries/intel-counts", req.path)
            assertEquals("""["a","b"]""", req.body.readUtf8())
        } finally {
            server.shutdown()
        }
    }
}
