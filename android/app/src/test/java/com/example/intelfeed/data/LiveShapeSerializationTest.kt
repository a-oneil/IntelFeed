package com.example.intelfeed.data

import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.EntryNote
import com.example.intelfeed.data.model.Malware
import com.example.intelfeed.data.model.PriorityQueueResponse
import com.example.intelfeed.data.model.SearchEntityItem
import com.example.intelfeed.data.model.ThreadDetail
import com.example.intelfeed.data.model.ThreatActor
import com.example.intelfeed.data.model.UnifiedSearchResponse
import com.example.intelfeed.data.model.Cve
import com.example.intelfeed.data.network.ApiJson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Payload shapes recorded from the live server on 2026-09-22 (trimmed). Each test pins a place
 * where the server differs from docs/api-reference.md or from what the app used to expect.
 */
class LiveShapeSerializationTest {

    private val json = ApiJson.json

    @Test
    fun threatActorTechniquesComeAsAssociatedTtps() {
        val actor = json.decodeFromString<ThreatActor>(
            """{ "id": "a", "name": "Qilin", "motivation": "financial", "actor_type": "ransomware",
                 "associated_ttps": [ { "count": 19, "tactic": "execution", "technique_id": "T1204.004", "technique_name": "Malicious Copy and Paste" } ] }"""
        )
        assertEquals(1, actor.ttps.size)
        assertEquals("T1204.004", actor.ttps[0].techniqueId)
        assertEquals("ransomware", actor.actorType)
    }

    @Test
    fun malwareTypeIsASingleString() {
        val m = json.decodeFromString<Malware>(
            """{ "id": "m", "name": "Elise", "malware_type": "backdoor", "mitre_id": "S0081",
                 "associated_actors": [ { "id": "x", "name": "Lotus Blossom", "count": 1, "country": "China" } ] }"""
        )
        assertEquals("backdoor", m.typeLabel)
        assertEquals("Lotus Blossom", m.associatedActors.single().name)
    }

    @Test
    fun malwareWithBareStringAssociatedActors() {
        // As returned by live backend for newly reported families like CLOSEDQUORUM and LAMEHUG
        val m = json.decodeFromString<Malware>(
            """{ "id": "m2", "name": "CLOSEDQUORUM", "malware_type": null, "malware_types": ["Backdoor"],
                 "associated_actors": ["Cisco Talos"], "targeted_sectors": ["Defense", "Government"],
                 "aliases": ["CQ-Backdoor"] }"""
        )
        assertEquals("Backdoor", m.typeLabel)
        assertEquals(1, m.associatedActors.size)
        assertEquals("Cisco Talos", m.associatedActors[0].name)
        assertEquals(listOf("Defense", "Government"), m.targetedSectors)
        assertEquals(listOf("CQ-Backdoor"), m.aliases)
    }

    @Test
    fun malwareWithNullOrPrimitiveAssociatedActors() {
        val withNull = json.decodeFromString<Malware>(
            """{ "id": "m3", "name": "TestNull", "associated_actors": null }"""
        )
        assertTrue(withNull.associatedActors.isEmpty())

        val withSingleString = json.decodeFromString<Malware>(
            """{ "id": "m4", "name": "TestSingle", "associated_actors": "Lone Actor" }"""
        )
        assertEquals("Lone Actor", withSingleString.associatedActors.single().name)
    }

    @Test
    fun cveTimelineIsIgnoredWhetherListOrObject() {
        val asList = json.decodeFromString<Cve>("""{ "id": "1", "cve_id": "CVE-2026-1", "timeline": [] }""")
        val asObject = json.decodeFromString<Cve>("""{ "id": "1", "cve_id": "CVE-2026-1", "timeline": { "first_seen": "x" }, "is_kev": true }""")
        assertEquals("CVE-2026-1", asList.cveId)
        assertTrue(asObject.isKev)
    }

    @Test
    fun searchHitsSendPublishedAtAsEpochSeconds() {
        val res = json.decodeFromString<UnifiedSearchResponse>(
            """{ "entries": { "hits": [ { "id": "e", "title": "t", "published_at": 1790094767.0 },
                                          { "id": "f", "title": "u", "published_at": 1781692461 } ],
                              "estimatedTotalHits": 1250, "facetDistribution": null },
                 "entities": { "items": [], "counts": {} },
                 "parsed_filters": [ { "field": "threat_actor", "value": "Qilin", "exact": true, "negated": false, "raw": "threat_actor:\"Qilin\"" } ],
                 "did_you_mean": null, "unknown_fields": [] }"""
        )
        assertEquals("1790094767.0", res.entries.hits[0].publishedAt)
        assertEquals("1781692461", res.entries.hits[1].publishedAt)
        assertEquals(1250, res.entries.estimatedTotalHits)
        assertEquals("threat_actor", res.parsedFilters.single().field)
    }

    @Test
    fun searchHitTagsAreBareStrings() {
        val res = json.decodeFromString<UnifiedSearchResponse>(
            """{ "entries": { "hits": [ { "id": "e", "title": "t", "tags": ["morning-brief", ""] },
                                          { "id": "f", "title": "u", "tags": [ { "name": "critical-cve", "color": "#8B5CF6" } ] } ],
                              "estimatedTotalHits": 2 } }"""
        )
        assertEquals(listOf("morning-brief"), res.entries.hits[0].tags.map { it.name })
        assertEquals("#8B5CF6", res.entries.hits[1].tags.single().color)
    }

    @Test
    fun searchNotesUseTitleNotName() {
        val note = json.decodeFromString<SearchEntityItem>(
            """{ "id": "n", "type": "note", "note_source": "note", "title": "Fortibleed", "entry_id": "e1", "entry_title": "DEW #147" }"""
        )
        assertTrue(note.isNote)
        assertEquals("Fortibleed", note.displayName)
        val entityNote = json.decodeFromString<SearchEntityItem>(
            """{ "id": "n2", "type": "note", "note_source": "entity_note", "entity_type": "cve", "entity_id": "c", "entity_name": "CVE-2026-20262" }"""
        )
        // type wins over entity_type (which names the note's subject).
        assertEquals("note", entityNote.displayType)
        assertEquals("Note on CVE-2026-20262", entityNote.displayName)
    }

    @Test
    fun searchCveFallsBackToCveIdOrIdNotUntitled() {
        val withCveId = json.decodeFromString<SearchEntityItem>(
            """{ "id": "uuid-123", "cve_id": "CVE-2026-352739", "type": "cve" }"""
        )
        assertEquals("CVE-2026-352739", withCveId.displayName)

        val withIdOnly = json.decodeFromString<SearchEntityItem>(
            """{ "id": "CVE-2026-352739", "type": "cve" }"""
        )
        assertEquals("CVE-2026-352739", withIdOnly.displayName)
    }

    @Test
    fun searchTechniqueFallsBackToTechniqueId() {
        val tech = json.decodeFromString<SearchEntityItem>(
            """{ "id": "ttp-1", "technique_id": "T1059.001", "type": "ttp" }"""
        )
        assertEquals("T1059.001", tech.displayName)
    }

    @Test
    fun notesStoreTheirBodyInContentMarkdown() {
        val notes = json.decodeFromString<List<EntryNote>>(
            """[ { "id": "1", "created_by": "u1", "entry_id": null, "title": "Fortibleed",
                   "content_markdown": "<p>body</p>", "content_html": "<p>body</p>", "tags": [], "is_pinned": true,
                   "creator_username": "aoneil", "updated_at": "2026-07-07T20:57:15Z" } ]"""
        )
        assertEquals("<p>body</p>", notes[0].contentMarkdown)
        assertTrue(notes[0].isPinned)
        assertEquals("aoneil", notes[0].creatorUsername)
    }

    @Test
    fun priorityQueueStoryRows() {
        val pq = json.decodeFromString<PriorityQueueResponse>(
            """{ "items": [ { "kind": "thread", "score": 6.57, "entry": null,
                 "thread": { "id": "t", "slug": "eviltokens", "title": "EvilTokens", "source_count": 6, "unread_count": 2,
                             "key_entities": [ { "entity_type": "tool", "entity_id": "x", "label": "EvilTokens", "count": 6 } ],
                             "entry_ids": ["a","b"] },
                 "absorbed_entry_ids": ["a","b"] } ],
                 "next_cursor": null, "has_more": false, "radar_threshold": 1.75 }"""
        )
        val thread = pq.items.single().thread!!
        assertEquals("eviltokens", thread.slug)
        assertEquals("EvilTokens", thread.keyEntities.single().label)
        assertFalse(pq.hasMore)
    }

    @Test
    fun threadDetail() {
        val t = json.decodeFromString<ThreadDetail>(
            """{ "slug": "s", "title": "T", "source_count": 6,
                 "beats": [ { "position": 0, "kind": "first_disclosure", "headline": "H", "lead_entry_id": "e", "is_ai": false } ],
                 "members": [ { "entry_id": "e", "title": "M", "published_at": "2026-09-22T15:00:00Z", "role": "origin", "similarity": 1.0, "is_read": true } ],
                 "thread_yield": { "techniques": 0, "cves": 0, "products": 10, "rules": 0, "echoes_folded": 0 },
                 "nearest": [ { "slug": "n", "title": "N", "status": "dormant", "entry_count": 10, "similarity": 0.86 } ] }"""
        )
        assertEquals("first_disclosure", t.beats.single().kind)
        assertEquals("origin", t.members.single().role)
        assertEquals(10, t.threadYield!!.products)
        assertEquals("n", t.nearest.single().slug)
    }

    @Test
    fun entryListCarriesSignalsAndEcho() {
        val e = json.decodeFromString<EntryItem>(
            """{ "id": "e", "title": "t", "priority_score": 8.78, "is_echo": true,
                 "top_signals": [ { "type": "novel_entity", "explanation": "First mention" } ] }"""
        )
        assertTrue(e.isEcho)
        assertEquals("novel_entity", e.topSignals.single().type)
        assertNull(e.thread)
    }
}
