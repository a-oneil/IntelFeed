package com.example.intelfeed.data.model

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNames
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

// Entity models. The same shapes come back from the list, detail and per-entry endpoints
// (e.g. /api/threat-actors, /api/threat-actors/{id}, /api/entries/{id}/threat-actors).
// Every field has a default so a missing field never fails a whole response.

@Serializable
data class EntityTtpRef(
    val count: Int = 1,
    val tactic: String? = null,
    @SerialName("technique_id") val techniqueId: String? = null,
    @SerialName("technique_name") val techniqueName: String? = null
)

@Serializable
data class AssociatedActor(
    val id: String? = null,
    val name: String = "",
    val count: Int = 0,
    val country: String? = null
)

object FlexibleAssociatedActorListSerializer : KSerializer<List<AssociatedActor>> {
    private val delegate = ListSerializer(AssociatedActor.serializer())
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun deserialize(decoder: Decoder): List<AssociatedActor> {
        val jsonDecoder = decoder as? JsonDecoder ?: return delegate.deserialize(decoder)
        val element = jsonDecoder.decodeJsonElement()
        if (element is JsonPrimitive) {
            val s = element.contentOrNull
            return if (!s.isNullOrBlank()) listOf(AssociatedActor(name = s)) else emptyList()
        }
        val array = element as? JsonArray ?: return emptyList()
        return array.mapNotNull { item ->
            when (item) {
                is JsonPrimitive -> item.contentOrNull?.takeIf { it.isNotBlank() }?.let { AssociatedActor(name = it) }
                is JsonObject -> runCatching { jsonDecoder.json.decodeFromJsonElement(AssociatedActor.serializer(), item) }.getOrNull()
                else -> null
            }
        }
    }

    override fun serialize(encoder: Encoder, value: List<AssociatedActor>) = delegate.serialize(encoder, value)
}

object FlexibleStringListSerializer : KSerializer<List<String>> {
    private val delegate = ListSerializer(String.serializer())
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun deserialize(decoder: Decoder): List<String> {
        val jsonDecoder = decoder as? JsonDecoder ?: return delegate.deserialize(decoder)
        return when (val element = jsonDecoder.decodeJsonElement()) {
            is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.contentOrNull?.takeIf { s -> s.isNotBlank() } }
            is JsonPrimitive -> element.contentOrNull?.takeIf { it.isNotBlank() }?.let { listOf(it) } ?: emptyList()
            else -> emptyList()
        }
    }

    override fun serialize(encoder: Encoder, value: List<String>) = delegate.serialize(encoder, value)
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class ThreatActor(
    val id: String,
    val name: String,
    @Serializable(with = FlexibleStringListSerializer::class) val aliases: List<String> = emptyList(),
    // Per-article endpoints only: the exact phrases the linker found in that article's text.
    @SerialName("matched_names") val matchedNames: List<String> = emptyList(),
    val country: String? = null,
    val description: String? = null,
    @SerialName("confidence_level") val confidenceLevel: String? = null,
    val motivation: String? = null,
    @SerialName("actor_type") val actorType: String? = null,
    @SerialName("mitre_id") val mitreId: String? = null,
    // The server calls this associated_ttps; "ttps" is accepted for older payloads.
    @JsonNames("ttps") @SerialName("associated_ttps") val ttps: List<EntityTtpRef> = emptyList(),
    @Serializable(with = FlexibleStringListSerializer::class) @SerialName("targeted_sectors") val targetedSectors: List<String> = emptyList(),
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("wikipedia_url") val wikipediaUrl: String? = null,
    @SerialName("wikipedia_image_url") val wikipediaImageUrl: String? = null
)

@Serializable
data class Malware(
    val id: String,
    val name: String,
    @Serializable(with = FlexibleStringListSerializer::class) val aliases: List<String> = emptyList(),
    // Per-article endpoints only: the exact phrases the linker found in that article's text.
    @SerialName("matched_names") val matchedNames: List<String> = emptyList(),
    val description: String? = null,
    @Serializable(with = FlexibleStringSerializer::class) @SerialName("malware_type") val malwareType: String? = null,
    @Serializable(with = FlexibleStringListSerializer::class) @SerialName("malware_types") val malwareTypes: List<String> = emptyList(),
    @SerialName("mitre_id") val mitreId: String? = null,
    @SerialName("malpedia_url") val malpediaUrl: String? = null,
    @Serializable(with = FlexibleAssociatedActorListSerializer::class) @SerialName("associated_actors") val associatedActors: List<AssociatedActor> = emptyList(),
    @Serializable(with = FlexibleStringListSerializer::class) @SerialName("targeted_sectors") val targetedSectors: List<String> = emptyList(),
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("wikipedia_url") val wikipediaUrl: String? = null,
    @SerialName("wikipedia_image_url") val wikipediaImageUrl: String? = null
) {
    val typeLabel: String? get() = malwareType ?: malwareTypes.firstOrNull()
}

@Serializable
data class Cve(
    val id: String,
    @SerialName("cve_id") val cveId: String,
    @SerialName("cvss_score") val cvssScore: String? = null,
    val severity: String? = null,
    val description: String? = null,
    @SerialName("is_kev") val isKev: Boolean = false,
    @SerialName("kev_date_added") val kevDateAdded: String? = null,
    @SerialName("kev_due_date") val kevDueDate: String? = null,
    @SerialName("epss_score") val epssScore: Double? = null,
    @SerialName("epss_percentile") val epssPercentile: Double? = null,
    @SerialName("exploit_availability") val exploitAvailability: String? = null,
    @SerialName("github_poc_count") val githubPocCount: Int? = null,
    @SerialName("metasploit_module") val metasploitModule: String? = null,
    @SerialName("exploit_status") val exploitStatus: String? = null,
    @SerialName("risk_tier") val riskTier: String? = null,
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null,
    @SerialName("article_count") val articleCount: Int = 0
    // Not modelled: "timeline" is a list in list responses but an object in per-entry ones.
)

@Serializable
data class Ttp(
    val id: String,
    @SerialName("technique_id") val techniqueId: String,
    @SerialName("technique_name") val techniqueName: String? = null,
    val tactic: String? = null,
    val tactics: List<String> = emptyList(),
    val description: String? = null,
    @SerialName("mitre_url") val mitreUrl: String? = null,
    val platforms: List<String> = emptyList(),
    @SerialName("data_sources") val dataSources: List<String> = emptyList(),
    val detection: String? = null,
    @SerialName("is_subtechnique") val isSubtechnique: Boolean = false,
    @SerialName("parent_technique_id") val parentTechniqueId: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("first_seen_at") val firstSeenAt: String? = null
)

@Serializable
data class Campaign(
    val id: String,
    val name: String,
    val description: String? = null,
    val status: String? = null,
    @SerialName("tlp_marking") val tlpMarking: String? = null,
    @SerialName("start_date") val startDate: String? = null,
    @SerialName("end_date") val endDate: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("entry_count") val entryCount: Int = 0,
    @SerialName("threat_actors") val threatActors: List<ThreatActorEntity> = emptyList(),
    val malware: List<MalwareEntity> = emptyList(),
    @SerialName("created_at") val createdAt: String? = null
) {
    val effectiveCount: Int get() = if (articleCount > 0) articleCount else entryCount
}

@Serializable
data class CreateCampaignRequest(
    val name: String,
    val description: String? = null,
    val status: String? = "active",
    @SerialName("tlp_marking") val tlpMarking: String? = "TLP:GREEN"
)

@Serializable
data class AttachEntryRequest(
    @SerialName("entry_id") val entryId: String
)

/** POST /api/campaigns/{id}/entries/bulk, as the web client sends it. */
@Serializable
data class EntryIdsRequest(
    @SerialName("entry_ids") val entryIds: List<String>
)

@Serializable
data class DetectionRule(
    val id: String,
    val title: String,
    @SerialName("rule_type") val ruleType: String,
    val severity: String? = null,
    val description: String? = null,
    // Only the detail endpoint returns the rule body.
    @SerialName("rule_content") val ruleContent: String? = null,
    @SerialName("content") val content: String? = null,
    val tags: List<String> = emptyList(),
    @SerialName("mitre_tactics") val mitreTactics: List<String> = emptyList(),
    @SerialName("data_sources") val dataSources: List<String> = emptyList(),
    @SerialName("source_repo") val sourceRepo: String? = null,
    @SerialName("source_author") val sourceAuthor: String? = null,
    val license: String? = null,
    @SerialName("is_draft") val isDraft: Boolean = false,
    @SerialName("entry_id") val entryId: String? = null,
    @SerialName("entry_title") val entryTitle: String? = null,
    @SerialName("entry_url") val entryUrl: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
) {
    val displayContent: String get() = ruleContent ?: content ?: ""
}

@Serializable
data class Vendor(
    val id: String,
    val name: String,
    @Serializable(with = FlexibleStringListSerializer::class) val aliases: List<String> = emptyList(),
    // Per-article endpoints only: the exact phrases the linker found in that article's text.
    @SerialName("matched_names") val matchedNames: List<String> = emptyList(),
    val description: String? = null,
    val website: String? = null,
    @SerialName("vendor_type") val vendorType: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("wikipedia_url") val wikipediaUrl: String? = null,
    @SerialName("wikipedia_image_url") val wikipediaImageUrl: String? = null
)

@Serializable
data class Product(
    val id: String,
    val name: String,
    @Serializable(with = FlexibleStringListSerializer::class) val aliases: List<String> = emptyList(),
    // Per-article endpoints only: the exact phrases the linker found in that article's text.
    @SerialName("matched_names") val matchedNames: List<String> = emptyList(),
    val description: String? = null,
    @SerialName("vendor_id") val vendorId: String? = null,
    @SerialName("vendor_name") val vendorName: String? = null,
    @SerialName("product_type") val productType: String? = null,
    val website: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("wikipedia_url") val wikipediaUrl: String? = null,
    @SerialName("wikipedia_image_url") val wikipediaImageUrl: String? = null
)

@Serializable
data class Tool(
    val id: String,
    val name: String,
    @Serializable(with = FlexibleStringListSerializer::class) val aliases: List<String> = emptyList(),
    // Per-article endpoints only: the exact phrases the linker found in that article's text.
    @SerialName("matched_names") val matchedNames: List<String> = emptyList(),
    val description: String? = null,
    @SerialName("tool_type") val toolType: String? = null,
    @Serializable(with = FlexibleStringListSerializer::class) val platforms: List<String> = emptyList(),
    @SerialName("mitre_id") val mitreId: String? = null,
    @SerialName("github_url") val githubUrl: String? = null,
    @SerialName("malpedia_url") val malpediaUrl: String? = null,
    // Free-form map of artifact kind to value(s); shown as "Detection artifacts" in the reader popover.
    @SerialName("detection_artifacts") val detectionArtifacts: kotlinx.serialization.json.JsonElement? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("wikipedia_url") val wikipediaUrl: String? = null,
    @SerialName("wikipedia_image_url") val wikipediaImageUrl: String? = null
)

@Serializable
data class Country(
    val id: String,
    val name: String,
    @SerialName("iso_code") val isoCode: String? = null,
    val aliases: List<String> = emptyList(),
    // Per-article endpoints only: the exact phrases the linker found in that article's text.
    @SerialName("matched_names") val matchedNames: List<String> = emptyList(),
    val region: String? = null,
    val description: String? = null,
    // Only on /api/entries/{id}/countries: origin | target | mentioned | infrastructure.
    val role: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("targeting_actor_count") val targetingActorCount: Int = 0,
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("wikipedia_url") val wikipediaUrl: String? = null,
    @SerialName("wikipedia_image_url") val wikipediaImageUrl: String? = null
)

@Serializable
data class Mitigation(
    val id: String,
    val name: String,
    @SerialName("mitre_id") val mitreId: String? = null,
    val description: String? = null,
    @SerialName("mitre_url") val mitreUrl: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null
)

/** A typed, evidenced link between two entities (GET /api/entity-relationships). */
@Serializable
data class EntityRelationship(
    val id: String,
    @SerialName("source_type") val sourceType: String,
    @SerialName("source_id") val sourceId: String,
    @SerialName("source_name") val sourceName: String? = null,
    @SerialName("target_type") val targetType: String,
    @SerialName("target_id") val targetId: String,
    @SerialName("target_name") val targetName: String? = null,
    @SerialName("relationship_type") val relationshipType: String = "related_to",
    val confidence: String? = null,
    val source: String? = null,
    val description: String? = null,
    @SerialName("evidence_entry_ids") val evidenceEntryIds: List<String> = emptyList()
)

/** Analyst note on an entity (GET/POST /api/entity-notes). Shared across the instance. */
@Serializable
data class EntityNote(
    val id: String,
    val title: String? = null,
    val content: String? = null,
    @SerialName("note_type") val noteType: String? = null,
    val username: String? = null,
    @SerialName("created_by") val createdBy: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
)

@Serializable
data class CreateEntityNoteRequest(
    @SerialName("entity_type") val entityType: String,
    @SerialName("entity_id") val entityId: String,
    val title: String? = null,
    val content: String
)

@Serializable
data class UpdateEntityNoteRequest(
    val title: String? = null,
    val content: String
)

@Serializable
data class Cwe(
    val id: String,
    @SerialName("cwe_id") val cweId: String,
    val name: String? = null,
    val description: String? = null,
    @SerialName("extended_description") val extendedDescription: String? = null,
    @SerialName("likelihood_of_exploit") val likelihoodOfExploit: String? = null,
    @SerialName("article_count") val articleCount: Int = 0,
    val url: String? = null,
    val abstraction: String? = null,
    @SerialName("parent_cwe_id") val parentCweId: String? = null,
    @SerialName("mapping_usage") val mappingUsage: String? = null,
    @SerialName("cwe_url") val cweUrl: String? = null,
    @Serializable(with = FlexibleStringListSerializer::class) @SerialName("alternate_terms") val alternateTerms: List<String> = emptyList(),
    @SerialName("first_seen_at") val firstSeenAt: String? = null
) {
    val displayTitle: String get() = if (!name.isNullOrBlank()) "$cweId: $name" else cweId
}

/**
 * GET /api/observables(/{id}). Field names follow the web client (Workbench columns and the
 * observable profile): the server calls the value's type `kind` (ipv4, domain, url, sha256,
 * cmdline, registry, script, …); there is no `type` or `is_ioc` field.
 */
@Serializable
data class ObservableItem(
    val id: String,
    val value: String,
    // Per-article endpoint only: the value as written in that article (e.g. defanged "evil[.]com").
    @SerialName("surface_form") val surfaceForm: String? = null,
    @SerialName("sighting_count") val sightingCount: Int? = null,
    val kind: String? = null,
    // What the value was doing, e.g. "c2", "delivery", "payload".
    val role: String? = null,
    // A readable name for long values (scripts).
    val label: String? = null,
    val description: String? = null,
    // 0..1; decays with age for network kinds and resets on a new sighting.
    @SerialName("current_confidence") val currentConfidence: Double? = null,
    // Lifecycle state; "active" is the normal one.
    val status: String? = null,
    // Dual-use infrastructure (e.g. a public paste site), excluded from publishing.
    @SerialName("infra_tag") val infraTag: String? = null,
    @SerialName("created_via") val createdVia: String? = null,
    val evidence: String? = null,
    @SerialName("first_seen_at") val firstSeenAt: String? = null,
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
    @SerialName("article_count") val articleCount: Int = 0
)

/**
 * A glossary term found in an article (POST /api/glossary/detect with {"entry_id"}; the web reader
 * calls it for every article it opens). The reader underlines the term and shows its definition.
 */
@Serializable
data class GlossaryMatch(val term: GlossaryTerm)

@Serializable
data class GlossaryTerm(
    val id: String,
    val name: String,
    // A NIST CSF function: govern, identify, protect, detect, respond or recover.
    val category: String = "",
    // Other spellings that also count as this term.
    @Serializable(with = FlexibleStringListSerializer::class) @SerialName("search_terms") val searchTerms: List<String> = emptyList(),
    val description: String? = null,
    val maturity: String? = null,
    val technologies: List<GlossaryTechnology> = emptyList()
)

@Serializable
data class GlossaryTechnology(val name: String = "", val url: String? = null)

@Serializable
data class GlossaryDetectRequest(@SerialName("entry_id") val entryId: String)
