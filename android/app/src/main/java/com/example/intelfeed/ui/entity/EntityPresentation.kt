package com.example.intelfeed.ui.entity

import android.net.Uri
import com.example.intelfeed.data.model.Campaign
import com.example.intelfeed.data.model.Country
import com.example.intelfeed.data.model.Cve
import com.example.intelfeed.data.model.Cwe
import com.example.intelfeed.data.model.DetectionRule
import com.example.intelfeed.data.model.EntityTtpRef
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.Malware
import com.example.intelfeed.data.model.Mitigation
import com.example.intelfeed.data.model.ObservableItem
import com.example.intelfeed.data.model.Product
import com.example.intelfeed.data.model.ThreatActor
import com.example.intelfeed.data.model.Tool
import com.example.intelfeed.data.model.Ttp
import com.example.intelfeed.data.model.Vendor
import com.example.intelfeed.util.HtmlText
import java.util.Locale

// UI models shared by the Workbench lists and the entity profile. Every entity type maps onto the
// same few shapes, so both screens render one layout instead of a branch per type.

enum class Tone { NEUTRAL, INFO, SUCCESS, WARNING, DANGER, CRITICAL, ACCENT }

data class Badge(val label: String, val tone: Tone = Tone.NEUTRAL, val ruleFormat: String? = null)

/** A tappable reference to another entity. */
data class EntityRef(val type: EntityType, val id: String, val name: String)

data class ExternalLink(val label: String, val url: String)

data class ProfileChip(val label: String, val ref: EntityRef? = null, val tone: Tone = Tone.NEUTRAL, val colorKey: String? = null)


data class ChipGroup(val title: String, val chips: List<ProfileChip>)

data class WorkbenchItem(
    val ref: EntityRef,
    val title: String,
    val monospaceTitle: Boolean = false,
    val subtitle: String? = null,
    val description: String? = null,
    val badges: List<Badge> = emptyList(),
    val articleCount: Int? = null
)

data class EntityProfile(
    val ref: EntityRef,
    val title: String,
    /**
     * The row id the watchlist, relationships and entity notes use. Differs from ref.id for CVEs and
     * techniques, which are opened by their public identifier (CVE-2024-1234, T1059).
     */
    val serverId: String = ref.id,
    val monospaceTitle: Boolean = false,
    val subtitle: String? = null,
    val aliases: List<String> = emptyList(),
    val description: String? = null,
    val badges: List<Badge> = emptyList(),
    /** Label/value rows, e.g. "First seen" / "Mar 5, 2026". */
    val facts: List<Pair<String, String>> = emptyList(),
    val chipGroups: List<ChipGroup> = emptyList(),
    val techniques: List<EntityTtpRef> = emptyList(),
    /** Titled prose blocks, e.g. a technique's detection guidance. */
    val sections: List<Pair<String, String>> = emptyList(),
    /** Detection rule body, shown as copyable code. */
    val code: String? = null,
    val links: List<ExternalLink> = emptyList(),
    val articleCount: Int = 0,
    /** Name used for the Articles tab search (the CVE id for CVEs, the ATT&CK id for techniques). */
    val searchName: String = title,
    /**
     * True when the server has no record for this entity (EntityViewModel's fallback). It has no
     * server id, so only the overview and the Articles search are shown: watch/mute, notes,
     * relationships and the timeline would read or write under a made-up id.
     */
    val placeholder: Boolean = false,
    /** Detection rules: the article the rule came from. */
    val sourceEntryId: String? = null
)

// ---- Shared helpers ----

fun severityTone(severity: String?): Tone = when (severity?.lowercase()) {
    "critical" -> Tone.CRITICAL
    "high" -> Tone.DANGER
    "medium" -> Tone.WARNING
    "low" -> Tone.SUCCESS
    else -> Tone.NEUTRAL
}

fun cvssTone(score: Double?): Tone = when {
    score == null -> Tone.NEUTRAL
    score >= 9.0 -> Tone.CRITICAL
    score >= 7.0 -> Tone.DANGER
    score >= 4.0 -> Tone.WARNING
    else -> Tone.SUCCESS
}

private fun String.humanize(): String =
    replace('_', ' ').replace('-', ' ').trim().replaceFirstChar { it.titlecase(Locale.US) }

private fun formatPercent(value: Double): String = String.format(Locale.US, "%.1f%%", value * 100)

private fun day(iso: String?): String? = iso?.takeIf { it.length >= 10 }?.take(10)

private fun count(n: Int, noun: String): String = if (n == 1) "1 $noun" else "$n ${noun}s"

private fun encode(s: String): String = Uri.encode(s)

private fun seenFacts(first: String?, last: String?): List<Pair<String, String>> = buildList {
    day(first)?.let { add("First seen" to it) }
    day(last)?.let { add("Last seen" to it) }
}

// ---- Workbench rows ----

fun ThreatActor.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.THREAT_ACTOR, id, name),
    title = name,
    subtitle = aliases.take(3).joinToString(", ").ifBlank { null },
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(
        country?.let { Badge(it, Tone.INFO) },
        (actorType ?: motivation)?.let { Badge(it.humanize()) }
    ),
    articleCount = articleCount
)

fun Malware.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.MALWARE, id, name),
    title = name,
    subtitle = aliases.take(3).joinToString(", ").ifBlank { null },
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(typeLabel?.let { Badge(it.humanize(), Tone.ACCENT) }),
    articleCount = articleCount
)

fun Cve.toWorkbenchItem(): WorkbenchItem {
    val score = cvssScore?.toDoubleOrNull()
    return WorkbenchItem(
        ref = EntityRef(EntityType.CVE, cveId, cveId),
        title = cveId,
        monospaceTitle = true,
        description = HtmlText.cleanAiArtifacts(description),
        badges = listOfNotNull(
            if (isKev) Badge("KEV", Tone.CRITICAL) else null,
            score?.let { Badge("CVSS $cvssScore", cvssTone(it)) },
            epssScore?.takeIf { it >= 0.01 }?.let { Badge("EPSS ${formatPercent(it)}", Tone.ACCENT) }
        ),
        articleCount = articleCount
    )
}

fun Ttp.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.TTP, techniqueId, techniqueId),
    title = "$techniqueId  ${techniqueName.orEmpty()}".trim(),
    description = description,
    badges = listOfNotNull(tactic?.let { Badge(it.humanize(), Tone.WARNING) }),
    articleCount = articleCount
)

fun Tool.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.TOOL, id, name),
    title = name,
    subtitle = aliases.take(3).joinToString(", ").ifBlank { null },
    description = description,
    badges = listOfNotNull(toolType?.let { Badge(it.humanize(), Tone.ACCENT) }),
    articleCount = articleCount
)

fun Vendor.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.VENDOR, id, name),
    title = name,
    description = description,
    badges = listOfNotNull(vendorType?.let { Badge(it.humanize()) }),
    articleCount = articleCount
)

fun Product.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.PRODUCT, id, name),
    title = name,
    subtitle = vendorName,
    description = description,
    badges = listOfNotNull(productType?.let { Badge(it.humanize()) }),
    articleCount = articleCount
)

fun Country.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.COUNTRY, id, name),
    title = name,
    subtitle = region,
    description = description,
    badges = listOfNotNull(isoCode?.let { Badge(it, Tone.INFO) }),
    articleCount = articleCount
)

fun Mitigation.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.MITIGATION, id, name),
    title = name,
    description = description,
    badges = listOfNotNull(mitreId?.let { Badge(it, Tone.INFO) }),
    articleCount = articleCount
)

fun DetectionRule.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.RULE, id, title),
    title = title,
    subtitle = listOfNotNull(sourceRepo, sourceAuthor?.let { "by $it" }).joinToString(" · ").ifBlank { null },
    description = description,
    badges = listOfNotNull(
        Badge(ruleType.uppercase(Locale.US), Tone.INFO, ruleFormat = ruleType),
        severity?.let { Badge(it.uppercase(Locale.US), severityTone(it)) },
        if (isDraft) Badge("Draft") else null
    )
)


fun Campaign.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.CAMPAIGN, id, name),
    title = name,
    subtitle = threatActors.joinToString(", ") { it.name }.ifBlank { null },
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(status?.let { Badge(it.humanize(), if (it.lowercase() in setOf("active", "ongoing")) Tone.SUCCESS else Tone.NEUTRAL) }),
    articleCount = effectiveCount
)

fun Cwe.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.WEAKNESS, cweId, displayTitle),
    title = displayTitle,
    description = HtmlText.cleanAiArtifacts(description ?: extendedDescription),
    badges = listOfNotNull(
        likelihoodOfExploit?.let { Badge(it.humanize(), Tone.WARNING) }
    ),
    articleCount = articleCount
)

fun ObservableItem.toWorkbenchItem() = WorkbenchItem(
    ref = EntityRef(EntityType.OBSERVABLE, id, value),
    title = value,
    monospaceTitle = true,
    subtitle = listOfNotNull(kindLabel(), role?.takeIf { it.isNotBlank() }?.let { "role: $it" }).joinToString(" · "),
    description = HtmlText.cleanAiArtifacts(description),
    badges = observableBadges(),
    articleCount = articleCount
)

/** "DOMAIN", "IPV4"… as the web shows the kind; "Observable" when the server didn't say. */
private fun ObservableItem.kindLabel(): String =
    kind?.takeIf { it.isNotBlank() }?.uppercase(Locale.US) ?: "Observable"

/** The web profile's signal badges: confidence, a non-active status, and dual-use infrastructure. */
private fun ObservableItem.observableBadges(): List<Badge> = listOfNotNull(
    currentConfidence?.let { c ->
        val tone = when { c >= 0.5 -> Tone.SUCCESS; c >= 0.15 -> Tone.WARNING; else -> Tone.NEUTRAL }
        Badge("Confidence ${Math.round(c * 100)}%", tone)
    },
    status?.takeIf { it.isNotBlank() && !it.equals("active", ignoreCase = true) }?.let { Badge(it.humanize(), Tone.WARNING) },
    infraTag?.takeIf { it.isNotBlank() }?.let { Badge("Dual-use", Tone.WARNING) }
)

// ---- Profiles ----

fun ThreatActor.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.THREAT_ACTOR, id, name),
    title = name,
    subtitle = EntityType.THREAT_ACTOR.label,
    aliases = aliases,
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(
        motivation?.let { Badge(it.humanize(), Tone.INFO) },
        actorType?.let { Badge(it.humanize(), Tone.ACCENT) },
        country?.let { Badge(it) },
        mitreId?.let { Badge("MITRE $it") }
    ),
    facts = seenFacts(firstSeenAt, lastSeenAt),
    chipGroups = listOfNotNull(
        targetedSectors.takeIf { it.isNotEmpty() }?.let { s -> ChipGroup("Targeted sectors", s.map { ProfileChip(it, colorKey = "sector") }) }
    ),
    techniques = ttps.sortedByDescending { it.count },
    links = listOfNotNull(
        mitreId?.let { ExternalLink("MITRE ATT&CK", "https://attack.mitre.org/groups/$it/") },
        ExternalLink("Malpedia", "https://malpedia.caad.fkie.fraunhofer.de/search?q=${encode(name)}"),
        wikipediaUrl?.let { ExternalLink("Wikipedia", it) }
    ),
    articleCount = articleCount
)

fun Malware.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.MALWARE, id, name),
    title = name,
    subtitle = EntityType.MALWARE.label,
    aliases = aliases,
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(typeLabel?.let { Badge(it.humanize(), Tone.ACCENT) }, mitreId?.let { Badge("MITRE $it") }),
    facts = seenFacts(firstSeenAt, lastSeenAt),
    chipGroups = listOfNotNull(
        associatedActors.takeIf { it.isNotEmpty() }?.let { actors ->
            ChipGroup("Used by", actors.sortedByDescending { it.count }.take(20).map { a ->
                ProfileChip(a.name, a.id?.let { EntityRef(EntityType.THREAT_ACTOR, it, a.name) })
            })
        },
        targetedSectors.takeIf { it.isNotEmpty() }?.let { s -> ChipGroup("Targeted sectors", s.map { ProfileChip(it, colorKey = "sector") }) }
    ),

    links = listOfNotNull(
        mitreId?.let { ExternalLink("MITRE ATT&CK", "https://attack.mitre.org/software/$it/") },
        malpediaUrl?.let { ExternalLink("Malpedia", it) },
        ExternalLink("MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search=signature%3A${encode(name)}"),
        wikipediaUrl?.let { ExternalLink("Wikipedia", it) }
    ),
    articleCount = articleCount
)

fun Cve.toProfile(): EntityProfile {
    val score = cvssScore?.toDoubleOrNull()
    return EntityProfile(
        ref = EntityRef(EntityType.CVE, cveId, cveId),
        title = cveId,
        serverId = id,
        monospaceTitle = true,
        subtitle = EntityType.CVE.label,
        description = HtmlText.cleanAiArtifacts(description),
        badges = listOfNotNull(
            if (isKev) Badge("Known exploited (KEV)", Tone.CRITICAL) else null,
            severity?.let { Badge(it.uppercase(Locale.US), severityTone(it)) },
            when (exploitAvailability?.lowercase()) {
                "active_exploitation" -> Badge("Exploited in the wild", Tone.CRITICAL)
                "weaponized" -> Badge("Weaponized exploit", Tone.DANGER)
                "poc" -> Badge("Proof of concept", Tone.WARNING)
                else -> null
            }
        ),
        facts = buildList {
            score?.let { add("CVSS" to "$cvssScore") }
            epssScore?.let { e ->
                add("EPSS" to formatPercent(e) + (epssPercentile?.let { " (higher than ${formatPercent(it)} of CVEs)" } ?: ""))
            }
            day(kevDateAdded)?.let { add("Added to KEV" to it) }
            day(kevDueDate)?.let { add("KEV remediation due" to it) }
            githubPocCount?.takeIf { it > 0 }?.let { add("Public PoCs on GitHub" to "$it") }
            metasploitModule?.let { add("Metasploit module" to it) }
            day(firstSeenAt)?.let { add("First seen" to it) }
        },
        links = listOfNotNull(
            ExternalLink("NVD", "https://nvd.nist.gov/vuln/detail/${encode(cveId)}"),
            ExternalLink("CVE.org", "https://www.cve.org/CVERecord?id=${encode(cveId)}"),
            if (isKev) ExternalLink("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encode(cveId)}") else null,
            ExternalLink("GitHub PoCs", "https://github.com/search?q=${encode(cveId)}&type=repositories")
        ),
        articleCount = articleCount,
        searchName = cveId
    )
}

fun Ttp.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.TTP, techniqueId, techniqueId),
    title = techniqueName ?: techniqueId,
    serverId = id,
    subtitle = "ATT&CK $techniqueId",
    description = HtmlText.cleanAiArtifacts(description),
    badges = (tactics.ifEmpty { listOfNotNull(tactic) }).map { Badge(it.humanize(), Tone.WARNING) } +
        listOfNotNull(if (isSubtechnique) Badge("Sub-technique") else null),
    chipGroups = listOfNotNull(
        platforms.takeIf { it.isNotEmpty() }?.let { p -> ChipGroup("Platforms", p.map { ProfileChip(it) }) },
        dataSources.takeIf { it.isNotEmpty() }?.let { d -> ChipGroup("Data sources", d.map { ProfileChip(it) }) },
        parentTechniqueId?.let { ChipGroup("Parent technique", listOf(ProfileChip(it, EntityRef(EntityType.TTP, it, it)))) }
    ),
    sections = listOfNotNull(detection?.takeIf { it.isNotBlank() }?.let { "How to detect it" to it }),
    links = listOfNotNull(
        ExternalLink("MITRE ATT&CK", mitreUrl ?: "https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/")
    ),
    articleCount = articleCount,
    searchName = techniqueId
)

fun Tool.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.TOOL, id, name),
    title = name,
    subtitle = EntityType.TOOL.label,
    aliases = aliases,
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(toolType?.let { Badge(it.humanize(), Tone.ACCENT) }, mitreId?.let { Badge("MITRE $it") }),
    facts = seenFacts(firstSeenAt, lastSeenAt),
    chipGroups = listOfNotNull(platforms.takeIf { it.isNotEmpty() }?.let { p -> ChipGroup("Platforms", p.map { ProfileChip(it) }) }),
    links = listOfNotNull(
        mitreId?.let { ExternalLink("MITRE ATT&CK", "https://attack.mitre.org/software/$it/") },
        githubUrl?.let { ExternalLink("GitHub", it) },
        malpediaUrl?.let { ExternalLink("Malpedia", it) },
        wikipediaUrl?.let { ExternalLink("Wikipedia", it) }
    ),
    articleCount = articleCount
)

fun Vendor.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.VENDOR, id, name),
    title = name,
    subtitle = EntityType.VENDOR.label,
    aliases = aliases,
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(vendorType?.let { Badge(it.humanize()) }),
    facts = seenFacts(firstSeenAt, lastSeenAt),
    links = listOfNotNull(website?.let { ExternalLink("Website", it) }, wikipediaUrl?.let { ExternalLink("Wikipedia", it) }),
    articleCount = articleCount
)

fun Product.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.PRODUCT, id, name),
    title = name,
    subtitle = listOfNotNull(EntityType.PRODUCT.label, vendorName).joinToString(" · "),
    aliases = aliases,
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(productType?.let { Badge(it.humanize()) }),
    facts = seenFacts(firstSeenAt, lastSeenAt),
    chipGroups = listOfNotNull(
        if (vendorId != null && vendorName != null) ChipGroup("Vendor", listOf(ProfileChip(vendorName, EntityRef(EntityType.VENDOR, vendorId, vendorName)))) else null
    ),
    links = listOfNotNull(website?.let { ExternalLink("Website", it) }, wikipediaUrl?.let { ExternalLink("Wikipedia", it) }),
    articleCount = articleCount
)

fun Country.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.COUNTRY, id, name),
    title = name,
    subtitle = listOfNotNull(EntityType.COUNTRY.label, region).joinToString(" · "),
    aliases = aliases,
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(isoCode?.let { Badge(it, Tone.INFO) }),
    facts = seenFacts(firstSeenAt, lastSeenAt) +
        listOfNotNull(targetingActorCount.takeIf { it > 0 }?.let { "Actors targeting it" to "$it" }),
    links = listOfNotNull(wikipediaUrl?.let { ExternalLink("Wikipedia", it) }),
    articleCount = articleCount
)

fun Mitigation.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.MITIGATION, id, name),
    title = name,
    subtitle = listOfNotNull(EntityType.MITIGATION.label, mitreId).joinToString(" · "),
    description = HtmlText.cleanAiArtifacts(description),
    facts = seenFacts(firstSeenAt, lastSeenAt),
    links = listOfNotNull(mitreUrl?.let { ExternalLink("MITRE ATT&CK", it) }),
    articleCount = articleCount
)

fun DetectionRule.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.RULE, id, title),
    title = title,
    subtitle = "${ruleType.uppercase(Locale.US)} rule",
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(
        Badge(ruleType.uppercase(Locale.US), Tone.INFO, ruleFormat = ruleType),
        severity?.let { Badge(it.uppercase(Locale.US), severityTone(it)) },
        if (isDraft) Badge("Draft") else null
    ),

    facts = buildList {
        sourceRepo?.let { add("Repository" to it) }
        sourceAuthor?.let { add("Author" to it) }
        license?.let { add("License" to it) }
        day(updatedAt)?.let { add("Updated" to it) }
    },
    chipGroups = listOfNotNull(
        mitreTactics.takeIf { it.isNotEmpty() }?.let { t -> ChipGroup("ATT&CK tactics", t.map { ProfileChip(it.humanize(), tone = Tone.WARNING) }) },
        dataSources.takeIf { it.isNotEmpty() }?.let { d -> ChipGroup("Data sources", d.map { ProfileChip(it) }) },
        tags.takeIf { it.isNotEmpty() }?.let { t -> ChipGroup("Tags", t.map { ProfileChip("#$it") }) }
    ),
    code = displayContent.ifBlank { null },
    links = listOfNotNull(entryUrl?.let { ExternalLink("Rule source", it) }),
    sourceEntryId = entryId
)

fun Campaign.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.CAMPAIGN, id, name),
    title = name,
    subtitle = EntityType.CAMPAIGN.label,
    description = HtmlText.cleanAiArtifacts(description),
    badges = listOfNotNull(status?.let { Badge(it.humanize(), if (it.lowercase() in setOf("active", "ongoing")) Tone.SUCCESS else Tone.NEUTRAL) }),
    facts = listOfNotNull(
        if (startDate != null || endDate != null) "Active" to "${day(startDate) ?: "?"} – ${day(endDate) ?: "present"}" else null
    ),
    chipGroups = listOfNotNull(
        threatActors.takeIf { it.isNotEmpty() }?.let { a ->
            ChipGroup("Attributed actors", a.map { ProfileChip(it.name, it.id?.let { id -> EntityRef(EntityType.THREAT_ACTOR, id, it.name) }) })
        },
        malware.takeIf { it.isNotEmpty() }?.let { m ->
            ChipGroup("Malware", m.map { ProfileChip(it.name, it.id?.let { id -> EntityRef(EntityType.MALWARE, id, it.name) }) })
        }
    ),
    articleCount = effectiveCount
)

fun Cwe.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.WEAKNESS, cweId, displayTitle),
    title = displayTitle,
    // Opened by its public id (CWE-416), like CVEs: the timeline, relationships and notes take the
    // row id (the website's profile route does too). The server rejected the timeline requests with
    // "CWE-416" (400/422), and the Articles tab searched the display title and found nothing.
    serverId = id,
    subtitle = "Weakness (CWE)",
    description = HtmlText.cleanAiArtifacts(description ?: extendedDescription),
    badges = listOfNotNull(
        likelihoodOfExploit?.let { Badge("Likelihood: ${it.humanize()}", Tone.WARNING) }
    ),
    sections = listOfNotNull(
        extendedDescription?.takeIf { !description.isNullOrBlank() && it != description }?.let { "Extended Description" to it }
    ),
    links = listOfNotNull(
        url?.let { ExternalLink("CWE Details", it) } ?: ExternalLink("MITRE CWE", "https://cwe.mitre.org/data/definitions/${cweId.removePrefix("CWE-").removePrefix("cwe-")}.html")
    ),
    articleCount = articleCount,
    searchName = cweId
)

fun ObservableItem.toProfile() = EntityProfile(
    ref = EntityRef(EntityType.OBSERVABLE, id, value),
    title = value,
    monospaceTitle = true,
    subtitle = kind?.takeIf { it.isNotBlank() }?.let { "Observable · ${it.uppercase(Locale.US)}" } ?: "Observable",
    description = HtmlText.cleanAiArtifacts(description),
    badges = observableBadges(),
    // The web profile's provenance panel.
    facts = buildList {
        kind?.takeIf { it.isNotBlank() }?.let { add("Kind" to it.uppercase(Locale.US)) }
        label?.takeIf { it.isNotBlank() && it != value }?.let { add("Label" to it) }
        role?.takeIf { it.isNotBlank() }?.let { add("Role" to it) }
        addAll(seenFacts(firstSeenAt, lastSeenAt))
        createdVia?.takeIf { it.isNotBlank() }?.let { add("Captured by" to it.replace('_', ' ')) }
        infraTag?.takeIf { it.isNotBlank() }?.let { add("Infrastructure" to "${it.replace('_', ' ')} (dual-use, excluded from publishing)") }
        evidence?.takeIf { it.isNotBlank() }?.let { add("Evidence" to it) }
    },
    articleCount = articleCount
)

/** "12 articles" style label, or null when the count is unknown/zero. */
fun articleCountLabel(n: Int?): String? = n?.takeIf { it > 0 }?.let { count(it, "article") }
