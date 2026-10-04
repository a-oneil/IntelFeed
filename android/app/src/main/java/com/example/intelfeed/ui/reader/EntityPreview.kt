package com.example.intelfeed.ui.reader

import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.EntryIntel
import com.example.intelfeed.ui.entity.ExternalLink
import com.example.intelfeed.util.DateUtils
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URLEncoder
import java.util.Locale

/**
 * What the reader shows when a highlighted name is tapped: the web reader's entity popover
 * (EntityPopover), built from the linked-intel rows the reader already has. [value] is the phrase
 * as written in the article; the popover's Search and Copy use it, like the web.
 */
data class EntityPreview(
    val type: EntityType,
    val id: String,
    val name: String,
    val value: String,
    val kev: Boolean = false,
    val severity: String? = null,
    val imageUrl: String? = null,
    val facts: List<Pair<String, String>> = emptyList(),
    val description: String? = null,
    val artifacts: List<Pair<String, String>> = emptyList(),
    val links: List<ExternalLink> = emptyList()
)

object EntityPreviews {

    /** Builds the popover for the tapped entity; null when it isn't in [intel] (shouldn't happen). */
    fun build(intel: EntryIntel?, type: EntityType, id: String, name: String, value: String): EntityPreview? {
        intel ?: return null
        fun seen(at: String?) = at?.let { DateUtils.formatRelativeTime(it) }?.takeIf { it.isNotBlank() }
        fun common(articleCount: Int?, firstSeen: String?, aliases: List<String>) = buildList {
            articleCount?.let { add("Articles" to "$it") }
            seen(firstSeen)?.let { add("First seen" to it) }
            aliases.filterNot { it.equals(value, ignoreCase = true) }.take(6).takeIf { it.isNotEmpty() }
                ?.let { add("Also known as" to it.joinToString(", ")) }
        }
        fun links(vararg pairs: Pair<String, String?>) = pairs.mapNotNull { (label, url) -> url?.takeIf { it.isNotBlank() }?.let { ExternalLink(label, it) } }

        return when (type) {
            EntityType.CVE -> intel.cves.firstOrNull { it.cveId == id || it.id == id }?.let { c ->
                val epss = c.epssScore
                val poc = listOfNotNull(c.githubPocCount?.takeIf { it > 0 }?.let { "$it GitHub" }, c.metasploitModule?.takeIf { it.isNotBlank() }?.let { "Metasploit" })
                EntityPreview(
                    type, id, name, value,
                    kev = c.isKev,
                    severity = c.severity,
                    facts = buildList {
                        c.cvssScore?.let { add("CVSS" to it) }
                        // The web shows one decimal below 10 %, none above.
                        epss?.let { add("EPSS" to String.format(Locale.US, if (it < 0.1) "%.1f%%" else "%.0f%%", it * 100)) }
                        if (poc.isNotEmpty()) add("PoC" to poc.joinToString(" · "))
                        c.exploitStatus?.takeIf { it.isNotBlank() }?.let { add("Exploit" to it) }
                        add("First seen" to (seen(c.firstSeenAt) ?: "—"))
                        add("Articles" to "${c.articleCount}")
                    },
                    description = c.description?.let { cut(it, 120) },
                    links = cveLinks(c.cveId)
                )
            }
            EntityType.TTP -> intel.ttps.firstOrNull { it.techniqueId == id || it.id == id }?.let { t ->
                EntityPreview(
                    type, id, name, value,
                    facts = buildList {
                        add("Technique" to t.techniqueId)
                        t.tactic?.let { add("Tactic" to it) }
                        add("First seen" to (seen(t.firstSeenAt) ?: "—"))
                        add("Articles" to "${t.articleCount}")
                    },
                    description = t.description?.let { cut(it, 220) }
                )
            }
            EntityType.THREAT_ACTOR -> intel.threatActors.firstOrNull { it.id == id }?.let { a ->
                EntityPreview(
                    type, id, name, value,
                    imageUrl = a.wikipediaImageUrl,
                    facts = listOfNotNull(
                        a.motivation?.let { "Motivation" to it },
                        a.country?.let { "Origin" to it },
                        a.targetedSectors.takeIf { it.isNotEmpty() }?.let { "Targets" to it.take(3).joinToString(", ") }
                    ) + common(a.articleCount, a.firstSeenAt, a.aliases),
                    description = a.description?.let { cut(it, 220) },
                    links = links("MITRE ATT&CK" to a.mitreId?.let { "https://attack.mitre.org/groups/$it/" }, "Wikipedia" to a.wikipediaUrl)
                )
            }
            EntityType.MALWARE -> intel.malware.firstOrNull { it.id == id }?.let { m ->
                EntityPreview(
                    type, id, name, value,
                    imageUrl = m.wikipediaImageUrl,
                    facts = listOfNotNull(m.typeLabel?.let { "Type" to it }) + common(m.articleCount, m.firstSeenAt, m.aliases),
                    description = m.description?.let { cut(it, 220) },
                    links = links("Malpedia" to m.malpediaUrl, "Wikipedia" to m.wikipediaUrl)
                )
            }
            EntityType.VENDOR -> intel.vendors.firstOrNull { it.id == id }?.let { v ->
                EntityPreview(
                    type, id, name, value,
                    imageUrl = v.wikipediaImageUrl,
                    facts = listOfNotNull(v.vendorType?.let { "Type" to it }) + common(v.articleCount, v.firstSeenAt, v.aliases),
                    description = v.description?.let { cut(it, 220) },
                    links = links("Website" to v.website, "Wikipedia" to v.wikipediaUrl)
                )
            }
            EntityType.PRODUCT -> intel.products.firstOrNull { it.id == id }?.let { p ->
                EntityPreview(
                    type, id, name, value,
                    imageUrl = p.wikipediaImageUrl,
                    facts = listOfNotNull(p.vendorName?.let { "Vendor" to it }, p.productType?.let { "Type" to it }) +
                        common(p.articleCount, p.firstSeenAt, p.aliases),
                    description = p.description?.let { cut(it, 220) },
                    links = links("Website" to p.website, "Wikipedia" to p.wikipediaUrl)
                )
            }
            EntityType.TOOL -> intel.tools.firstOrNull { it.id == id }?.let { t ->
                EntityPreview(
                    type, id, name, value,
                    imageUrl = t.wikipediaImageUrl,
                    facts = listOfNotNull(
                        t.toolType?.let { "Type" to it },
                        t.platforms.takeIf { it.isNotEmpty() }?.let { "Platforms" to it.take(3).joinToString(", ") }
                    ) + common(t.articleCount, t.firstSeenAt, t.aliases),
                    description = t.description?.let { cut(it, 220) },
                    artifacts = artifacts(t.detectionArtifacts),
                    links = links("GitHub" to t.githubUrl, "Malpedia" to t.malpediaUrl, "Wikipedia" to t.wikipediaUrl)
                )
            }
            EntityType.COUNTRY -> intel.countries.firstOrNull { it.id == id }?.let { c ->
                EntityPreview(
                    type, id, name, value,
                    imageUrl = c.wikipediaImageUrl,
                    facts = listOfNotNull(c.region?.let { "Region" to it }) + common(c.articleCount, c.firstSeenAt, c.aliases),
                    description = c.description?.let { cut(it, 220) },
                    links = links("Wikipedia" to c.wikipediaUrl)
                )
            }
            EntityType.MITIGATION -> intel.mitigations.firstOrNull { it.id == id }?.let { m ->
                EntityPreview(
                    type, id, name, value,
                    facts = listOfNotNull(m.mitreId?.let { "MITRE ID" to it }) + common(m.articleCount, m.firstSeenAt, emptyList()),
                    description = m.description?.let { cut(it, 220) },
                    links = links("MITRE ATT&CK" to m.mitreUrl)
                )
            }
            EntityType.WEAKNESS -> intel.cwes.firstOrNull { it.cweId == id || it.id == id }?.let { w ->
                EntityPreview(
                    type, id, name, value,
                    facts = listOfNotNull(
                        w.abstraction?.let { "Abstraction" to it },
                        w.parentCweId?.let { "Parent" to it },
                        w.mappingUsage?.takeIf { it != "Allowed" }?.let { "MITRE mapping" to it },
                        w.likelihoodOfExploit?.let { "Likelihood" to it }
                    ) + common(w.articleCount, w.firstSeenAt, w.alternateTerms),
                    description = (w.description ?: w.extendedDescription)?.let { cut(it, 220) },
                    links = links("MITRE CWE" to (w.cweUrl ?: w.url))
                )
            }
            EntityType.OBSERVABLE -> intel.observables.firstOrNull { it.id == id }?.let { o ->
                EntityPreview(
                    type, id, name, value,
                    facts = buildList {
                        o.kind?.let { add("Kind" to it) }
                        o.role?.takeIf { it.isNotBlank() }?.let { add("Role" to it) }
                        o.currentConfidence?.let {
                            val status = o.status?.takeIf { s -> s.isNotBlank() && s != "active" }?.let { s -> " · $s" }.orEmpty()
                            add("Confidence" to "${Math.round(it * 100)}%$status")
                        }
                        o.sightingCount?.let { add("Sightings" to "$it") }
                        o.createdVia?.let { add("Captured by" to it.replace('_', ' ')) }
                        o.lastSeenAt?.let { DateUtils.parseDate(it) }?.let {
                            add("Last seen" to java.text.SimpleDateFormat("MMM d", Locale.US).format(it))
                        }
                        add("Articles" to "${o.articleCount}")
                        seen(o.firstSeenAt)?.let { add("First seen" to it) }
                    },
                    description = o.description?.let { cut(it, 220) },
                    artifacts = listOfNotNull(o.evidence?.takeIf { it.isNotBlank() }?.let { "evidence" to "“$it”" }),
                    links = observableLinks(o.kind, o.value)
                )
            }
            else -> null
        }
    }

    /** Where the web's CVE popover links (it shows the first four). */
    fun cveLinks(cveId: String): List<ExternalLink> {
        val v = enc(cveId)
        return listOf(
            ExternalLink("CVE.org", "https://www.cve.org/CVERecord?id=$v"),
            ExternalLink("NVD", "https://nvd.nist.gov/vuln/detail/$v"),
            ExternalLink("CVEDetails", "https://www.cvedetails.com/cve/$v/"),
            ExternalLink("MITRE", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=$v")
        )
    }

    /** The web's lookup links for an observable, by kind. */
    fun observableLinks(kind: String?, value: String): List<ExternalLink> {
        val n = enc(value)
        return when (kind?.lowercase()) {
            "ipv4", "ipv6" -> listOf(
                ExternalLink("VirusTotal", "https://www.virustotal.com/gui/ip-address/$n"),
                ExternalLink("Shodan", "https://www.shodan.io/host/$n"),
                ExternalLink("GreyNoise", "https://viz.greynoise.io/ip/$n"),
                ExternalLink("AbuseIPDB", "https://www.abuseipdb.com/check/$n")
            )
            "domain" -> listOf(
                ExternalLink("VirusTotal", "https://www.virustotal.com/gui/domain/$n"),
                ExternalLink("urlscan", "https://urlscan.io/search/#page.domain%3A$n"),
                ExternalLink("Shodan", "https://www.shodan.io/search?query=hostname%3A$n")
            )
            "url" -> listOf(ExternalLink("urlscan", "https://urlscan.io/search/#page.url%3A%22$n%22"))
            "md5", "sha1", "sha256" -> listOf(
                ExternalLink("VirusTotal", "https://www.virustotal.com/gui/file/$n"),
                ExternalLink("MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search=hash%3A$n")
            )
            "ja3", "ja4" -> listOf(ExternalLink("ja4db", "https://ja4db.com/search?q=$n"))
            "cert_fingerprint" -> listOf(ExternalLink("crt.sh", "https://crt.sh/?q=$n"))
            else -> emptyList()
        }
    }

    /** A tool's detection_artifacts map as label/value rows (the web shows up to four). */
    private fun artifacts(element: kotlinx.serialization.json.JsonElement?): List<Pair<String, String>> {
        val obj = element as? JsonObject ?: return emptyList()
        return obj.mapNotNull { (key, v) ->
            val text = when (v) {
                is JsonArray -> v.joinToString(", ") { (it as? JsonPrimitive)?.content ?: it.toString() }
                is JsonPrimitive -> v.content
                is JsonObject -> if (v.isEmpty()) "" else v.toString()
            }
            text.takeIf { it.isNotBlank() && it != "null" && it != "{}" }?.let { key.replace('_', ' ') to cut(it, 90) }
        }.take(4)
    }

    // encodeURIComponent: spaces as %20, not +.
    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    private fun cut(s: String, max: Int): String {
        val clean = s.trim()
        return if (clean.length > max) clean.take(max).trimEnd() + "…" else clean
    }
}
