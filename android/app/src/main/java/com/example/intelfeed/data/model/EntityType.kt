package com.example.intelfeed.data.model

/**
 * The entity types the app can open as a profile. [key] is the server's type name (search results,
 * relationships, watchlist, entity notes). [searchField] is the unified-search filter that returns
 * the entity's articles, e.g. threat_actor:"APT29".
 */
enum class EntityType(
    val key: String,
    val label: String,
    val pluralLabel: String,
    val searchField: String?,
    // Types the web app offers Watch/Mute for (EntityActionsMenu).
    val watchable: Boolean
) {
    THREAT_ACTOR("threat_actor", "Threat actor", "Threat actors", "threat_actor", true),
    MALWARE("malware", "Malware", "Malware", "malware", true),
    CVE("cve", "Vulnerability", "Vulnerabilities", "cve", true),
    TTP("ttp", "ATT&CK technique", "Techniques", "ttp", false),
    TOOL("tool", "Tool", "Tools", "tool", true),
    VENDOR("vendor", "Vendor", "Vendors", "vendor", true),
    PRODUCT("product", "Product", "Products", "product", true),
    COUNTRY("country", "Country", "Countries", "country", true),
    CAMPAIGN("campaign", "Campaign", "Campaigns", "campaign", false),
    MITIGATION("mitigation", "Mitigation", "Mitigations", "mitigation", false),
    // The server's type name is "cwe" (docs/data-model.md, the website's profile routes). It was
    // "weakness", so relationships and shared notes for weaknesses never matched the server's.
    WEAKNESS("cwe", "Weakness", "Weaknesses", "cwe", false),
    OBSERVABLE("observable", "Observable", "Observables", "observable", false),
    RULE("rule", "Detection rule", "Detection rules", null, false);

    /**
     * The type's name in the profile timeline paths (/api/entities/{type}/…, /api/intelligence/timeline/{type}/…).
     * Null for types without a timeline.
     */
    val timelinePath: String?
        get() = if (this == RULE) null else key

    /** Unified-search query for this entity's articles, or null if it has none. */
    fun articlesQuery(name: String): String? {
        val field = searchField ?: return null
        val value = name.replace("\"", "")
        return "$field:\"$value\""
    }

    companion object {
        fun fromKey(raw: String?): EntityType? = when (raw?.lowercase()?.replace('-', '_')) {
            "threat_actor", "threat_actors", "actor" -> THREAT_ACTOR
            "malware" -> MALWARE
            "cve", "cves", "vulnerability" -> CVE
            "ttp", "ttps", "technique" -> TTP
            "tool", "tools" -> TOOL
            "vendor", "vendors" -> VENDOR
            "product", "products" -> PRODUCT
            "country", "countries" -> COUNTRY
            "campaign", "campaigns" -> CAMPAIGN
            "mitigation", "mitigations" -> MITIGATION
            "weakness", "weaknesses", "cwe", "cwes" -> WEAKNESS
            "observable", "observables", "ioc", "iocs" -> OBSERVABLE
            "rule", "detection_rule", "detection_rules" -> RULE
            else -> null
        }
    }
}
