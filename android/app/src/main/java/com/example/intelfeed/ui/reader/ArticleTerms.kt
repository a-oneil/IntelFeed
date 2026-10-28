package com.example.intelfeed.ui.reader

import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.EntryIntel
import com.example.intelfeed.data.model.GlossaryMatch
import com.example.intelfeed.data.model.PirMatch
import com.example.intelfeed.util.ArticleHtml.SpanKind
import com.example.intelfeed.util.ArticleLinker.Term

/** The web reader skips observable highlighting when an article has more than this many. */
const val MAX_HIGHLIGHTED_OBSERVABLES = 200

/**
 * The phrases to mark for an article's linked entities, built exactly as the web reader builds
 * them, in its order (on the same phrase the last one wins):
 * CVE ids; technique ids and names; then threat actors, malware, countries, vendors, products and
 * tools, each by its `matched_names` (the phrases the server's linker found in this article) or,
 * without those, its name and aliases; CWE ids; mitigation names and ATT&CK ids; observables
 * (value, and the article's own spelling when it differs), only when there are at most 200.
 *
 * [Term.entityId] is what opens the profile in the app: the CVE, technique and CWE identifiers,
 * and the row id for everything else.
 */
fun entityTerms(intel: EntryIntel): List<Term> = buildList {
    fun term(type: EntityType, id: String, value: String?, name: String) {
        if (!value.isNullOrEmpty()) add(Term(value, SpanKind.ENTITY, type.key, id, name))
    }
    fun named(type: EntityType, id: String, name: String, aliases: List<String>, matched: List<String>) {
        if (matched.isNotEmpty()) matched.forEach { term(type, id, it, name) }
        else (listOf(name) + aliases).forEach { term(type, id, it, name) }
    }

    intel.cves.forEach { term(EntityType.CVE, it.cveId, it.cveId, it.cveId) }
    intel.ttps.forEach { t ->
        term(EntityType.TTP, t.techniqueId, t.techniqueId, t.techniqueId)
        term(EntityType.TTP, t.techniqueId, t.techniqueName, t.techniqueId)
    }
    intel.threatActors.forEach { named(EntityType.THREAT_ACTOR, it.id, it.name, it.aliases, it.matchedNames) }
    intel.malware.forEach { named(EntityType.MALWARE, it.id, it.name, it.aliases, it.matchedNames) }
    intel.countries.forEach { named(EntityType.COUNTRY, it.id, it.name, it.aliases, it.matchedNames) }
    intel.vendors.forEach { named(EntityType.VENDOR, it.id, it.name, it.aliases, it.matchedNames) }
    intel.products.forEach { named(EntityType.PRODUCT, it.id, it.name, it.aliases, it.matchedNames) }
    intel.tools.forEach { named(EntityType.TOOL, it.id, it.name, it.aliases, it.matchedNames) }
    intel.cwes.forEach { term(EntityType.WEAKNESS, it.cweId, it.cweId, it.cweId) }
    intel.mitigations.forEach { m ->
        term(EntityType.MITIGATION, m.id, m.name, m.name)
        term(EntityType.MITIGATION, m.id, m.mitreId, m.name)
    }
    if (intel.observables.size <= MAX_HIGHLIGHTED_OBSERVABLES) intel.observables.forEach { o ->
        term(EntityType.OBSERVABLE, o.id, o.value, o.value)
        val surface = o.surfaceForm
        if (!surface.isNullOrEmpty() && !surface.equals(o.value, ignoreCase = true)) term(EntityType.OBSERVABLE, o.id, surface, o.value)
    }
}

/**
 * Glossary phrases, as the web builds them: terms by name length (longest first), each by its
 * name and its search terms. [Term.entityId] is the glossary term id.
 */
fun glossaryTerms(matches: List<GlossaryMatch>): List<Term> =
    matches.map { it.term }.sortedByDescending { it.name.length }.flatMap { term ->
        (listOf(term.name) + term.searchTerms).filter { it.isNotEmpty() }
            .map { Term(it, SpanKind.GLOSSARY, entityId = term.id, entityName = term.name) }
    }

/**
 * Keyword phrases to highlight: the keywords that made the article match an intelligence
 * requirement (the web shows these as "keyword: <term>").
 */
fun keywordTerms(pirMatches: List<PirMatch>): List<Term> =
    pirMatches.filter { it.matchType.equals("keyword", ignoreCase = true) }.mapNotNull { it.matchedOn }
        .filter { it.isNotBlank() }
        .map { Term(it, SpanKind.KEYWORD) }
