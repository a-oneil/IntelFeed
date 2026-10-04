package com.example.intelfeed.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * GET /api/attack/matrix?domain=enterprise|mobile|ics&days=N (no days = all time), the web's
 * Workbench "ATT&CK Matrix": every tactic with its techniques, how often each was seen in the
 * feeds in the window, and whether the rule library covers it.
 */
@Serializable
data class AttackMatrix(
    val domain: String = "enterprise",
    val days: Int? = null,
    @SerialName("technique_count") val techniqueCount: Int = 0,
    @SerialName("max_article_count") val maxArticleCount: Int = 0,
    @SerialName("coverage_summary") val coverageSummary: AttackCoverageSummary = AttackCoverageSummary(),
    val tactics: List<AttackTactic> = emptyList()
)

@Serializable
data class AttackCoverageSummary(
    val covered: Int = 0,
    @SerialName("library_only") val libraryOnly: Int = 0,
    @SerialName("no_rule") val noRule: Int = 0
)

@Serializable
data class AttackTactic(val id: String = "", val name: String = "", val techniques: List<AttackTechnique> = emptyList())

@Serializable
data class AttackTechnique(
    val id: String = "",
    @SerialName("technique_id") val techniqueId: String = "",
    val name: String = "",
    @SerialName("article_count") val articleCount: Int = 0,
    // Articles for the technique plus its sub-techniques; shown while the subs are collapsed.
    @SerialName("rollup_article_count") val rollupArticleCount: Int? = null,
    @SerialName("rule_count") val ruleCount: Int = 0,
    // "covered" (rule with telemetry), "library_only" (rule, telemetry missing) or "no_rule".
    val coverage: String = "no_rule",
    @SerialName("missing_data_sources") val missingDataSources: List<String> = emptyList(),
    val subtechniques: List<AttackTechnique> = emptyList()
)
