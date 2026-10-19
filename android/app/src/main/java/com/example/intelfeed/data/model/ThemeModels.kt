package com.example.intelfeed.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ThemeDto(
    val id: String,
    val name: String,
    val description: String = "",
    @SerialName("is_system") val isSystem: Boolean = false,
    @SerialName("is_default") val isDefault: Boolean = false,
    @SerialName("created_by") val createdBy: String? = null,
    @SerialName("css_variables") val cssVariables: Map<String, String> = emptyMap(),
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
) {
    val variables: Map<String, String> get() = cssVariables
    val isBuiltIn: Boolean get() = isSystem
}

@Serializable
data class ThemePreferenceUpdateRequest(
    @SerialName("theme_id") val themeId: String? = null,
    @SerialName("custom_css") val customCss: String? = null,
    @SerialName("clear_theme") val clearTheme: Boolean = false
)

@Serializable
data class ThemePreferenceUpdateResponse(
    val status: String = "ok",
    @SerialName("theme_id") val themeId: String? = null
)

@Serializable
data class ColorSchemaDto(
    val base: Map<String, String> = emptyMap(),
    @SerialName("domain_accents") val domainAccents: Map<String, String> = emptyMap(),
    @SerialName("entity_types") val entityTypes: Map<String, String> = emptyMap(),
    val severity: Map<String, String> = emptyMap(),
    @SerialName("rule_formats") val ruleFormats: Map<String, String> = emptyMap(),
    @SerialName("ransomware_groups") val ransomwareGroups: Map<String, String> = emptyMap(),
    val pir: Map<String, String> = emptyMap(),
    val tlp: Map<String, String> = emptyMap(),
    @SerialName("automation_nodes") val automationNodes: Map<String, String> = emptyMap(),
    val syntax: Map<String, String> = emptyMap(),
    val heatmap: Map<String, String> = emptyMap(),
    @SerialName("css_variables") val cssVariables: Map<String, String> = emptyMap()
)
