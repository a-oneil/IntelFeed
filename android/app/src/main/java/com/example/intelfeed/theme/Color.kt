package com.example.intelfeed.theme

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import com.example.intelfeed.data.local.CachedThemeState
import com.example.intelfeed.data.model.ColorSchemaDto
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.ThemeDto
import com.example.intelfeed.data.model.UserProfile
import kotlin.math.pow

/**
 * Resolved theme + color-vocabulary state driven by the backend (`/api/themes`, `/api/themes/default`,
 * and `/api/themes/schema`). All top-level color properties in `Color.kt` delegate to [ThemeEngine],
 * so any Compose screen reading them recomposes automatically when the active theme or color schema
 * changes.
 */
data class ResolvedThemeSelection(
    val theme: ThemeDto,
    val source: String // "user" or "default"
)

object ThemeEngine {

    /**
     * Default CSS variables matching the workbench's `:root` (`frontend/src/index.css`,
     * `entityTheme.ts`, `colorSchemes.ts`, `ransomwareColors.ts`, `severity.ts`, and
     * `backend/app/api/themes.py` `COLOR_SCHEMA`).
     */
    val DEFAULT_VARIABLES: Map<String, String> = mapOf(
        // Base theme variables (GitHub Dark)
        "bg-primary" to "#0d1117",
        "bg-secondary" to "#161b22",
        "bg-tertiary" to "#21262d",
        "bg-hover" to "#30363d",
        "text-primary" to "#e6edf3",
        "text-secondary" to "#8b949e",
        "text-muted" to "#484f58",
        "accent" to "#f78166",
        "accent-hover" to "#ffa28b",
        "accent-text" to "#ffffff",
        "accent-fg" to "#ffffff",
        "border" to "#30363d",
        "danger" to "#f85149",
        "danger-fg" to "#000000",
        "success" to "#3fb950",
        "warning" to "#d29922",
        "sidebar-bg" to "#010409",
        "sidebar-hover" to "#161b22",
        "sidebar-active" to "#21262d",
        "card-bg" to "#161b22",
        "card-border" to "#30363d",
        // 1. Domain accents
        "accent-feeds" to "#f78166",
        "accent-intel" to "#58a6ff",
        "accent-intel-fg" to "#0d1117",
        "accent-detect" to "#3fb950",
        "accent-rules" to "#3fb950",
        "accent-ops" to "#e0555b",
        "accent-dash" to "#bc8cff",
        "accent-ai" to "#bc8cff",
        "accent-search" to "#58a6ff",
        "accent-settings" to "#8b949e",
        // 2. Entity types (matching frontend/src/utils/entityTheme.ts & backend COLOR_SCHEMA)
        "entity-actor" to "#f97316",
        "entity-malware" to "#a855f7",
        "entity-ttp" to "#3b82f6",
        "entity-cve" to "#ef4444",
        "entity-cwe" to "#b45309",
        "entity-country" to "#06b6d4",
        "entity-rule" to "#22c55e",
        "entity-campaign" to "#14b8a6",
        "entity-vendor" to "#6366f1",
        "entity-product" to "#ec4899",
        "entity-tool" to "#eab308",
        "entity-mitigation" to "#84cc16",
        "entity-sector" to "#10b981",
        "entity-victim" to "#e0555b",
        "entity-pir" to "#06b6d4",
        "entity-ioc" to "#d946ef",
        "entity-note" to "#9aa4b2",
        // 3. Severity scale
        "severity-critical" to "#dc2626",
        "severity-critical-fg" to "#ffffff",
        "severity-high" to "#fb923c",
        "severity-high-fg" to "#0d1117",
        "severity-medium" to "#d29922",
        "severity-medium-fg" to "#0d1117",
        "severity-low" to "#3fb950",
        "severity-low-fg" to "#0d1117",
        "severity-info" to "#58a6ff",
        "severity-info-fg" to "#ffffff",
        // 4. Detection rule formats
        "fmt-sigma" to "#56d364",
        "fmt-yara" to "#d2a8ff",
        "fmt-kql" to "#79c0ff",
        "fmt-elastic-ql" to "#79c0ff",
        "fmt-nuclei" to "#ffa657",
        "fmt-splunk-spl" to "#7ee787",
        // 5. Ransomware groups
        "rgroup-lockbit" to "#e05c2f",
        "rgroup-clop" to "#12996a",
        "rgroup-akira" to "#2a78d6",
        "rgroup-qilin" to "#c2537f",
        "rgroup-play" to "#b5820f",
        "rgroup-ransomhub" to "#2f8f2f",
        "rgroup-other" to "#8b94a3",
        // 6. PIR categories
        "pir-strategic" to "#8b5cf6",
        "pir-operational" to "#f97316",
        "pir-tactical" to "#ef4444",
        "pir-technical" to "#06b6d4",
        // 7. TLP
        "tlp-red" to "#ef4444",
        "tlp-red-bg" to "#2d0b0b",
        "tlp-amber" to "#f59e0b",
        "tlp-amber-bg" to "#2a1d05",
        "tlp-amber-strict" to "#f59e0b",
        "tlp-amber-strict-bg" to "#2c1608",
        "tlp-green" to "#22c55e",
        "tlp-green-bg" to "#082614",
        "tlp-clear" to "#6b7280",
        "tlp-clear-bg" to "#1e293b",
        // 8. Automation nodes
        "node-trigger" to "#f59e0b",
        "node-condition" to "#3b82f6",
        "node-action" to "#22c55e",
        "node-branch" to "#a855f7",
        "node-enrichment" to "#a855f7",
        "node-transform" to "#06b6d4",
        "node-notification" to "#f97316",
        "node-control" to "#8b949e",
        // 9. Syntax tokens
        "syntax-keyword" to "#cba6f7",
        "syntax-string" to "#a6e3a1",
        "syntax-number" to "#fab387",
        "syntax-comment" to "#6c7086",
        "syntax-function" to "#89b4fa",
        "syntax-operator" to "#89dceb",
        "syntax-attr" to "#f9e2af",
        "syntax-field" to "#89b4fa",
        "syntax-regex" to "#a6e3a1",
        "syntax-meta" to "#f9e2af",
        // Heatmap
        "heatmap-empty" to "#161b22",
        "heatmap-1" to "#0e4429",
        "heatmap-2" to "#006d32",
        "heatmap-3" to "#26a641",
        "heatmap-4" to "#39d353",
        "heatmap-5" to "#56e373"
    )

    private var schemaVariables by mutableStateOf<Map<String, String>>(emptyMap())
    private var themeVariables by mutableStateOf<Map<String, String>>(emptyMap())

    var activeThemeId by mutableStateOf<String?>(null)
        private set
    var activeThemeName by mutableStateOf("GitHub Dark")
        private set
    var activeThemeSource by mutableStateOf("default")
        private set

    // Merged variable map observed by Compose UI
    var variables by mutableStateOf(DEFAULT_VARIABLES)
        private set

    private fun normalizeVarKey(rawKey: String): String {
        return when (val clean = rawKey.removePrefix("--").trim()) {
            "bg-base" -> "bg-primary"
            "bg-surface" -> "bg-secondary"
            "bg-elevated" -> "bg-tertiary"
            "accent-primary" -> "accent"
            else -> clean
        }
    }

    private fun rebuildVariables() {
        val merged = LinkedHashMap<String, String>(DEFAULT_VARIABLES.size + 32)
        merged.putAll(DEFAULT_VARIABLES)
        merged.putAll(schemaVariables)
        themeVariables.forEach { (k, v) ->
            val rawClean = k.removePrefix("--").trim()
            val normKey = normalizeVarKey(rawClean)
            if (normKey.isNotEmpty() && v.isNotBlank()) {
                val trimmed = v.trim()
                merged[rawClean] = trimmed
                merged[normKey] = trimmed
                if (normKey == "accent-text") {
                    merged["accent-fg"] = trimmed
                } else if (normKey == "accent-fg") {
                    merged["accent-text"] = trimmed
                }
            }
        }
        // Compute WCAG AA contrast foreground for accent when not explicitly provided by theme
        val hasExplicitAccentFg = themeVariables.keys.any {
            val k = it.removePrefix("--").trim()
            k == "accent-fg" || k == "accent-text"
        }
        if (!hasExplicitAccentFg) {
            val accentColor = parseHexColor(merged["accent"]) ?: Color(0xFFF78166)
            val fgHex = if (relativeLuminance(accentColor) >= 0.4f) "#0d1117" else "#ffffff"
            merged["accent-fg"] = fgHex
            merged["accent-text"] = fgHex
        }
        variables = merged
    }

    /** Applies the server's `/api/themes/schema` color vocabulary. */
    fun applyColorSchema(schema: ColorSchemaDto) {
        val extracted = LinkedHashMap<String, String>()
        schema.cssVariables.forEach { (k, v) ->
            val norm = normalizeVarKey(k)
            extracted[k.removePrefix("--")] = v
            extracted[norm] = v
        }
        schema.base.forEach { (k, v) ->
            val norm = normalizeVarKey(k)
            extracted[k.removePrefix("--")] = v
            extracted[norm] = v
        }
        schema.domainAccents.forEach { (k, v) ->
            val key = k.removePrefix("--")
            val fullKey = if (key.startsWith("accent-")) key else "accent-$key"
            extracted[fullKey] = v
            if (fullKey == "accent-detect") {
                extracted["accent-rules"] = v
            }
        }
        schema.entityTypes.forEach { (k, v) ->
            val key = k.removePrefix("--")
            when (key) {
                "threat_actor", "actor" -> extracted["entity-actor"] = v
                "malware" -> extracted["entity-malware"] = v
                "cve" -> extracted["entity-cve"] = v
                "ttp" -> extracted["entity-ttp"] = v
                "rule", "detection_rule" -> extracted["entity-rule"] = v
                "campaign" -> extracted["entity-campaign"] = v
                "tool" -> extracted["entity-tool"] = v
                "vendor" -> extracted["entity-vendor"] = v
                "product" -> extracted["entity-product"] = v
                "country" -> extracted["entity-country"] = v
                "sector", "industry" -> extracted["entity-sector"] = v
                "cwe" -> extracted["entity-cwe"] = v
                "mitigation" -> extracted["entity-mitigation"] = v
                "ioc", "observable" -> extracted["entity-ioc"] = v
                "pir" -> extracted["entity-pir"] = v
                "ransomware_victim", "victim" -> extracted["entity-victim"] = v
                "note" -> extracted["entity-note"] = v
                else -> extracted[if (key.startsWith("entity-")) key else "entity-$key"] = v
            }
        }
        schema.severity.forEach { (level, v) ->
            val norm = level.lowercase().removePrefix("severity-")
            extracted["severity-$norm"] = v
        }
        schema.ruleFormats.forEach { (fmt, v) ->
            val norm = fmt.lowercase().replace('_', '-')
            extracted[if (norm.startsWith("fmt-")) norm else "fmt-$norm"] = v
        }
        schema.ransomwareGroups.forEach { (grp, v) ->
            val norm = grp.lowercase().replace('_', '-')
            extracted[if (norm.startsWith("rgroup-")) norm else "rgroup-$norm"] = v
        }
        schema.pir.forEach { (cat, v) ->
            val norm = cat.lowercase()
            extracted[if (norm.startsWith("pir-")) norm else "pir-$norm"] = v
        }
        schema.tlp.forEach { (lvl, v) ->
            val norm = lvl.lowercase().removePrefix("tlp:").removePrefix("tlp-").replace('+', '-').replace('_', '-')
            extracted["tlp-$norm"] = v
        }
        schema.automationNodes.forEach { (node, v) ->
            val norm = node.lowercase()
            extracted[if (norm.startsWith("node-")) norm else "node-$norm"] = v
        }
        schema.syntax.forEach { (tok, v) ->
            val norm = tok.lowercase()
            extracted[if (norm.startsWith("syntax-")) norm else "syntax-$norm"] = v
        }
        schema.heatmap.forEach { (lvl, v) ->
            val norm = lvl.lowercase()
            extracted[if (norm.startsWith("heatmap-")) norm else "heatmap-$norm"] = v
        }
        schemaVariables = extracted
        rebuildVariables()
    }

    /** Applies a theme's CSS variable overrides. */
    fun applyTheme(
        themeId: String?,
        themeName: String,
        vars: Map<String, String>,
        source: String = "default"
    ) {
        activeThemeId = themeId
        activeThemeName = themeName
        activeThemeSource = source
        themeVariables = vars
        rebuildVariables()
    }

    fun applyThemeDto(theme: ThemeDto, source: String = "default") {
        applyTheme(
            themeId = theme.id,
            themeName = theme.name,
            vars = theme.variables,
            source = source
        )
    }

    /** Restores cached theme and color schema from DataStore immediately at startup. */
    fun restoreFromCache(cached: CachedThemeState) {
        cached.colorSchema?.let { applyColorSchema(it) }
        if (cached.variables.isNotEmpty()) {
            applyTheme(
                themeId = cached.themeId,
                themeName = cached.themeName ?: "Custom",
                vars = cached.variables,
                source = cached.source ?: "default"
            )
        }
    }

    fun resetToDefault() {
        activeThemeId = null
        activeThemeName = "GitHub Dark"
        activeThemeSource = "default"
        themeVariables = emptyMap()
        rebuildVariables()
    }

    fun resetToBuiltInDefaults() {
        schemaVariables = emptyMap()
        resetToDefault()
    }

    /**
     * Resolves which theme should be active when signed in, matching the web workbench's
     * `useAutoTheme` precedence (`frontend/src/hooks/useThemes.ts`):
     * 1. User's saved `themeId` (`source = "user"`)
     * 2. Instance default theme `isDefault == true` (`source = "default"`)
     * 3. Cached theme ID if no user object is loaded yet
     * 4. Built-in "GitHub Dark" (`source = "default"`)
     */
    fun resolveSignedInTheme(
        themes: List<ThemeDto>,
        user: UserProfile?,
        cached: CachedThemeState?
    ): ResolvedThemeSelection? {
        if (themes.isEmpty()) return null

        if (user?.themeId != null) {
            themes.find { it.id == user.themeId }?.let {
                return ResolvedThemeSelection(it, "user")
            }
        }

        if (user != null) {
            themes.find { it.isDefault }?.let {
                return ResolvedThemeSelection(it, "default")
            }
        } else if (cached?.themeId != null) {
            themes.find { it.id == cached.themeId }?.let {
                return ResolvedThemeSelection(it, cached.source ?: "default")
            }
        }

        val fallback = themes.find { it.name == "GitHub Dark" } ?: themes.first()
        return ResolvedThemeSelection(fallback, "default")
    }

    /**
     * Resolves whether a signed-out screen should apply the server's public default theme or keep
     * the user's cached choice (`frontend/src/hooks/useThemes.ts`).
     */
    fun shouldApplyPublicDefaultWhenSignedOut(
        publicDefault: ThemeDto?,
        cached: CachedThemeState?
    ): Boolean {
        if (publicDefault == null) return false
        val hasCachedVars = !cached?.variables.isNullOrEmpty()
        val hasUserSelectedCache = hasCachedVars && (
            cached?.source == "user" ||
                (cached?.source == null && !cached?.themeId.isNullOrBlank() && cached.themeId != publicDefault.id)
            )
        return !hasUserSelectedCache
    }

    fun color(variableName: String, fallback: Color = Color(0xFF8B949E)): Color {
        val clean = normalizeVarKey(variableName)
        val rawClean = variableName.removePrefix("--").trim()
        return parseHexColor(variables[rawClean])
            ?: parseHexColor(variables[clean])
            ?: parseHexColor(DEFAULT_VARIABLES[rawClean])
            ?: parseHexColor(DEFAULT_VARIABLES[clean])
            ?: fallback
    }

    fun parseCssColor(raw: String?, fallback: Color): Color {
        return parseHexColor(raw) ?: fallback
    }

    val isLightTheme: Boolean
        get() = relativeLuminance(color("bg-primary", Color(0xFF0D1117))) >= 0.45f

    // --- Semantic Color Vocabulary Resolvers ---

    fun domainAccentColor(domain: String): Color = when (domain.lowercase().trim()) {
        "feeds", "feed" -> color("accent-feeds")
        "intel", "intelligence" -> color("accent-intel")
        "detect", "rules", "detection", "detections" -> color("accent-detect", color("accent-rules"))
        "ops", "campaigns", "operations", "ransomware" -> color("accent-ops", color("entity-victim"))
        "dash", "dashboard", "workbench" -> color("accent-dash")
        "ai", "briefing", "summary" -> color("accent-ai", color("accent-dash"))
        "search" -> color("accent-search", color("accent-intel"))
        "settings" -> color("accent-settings")
        else -> color("accent")
    }

    fun entityColor(type: EntityType): Color = when (type) {
        EntityType.THREAT_ACTOR -> color("entity-actor")
        EntityType.MALWARE -> color("entity-malware")
        EntityType.CVE -> color("entity-cve")
        EntityType.TTP -> color("entity-ttp")
        EntityType.RULE -> color("entity-rule")
        EntityType.CAMPAIGN -> color("entity-campaign")
        EntityType.TOOL -> color("entity-tool")
        EntityType.VENDOR -> color("entity-vendor")
        EntityType.PRODUCT -> color("entity-product")
        EntityType.COUNTRY -> color("entity-country")
        EntityType.MITIGATION -> color("entity-mitigation")
        EntityType.WEAKNESS -> color("entity-cwe")
        EntityType.OBSERVABLE -> color("entity-ioc")
    }

    fun entityColor(entityTypeKey: String?): Color {
        return when (val key = entityTypeKey?.lowercase()?.trim()) {
            "threat_actor", "actor", "intrusion_set" -> color("entity-actor")
            "malware" -> color("entity-malware")
            "cve", "vulnerability" -> color("entity-cve")
            "ttp", "technique", "attack", "attack_pattern" -> color("entity-ttp")
            "rule", "detection_rule", "detection-rule" -> color("entity-rule")
            "campaign" -> color("entity-campaign")
            "tool" -> color("entity-tool")
            "vendor" -> color("entity-vendor")
            "product" -> color("entity-product")
            "country" -> color("entity-country")
            "sector", "industry" -> color("entity-sector")
            "cwe", "weakness" -> color("entity-cwe")
            "mitigation", "course_of_action" -> color("entity-mitigation")
            "ioc", "observable" -> color("entity-ioc")
            "pir" -> color("entity-pir")
            "ransomware_victim", "victim" -> color("entity-victim")
            "note" -> color("entity-note")
            else -> if (!key.isNullOrBlank()) color("entity-$key", color("accent-intel")) else color("accent-intel")
        }
    }

    fun severityColor(level: String?): Color = when (level?.lowercase()?.trim()) {
        "critical", "crit" -> color("severity-critical")
        "high", "danger", "error" -> color("severity-high")
        "medium", "moderate", "med", "warning", "warn" -> color("severity-medium")
        "low", "success", "positive" -> color("severity-low")
        "info", "informational", "none" -> color("severity-info")
        else -> color("text-secondary")
    }

    fun severityFgColor(level: String?): Color = when (level?.lowercase()?.trim()) {
        "critical", "crit" -> color("severity-critical-fg", contrastTextColor(severityColor("critical")))
        "high", "danger", "error" -> color("severity-high-fg", contrastTextColor(severityColor("high")))
        "medium", "moderate", "med", "warning", "warn" -> color("severity-medium-fg", contrastTextColor(severityColor("medium")))
        "low", "success", "positive" -> color("severity-low-fg", contrastTextColor(severityColor("low")))
        "info", "informational", "none" -> color("severity-info-fg", contrastTextColor(severityColor("info")))
        else -> contrastTextColor(color("text-secondary"))
    }

    fun ruleFormatColor(format: String?): Color {
        val norm = format?.lowercase()?.trim()?.replace('-', '_') ?: return color("entity-rule")
        return when {
            norm == "sigma" -> color("fmt-sigma")
            norm == "yara" -> color("fmt-yara")
            norm == "kql" -> color("fmt-kql")
            norm == "splunk" || norm == "splunk_spl" || norm == "spl" -> color("fmt-splunk-spl")
            norm == "elastic" || norm == "elastic_ql" || norm == "eql" || norm == "esql" -> color("fmt-elastic-ql")
            norm == "nuclei" -> color("fmt-nuclei")
            else -> color("fmt-${norm.replace('_', '-')}", color("entity-rule"))
        }
    }

    fun ransomwareGroupColor(groupName: String?): Color {
        val key = groupName?.lowercase()?.trim() ?: return color("rgroup-other")
        return when {
            "lockbit" in key -> color("rgroup-lockbit")
            "clop" in key || "cl0p" in key -> color("rgroup-clop")
            "akira" in key -> color("rgroup-akira")
            "qilin" in key -> color("rgroup-qilin")
            key == "play" || "playcrypt" in key -> color("rgroup-play")
            "ransomhub" in key -> color("rgroup-ransomhub")
            else -> color("rgroup-$key", color("rgroup-other"))
        }
    }

    fun pirCategoryColor(category: String?): Color = when (category?.lowercase()?.trim()) {
        "strategic" -> color("pir-strategic")
        "operational" -> color("pir-operational")
        "tactical" -> color("pir-tactical")
        "technical" -> color("pir-technical")
        else -> color("entity-pir")
    }

    fun tlpColor(tlp: String?): Color {
        val norm = tlp?.uppercase()?.trim()?.removePrefix("TLP:")?.trim() ?: return color("tlp-clear")
        return when (norm) {
            "RED" -> color("tlp-red")
            "AMBER+STRICT", "AMBER-STRICT", "AMBER_STRICT" -> color("tlp-amber-strict")
            "AMBER" -> color("tlp-amber")
            "GREEN" -> color("tlp-green")
            "CLEAR", "WHITE" -> color("tlp-clear")
            else -> color("tlp-clear")
        }
    }

    fun tlpBgColor(tlp: String?): Color {
        val norm = tlp?.uppercase()?.trim()?.removePrefix("TLP:")?.trim() ?: return color("tlp-clear-bg")
        return when (norm) {
            "RED" -> color("tlp-red-bg")
            "AMBER+STRICT", "AMBER-STRICT", "AMBER_STRICT" -> color("tlp-amber-strict-bg")
            "AMBER" -> color("tlp-amber-bg")
            "GREEN" -> color("tlp-green-bg")
            "CLEAR", "WHITE" -> color("tlp-clear-bg")
            else -> color("tlp-clear-bg")
        }
    }

    fun automationNodeColor(nodeType: String?): Color = when (nodeType?.lowercase()?.trim()) {
        "trigger" -> color("node-trigger")
        "condition" -> color("node-condition")
        "action" -> color("node-action")
        "branch" -> color("node-branch")
        "enrichment" -> color("node-enrichment", color("node-branch"))
        "transform" -> color("node-transform")
        "notification" -> color("node-notification")
        "control" -> color("node-control")
        else -> color("node-control")
    }

    fun syntaxColor(tokenType: String?): Color = when (tokenType?.lowercase()?.trim()) {
        "keyword" -> color("syntax-keyword")
        "string" -> color("syntax-string")
        "number" -> color("syntax-number")
        "comment" -> color("syntax-comment")
        "function" -> color("syntax-function")
        "operator" -> color("syntax-operator")
        "attr" -> color("syntax-attr")
        "field" -> color("syntax-field")
        "regex" -> color("syntax-regex")
        "meta" -> color("syntax-meta")
        else -> color("text-primary")
    }

    /**
     * Picks dark (`#0d1117`) or white (`#ffffff`) foreground text for a filled chip or button
     * background using WCAG relative luminance (matching `frontend/src/utils/contrast.ts`).
     */
    fun contrastTextColor(bg: Color): Color {
        return if (relativeLuminance(bg) >= 0.4f) Color(0xFF0D1117) else Color.White
    }

    fun relativeLuminance(color: Color): Float {
        fun channel(c: Float): Float =
            if (c <= 0.03928f) c / 12.92f else ((c + 0.055f) / 1.055f).pow(2.4f)
        return 0.2126f * channel(color.red) + 0.7152f * channel(color.green) + 0.0722f * channel(color.blue)
    }

    fun parseHexColor(raw: String?): Color? {
        val hex = raw?.trim()?.removePrefix("#") ?: return null
        return when (hex.length) {
            3 -> {
                val r = hex[0].toString().repeat(2)
                val g = hex[1].toString().repeat(2)
                val b = hex[2].toString().repeat(2)
                "$r$g$b".toLongOrNull(16)?.let { Color(0xFF000000 or it) }
            }
            6 -> hex.toLongOrNull(16)?.let { Color(0xFF000000 or it) }
            8 -> hex.toLongOrNull(16)?.let { Color(it) }
            else -> null
        }
    }
}

// IntelFeed Core Dynamic Theme Palette (backed by ThemeEngine Compose state)
val SlateDark950: Color
    get() = ThemeEngine.color("bg-primary", Color(0xFF0D1117))

val SlateDark900: Color
    get() = ThemeEngine.color("bg-primary", Color(0xFF0D1117))

val SlateDark800: Color
    get() = ThemeEngine.color("bg-secondary", Color(0xFF161B22))

val SlateDark700: Color
    get() = ThemeEngine.color("bg-tertiary", Color(0xFF21262D))

val SlateDark600: Color
    get() = ThemeEngine.color("border", Color(0xFF30363D))

val SlateDark500: Color
    get() = lerp(SlateDark600, TextMuted, 0.35f)

val TextPrimary: Color
    get() = ThemeEngine.color("text-primary", Color(0xFFE6EDF3))

val TextMuted: Color
    get() = ThemeEngine.color("text-secondary", Color(0xFF8B949E))

val TextSecondary: Color
    get() = lerp(TextPrimary, TextMuted, 0.38f)

val CyberBlue: Color
    get() = ThemeEngine.color("accent", Color(0xFF58A6FF))

val CyberBlueDim: Color
    get() = ThemeEngine.color("accent-hover", Color(0xFF1F6FEB))

val CyberGreen: Color
    get() = ThemeEngine.color("success", Color(0xFF3FB950))

val CyberGreenDim: Color
    get() = lerp(CyberGreen, SlateDark900, 0.35f)

val CyberAmber: Color
    get() = ThemeEngine.color("warning", Color(0xFFD29922))

val CyberRed: Color
    get() = ThemeEngine.color("danger", Color(0xFFF85149))

val CyberPurple: Color
    get() = ThemeEngine.color("entity-ttp", Color(0xFF3B82F6))

val CyberOrange: Color
    get() = ThemeEngine.color("entity-actor", Color(0xFFF97316))

val CyberCyan: Color
    get() = ThemeEngine.color("entity-country", Color(0xFF06B6D4))

// Threat Intel Indicator Badge Colors
val IntelCveBg: Color
    get() = ThemeEngine.entityColor(EntityType.CVE).copy(alpha = 0.15f)
val IntelCveText: Color
    get() = ThemeEngine.entityColor(EntityType.CVE)

val IntelActorBg: Color
    get() = ThemeEngine.entityColor(EntityType.THREAT_ACTOR).copy(alpha = 0.15f)
val IntelActorText: Color
    get() = ThemeEngine.entityColor(EntityType.THREAT_ACTOR)

val IntelMalwareBg: Color
    get() = ThemeEngine.entityColor(EntityType.MALWARE).copy(alpha = 0.15f)
val IntelMalwareText: Color
    get() = ThemeEngine.entityColor(EntityType.MALWARE)

val IntelTtpBg: Color
    get() = ThemeEngine.entityColor(EntityType.TTP).copy(alpha = 0.15f)
val IntelTtpText: Color
    get() = ThemeEngine.entityColor(EntityType.TTP)

val IntelCountryBg: Color
    get() = ThemeEngine.entityColor(EntityType.COUNTRY).copy(alpha = 0.15f)
val IntelCountryText: Color
    get() = ThemeEngine.entityColor(EntityType.COUNTRY)
