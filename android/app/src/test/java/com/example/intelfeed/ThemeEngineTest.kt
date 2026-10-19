package com.example.intelfeed

import androidx.compose.ui.graphics.Color
import com.example.intelfeed.data.local.CachedThemeState
import com.example.intelfeed.data.model.ColorSchemaDto
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.ThemeDto
import com.example.intelfeed.data.model.UserProfile
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.SlateDark950
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.ThemeEngine
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ThemeEngineTest {

    @Before
    fun setUp() {
        ThemeEngine.resetToBuiltInDefaults()
    }

    @After
    fun tearDown() {
        ThemeEngine.resetToBuiltInDefaults()
    }

    @Test
    fun `default color vocabulary matches workbench specification across all 9 families`() {
        // 1. Entity types
        assertEquals(Color(0xFFF97316), ThemeEngine.entityColor(EntityType.THREAT_ACTOR))
        assertEquals(Color(0xFFF97316), ThemeEngine.entityColor("actor"))
        assertEquals(Color(0xFFA855F7), ThemeEngine.entityColor(EntityType.MALWARE))
        assertEquals(Color(0xFF3B82F6), ThemeEngine.entityColor(EntityType.TTP))
        assertEquals(Color(0xFFEF4444), ThemeEngine.entityColor(EntityType.CVE))
        assertEquals(Color(0xFFB45309), ThemeEngine.entityColor(EntityType.WEAKNESS))
        assertEquals(Color(0xFF06B6D4), ThemeEngine.entityColor(EntityType.COUNTRY))
        assertEquals(Color(0xFF22C55E), ThemeEngine.entityColor(EntityType.RULE))
        assertEquals(Color(0xFF14B8A6), ThemeEngine.entityColor(EntityType.CAMPAIGN))
        assertEquals(Color(0xFF6366F1), ThemeEngine.entityColor(EntityType.VENDOR))
        assertEquals(Color(0xFFEC4899), ThemeEngine.entityColor(EntityType.PRODUCT))
        assertEquals(Color(0xFFEAB308), ThemeEngine.entityColor(EntityType.TOOL))
        assertEquals(Color(0xFF84CC16), ThemeEngine.entityColor(EntityType.MITIGATION))
        assertEquals(Color(0xFFD946EF), ThemeEngine.entityColor(EntityType.OBSERVABLE))
        assertEquals(Color(0xFF10B981), ThemeEngine.entityColor("sector"))
        assertEquals(Color(0xFFE0555B), ThemeEngine.entityColor("ransomware_victim"))
        assertEquals(Color(0xFF06B6D4), ThemeEngine.entityColor("pir"))

        // 2. Severity & status
        assertEquals(Color(0xFFDC2626), ThemeEngine.severityColor("critical"))
        assertEquals(Color(0xFFFB923C), ThemeEngine.severityColor("high"))
        assertEquals(Color(0xFFD29922), ThemeEngine.severityColor("medium"))
        assertEquals(Color(0xFF3FB950), ThemeEngine.severityColor("low"))
        assertEquals(Color(0xFF58A6FF), ThemeEngine.severityColor("info"))
        assertEquals(Color(0xFFFFFFFF), ThemeEngine.severityFgColor("critical"))
        assertEquals(Color(0xFF0D1117), ThemeEngine.severityFgColor("high"))

        // 3. Domain accents
        assertEquals(Color(0xFFF78166), ThemeEngine.domainAccentColor("feeds"))
        assertEquals(Color(0xFF58A6FF), ThemeEngine.domainAccentColor("intel"))
        assertEquals(Color(0xFF3FB950), ThemeEngine.domainAccentColor("detect"))
        assertEquals(Color(0xFFBC8CFF), ThemeEngine.domainAccentColor("dash"))
        assertEquals(Color(0xFFE0555B), ThemeEngine.domainAccentColor("ransomware"))

        // 4. Detection rule formats
        assertEquals(Color(0xFF56D364), ThemeEngine.ruleFormatColor("sigma"))
        assertEquals(Color(0xFFD2A8FF), ThemeEngine.ruleFormatColor("yara"))
        assertEquals(Color(0xFF79C0FF), ThemeEngine.ruleFormatColor("kql"))
        assertEquals(Color(0xFF79C0FF), ThemeEngine.ruleFormatColor("elastic-ql"))
        assertEquals(Color(0xFFFFA657), ThemeEngine.ruleFormatColor("nuclei"))
        assertEquals(Color(0xFF7EE787), ThemeEngine.ruleFormatColor("splunk-spl"))

        // 5. Ransomware groups
        assertEquals(Color(0xFFE05C2F), ThemeEngine.ransomwareGroupColor("lockbit"))
        assertEquals(Color(0xFF12996A), ThemeEngine.ransomwareGroupColor("clop"))
        assertEquals(Color(0xFF2A78D6), ThemeEngine.ransomwareGroupColor("akira"))
        assertEquals(Color(0xFFC2537F), ThemeEngine.ransomwareGroupColor("qilin"))
        assertEquals(Color(0xFFB5820F), ThemeEngine.ransomwareGroupColor("play"))
        assertEquals(Color(0xFF2F8F2F), ThemeEngine.ransomwareGroupColor("ransomhub"))
        assertEquals(Color(0xFF8B94A3), ThemeEngine.ransomwareGroupColor("unknown_group"))

        // 6. PIR categories
        assertEquals(Color(0xFF8B5CF6), ThemeEngine.pirCategoryColor("strategic"))
        assertEquals(Color(0xFFF97316), ThemeEngine.pirCategoryColor("operational"))
        assertEquals(Color(0xFFEF4444), ThemeEngine.pirCategoryColor("tactical"))
        assertEquals(Color(0xFF06B6D4), ThemeEngine.pirCategoryColor("technical"))

        // 7. TLP levels
        assertEquals(Color(0xFFEF4444), ThemeEngine.tlpColor("TLP:RED"))
        assertEquals(Color(0xFFF59E0B), ThemeEngine.tlpColor("TLP:AMBER"))
        assertEquals(Color(0xFFF59E0B), ThemeEngine.tlpColor("TLP:AMBER+STRICT"))
        assertEquals(Color(0xFF22C55E), ThemeEngine.tlpColor("TLP:GREEN"))
        assertEquals(Color(0xFF6B7280), ThemeEngine.tlpColor("TLP:CLEAR"))
        assertEquals(Color(0xFF2D0B0B), ThemeEngine.tlpBgColor("TLP:RED"))

        // 8. Automation node types
        assertEquals(Color(0xFFF59E0B), ThemeEngine.automationNodeColor("trigger"))
        assertEquals(Color(0xFF3B82F6), ThemeEngine.automationNodeColor("condition"))
        assertEquals(Color(0xFF22C55E), ThemeEngine.automationNodeColor("action"))
        assertEquals(Color(0xFFA855F7), ThemeEngine.automationNodeColor("branch"))

        // 9. Syntax highlighting tokens
        assertEquals(Color(0xFFCBA6F7), ThemeEngine.syntaxColor("keyword"))
        assertEquals(Color(0xFFA6E3A1), ThemeEngine.syntaxColor("string"))
        assertEquals(Color(0xFFFAB387), ThemeEngine.syntaxColor("number"))
        assertEquals(Color(0xFF6C7086), ThemeEngine.syntaxColor("comment"))
        assertEquals(Color(0xFF89B4FA), ThemeEngine.syntaxColor("function"))
        assertEquals(Color(0xFF89DCEB), ThemeEngine.syntaxColor("operator"))
        assertEquals(Color(0xFFF9E2AF), ThemeEngine.syntaxColor("attr"))
    }

    @Test
    fun `applyThemeDto updates palette, detects light mode, and applies variable overrides`() {
        val analystLight = ThemeDto(
            id = "analyst-light",
            name = "Analyst Light",
            description = "Clean light theme",
            isSystem = true,
            isDefault = false,
            cssVariables = mapOf(
                "bg-primary" to "#f8fafc",
                "bg-secondary" to "#f1f5f9",
                "bg-tertiary" to "#ffffff",
                "text-primary" to "#0f172a",
                "accent" to "#2563eb",
                "entity-actor" to "#dc2626",
                "syntax-keyword" to "#7c3aed"
            )
        )

        ThemeEngine.applyThemeDto(analystLight, source = "user")

        assertEquals("analyst-light", ThemeEngine.activeThemeId)
        assertEquals("Analyst Light", ThemeEngine.activeThemeName)
        assertEquals("user", ThemeEngine.activeThemeSource)
        assertTrue(ThemeEngine.isLightTheme)
        assertEquals(Color(0xFFF8FAFC), SlateDark900)
        assertEquals(Color(0xFFF8FAFC), SlateDark950)
        assertEquals(Color(0xFF0F172A), TextPrimary)
        assertEquals(Color(0xFF2563EB), CyberBlue)
        // Theme variable overrides take priority over schema defaults
        assertEquals(Color(0xFFDC2626), ThemeEngine.entityColor("actor"))
        assertEquals(Color(0xFF7C3AED), ThemeEngine.syntaxColor("keyword"))
    }

    @Test
    fun `applyColorSchema updates server-driven vocabulary dynamically`() {
        val customSchema = ColorSchemaDto(
            entityTypes = mapOf("threat_actor" to "#112233"),
            domainAccents = mapOf("feeds" to "#445566"),
            severity = mapOf("critical" to "#990011"),
            ruleFormats = mapOf("yara" to "#778899"),
            ransomwareGroups = mapOf("lockbit" to "#aabbcc"),
            pir = mapOf("strategic" to "#ddeeff"),
            tlp = mapOf("TLP:RED" to "#ff0055"),
            automationNodes = mapOf("trigger" to "#123456"),
            syntax = mapOf("keyword" to "#654321")
        )

        ThemeEngine.applyColorSchema(customSchema)

        assertEquals(Color(0xFF112233), ThemeEngine.entityColor("actor"))
        assertEquals(Color(0xFF445566), ThemeEngine.domainAccentColor("feeds"))
        assertEquals(Color(0xFF990011), ThemeEngine.severityColor("critical"))
        assertEquals(Color(0xFF778899), ThemeEngine.ruleFormatColor("yara"))
        assertEquals(Color(0xFFAABBCC), ThemeEngine.ransomwareGroupColor("lockbit"))
        assertEquals(Color(0xFFDDEEFF), ThemeEngine.pirCategoryColor("strategic"))
        assertEquals(Color(0xFFFF0055), ThemeEngine.tlpColor("TLP:RED"))
        assertEquals(Color(0xFF123456), ThemeEngine.automationNodeColor("trigger"))
        assertEquals(Color(0xFF654321), ThemeEngine.syntaxColor("keyword"))
    }

    @Test
    fun `contrastTextColor follows WCAG 0_4 luminance cutoff`() {
        // Bright colors (>= 0.4 luminance) get dark text (#0D1117)
        assertEquals(Color(0xFF0D1117), ThemeEngine.contrastTextColor(Color(0xFFFFFFFF)))
        assertEquals(Color(0xFF0D1117), ThemeEngine.contrastTextColor(Color(0xFFFBBF24)))
        // Dark colors (< 0.4 luminance) get white text (#FFFFFF)
        assertEquals(Color(0xFFFFFFFF), ThemeEngine.contrastTextColor(Color(0xFF0D1117)))
        assertEquals(Color(0xFFFFFFFF), ThemeEngine.contrastTextColor(Color(0xFF1E3A8A)))
    }

    @Test
    fun `auto-theme precedence matches web useAutoTheme rules`() {
        val githubDark = ThemeDto(id = "t-gh", name = "GitHub Dark", isDefault = false)
        val blacklight = ThemeDto(id = "t-black", name = "Blacklight (Orange)", isDefault = true, cssVariables = mapOf("bg-primary" to "#000000"))
        val nord = ThemeDto(id = "t-nord", name = "Nord", isDefault = false, cssVariables = mapOf("bg-primary" to "#2e3440"))
        val themes = listOf(githubDark, blacklight, nord)

        // 1. User has explicit theme_id -> wins with source "user"
        val resolvedUser = ThemeEngine.resolveSignedInTheme(
            themes = themes,
            user = UserProfile(id = "u1", username = "kurt", themeId = "t-nord"),
            cached = CachedThemeState(themeId = "t-gh", themeName = "GitHub Dark", variables = emptyMap(), source = "user")
        )
        assertNotNull(resolvedUser)
        assertEquals("t-nord", resolvedUser!!.theme.id)
        assertEquals("user", resolvedUser.source)

        // 2. User has no theme_id -> instance default wins with source "default"
        val resolvedDefault = ThemeEngine.resolveSignedInTheme(
            themes = themes,
            user = UserProfile(id = "u1", username = "kurt", themeId = null),
            cached = CachedThemeState(themeId = "t-gh", themeName = "GitHub Dark", variables = emptyMap(), source = "default")
        )
        assertNotNull(resolvedDefault)
        assertEquals("t-black", resolvedDefault!!.theme.id)
        assertEquals("default", resolvedDefault.source)

        // 3. Signed out: public default applies when no local "user" choice is cached
        assertTrue(ThemeEngine.shouldApplyPublicDefaultWhenSignedOut(blacklight, null))
        assertTrue(
            ThemeEngine.shouldApplyPublicDefaultWhenSignedOut(
                blacklight,
                CachedThemeState(themeId = "t-black", themeName = "Blacklight", variables = mapOf("bg-primary" to "#111111"), source = "default")
            )
        )
        assertFalse(
            ThemeEngine.shouldApplyPublicDefaultWhenSignedOut(
                blacklight,
                CachedThemeState(themeId = "t-nord", themeName = "Nord", variables = mapOf("bg-primary" to "#2e3440"), source = "user")
            )
        )
    }
}
