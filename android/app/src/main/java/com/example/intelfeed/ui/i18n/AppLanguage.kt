package com.example.intelfeed.ui.i18n

import java.util.Locale

enum class AppLanguage(val code: String, val displayName: String, val nativeName: String) {
    SYSTEM("system", "System default", "System default"),
    ENGLISH("en", "English", "English"),
    SPANISH("es", "Spanish", "Español"),
    FRENCH("fr", "French", "Français"),
    GERMAN("de", "German", "Deutsch"),
    UKRAINIAN("uk", "Ukrainian", "Українська"),
    RUSSIAN("ru", "Russian", "Русский"),
    CHINESE("zh", "Chinese", "简体中文"),
    JAPANESE("ja", "Japanese", "日本語"),
    PORTUGUESE("pt", "Portuguese", "Português"),
    ITALIAN("it", "Italian", "Italiano");

    fun getEffectiveName(): String {
        return if (this == SYSTEM) {
            val systemLocale = Locale.getDefault()
            val sysName = systemLocale.getDisplayLanguage(systemLocale).replaceFirstChar { it.uppercase() }
            "System default ($sysName)"
        } else {
            if (displayName == nativeName) displayName else "$displayName ($nativeName)"
        }
    }

    companion object {
        fun fromCode(code: String): AppLanguage {
            return entries.find { it.code.equals(code, ignoreCase = true) } ?: SYSTEM
        }
    }
}
