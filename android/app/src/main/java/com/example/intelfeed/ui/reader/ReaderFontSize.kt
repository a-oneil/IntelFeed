package com.example.intelfeed.ui.reader

import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp

/** Article text sizes. The choice is saved on the device (UserPreferences) and applies to every article. */
enum class ReaderFontSize(val label: String, val size: TextUnit, val lineHeight: TextUnit) {
    SMALL("Small", 14.sp, 22.sp),
    MEDIUM("Medium", 16.sp, 26.sp),
    LARGE("Large", 18.sp, 29.sp),
    XLARGE("Extra large", 21.sp, 33.sp);

    companion object {
        fun fromName(name: String?): ReaderFontSize = entries.firstOrNull { it.name == name } ?: MEDIUM
    }
}
