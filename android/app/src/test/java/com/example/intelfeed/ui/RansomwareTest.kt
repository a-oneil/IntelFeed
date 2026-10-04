package com.example.intelfeed.ui

import com.example.intelfeed.data.model.RansomwareDisclosurePage
import com.example.intelfeed.data.model.RansomwareStats
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.ui.workbench.RansomwareFilters
import com.example.intelfeed.ui.workbench.ransomwareBucket
import com.example.intelfeed.ui.workbench.ransomwareGroupColor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class RansomwareTest {

    @Test
    fun decodesDisclosuresAndStats() {
        val page = ApiJson.json.decodeFromString<RansomwareDisclosurePage>("""{"items":[{"id":"d1","victim_id":"v1","victim_name":"Dao Group",
            "domain":"www.daogroup.com","is_new":true,"watched":false,"group_id":"g1","group_name":"Qilin","group_color":"qilin",
            "sector_label":null,"country_code":"US","posted_at":"2026-09-24T10:00:00Z","source":"ransomware.live"}],"total":161,"offset":0,"limit":60,"has_more":true}""")
        assertEquals("Qilin", page.items.single().groupName)
        assertTrue(page.hasMore)
        val stats = ApiJson.json.decodeFromString<RansomwareStats>("""{"totals":{"victims":2661,"victims_wow":10.1,"groups_active":43,"sectors_hit":12,"watchlist_hits":1},
            "groups":[{"id":"g1","name":"Qilin","color":"qilin","victims":363,"share":13.6,"wow_trend":0,"trend_up":true}],
            "sectors":[{"sector":"manufacturing","label":"Manufacturing","victims":436,"share":16.4}],
            "countries":[{"id":"c1","name":"United States","iso_code":"US","victims":900}],
            "most_active_group":{"id":"g1","name":"Qilin","color":"qilin","victims":363,"share":13.6},
            "timeseries":[{"label":"Jun 22","count":40},{"label":"Jun 29","count":180}],
            "watchlist_exposure":[{"name":"Healthcare","kind":"sector","detail":"3 victims","hit":true}]}""")
        assertEquals(10.1, stats.totals.victimsWow, 0.0)
        assertEquals(2, stats.timeseries.size)
        assertTrue(stats.watchlistExposure.single().hit)
    }

    @Test
    fun groupColoursAndBuckets() {
        assertEquals(ransomwareGroupColor("clop"), ransomwareGroupColor("Cl0p"))
        assertEquals(ransomwareGroupColor("other"), ransomwareGroupColor(null))
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        fun ago(h: Long) = fmt.format(Date(System.currentTimeMillis() - h * 3_600_000))
        assertEquals("Today", ransomwareBucket(ago(2)))
        assertEquals("Yesterday", ransomwareBucket(ago(30)))
        assertEquals("This week", ransomwareBucket(ago(100)))
        assertEquals("Earlier", ransomwareBucket(ago(400)))
        assertEquals(365, RansomwareFilters(days = RansomwareFilters.ALL_DAYS).statsDays)
    }
}
