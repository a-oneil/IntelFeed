package com.example.intelfeed.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// The web Workbench's Ransomware tracker (RansomwareSection): leak-site victim postings and their
// statistics. Field names as the web client reads them.

/** GET /api/ransomware/disclosures (limit, offset, sort=recent|group|sector, group/sector/country repeated, watched_only, since=days, q). */
@Serializable
data class RansomwareDisclosurePage(
    val items: List<RansomwareDisclosure> = emptyList(),
    val total: Int = 0,
    val offset: Int = 0,
    val limit: Int = 60,
    @SerialName("has_more") val hasMore: Boolean = false
)

@Serializable
data class RansomwareDisclosure(
    val id: String,
    @SerialName("victim_id") val victimId: String? = null,
    @SerialName("victim_name") val victimName: String = "",
    val domain: String? = null,
    @SerialName("is_new") val isNew: Boolean = false,
    // The organisation is on your watchlist (entity type "ransomware_victim").
    val watched: Boolean = false,
    // The group is a threat-actor row; its profile opens by this id.
    @SerialName("group_id") val groupId: String? = null,
    @SerialName("group_name") val groupName: String? = null,
    @SerialName("group_color") val groupColor: String? = null,
    @SerialName("sector_label") val sectorLabel: String? = null,
    @SerialName("country_code") val countryCode: String? = null,
    @SerialName("claimed_data") val claimedData: String? = null,
    @SerialName("posted_at") val postedAt: String? = null,
    // The leak site's publish deadline.
    @SerialName("published_at") val publishedAt: String? = null,
    val source: String? = null,
    @SerialName("leak_site_url") val leakSiteUrl: String? = null
)

/** GET /api/ransomware/stats?days=N. */
@Serializable
data class RansomwareStats(
    val totals: RansomwareTotals = RansomwareTotals(),
    val groups: List<RansomwareGroupStat> = emptyList(),
    val sectors: List<RansomwareSectorStat> = emptyList(),
    val countries: List<RansomwareCountryStat> = emptyList(),
    @SerialName("most_active_group") val mostActiveGroup: RansomwareGroupStat? = null,
    @SerialName("fastest_riser") val fastestRiser: RansomwareGroupStat? = null,
    // Weekly new-victim postings.
    val timeseries: List<RansomwarePoint> = emptyList(),
    @SerialName("watchlist_exposure") val watchlistExposure: List<RansomwareExposure> = emptyList()
)

@Serializable
data class RansomwareTotals(
    val victims: Int = 0,
    // Percent change against the previous window.
    @SerialName("victims_wow") val victimsWow: Double = 0.0,
    @SerialName("groups_active") val groupsActive: Int = 0,
    @SerialName("sectors_hit") val sectorsHit: Int = 0,
    @SerialName("watchlist_hits") val watchlistHits: Int = 0
)

@Serializable
data class RansomwareGroupStat(
    val id: String? = null,
    val name: String = "",
    val color: String? = null,
    val victims: Int = 0,
    val share: Double = 0.0,
    @SerialName("wow_trend") val wowTrend: Double = 0.0,
    @SerialName("trend_up") val trendUp: Boolean = false
)

@Serializable
data class RansomwareSectorStat(val sector: String = "", val label: String = "", val victims: Int = 0, val share: Double = 0.0)

@Serializable
data class RansomwareCountryStat(val id: String? = null, val name: String = "", @SerialName("iso_code") val isoCode: String? = null, val victims: Int = 0)

@Serializable
data class RansomwarePoint(val label: String = "", val count: Int = 0)

@Serializable
data class RansomwareExposure(val name: String = "", val kind: String = "", val detail: String = "", val hit: Boolean = false)
