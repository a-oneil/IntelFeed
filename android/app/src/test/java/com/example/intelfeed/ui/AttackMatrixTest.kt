package com.example.intelfeed.ui

import com.example.intelfeed.data.model.AttackMatrix
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.ui.workbench.matrixHeat
import org.junit.Assert.assertEquals
import org.junit.Test

class AttackMatrixTest {

    @Test
    fun decodesTheMatrixPayload() {
        // Field names as the web's AttackMatrixSection reads them.
        val m = ApiJson.json.decodeFromString<AttackMatrix>("""{"domain":"enterprise","days":30,"technique_count":2,"max_article_count":24,
            "coverage_summary":{"covered":1,"library_only":0,"no_rule":1},
            "tactics":[{"id":"TA0043","name":"Reconnaissance","techniques":[{"id":"r1","technique_id":"T1595","name":"Active Scanning",
              "article_count":12,"rollup_article_count":24,"rule_count":3,"coverage":"covered","missing_data_sources":[],
              "subtechniques":[{"id":"r2","technique_id":"T1595.001","name":"Scanning IP Blocks","article_count":4,"rule_count":0,"coverage":"no_rule"}]}]}]}""")
        assertEquals(1, m.tactics.size)
        val t = m.tactics.single().techniques.single()
        assertEquals(24, t.rollupArticleCount)
        assertEquals("no_rule", t.subtechniques.single().coverage)
        assertEquals(1, m.coverageSummary.noRule)
    }

    @Test
    fun heatFollowsTheWebFormula() {
        assertEquals(0f, matrixHeat(0, 24), 0f)
        assertEquals(0.9f, matrixHeat(24, 24), 1e-6f)
        // 0.15 + 0.75 * sqrt(6/24) = 0.525
        assertEquals(0.525f, matrixHeat(6, 24), 1e-6f)
    }
}
