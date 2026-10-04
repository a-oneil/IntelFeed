package com.example.intelfeed.ui

import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.ui.navigation.Route
import com.example.intelfeed.ui.navigation.RouteCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RouteCodecTest {

    @Test
    fun everyRouteSurvivesARoundTrip() {
        val stack = listOf(
            Route.Home,
            Route.Reader("a1", listOf("a0", "a1", "a2")),
            Route.Reader("b1"),
            Route.Entity(EntityType.WEAKNESS, "CWE-416", "CWE-416: Use After Free"),
            Route.Thread("check-point-vpn", null),
            Route.Settings,
            Route.Requirements
        )
        assertEquals(stack, RouteCodec.decode(RouteCodec.encode(stack)!!))
    }

    @Test
    fun unreadableSavedStateIsIgnored() {
        assertNull(RouteCodec.decode("not json"))
        assertNull(RouteCodec.decode("""[{"route":"SomethingNew"}]"""))
    }
}
