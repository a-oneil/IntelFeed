package com.example.intelfeed.data

import com.example.intelfeed.data.network.ServerUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerUrlTest {

    @Test
    fun testValidUrlsAreNormalized() {
        assertEquals("https://intelfeed.example.com", ServerUrl.normalize("https://intelfeed.example.com/"))
        assertEquals("https://intelfeed.example.com", ServerUrl.normalize("  intelfeed.example.com  "))
        assertEquals("http://192.168.1.10:8000", ServerUrl.normalize("http://192.168.1.10:8000"))
        assertEquals("https://intelfeed.local:8443", ServerUrl.normalize("intelfeed.local:8443"))
        assertEquals("https://host.example/app", ServerUrl.normalize("https://host.example/app/?x=1#frag"))
    }

    @Test
    fun testPartialAndUnsupportedUrlsAreRejected() {
        // Partial values typed mid-edit. Each of these used to crash Retrofit.baseUrl().
        assertNull(ServerUrl.normalize(""))
        assertNull(ServerUrl.normalize("https://"))
        assertNull(ServerUrl.normalize("https:/"))
        assertNull(ServerUrl.normalize("http:"))
        assertNull(ServerUrl.normalize("ftp://intelfeed.example.com"))
        assertNull(ServerUrl.normalize("https://user:password@intelfeed.example.com"))
    }

    @Test
    fun cleartextAddressesAreFlagged() {
        assertTrue(ServerUrl.isCleartext("http://192.168.1.20:8080"))
        assertTrue(ServerUrl.isCleartext("HTTP://intelfeed.lan"))
        assertFalse(ServerUrl.isCleartext("https://intelfeed.example.com"))
        assertFalse(ServerUrl.isCleartext("intelfeed.example.com")) // no scheme means https
        assertFalse(ServerUrl.isCleartext("http:")) // not a usable address yet
    }
}
