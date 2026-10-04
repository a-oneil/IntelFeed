package com.example.intelfeed.data

import com.example.intelfeed.data.local.TokenCipher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Session-token encryption, with a software AES key standing in for the Keystore key. */
class TokenCipherTest {

    private fun newKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJrdXJ0In0.signature-part_123"

    @Test
    fun roundTripsAndHidesTheToken() {
        val key = newKey()
        val cipher = TokenCipher { key }
        val stored = cipher.encrypt(token)
        assertTrue(cipher.isEncrypted(stored))
        assertFalse(stored.contains("eyJ"))
        assertEquals(token, cipher.decrypt(stored))
    }

    @Test
    fun everyEncryptionUsesAFreshIv() {
        val key = newKey()
        val cipher = TokenCipher { key }
        assertNotEquals(cipher.encrypt(token), cipher.encrypt(token))
    }

    @Test
    fun aTokenSavedByAnOlderVersionIsReadAsIs() {
        // Existing installs stored plain tokens; they must keep working until re-saved encrypted.
        assertEquals(token, TokenCipher { newKey() }.decrypt(token))
    }

    @Test
    fun withoutAKeyTokensAreKeptRatherThanLost() {
        val noKey = TokenCipher { null }
        assertEquals(token, noKey.encrypt(token))
        assertEquals(token, noKey.decrypt(token))
        // An encrypted value can't be read without the key: treated as signed out.
        assertNull(noKey.decrypt(TokenCipher { newKey() }.encrypt(token)))
    }

    @Test
    fun aWrongKeyOrTamperedValueDecryptsToNull() {
        val stored = TokenCipher { newKey() }.encrypt(token)
        assertNull(TokenCipher { newKey() }.decrypt(stored))
        val key = newKey()
        val cipher = TokenCipher { key }
        val good = cipher.encrypt(token)
        val tampered = good.dropLast(2) + if (good.endsWith("00")) "11" else "00"
        assertNull(cipher.decrypt(tampered))
        assertNull(cipher.decrypt("v1:not-hex"))
        assertNull(cipher.decrypt("v1:abc:def"))
    }
}
