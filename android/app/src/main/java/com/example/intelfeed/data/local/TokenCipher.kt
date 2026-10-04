package com.example.intelfeed.data.local

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts the session tokens before they're written to DataStore, with an AES-256-GCM key that
 * lives in the Android Keystore and can't be read out of it. On a rooted or compromised device the
 * DataStore file used to hold the access token and the 7-day refresh token in plain text.
 *
 * Stored form: "v1:" + hex(iv) + ":" + hex(ciphertext). Hex rather than Base64 because
 * java.util.Base64 needs Android 8 (minSdk is 24) and android.util.Base64 isn't available in JVM
 * unit tests.
 *
 * Failure handling is deliberately forgiving, so encryption can never lock someone out or crash:
 * - a value without the prefix is a token saved by an older version; it's returned as is and
 *   re-saved encrypted (see AuthPreferences.encryptStoredTokens);
 * - if the Keystore can't provide a key, tokens are stored as before (plain) rather than lost;
 * - if a stored value can't be decrypted (key deleted or invalidated), decrypt returns null and the
 *   app treats the session as signed out.
 *
 * [keyProvider] returns the key, or null when none is available; tests pass a software key.
 */
class TokenCipher(private val keyProvider: () -> SecretKey?) {

    fun isEncrypted(stored: String): Boolean = stored.startsWith(PREFIX)

    fun encrypt(plain: String): String {
        val key = keyProvider() ?: return plain
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key) // the provider picks a random 12-byte IV
            val ciphertext = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            PREFIX + cipher.iv.toHex() + ":" + ciphertext.toHex()
        } catch (e: Exception) {
            plain
        }
    }

    fun decrypt(stored: String): String? {
        if (!isEncrypted(stored)) return stored
        val parts = stored.removePrefix(PREFIX).split(':')
        if (parts.size != 2) return null
        val key = keyProvider() ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, parts[0].hexToBytes()))
            String(cipher.doFinal(parts[1].hexToBytes()), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    companion object {
        private const val PREFIX = "v1:"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val KEY_ALIAS = "intelfeed_session_tokens"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        @Volatile
        private var cachedKey: SecretKey? = null

        /** The app's cipher, backed by a key in the Android Keystore (created on first use). */
        fun androidKeystore(): TokenCipher = TokenCipher(::keystoreKey)

        @Synchronized
        private fun keystoreKey(): SecretKey? {
            cachedKey?.let { return it }
            return try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                val key = (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                    .apply {
                        init(
                            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setKeySize(256)
                                .build()
                        )
                    }
                    .generateKey()
                key.also { cachedKey = it }
            } catch (e: Exception) {
                null
            }
        }

        private val HEX = "0123456789abcdef".toCharArray()

        private fun ByteArray.toHex(): String {
            val out = CharArray(size * 2)
            forEachIndexed { i, b ->
                val v = b.toInt() and 0xff
                out[i * 2] = HEX[v ushr 4]
                out[i * 2 + 1] = HEX[v and 0x0f]
            }
            return String(out)
        }

        private fun String.hexToBytes(): ByteArray {
            require(length % 2 == 0) { "Odd-length hex" }
            return ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        }
    }
}
