package com.example.intelfeed.ui

import retrofit2.HttpException
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/** Turns exceptions into short sentences for people, instead of raw exception messages. */
object ErrorText {
    fun describe(error: Throwable?): String = when {
        error == null -> "Something went wrong."
        // Cleartext / SSL policy issues
        error.message?.contains("CLEARTEXT", ignoreCase = true) == true ->
            "Cleartext HTTP is not permitted for this domain. Use an HTTPS address."
        error is SSLException ->
            "Secure connection failed. Check your server's SSL certificate."
        error is ConnectException ->
            "Could not connect to the server. Check the address and port."
        // The server sent a shape the app doesn't understand (usually a newer server). The raw
        // parser message is useless to a reader; it's still in logcat via the exception.
        error is kotlinx.serialization.SerializationException ->
            "The server sent data this version of the app can't read. Try again, or update the app."
        error is UnknownHostException ->
            "Can't reach the server. Check your connection or the server address."
        error is SocketTimeoutException ->
            "The server took too long to answer. Try again."
        error is HttpException -> when (error.code()) {
            400, 422 -> "The server rejected the request."
            401 -> "Your session has expired. Sign in again."
            403 -> "You don't have permission to do that."
            404 -> "It isn't on the server any more."
            409 -> "That conflicts with a change someone else made."
            429 -> "Too many requests. Wait a moment and try again."
            in 500..599 -> "The server had a problem (${error.code()}). Try again shortly."
            else -> "The server returned an error (${error.code()})."
        }
        error is IOException -> "Network problem. Check your connection and try again."
        else -> error.localizedMessage?.takeIf { it.isNotBlank() } ?: "Something went wrong."
    }
}
