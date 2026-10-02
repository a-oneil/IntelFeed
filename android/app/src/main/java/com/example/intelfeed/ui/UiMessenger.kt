package com.example.intelfeed.ui

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/** A snackbar message, optionally with one action (e.g. Undo, Retry, Open). */
data class UiMessage(
    val text: String,
    val actionLabel: String? = null,
    val onAction: (() -> Unit)? = null
)

/**
 * App-wide snackbar channel. ViewModels post here; the root composable shows the messages. One
 * instance per process (IntelFeedApplication), so a message survives navigating away from the
 * screen that posted it.
 */
class UiMessenger {
    private val _messages = MutableSharedFlow<UiMessage>(extraBufferCapacity = 16)
    val messages: SharedFlow<UiMessage> = _messages.asSharedFlow()

    fun show(text: String, actionLabel: String? = null, onAction: (() -> Unit)? = null) {
        _messages.tryEmit(UiMessage(text, actionLabel, onAction))
    }

    /** "Couldn't <action>: <reason>" with the server's reason cleaned up. */
    fun showError(action: String, error: Throwable, retry: (() -> Unit)? = null) {
        show("Couldn't $action. ${ErrorText.describe(error)}", if (retry != null) "Retry" else null, retry)
    }
}
