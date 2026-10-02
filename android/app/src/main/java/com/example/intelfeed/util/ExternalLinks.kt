package com.example.intelfeed.util

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast

object ExternalLinks {

    /**
     * Opens [url] in a browser. URLs come from feed content and aren't trusted, so only http(s)
     * links are opened. Other schemes (deep links into other apps, file:, content:, …) are
     * refused. A missing browser shows a toast instead of crashing.
     */
    fun openInBrowser(context: Context, url: String?) {
        val uri = url?.trim()?.takeIf { it.isNotEmpty() }?.let(Uri::parse)
        val scheme = uri?.scheme?.lowercase()
        if (uri == null || (scheme != "http" && scheme != "https")) {
            Toast.makeText(context, "This link can't be opened", Toast.LENGTH_SHORT).show()
            return
        }
        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
            if (context !is android.app.Activity) {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }
        try {
            context.startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(context, "No browser available to open this link", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(context, "This link can't be opened", Toast.LENGTH_SHORT).show()
        }
    }
}
