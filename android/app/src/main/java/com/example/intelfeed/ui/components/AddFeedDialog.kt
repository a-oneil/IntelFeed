package com.example.intelfeed.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.Category
import com.example.intelfeed.data.model.DiscoveredFeed
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.ErrorText
import com.example.intelfeed.util.WebUrl

private enum class AddMode { FEED, ARTICLE }

// The web's Add Feed choices; null keeps the server default.
private val POLL_INTERVALS = listOf(
    null to "Default (30 min)",
    15 to "Every 15 min",
    30 to "Every 30 min",
    60 to "Every hour",
    360 to "Every 6 hours",
    1440 to "Once a day"
)

/**
 * "Add" from the feeds drawer. Two explicit choices, like the website:
 * - Subscribe to a feed: find the feed at an address first (discover, which changes nothing),
 *   show what was found, then subscribe with a folder and polling interval.
 * - Add one article: fetch one page and add it as an article.
 * Nothing is added until the user confirms the preview. (The old dialog subscribed and, if that
 * failed for any reason, silently added the address as an article instead.)
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AddFeedDialog(
    categories: List<Category>,
    onDismiss: () -> Unit,
    onDiscover: (url: String, onResult: (Result<List<DiscoveredFeed>>) -> Unit) -> Unit,
    onSubscribe: (feed: DiscoveredFeed, categoryId: String?, intervalMinutes: Int?) -> Unit,
    onAddArticle: (url: String) -> Unit
) {
    var mode by rememberSaveable { mutableStateOf(AddMode.FEED) }
    var input by rememberSaveable { mutableStateOf("") }
    var categoryId by rememberSaveable { mutableStateOf<String?>(null) }
    var interval by rememberSaveable { mutableStateOf<Int?>(null) }
    // Discovery results belong to the address they were found for; editing the address clears them.
    var discovered by remember { mutableStateOf<List<DiscoveredFeed>>(emptyList()) }
    var chosen by remember { mutableStateOf<DiscoveredFeed?>(null) }
    var searching by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    // The theme's secondary colour is green; the rest of the app uses blue for selection.
    val chipColors = FilterChipDefaults.filterChipColors(selectedContainerColor = CyberBlue, selectedLabelColor = SlateDark900)
    val segmentColors = SegmentedButtonDefaults.colors(
        activeContainerColor = CyberBlue.copy(alpha = 0.2f),
        activeContentColor = CyberBlue,
        activeBorderColor = CyberBlue
    )

    val url = WebUrl.normalize(input)
    val folders = remember(categories) { flattenCategories(categories) }

    fun resetDiscovery() {
        discovered = emptyList(); chosen = null; error = null
    }

    fun discover() {
        val target = url ?: run { error = "Enter a web address, e.g. example.com/feed"; return }
        searching = true
        error = null
        onDiscover(target) { result ->
            searching = false
            result.fold(
                onSuccess = { found -> discovered = found; chosen = found.firstOrNull() },
                onFailure = { e ->
                    discovered = emptyList(); chosen = null
                    error = if (e is NoSuchElementException) "Couldn't find a feed at this address. Try the site's RSS or Atom link."
                    else "Couldn't check this address. ${ErrorText.describe(e)}"
                }
            )
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add to IntelFeed") },
        text = {
            Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    SegmentedButton(
                        selected = mode == AddMode.FEED,
                        onClick = { mode = AddMode.FEED; error = null },
                        shape = SegmentedButtonDefaults.itemShape(0, 2),
                        colors = segmentColors,
                        label = { Text("Subscribe to feed", fontSize = 12.sp, maxLines = 1) }
                    )
                    SegmentedButton(
                        selected = mode == AddMode.ARTICLE,
                        onClick = { mode = AddMode.ARTICLE; error = null },
                        shape = SegmentedButtonDefaults.itemShape(1, 2),
                        colors = segmentColors,
                        label = { Text("Add one article", fontSize = 12.sp, maxLines = 1) }
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    if (mode == AddMode.FEED) "Paste a feed address or a website. IntelFeed looks for its RSS or Atom feed and shows it before you subscribe."
                    else "IntelFeed fetches this one page, adds it as an article and extracts its intelligence. It doesn't subscribe to the site.",
                    fontSize = 13.sp,
                    color = TextMuted
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it; resetDiscovery() },
                    label = { Text(if (mode == AddMode.FEED) "Feed or website address" else "Page address") },
                    placeholder = { Text(if (mode == AddMode.FEED) "example.com/feed" else "https://example.com/article") },
                    singleLine = true,
                    isError = input.isNotBlank() && url == null,
                    supportingText = if (input.isNotBlank() && url == null) { { Text("That doesn't look like a web address.") } } else null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
                    modifier = Modifier.fillMaxWidth()
                )

                error?.let {
                    Spacer(Modifier.height(6.dp))
                    Text(it, color = CyberAmber, fontSize = 13.sp)
                }

                if (mode == AddMode.FEED && discovered.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        if (discovered.size == 1) "Feed found" else "${discovered.size} feeds found. Pick one:",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(6.dp))
                    discovered.forEach { feed ->
                        DiscoveredFeedRow(
                            feed = feed,
                            selected = chosen?.url == feed.url,
                            showRadio = discovered.size > 1,
                            onClick = { chosen = feed }
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Text("Folder", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
                    Spacer(Modifier.height(4.dp))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        FilterChip(selected = categoryId == null, onClick = { categoryId = null }, label = { Text("Uncategorized", fontSize = 12.sp) }, colors = chipColors)
                        folders.forEach { (id, name) ->
                            FilterChip(selected = categoryId == id, onClick = { categoryId = id }, label = { Text(name, fontSize = 12.sp) }, colors = chipColors)
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    Text("Check for new articles", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
                    Spacer(Modifier.height(4.dp))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        POLL_INTERVALS.forEach { (minutes, label) ->
                            FilterChip(selected = interval == minutes, onClick = { interval = minutes }, label = { Text(label, fontSize = 12.sp) }, colors = chipColors)
                        }
                    }
                }
            }
        },
        confirmButton = {
            when {
                mode == AddMode.ARTICLE -> TextButton(
                    enabled = url != null,
                    onClick = { url?.let { onAddArticle(it); onDismiss() } }
                ) { Text("Add article") }
                chosen == null -> TextButton(
                    enabled = url != null && !searching,
                    onClick = { discover() }
                ) { Text(if (searching) "Looking…" else "Find feed") }
                else -> TextButton(onClick = {
                    chosen?.let { onSubscribe(it, categoryId, interval) }
                    onDismiss()
                }) { Text("Subscribe") }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
private fun DiscoveredFeedRow(feed: DiscoveredFeed, selected: Boolean, showRadio: Boolean, onClick: () -> Unit) {
    Surface(
        color = if (selected) CyberBlue.copy(alpha = 0.12f) else SlateDark700.copy(alpha = 0.4f),
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .clip(RoundedCornerShape(10.dp))
            .then(if (showRadio) Modifier.selectable(selected = selected, onClick = onClick, role = Role.RadioButton) else Modifier.clickable(onClick = onClick))
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(10.dp)) {
            if (showRadio) {
                RadioButton(selected = selected, onClick = null)
                Spacer(Modifier.width(8.dp))
            }
            Column(Modifier.weight(1f)) {
                Text(feed.title?.takeIf { it.isNotBlank() } ?: feed.url, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                feed.description?.takeIf { it.isNotBlank() }?.let {
                    Text(it, fontSize = 12.sp, color = TextSecondary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
                Text(listOfNotNull(feed.typeLabel, feed.url).joinToString(" · "), fontSize = 11.sp, color = TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

/** Every folder, children indented under their parent as "Parent › Child", in server order. */
private fun flattenCategories(categories: List<Category>): List<Pair<String, String>> = buildList {
    fun visit(c: Category, prefix: String) {
        val name = if (prefix.isEmpty()) c.name else "$prefix › ${c.name}"
        add(c.id to name)
        c.children.sortedBy { it.position }.forEach { visit(it, name) }
    }
    categories.sortedBy { it.position }.forEach { visit(it, "") }
}
