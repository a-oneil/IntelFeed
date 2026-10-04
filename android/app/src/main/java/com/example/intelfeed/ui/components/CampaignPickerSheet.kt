package com.example.intelfeed.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Campaign
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.Campaign
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.ui.ErrorText
import com.example.intelfeed.theme.CyberGreen
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CampaignPickerSheet(
    entryIds: List<String>,
    repository: IntelFeedRepository,
    onDismiss: () -> Unit,
    onSuccess: (campaignName: String, count: Int) -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()

    var campaigns by remember { mutableStateOf<List<Campaign>>(emptyList()) }
    var existingCampaignIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var loading by remember { mutableStateOf(true) }
    var actionInProgress by remember { mutableStateOf(false) }
    var errorText by remember { mutableStateOf<String?>(null) }

    var showCreateForm by remember { mutableStateOf(false) }
    var newCampaignName by remember { mutableStateOf("") }
    var newCampaignDescription by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        loading = true
        errorText = null
        repository.getCampaigns(limit = 50).fold(
            onSuccess = { page ->
                campaigns = page.items
                if (entryIds.size == 1) {
                    repository.getCampaignsByEntry(entryIds.first()).onSuccess { ids ->
                        existingCampaignIds = ids.toSet()
                    }
                }
                loading = false
            },
            onFailure = { err ->
                errorText = "Couldn't load campaigns. ${ErrorText.describe(err)}"
                loading = false
            }
        )
    }

    fun attachTo(campaignId: String, campaignName: String) {
        actionInProgress = true
        scope.launch {
            // One request for the whole selection (it used to send one request per article and
            // could half-succeed).
            repository.attachEntriesToCampaign(campaignId, entryIds).fold(
                onSuccess = {
                    actionInProgress = false
                    onSuccess(campaignName, entryIds.size)
                    onDismiss()
                },
                onFailure = { err ->
                    actionInProgress = false
                    errorText = "Couldn't add to $campaignName. ${ErrorText.describe(err)}"
                }
            )
        }
    }

    fun createAndAttach() {
        val name = newCampaignName.trim()
        if (name.isBlank()) return
        actionInProgress = true
        scope.launch {
            repository.createCampaign(name, newCampaignDescription.takeIf { it.isNotBlank() }).fold(
                onSuccess = { created ->
                    attachTo(created.id, created.name)
                },
                onFailure = { err ->
                    actionInProgress = false
                    errorText = "Couldn't create the campaign. ${ErrorText.describe(err)}"
                }
            )
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = SlateDark900,
        dragHandle = null
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 32.dp)
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Campaign, contentDescription = null, tint = CyberPurple, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        text = if (entryIds.size == 1) "Add to Campaign" else "Add ${entryIds.size} Articles to Campaign",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Text(
                        text = "Track and correlate intelligence under an active investigation",
                        fontSize = 12.sp,
                        color = TextMuted
                    )
                }
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary)
                }
            }

            HorizontalDivider(color = SlateDark700)

            if (errorText != null) {
                Text(
                    text = errorText!!,
                    color = Color(0xFFEF4444),
                    fontSize = 13.sp,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp)
                )
            }

            // Inline Create Toggle / Form
            if (!showCreateForm) {
                Surface(
                    color = SlateDark800,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 10.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .clickable { showCreateForm = true }
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(CircleShape)
                                .background(CyberPurple.copy(alpha = 0.2f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, tint = CyberPurple, modifier = Modifier.size(18.dp))
                        }
                        Spacer(Modifier.width(12.dp))
                        Text(
                            text = "Create New Campaign",
                            color = CyberPurple,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 14.sp
                        )
                    }
                }
            } else {
                CardSurface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 10.dp)
                ) {
                    Column(Modifier.padding(14.dp)) {
                        Text("New Campaign", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 15.sp)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = newCampaignName,
                            onValueChange = { newCampaignName = it },
                            placeholder = { Text("Campaign Name (e.g. Operation Sentinel)", fontSize = 13.sp, color = TextMuted) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = CyberPurple,
                                unfocusedBorderColor = SlateDark600,
                                focusedTextColor = TextPrimary,
                                unfocusedTextColor = TextPrimary
                            )
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = newCampaignDescription,
                            onValueChange = { newCampaignDescription = it },
                            placeholder = { Text("Description / Objective (optional)", fontSize = 13.sp, color = TextMuted) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = CyberPurple,
                                unfocusedBorderColor = SlateDark600,
                                focusedTextColor = TextPrimary,
                                unfocusedTextColor = TextPrimary
                            )
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                            Button(
                                onClick = { showCreateForm = false },
                                colors = ButtonDefaults.buttonColors(containerColor = SlateDark700),
                                modifier = Modifier.padding(end = 8.dp)
                            ) {
                                Text("Cancel", color = TextSecondary)
                            }
                            Button(
                                onClick = { createAndAttach() },
                                enabled = newCampaignName.isNotBlank() && !actionInProgress,
                                colors = ButtonDefaults.buttonColors(containerColor = CyberPurple)
                            ) {
                                if (actionInProgress) {
                                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = TextPrimary, strokeWidth = 2.dp)
                                } else {
                                    Text("Create & Add", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                    }
                }
            }

            // Existing Campaigns List
            when {
                loading -> {
                    Box(modifier = Modifier.fillMaxWidth().height(140.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = CyberPurple, modifier = Modifier.size(32.dp))
                    }
                }
                campaigns.isEmpty() -> {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("No active campaigns yet.", color = TextMuted, fontSize = 14.sp)
                        Text("Create a new campaign above to get started.", color = TextSecondary, fontSize = 13.sp)
                    }
                }
                else -> {
                    Text(
                        text = "SELECT AN EXISTING CAMPAIGN",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextMuted,
                        letterSpacing = 1.sp,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp)
                    )

                    LazyColumn(modifier = Modifier.fillMaxWidth().height(260.dp)) {
                        items(campaigns, key = { it.id }) { c ->
                            val isAlreadyIn = c.id in existingCampaignIds
                            Surface(
                                color = if (isAlreadyIn) SlateDark800.copy(alpha = 0.6f) else SlateDark800,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 20.dp, vertical = 4.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    // Already holds this article: adding it again would only re-post it.
                                    .clickable(enabled = !actionInProgress && !isAlreadyIn) {
                                        attachTo(c.id, c.name)
                                    }
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = c.name,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 15.sp,
                                                color = TextPrimary,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                            Spacer(Modifier.width(8.dp))
                                            val count = c.effectiveCount
                                            Text(
                                                text = "$count article${if (count == 1) "" else "s"}",
                                                fontSize = 11.sp,
                                                color = TextMuted
                                            )
                                        }
                                        c.description?.takeIf { it.isNotBlank() }?.let { desc ->
                                            Spacer(Modifier.height(2.dp))
                                            Text(
                                                text = desc,
                                                fontSize = 12.sp,
                                                color = TextSecondary,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }
                                    if (isAlreadyIn) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Icon(
                                                Icons.Default.Check,
                                                contentDescription = "Already in campaign",
                                                tint = CyberGreen,
                                                modifier = Modifier.size(18.dp)
                                            )
                                            Spacer(Modifier.width(4.dp))
                                            Text("Added", fontSize = 12.sp, color = CyberGreen, fontWeight = FontWeight.Medium)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
