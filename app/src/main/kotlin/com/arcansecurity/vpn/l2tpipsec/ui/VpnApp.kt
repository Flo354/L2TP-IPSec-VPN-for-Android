package com.arcansecurity.vpn.l2tpipsec.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.data.ProfileField
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.isTransient
import com.arcansecurity.vpn.l2tpipsec.ui.components.AdvancedSection
import com.arcansecurity.vpn.l2tpipsec.ui.components.ProfileForm
import com.arcansecurity.vpn.l2tpipsec.ui.components.StatusCard

/** The whole app: one screen, plus the logs on a bottom sheet. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnApp(
    controller: VpnController,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val profile by controller.draft.collectAsState()
    val touched by controller.touched.collectAsState()
    val showAllErrors by controller.showAllErrors.collectAsState()
    val advancedExpanded by controller.advancedExpanded.collectAsState()
    val message by controller.message.collectAsState()
    val profileWasUnreadable by controller.profileWasUnreadable.collectAsState()

    val state by controller.status.state.collectAsState()
    val detail by controller.status.detail.collectAsState()
    val info by controller.status.info.collectAsState()
    val stats by controller.status.stats.collectAsState()
    val failure by controller.status.failure.collectAsState()
    val connectedSince by controller.status.connectedSinceMs.collectAsState()

    var logsVisible by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(message) {
        message?.let {
            snackbarHostState.showSnackbar(it)
            controller.consumeMessage()
        }
    }

    val validation = remember(profile) { controller.validation }
    val errorFor: (ProfileField) -> String? = { field ->
        validation[field]?.takeIf { showAllErrors || field in touched }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("L2TP/IPsec VPN") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                actions = {
                    IconButton(onClick = { logsVisible = true }) {
                        Icon(Icons.AutoMirrored.Filled.List, contentDescription = "Logs")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            StatusCard(
                state = state,
                detail = detail,
                info = info,
                stats = stats,
                failure = failure,
                connectedSinceMs = connectedSince,
            )

            Spacer(Modifier.height(16.dp))
            ConnectButton(state = state, onConnect = onConnect, onDisconnect = onDisconnect)

            if (!controller.usesEncryptedStorage) {
                Spacer(Modifier.height(12.dp))
                Warning(
                    "This device's keystore is unavailable, so the pre-shared key and password " +
                        "are stored unencrypted.",
                )
            }

            if (profileWasUnreadable) {
                Spacer(Modifier.height(12.dp))
                Warning(
                    "The saved profile could not be decrypted and has been cleared. This happens " +
                        "when the device's master key is replaced, usually after a restore. " +
                        "Please enter the settings again.",
                )
            }

            Spacer(Modifier.height(16.dp))
            ProfileForm(
                profile = profile,
                enabled = state == TunnelState.IDLE || state == TunnelState.FAILED,
                errorFor = errorFor,
                onChange = { field, transform -> controller.edit(field, transform) },
            )

            Spacer(Modifier.height(16.dp))
            AdvancedSection(
                profile = profile,
                expanded = advancedExpanded,
                onToggle = controller::toggleAdvanced,
                errorFor = errorFor,
                onChange = { field, transform -> controller.edit(field, transform) },
            )

            Spacer(Modifier.height(16.dp))
            Footer(profile)
            Spacer(Modifier.height(32.dp))
        }
    }

    if (logsVisible) {
        LogsSheet(logger = controller.logger, onDismiss = { logsVisible = false })
    }
}

/** One big button whose meaning is never ambiguous. */
@Composable
private fun ConnectButton(
    state: TunnelState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val busy = state.isTransient
    val connected = state == TunnelState.CONNECTED

    if (connected || busy) {
        OutlinedButton(
            onClick = onDisconnect,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.size(12.dp))
            }
            Text(
                text = if (connected) "Disconnect" else "Cancel",
                style = MaterialTheme.typography.titleMedium,
            )
        }
    } else {
        Button(
            onClick = onConnect,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            ),
        ) {
            Text("Connect", style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
private fun Warning(text: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.errorContainer, RoundedCornerShape(12.dp))
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
    }
}

@Composable
private fun Footer(profile: VpnProfile) {
    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Text(
            text = "IKEv1 · ESP in UDP/4500 · L2TP · PPP" +
                if (profile.debugLogging) " · debug logging on" else "",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}
