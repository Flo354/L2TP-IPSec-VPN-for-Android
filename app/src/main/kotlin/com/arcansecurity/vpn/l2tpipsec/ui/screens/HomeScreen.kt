package com.arcansecurity.vpn.l2tpipsec.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelStats
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.isTransient
import com.arcansecurity.vpn.l2tpipsec.service.VpnFailure
import com.arcansecurity.vpn.l2tpipsec.ui.components.StatusCard
import com.arcansecurity.vpn.l2tpipsec.ui.profile.displayServer

/**
 * What the app opens on: the tunnel's state, one button, and the profile that button will use.
 *
 * The profile list is deliberately one tap away rather than the landing screen. Most installations
 * have exactly one profile, and making those users walk through a list of one to reach the connect
 * button would be paying for the rare case with the common one.
 */
@Composable
fun HomeScreen(
    state: TunnelState,
    detail: String?,
    info: TunnelInfo?,
    stats: TunnelStats,
    failure: VpnFailure?,
    connectedSinceMs: Long,
    activeProfile: VpnProfile?,
    profileCount: Int,
    storeIsUnreadable: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onEditActive: () -> Unit,
    onOpenProfiles: () -> Unit,
    onCreateProfile: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
    ) {
        StatusCard(
            state = state,
            detail = detail,
            info = info,
            stats = stats,
            failure = failure,
            connectedSinceMs = connectedSinceMs,
        )

        // Without the credential store there is nothing to connect with and nowhere to put a
        // profile, so the rest of the screen is not merely disabled — it is absent. Offering a
        // Connect button that can only fail, or a form whose Save is guaranteed to be lost, would
        // read as a bug rather than as the deliberate refusal it is.
        if (storeIsUnreadable) {
            Spacer(Modifier.height(16.dp))
            Warning(
                "The secure credential store is unavailable, so this app cannot run. It refuses to " +
                    "keep a pre-shared key or a password anywhere but the device keystore. This " +
                    "usually follows a restore onto another device or an OS upgrade that replaced " +
                    "the master key; reinstalling the app normally clears it.",
            )
            Spacer(Modifier.height(32.dp))
            return@Column
        }

        Spacer(Modifier.height(16.dp))
        ConnectButton(
            state = state,
            enabled = activeProfile != null,
            onConnect = onConnect,
            onDisconnect = onDisconnect,
        )

        Spacer(Modifier.height(16.dp))
        if (activeProfile == null) {
            NoProfileCard(onCreateProfile = onCreateProfile)
        } else {
            ActiveProfileCard(
                profile = activeProfile,
                profileCount = profileCount,
                onEdit = onEditActive,
                onOpenProfiles = onOpenProfiles,
            )
        }

        Spacer(Modifier.height(16.dp))
        Footer(activeProfile)
        Spacer(Modifier.height(32.dp))
    }
}

@Composable
private fun ActiveProfileCard(
    profile: VpnProfile,
    profileCount: Int,
    onEdit: () -> Unit,
    onOpenProfiles: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                text = "ACTIVE PROFILE",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.height(8.dp))
            Text(profile.displayName, style = MaterialTheme.typography.titleMedium)
            Text(
                text = profile.displayServer,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = onEdit) { Text("Edit") }
                TextButton(onClick = onOpenProfiles) {
                    Text(if (profileCount > 1) "Profiles ($profileCount)" else "All profiles")
                }
            }
        }
    }
}

@Composable
private fun NoProfileCard(onCreateProfile: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text("No profile yet", style = MaterialTheme.typography.titleMedium)
            Text(
                text = "Add the server address, the pre-shared key and your PPP credentials to " +
                    "get started.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            Button(onClick = onCreateProfile) { Text("Create a profile") }
        }
    }
}

/** One big button whose meaning is never ambiguous. */
@Composable
private fun ConnectButton(
    state: TunnelState,
    enabled: Boolean,
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
            enabled = enabled,
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
internal fun Warning(text: String) {
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
private fun Footer(profile: VpnProfile?) {
    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Text(
            text = "IKEv1 · ESP in UDP/4500 · L2TP · PPP" +
                if (profile?.debugLogging == true) " · debug logging on" else "",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}
