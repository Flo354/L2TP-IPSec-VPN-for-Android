package com.arcansecurity.vpn.l2tpipsec.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelStats
import com.arcansecurity.vpn.l2tpipsec.isTransient
import com.arcansecurity.vpn.l2tpipsec.label
import com.arcansecurity.vpn.l2tpipsec.service.VpnFailure
import com.arcansecurity.vpn.l2tpipsec.ui.formatBytes
import com.arcansecurity.vpn.l2tpipsec.ui.formatDuration
import com.arcansecurity.vpn.l2tpipsec.ui.theme.MonoTextStyle
import com.arcansecurity.vpn.l2tpipsec.ui.theme.statusColors
import kotlinx.coroutines.delay

/**
 * The card the user watches while debugging: connection state, everything the peer negotiated,
 * live counters and the uptime.
 */
@Composable
fun StatusCard(
    state: TunnelState,
    detail: String?,
    info: TunnelInfo?,
    stats: TunnelStats,
    failure: VpnFailure?,
    connectedSinceMs: Long,
    modifier: Modifier = Modifier,
) {
    val palette = statusColors
    val accent = when {
        state == TunnelState.CONNECTED -> palette.connected
        state == TunnelState.FAILED -> palette.failed
        state.isTransient -> palette.working
        else -> palette.idle
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusDot(color = accent, pulsing = state.isTransient)
                Spacer(Modifier.size(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = state.label,
                        style = MaterialTheme.typography.titleLarge,
                        color = accent,
                    )
                    val subtitle = detail ?: failure?.message?.takeIf { state == TunnelState.FAILED }
                    if (subtitle != null) {
                        Text(
                            text = subtitle,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                if (state == TunnelState.CONNECTED) {
                    Uptime(connectedSinceMs = connectedSinceMs, statsSinceMs = stats.connectedSinceMs)
                }
            }

            AnimatedVisibility(visible = failure != null && state != TunnelState.CONNECTED) {
                failure?.let { FailureBanner(it) }
            }

            AnimatedVisibility(visible = info != null) {
                info?.let { TunnelDetails(it, stats) }
            }
        }
    }
}

@Composable
private fun StatusDot(color: Color, pulsing: Boolean) {
    val transition = rememberInfiniteTransition(label = "status-pulse")
    val alpha by transition.animateFloat(
        initialValue = 1f,
        targetValue = 0.25f,
        animationSpec = infiniteRepeatable(tween(900), RepeatMode.Reverse),
        label = "status-pulse-alpha",
    )
    Box(
        modifier = Modifier
            .size(14.dp)
            .alpha(if (pulsing) alpha else 1f)
            .clip(RoundedCornerShape(50))
            .background(color),
    )
}

@Composable
private fun Uptime(connectedSinceMs: Long, statsSinceMs: Long) {
    // The service's own wall-clock stamp is authoritative; the stack's is only a fallback.
    val since = if (connectedSinceMs > 0) connectedSinceMs else statsSinceMs
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    androidx.compose.runtime.LaunchedEffect(since) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1_000)
        }
    }
    Text(
        text = if (since > 0) formatDuration(now - since) else "—",
        style = MonoTextStyle,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.End,
    )
}

@Composable
private fun FailureBanner(failure: VpnFailure) {
    Column(modifier = Modifier.padding(top = 16.dp)) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.errorContainer)
                .padding(14.dp),
        ) {
            Column {
                Text(
                    text = failure.kind.label,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
                Text(
                    text = failure.message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }
    }
}

@Composable
private fun TunnelDetails(info: TunnelInfo, stats: TunnelStats) {
    Column(modifier = Modifier.padding(top = 16.dp)) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(12.dp))

        DetailRow("Server", info.serverAddress)
        DetailRow("Assigned IP", info.assignedAddress)
        DetailRow("Peer", info.peerAddress)
        DetailRow("DNS", info.dnsServers.joinToString(", ").ifEmpty { "—" })
        DetailRow("MTU", info.mtu.toString())
        DetailRow(
            "Encapsulation",
            buildString {
                append(if (info.udpEncapsulated) "UDP 4500" else "raw ESP")
                append(if (info.natDetected) " · NAT detected" else " · no NAT")
            },
        )
        DetailRow("Phase 1", info.phase1Description)
        DetailRow("Phase 2", info.phase2Description)
        DetailRow("PPP auth", info.pppAuthDescription)

        Spacer(Modifier.height(12.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Counter("Received", formatBytes(stats.bytesIn), "${stats.packetsIn} pkt")
            Counter("Sent", formatBytes(stats.bytesOut), "${stats.packetsOut} pkt")
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.38f),
        )
        Text(
            text = value,
            style = MonoTextStyle,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(0.62f),
        )
    }
}

@Composable
private fun Counter(label: String, value: String, sub: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(text = value, style = MaterialTheme.typography.titleMedium)
        Text(
            text = sub,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
