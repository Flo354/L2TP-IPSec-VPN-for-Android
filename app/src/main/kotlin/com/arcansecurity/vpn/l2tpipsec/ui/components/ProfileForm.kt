package com.arcansecurity.vpn.l2tpipsec.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.label
import com.arcansecurity.vpn.l2tpipsec.ui.profile.ProfileField
import com.arcansecurity.vpn.l2tpipsec.ui.profile.ProfileFormState

/**
 * The always-visible half of the form: what you need to type to reach a router.
 *
 * The two secret fields arrive as slots rather than parameters. That is not decoration: it keeps
 * the characters the user is typing inside the single composable that owns them
 * (`ProfileEditScreen`) instead of threading them through every layer of the form, and it makes it
 * obvious by inspection that this file never sees a secret at all.
 */
@Composable
fun ConnectionSection(
    form: ProfileFormState,
    errorFor: (ProfileField) -> String?,
    onChange: (ProfileField?, (VpnProfile) -> VpnProfile) -> Unit,
    presharedKeyField: @Composable () -> Unit,
    passwordField: @Composable () -> Unit,
    modifier: Modifier = Modifier,
) {
    SectionCard(title = "Connection", modifier = modifier) {
        VpnTextField(
            label = "Profile name",
            value = form.profile.name,
            onValueChange = { value -> onChange(ProfileField.NAME) { it.copy(name = value) } },
            error = errorFor(ProfileField.NAME),
        )
        Spacer(Modifier.height(12.dp))
        VpnTextField(
            label = "Server",
            value = form.profile.server,
            onValueChange = { value -> onChange(ProfileField.SERVER) { it.copy(server = value) } },
            error = errorFor(ProfileField.SERVER),
            placeholder = "vpn.example.com",
            keyboardType = KeyboardType.Uri,
        )
        Spacer(Modifier.height(12.dp))
        presharedKeyField()
        Spacer(Modifier.height(12.dp))
        VpnTextField(
            label = "User name",
            value = form.profile.username,
            onValueChange = { value -> onChange(ProfileField.USERNAME) { it.copy(username = value) } },
            error = errorFor(ProfileField.USERNAME),
        )
        Spacer(Modifier.height(12.dp))
        passwordField()
    }
}

/** Everything a normal user should never have to open. */
@Composable
fun AdvancedSection(
    form: ProfileFormState,
    expanded: Boolean,
    onToggle: () -> Unit,
    errorFor: (ProfileField) -> String?,
    onChange: (ProfileField?, (VpnProfile) -> VpnProfile) -> Unit,
    onMtuChange: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val profile = form.profile
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onToggle)
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text("Advanced", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "${profile.phase1Encryption.label}-${profile.phase1Hash.label}-" +
                        "${profile.phase1DhGroup.label.substringBefore(' ')} · MTU ${form.mtuText}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                imageVector = if (expanded) {
                    Icons.Filled.KeyboardArrowUp
                } else {
                    Icons.Filled.KeyboardArrowDown
                },
                contentDescription = if (expanded) "Collapse" else "Expand",
            )
        }

        AnimatedVisibility(visible = expanded) {
            Column(modifier = Modifier.padding(start = 20.dp, end = 20.dp, bottom = 20.dp)) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(Modifier.height(16.dp))

                SubHeading("IKE (phase 1)")
                EnumDropdown(
                    label = "Exchange mode",
                    options = IkeExchangeMode.entries,
                    selected = profile.exchangeMode,
                    onSelected = { value -> onChange(null) { it.copy(exchangeMode = value) } },
                    labelFor = { it.label },
                )
                Spacer(Modifier.height(12.dp))
                EnumDropdown(
                    label = "Encryption",
                    options = IkeEncryption.entries,
                    selected = profile.phase1Encryption,
                    onSelected = { value -> onChange(null) { it.copy(phase1Encryption = value) } },
                    labelFor = { it.label },
                )
                Spacer(Modifier.height(12.dp))
                EnumDropdown(
                    label = "Hash",
                    options = IkeHash.entries,
                    selected = profile.phase1Hash,
                    onSelected = { value -> onChange(null) { it.copy(phase1Hash = value) } },
                    labelFor = { it.label },
                )
                Spacer(Modifier.height(12.dp))
                EnumDropdown(
                    label = "Diffie-Hellman group",
                    options = DhGroup.entries,
                    selected = profile.phase1DhGroup,
                    onSelected = { value -> onChange(null) { it.copy(phase1DhGroup = value) } },
                    labelFor = { it.label },
                )

                Spacer(Modifier.height(20.dp))
                SubHeading("IPsec (phase 2)")
                EnumDropdown(
                    label = "ESP encryption",
                    options = EspEncryption.entries,
                    selected = profile.phase2Encryption,
                    onSelected = { value -> onChange(null) { it.copy(phase2Encryption = value) } },
                    labelFor = { it.label },
                )
                Spacer(Modifier.height(12.dp))
                EnumDropdown(
                    label = "ESP integrity",
                    options = EspIntegrity.entries,
                    selected = profile.phase2Integrity,
                    onSelected = { value -> onChange(null) { it.copy(phase2Integrity = value) } },
                    labelFor = { it.label },
                )
                Spacer(Modifier.height(12.dp))
                EnumDropdown(
                    label = "PFS group",
                    options = PFS_OPTIONS,
                    selected = profile.phase2PfsGroup,
                    onSelected = { value -> onChange(null) { it.copy(phase2PfsGroup = value) } },
                    labelFor = { group -> group?.label ?: "No PFS" },
                )

                Spacer(Modifier.height(20.dp))
                SubHeading("Identity")
                EnumDropdown(
                    label = "Local identity type",
                    options = IkeIdentityType.entries,
                    selected = profile.identityType,
                    onSelected = { value -> onChange(null) { it.copy(identityType = value) } },
                    labelFor = { it.label },
                )
                if (profile.identityType != IkeIdentityType.AUTO_IPV4) {
                    Spacer(Modifier.height(12.dp))
                    VpnTextField(
                        label = "Identity value",
                        value = profile.identityValue,
                        onValueChange = { value ->
                            onChange(ProfileField.IDENTITY_VALUE) { it.copy(identityValue = value) }
                        },
                        error = errorFor(ProfileField.IDENTITY_VALUE),
                    )
                }

                Spacer(Modifier.height(20.dp))
                SubHeading("PPP authentication")
                PppAuthChips(
                    selected = profile.allowedPppAuth,
                    error = errorFor(ProfileField.PPP_AUTH),
                    onToggle = { protocol ->
                        onChange(ProfileField.PPP_AUTH) { current ->
                            val next = if (protocol in current.allowedPppAuth) {
                                current.allowedPppAuth - protocol
                            } else {
                                current.allowedPppAuth + protocol
                            }
                            current.copy(
                                allowedPppAuth = PppAuthProtocol.entries.filter { it in next },
                            )
                        }
                    },
                )

                Spacer(Modifier.height(20.dp))
                SubHeading("Network")
                VpnTextField(
                    label = "MTU",
                    value = form.mtuText,
                    onValueChange = onMtuChange,
                    error = errorFor(ProfileField.MTU),
                    supporting = "1400 leaves room for the ESP and L2TP headers",
                    keyboardType = KeyboardType.Number,
                )
                Spacer(Modifier.height(12.dp))
                VpnTextField(
                    label = "DNS override",
                    value = profile.dnsServers,
                    onValueChange = { value ->
                        onChange(ProfileField.DNS_SERVERS) { it.copy(dnsServers = value) }
                    },
                    error = errorFor(ProfileField.DNS_SERVERS),
                    supporting = "Comma-separated; empty keeps what IPCP negotiated",
                    placeholder = "192.168.1.1, 9.9.9.9",
                )

                Spacer(Modifier.height(12.dp))
                SwitchRow(
                    title = "Block IPv6",
                    description = "Blackhole ::/0 so dual-stack traffic cannot leak around the tunnel",
                    checked = profile.blockIpv6,
                    onCheckedChange = { value -> onChange(null) { it.copy(blockIpv6 = value) } },
                )
                SwitchRow(
                    title = "Force UDP encapsulation",
                    description = "Always wrap ESP in UDP/4500; Android cannot open raw ESP sockets",
                    checked = profile.forceUdpEncapsulation,
                    onCheckedChange = { value ->
                        onChange(null) { it.copy(forceUdpEncapsulation = value) }
                    },
                )
                SwitchRow(
                    title = "Debug logging",
                    description = "Log every IKE payload and PPP frame to the Logs screen",
                    checked = profile.debugLogging,
                    onCheckedChange = { value -> onChange(null) { it.copy(debugLogging = value) } },
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PppAuthChips(
    selected: List<PppAuthProtocol>,
    error: String?,
    onToggle: (PppAuthProtocol) -> Unit,
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        PppAuthProtocol.entries.forEach { protocol ->
            ToggleChip(
                label = protocol.label,
                selected = protocol in selected,
                onClick = { onToggle(protocol) },
            )
        }
    }
    if (error != null) {
        Text(
            text = error,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(top = 6.dp),
        )
    }
}

@Composable
private fun SubHeading(text: String) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(bottom = 10.dp),
    )
}

/** A titled card wrapper so every block on the screen has the same rhythm. */
@Composable
fun SectionCard(
    title: String,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(16.dp))
            content()
        }
    }
}

private val PFS_OPTIONS: List<DhGroup?> = listOf(null) + DhGroup.entries
