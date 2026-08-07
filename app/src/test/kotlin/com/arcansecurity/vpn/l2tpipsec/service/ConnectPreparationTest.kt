package com.arcansecurity.vpn.l2tpipsec.service

import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The only place a profile and its secrets are combined. Everything here runs on the tunnel worker
 * thread in production, so the failure paths must be values rather than exceptions.
 */
class ConnectPreparationTest {

    private val profile = VpnProfile(
        id = "p1",
        name = "Home",
        server = "  vpn.example.com  ",
        username = "  alice  ",
    )

    private fun ready(result: ConnectPreparation) =
        (result as ConnectPreparation.Ready).config

    private fun rejection(result: ConnectPreparation) =
        (result as ConnectPreparation.Rejected).reason

    @Test
    fun `a profile and its secrets become a configuration`() {
        val config = ready(
            prepareConnect(profile, "psk-value".toCharArray(), "pass-value".toCharArray()),
        )
        assertEquals("vpn.example.com", config.serverHost)
        assertEquals("psk-value", config.presharedKey)
        assertEquals("alice", config.username)
        assertEquals("pass-value", config.password)
    }

    @Test
    fun `no active profile is rejected with something the user can act on`() {
        val reason = rejection(prepareConnect(null, "psk".toCharArray(), null))
        assertTrue(reason.contains("No VPN profile is selected"))
    }

    /** The same sentence the form shows, so the user recognises it. */
    @Test
    fun `a missing pre-shared key is rejected`() {
        assertEquals(
            "A pre-shared key is required",
            rejection(prepareConnect(profile, null, "pass".toCharArray())),
        )
    }

    @Test
    fun `an empty pre-shared key is rejected like a missing one`() {
        assertEquals(
            "A pre-shared key is required",
            rejection(prepareConnect(profile, CharArray(0), null)),
        )
    }

    /** A peer that authenticates on the pre-shared key alone needs no PPP password. */
    @Test
    fun `a missing password becomes an empty one`() {
        val config = ready(prepareConnect(profile, "psk".toCharArray(), null))
        assertEquals("", config.password)
    }

    @Test
    fun `the crypto proposals are carried across`() {
        val tuned = profile.copy(
            phase1DhGroup = DhGroup.MODP_1536,
            phase2PfsGroup = DhGroup.MODP_2048,
            mtu = 1380,
            blockIpv6 = false,
            forceUdpEncapsulation = false,
            debugLogging = true,
        )
        val config = ready(prepareConnect(tuned, "psk".toCharArray(), null))
        assertEquals(DhGroup.MODP_1536, config.phase1.dhGroup)
        assertEquals(DhGroup.MODP_2048, config.phase2.pfsGroup)
        assertEquals(1380, config.mtu)
        assertEquals(false, config.blockIpv6)
        assertEquals(false, config.forceUdpEncapsulation)
        assertEquals(true, config.debugLogging)
    }

    @Test
    fun `the DNS override is split out of the free-text field`() {
        val config = ready(
            prepareConnect(
                profile.copy(dnsServers = "9.9.9.9, 192.168.1.1"),
                "psk".toCharArray(),
                null,
            ),
        )
        assertEquals(listOf("9.9.9.9", "192.168.1.1"), config.dnsOverride)
    }

    @Test
    fun `the automatic identity is emptied and an explicit one is trimmed`() {
        val auto = ready(prepareConnect(profile, "psk".toCharArray(), null))
        assertEquals(IkeIdentityType.AUTO_IPV4, auto.localIdentity.type)
        assertEquals("", auto.localIdentity.value)

        val explicit = ready(
            prepareConnect(
                profile.copy(identityType = IkeIdentityType.FQDN, identityValue = "  host.example  "),
                "psk".toCharArray(),
                null,
            ),
        )
        assertEquals(IkeIdentityType.FQDN, explicit.localIdentity.type)
        assertEquals("host.example", explicit.localIdentity.value)
    }

    /** `VpnConfig`'s own require() blocks must surface as a message, never as a crashed thread. */
    @Test
    fun `a profile the protocol stack refuses is rejected rather than thrown`() {
        val reason = rejection(
            prepareConnect(profile.copy(mtu = 99), "psk".toCharArray(), null),
        )
        assertTrue(reason.contains("mtu"))
    }

    @Test
    fun `an empty server is rejected rather than thrown`() {
        val reason = rejection(
            prepareConnect(profile.copy(server = "   "), "psk".toCharArray(), null),
        )
        assertTrue(reason.contains("serverHost"))
    }

}
