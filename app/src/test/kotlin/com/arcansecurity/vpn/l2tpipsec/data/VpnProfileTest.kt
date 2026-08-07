package com.arcansecurity.vpn.l2tpipsec.data

import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** [VpnProfile.toVpnConfig] is the only bridge to the protocol stack; nothing may be dropped. */
class VpnProfileTest {

    private val fullyPopulated = VpnProfile(
        name = "Livebox",
        server = "  vpn.example.com  ",
        presharedKey = "s3cr3t-psk",
        username = "  alice  ",
        password = "hunter2",
        exchangeMode = IkeExchangeMode.AGGRESSIVE,
        identityType = IkeIdentityType.USER_FQDN,
        identityValue = " alice@example.com ",
        phase1Encryption = IkeEncryption.AES_CBC_192,
        phase1Hash = IkeHash.SHA2_512,
        phase1DhGroup = DhGroup.MODP_1536,
        phase2Encryption = EspEncryption.ESP_3DES,
        phase2Integrity = EspIntegrity.HMAC_SHA1_96,
        phase2PfsGroup = DhGroup.MODP_1024,
        allowedPppAuth = listOf(PppAuthProtocol.PAP),
        mtu = 1280,
        dnsServers = "9.9.9.9, 149.112.112.112",
        blockIpv6 = false,
        forceUdpEncapsulation = false,
        debugLogging = true,
    )

    @Test
    fun `maps every field into the core configuration`() {
        val config = fullyPopulated.toVpnConfig()

        assertEquals("vpn.example.com", config.serverHost)
        assertEquals("s3cr3t-psk", config.presharedKey)
        assertEquals("alice", config.username)
        assertEquals("hunter2", config.password)

        assertEquals(IkeExchangeMode.AGGRESSIVE, config.exchangeMode)
        assertEquals(IkeIdentityType.USER_FQDN, config.localIdentity.type)
        assertEquals("alice@example.com", config.localIdentity.value)

        assertEquals(IkeEncryption.AES_CBC_192, config.phase1.encryption)
        assertEquals(IkeHash.SHA2_512, config.phase1.hash)
        assertEquals(DhGroup.MODP_1536, config.phase1.dhGroup)

        assertEquals(EspEncryption.ESP_3DES, config.phase2.encryption)
        assertEquals(EspIntegrity.HMAC_SHA1_96, config.phase2.integrity)
        assertEquals(DhGroup.MODP_1024, config.phase2.pfsGroup)

        assertEquals(listOf(PppAuthProtocol.PAP), config.allowedPppAuth)
        assertEquals(1280, config.mtu)
        assertEquals(listOf("9.9.9.9", "149.112.112.112"), config.dnsOverride)
        assertEquals(false, config.blockIpv6)
        assertEquals(false, config.forceUdpEncapsulation)
        assertEquals(true, config.debugLogging)
    }

    @Test
    fun `defaults match the target hardware`() {
        val config = VpnProfile(server = "10.0.0.1", presharedKey = "psk").toVpnConfig()

        assertEquals(IkeExchangeMode.MAIN, config.exchangeMode)
        assertEquals(IkeEncryption.AES_CBC_256, config.phase1.encryption)
        assertEquals(IkeHash.SHA2_256, config.phase1.hash)
        assertEquals(DhGroup.MODP_2048, config.phase1.dhGroup)
        assertEquals(EspEncryption.ESP_AES_CBC_256, config.phase2.encryption)
        assertEquals(EspIntegrity.HMAC_SHA2_256_128, config.phase2.integrity)
        assertNull("PFS is off by default", config.phase2.pfsGroup)
        assertTrue("UDP encapsulation must be forced on Android", config.forceUdpEncapsulation)
        assertEquals(1400, config.mtu)
        assertTrue(config.blockIpv6)
        assertEquals(
            listOf(PppAuthProtocol.MSCHAP_V2, PppAuthProtocol.CHAP_MD5, PppAuthProtocol.PAP),
            config.allowedPppAuth,
        )
    }

    @Test
    fun `the automatic identity carries no value`() {
        val config = VpnProfile(
            server = "10.0.0.1",
            presharedKey = "psk",
            identityType = IkeIdentityType.AUTO_IPV4,
            identityValue = "ignored",
        ).toVpnConfig()

        assertEquals(IkeIdentityType.AUTO_IPV4, config.localIdentity.type)
        assertEquals("", config.localIdentity.value)
    }

    @Test
    fun `the DNS override accepts commas, semicolons and whitespace`() {
        val profile = VpnProfile(dnsServers = " 1.1.1.1 ,8.8.8.8;  8.8.4.4 \n")
        assertEquals(listOf("1.1.1.1", "8.8.8.8", "8.8.4.4"), profile.dnsServerList)
    }

    @Test
    fun `an empty DNS override maps to an empty list`() {
        val config = VpnProfile(server = "10.0.0.1", presharedKey = "psk").toVpnConfig()
        assertEquals(emptyList<String>(), config.dnsOverride)
    }

    @Test
    fun `toString never leaks the secrets`() {
        val rendered = fullyPopulated.toString()
        assertTrue(!rendered.contains("s3cr3t-psk"))
        assertTrue(!rendered.contains("hunter2"))
    }
}
