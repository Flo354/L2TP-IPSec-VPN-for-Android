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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** [VpnProfile.toVpnConfig] is the only bridge to the protocol stack; nothing may be dropped. */
class VpnProfileTest {

    private val fullyPopulated = VpnProfile(
        id = "p1",
        name = "Livebox",
        server = "  vpn.example.com  ",
        username = "  alice  ",
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
        val config = fullyPopulated.toVpnConfig("s3cr3t-psk".toCharArray(), "hunter2".toCharArray())

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
        val config = VpnProfile(id = "p1", server = "10.0.0.1")
            .toVpnConfig("psk".toCharArray(), CharArray(0))

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
            id = "p1",
            server = "10.0.0.1",
            identityType = IkeIdentityType.AUTO_IPV4,
            identityValue = "ignored",
        ).toVpnConfig("psk".toCharArray(), CharArray(0))

        assertEquals(IkeIdentityType.AUTO_IPV4, config.localIdentity.type)
        assertEquals("", config.localIdentity.value)
    }

    @Test
    fun `the DNS override accepts commas, semicolons and whitespace`() {
        val profile = VpnProfile(id = "p1", dnsServers = " 1.1.1.1 ,8.8.8.8;  8.8.4.4 \n")
        assertEquals(listOf("1.1.1.1", "8.8.8.8", "8.8.4.4"), profile.dnsServerList)
    }

    @Test
    fun `an empty DNS override maps to an empty list`() {
        val config = VpnProfile(id = "p1", server = "10.0.0.1")
            .toVpnConfig("psk".toCharArray(), CharArray(0))
        assertEquals(emptyList<String>(), config.dnsOverride)
    }

    @Test
    fun `an unnamed profile is shown by its server`() {
        assertEquals("10.0.0.1", VpnProfile(id = "p1", name = " ", server = "10.0.0.1").displayName)
        assertEquals(VpnProfile.DEFAULT_NAME, VpnProfile(id = "p1", name = "").displayName)
    }

    // ------------------------------------------------------------------ the redaction guarantee

    /**
     * The security defect this rewrite exists for, pinned structurally.
     *
     * The old profile carried `presharedKey` and `password` as `String` fields, so the generated
     * `toString` printed both into the in-app log buffer. Putting a credential back on this class
     * fails here — before anyone has to notice that a log line now reads differently.
     */
    @Test
    fun `VpnProfile declares no field that could hold a secret`() {
        val forbidden = listOf("psk", "presharedkey", "password", "secret", "passphrase", "key")

        val offenders = VpnProfile::class.java.declaredFields
            .filterNot { it.isSynthetic }
            .map { it.name }
            .filter { name -> forbidden.any { name.lowercase().contains(it) } }

        assertEquals(
            "VpnProfile must hold no credential; SecretVault does. Offending fields: $offenders",
            emptyList<String>(),
            offenders,
        )
    }

    @Test
    fun `toString prints the settings and has nothing else to print`() {
        val rendered = fullyPopulated.toString()

        assertTrue(rendered, rendered.contains("Livebox"))
        assertTrue(rendered, rendered.contains("vpn.example.com"))
        assertTrue(rendered, rendered.contains("mtu=1280"))
        assertFalse("no credential may appear", rendered.contains("s3cr3t"))
        assertFalse("no credential may appear", rendered.contains("hunter2"))
    }

    /** The one place a stored secret becomes readable; it must clean up after itself. */
    @Test
    fun `buildVpnConfig resolves the secrets and wipes the plaintext it read`() {
        val fixture = StoreFixture()
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "s3cr3t-psk".toCharArray())
        fixture.secrets.store("p1", SecretKind.PASSWORD, "hunter2".toCharArray())

        val reader = TrackingReader(fixture.reader)
        val config = buildVpnConfig(fullyPopulated, reader)

        assertEquals("s3cr3t-psk", config.presharedKey)
        assertEquals("hunter2", config.password)
        assertEquals("both secrets should have been read", 2, reader.handedOut.size)
        reader.handedOut.forEach { secret ->
            assertTrue(
                "a plaintext secret was left in the heap: ${secret.joinToString("") { it.code.toString(16) }}",
                secret.all { it.code == 0 },
            )
        }
    }

    @Test
    fun `buildVpnConfig treats a missing password as an empty one`() {
        val fixture = StoreFixture()
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "psk".toCharArray())

        val config = buildVpnConfig(VpnProfile(id = "p1", server = "10.0.0.1"), fixture.reader)

        assertEquals("", config.password)
    }
}

/** Keeps hold of every array handed out so the test can check it was wiped. */
private class TrackingReader(private val delegate: SecretReader) : SecretReader {

    val handedOut = mutableListOf<CharArray>()

    override fun read(profileId: String, kind: SecretKind): CharArray? =
        delegate.read(profileId, kind)?.also { handedOut += it }
}
