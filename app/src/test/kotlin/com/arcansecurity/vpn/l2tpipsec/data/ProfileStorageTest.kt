package com.arcansecurity.vpn.l2tpipsec.data

import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import com.arcansecurity.vpn.l2tpipsec.core.util.Log as CoreLog

/** The key/value layout, driven directly against a fake [android.content.SharedPreferences]. */
class ProfileStorageTest {

    private val logged = mutableListOf<String>()
    private val log = CoreLog("Test", VpnLogger { level, _, message, _ -> logged += "$level $message" })

    private val populated = VpnProfile(
        id = "a",
        name = "Livebox",
        server = "vpn.example.com",
        username = "road",
        exchangeMode = IkeExchangeMode.AGGRESSIVE,
        identityType = IkeIdentityType.USER_FQDN,
        identityValue = "road@example.com",
        phase1Hash = IkeHash.SHA2_512,
        phase2PfsGroup = DhGroup.MODP_1536,
        allowedPppAuth = listOf(PppAuthProtocol.PAP),
        mtu = 1380,
        dnsServers = "9.9.9.9",
        blockIpv6 = false,
        forceUdpEncapsulation = false,
        debugLogging = true,
    )

    // ------------------------------------------------------------------ round trips

    @Test
    fun `a profile survives a write and a read unchanged`() {
        val prefs = FakePreferences()

        assertTrue(writeProfiles(prefs, listOf(populated), "a", log))
        val stored = readProfiles(prefs, log)

        assertEquals(listOf(populated), stored.profiles)
        assertEquals("a", stored.activeId)
        assertEquals(SCHEMA_VERSION, stored.version)
    }

    @Test
    fun `an empty store reads back nothing at all`() {
        val stored = readProfiles(FakePreferences(), log)

        assertEquals(emptyList<VpnProfile>(), stored.profiles)
        assertNull(stored.activeId)
        assertEquals(0, stored.version)
    }

    /**
     * The reason the order is a string and not a `StringSet`: a set comes back in hash order, so
     * the list would rearrange itself on every restart.
     */
    @Test
    fun `the list order is the one that was written, not an incidental one`() {
        val prefs = FakePreferences()
        val ids = listOf("zzz", "aaa", "mmm", "bbb")
        val profiles = ids.map { VpnProfile(id = it, name = it) }

        writeProfiles(prefs, profiles, "mmm", log)

        assertEquals(ids, readProfiles(prefs, log).profiles.map { it.id })
    }

    @Test
    fun `a removed profile leaves no row behind`() {
        val prefs = FakePreferences()
        val a = VpnProfile(id = "a", server = "a.example.com")
        val b = VpnProfile(id = "b", server = "b.example.com")
        writeProfiles(prefs, listOf(a, b), "a", log)

        writeProfiles(prefs, listOf(b), "b", log)

        assertEquals(listOf(b), readProfiles(prefs, log).profiles)
        assertTrue(
            "orphan rows left: ${prefs.values.keys}",
            prefs.values.keys.none { it.startsWith("profile.a.") },
        )
    }

    @Test
    fun `an active id that no longer exists falls back to the first profile`() {
        val prefs = FakePreferences()
        writeProfiles(prefs, listOf(VpnProfile(id = "a"), VpnProfile(id = "b")), "a", log)
        prefs.values[KEY_ACTIVE] = "gone"

        assertEquals("a", readProfiles(prefs, log).activeId)
    }

    /** "No PFS" is a real choice; writing nothing would silently re-enable it on the next read. */
    @Test
    fun `clearing the PFS group persists as no PFS rather than leaving the old one`() {
        val prefs = FakePreferences()
        writeProfiles(prefs, listOf(VpnProfile(id = "a", phase2PfsGroup = DhGroup.MODP_2048)), "a", log)
        assertEquals(DhGroup.MODP_2048, readProfiles(prefs, log).profiles.single().phase2PfsGroup)

        writeProfiles(prefs, listOf(VpnProfile(id = "a", phase2PfsGroup = null)), "a", log)

        assertNull(readProfiles(prefs, log).profiles.single().phase2PfsGroup)
    }

    /** A value written by a newer build falls back on its own and leaves the rest alone. */
    @Test
    fun `an unparseable enum falls back without failing the read`() {
        val prefs = FakePreferences(
            mapOf(
                KEY_ORDER to "a",
                "profile.a.p1_hash" to "SHA3_512",
                "profile.a.server" to "vpn.example.com",
            ),
        )

        val profile = readProfiles(prefs, log).profiles.single()

        assertEquals(VpnProfile(id = "a").phase1Hash, profile.phase1Hash)
        assertEquals("vpn.example.com", profile.server)
        assertTrue(logged.toString(), logged.any { it.startsWith("WARN") && it.contains("SHA3_512") })
    }

    @Test
    fun `a PPP auth list of only unknown names falls back to the default`() {
        val prefs = FakePreferences(
            mapOf(KEY_ORDER to "a", "profile.a.ppp_auth" to "EAP_TLS,SPAP"),
        )

        assertEquals(
            VpnProfile.DEFAULT_PPP_AUTH,
            readProfiles(prefs, log).profiles.single().allowedPppAuth,
        )
    }

    @Test
    fun `a write the store refuses is reported rather than thrown`() {
        val prefs = FakePreferences(writesFail = true)

        assertFalse(writeProfiles(prefs, listOf(populated), "a", log))
        assertTrue(logged.toString(), logged.any { it.startsWith("ERROR") })
    }

    @Test
    fun `an id that would corrupt the order list is rejected`() {
        assertTrue(isUsableProfileId(VpnProfile.newId()))
        assertTrue(isUsableProfileId(LEGACY_PROFILE_ID))
        assertFalse(isUsableProfileId(""))
        assertFalse(isUsableProfileId("  "))
        assertFalse("the order list is comma-separated", isUsableProfileId("a,b"))
        assertFalse(isUsableProfileId("a b"))
    }

    @Test
    fun `every generated id is different`() {
        val ids = List(100) { VpnProfile.newId() }
        assertEquals(ids.size, ids.toSet().size)
    }

    // ------------------------------------------------------------------ schema 1

    @Test
    fun `an empty store holds no schema-1 install`() {
        assertNull(readLegacyProfile(FakePreferences()))
    }

    @Test
    fun `a schema-2 store is not mistaken for a schema-1 one`() {
        val prefs = FakePreferences()
        writeProfiles(prefs, listOf(populated), "a", log)

        assertNull(readLegacyProfile(prefs))
    }

    @Test
    fun `a schema-1 install is read back with its settings and both secrets`() {
        val legacy = readLegacyProfile(legacyPreferences())!!

        assertEquals(LEGACY_PROFILE_ID, legacy.profile.id)
        assertEquals("Home", legacy.profile.name)
        assertEquals("vpn.example.com", legacy.profile.server)
        assertEquals("alice", legacy.profile.username)
        assertEquals(IkeExchangeMode.AGGRESSIVE, legacy.profile.exchangeMode)
        assertEquals(IkeIdentityType.USER_FQDN, legacy.profile.identityType)
        assertEquals("alice@example.com", legacy.profile.identityValue)
        assertEquals(IkeHash.SHA2_512, legacy.profile.phase1Hash)
        assertEquals(DhGroup.MODP_1536, legacy.profile.phase2PfsGroup)
        assertEquals(listOf(PppAuthProtocol.PAP), legacy.profile.allowedPppAuth)
        assertEquals(1380, legacy.profile.mtu)
        assertEquals("9.9.9.9", legacy.profile.dnsServers)
        assertFalse(legacy.profile.blockIpv6)
        assertFalse(legacy.profile.forceUdpEncapsulation)
        assertTrue(legacy.profile.debugLogging)

        assertArrayEquals("s3cr3t-psk".toCharArray(), legacy.presharedKey)
        assertArrayEquals("hunter2".toCharArray(), legacy.password)
    }

    @Test
    fun `a schema-1 install with no credentials still comes back`() {
        val prefs = FakePreferences(mapOf("name" to "Home", "server" to "vpn.example.com"))

        val legacy = readLegacyProfile(prefs)!!

        assertEquals("Home", legacy.profile.name)
        assertNull(legacy.presharedKey)
        assertNull(legacy.password)
    }

    @Test
    fun `purging drops the schema-1 keys, credentials included`() {
        val prefs = legacyPreferences()

        assertTrue(purgeLegacyProfile(prefs, log))

        assertNull(readLegacyProfile(prefs))
        assertEquals(emptyMap<String, Any>(), prefs.values)
    }

    private fun legacyPreferences() = FakePreferences(
        mapOf(
            "name" to "Home",
            "server" to "vpn.example.com",
            "psk" to "s3cr3t-psk",
            "username" to "alice",
            "password" to "hunter2",
            "exchange_mode" to "AGGRESSIVE",
            "identity_type" to "USER_FQDN",
            "identity_value" to "alice@example.com",
            "p1_hash" to "SHA2_512",
            "p2_pfs" to "MODP_1536",
            "ppp_auth" to "PAP",
            "mtu" to 1380,
            "dns" to "9.9.9.9",
            "block_ipv6" to false,
            "force_udp" to false,
            "debug_log" to true,
        ),
    )
}
