package com.arcansecurity.vpn.l2tpipsec.data

import android.content.SharedPreferences
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import com.arcansecurity.vpn.l2tpipsec.core.util.Log as CoreLog

class ProfileStoreTest {

    private val logged = mutableListOf<String>()
    private val log = CoreLog("Test", VpnLogger { level, _, message, _ -> logged += "$level $message" })

    // ------------------------------------------------------------------ decryption failures

    /**
     * The crash this guards against: `EncryptedSharedPreferences` throws `SecurityException` out of
     * every getter once its keyset no longer matches the data, which propagated out of
     * `ProfileRepository`'s constructor and killed the app in `Activity.onCreate` — with no way for
     * the user to reach the screen that would let them retype the profile.
     */
    @Test
    fun `a store whose reads throw yields a blank profile instead of propagating`() {
        val stored = readProfile(ThrowingPreferences(), log)

        assertTrue(stored.unreadable)
        assertEquals(VpnProfile(), stored.profile)
        assertTrue(logged.toString(), logged.any { it.startsWith("ERROR") })
    }

    /**
     * A partial failure discards the readable values too. Pinning it here because the alternative
     * is defensible and someone will be tempted: a form showing the server and user name with a
     * silently empty pre-shared key is worse than an obviously blank one.
     */
    @Test
    fun `one unreadable value discards the whole profile, not just that field`() {
        val prefs = FakePreferences(
            mapOf("name" to "Home", "server" to "vpn.example.com", "psk" to "secret"),
            unreadableKeys = setOf("psk"),
        )

        val stored = readProfile(prefs, log)

        assertTrue(stored.unreadable)
        assertEquals(VpnProfile(), stored.profile)
    }

    @Test
    fun `a write the store refuses is reported rather than thrown`() {
        val written = writeProfile(ThrowingPreferences(), VpnProfile(server = "host"), log)

        assertFalse(written)
        assertTrue(logged.toString(), logged.any { it.startsWith("ERROR") })
    }

    // ------------------------------------------------------------------ the happy path

    @Test
    fun `a profile survives a write and a read unchanged`() {
        val prefs = FakePreferences()
        val original = VpnProfile(
            name = "Livebox",
            server = "vpn.example.com",
            presharedKey = "psk",
            username = "road",
            password = "warrior",
            exchangeMode = IkeExchangeMode.AGGRESSIVE,
            phase1Hash = IkeHash.SHA2_512,
            phase2PfsGroup = DhGroup.MODP_1536,
            allowedPppAuth = listOf(PppAuthProtocol.PAP),
            mtu = 1380,
            dnsServers = "9.9.9.9",
            blockIpv6 = false,
            forceUdpEncapsulation = false,
            debugLogging = true,
        )

        assertTrue(writeProfile(prefs, original, log))
        val stored = readProfile(prefs, log)

        assertFalse(stored.unreadable)
        assertEquals(original, stored.profile)
    }

    @Test
    fun `an empty store reads back the defaults`() {
        val stored = readProfile(FakePreferences(), log)

        assertFalse(stored.unreadable)
        assertEquals(VpnProfile(), stored.profile)
    }

    /**
     * "No PFS" is a real choice, not the absence of one, so it is stored as an explicit sentinel.
     * Turning it off has to actually turn it off: writing nothing would leave the previous group on
     * disk and silently re-enable PFS on the next read.
     */
    @Test
    fun `clearing the PFS group persists as no PFS rather than leaving the old one`() {
        val prefs = FakePreferences()
        writeProfile(prefs, VpnProfile(phase2PfsGroup = DhGroup.MODP_2048), log)
        assertEquals(DhGroup.MODP_2048, readProfile(prefs, log).profile.phase2PfsGroup)

        writeProfile(prefs, VpnProfile(phase2PfsGroup = null), log)

        assertEquals(null, readProfile(prefs, log).profile.phase2PfsGroup)
    }

    /**
     * A value written by a newer build is not a decryption failure: it falls back on its own and
     * leaves the rest of the profile — and the unreadable flag — alone.
     */
    @Test
    fun `an unparseable enum falls back without flagging the profile unreadable`() {
        val prefs = FakePreferences(mapOf("p1_hash" to "SHA3_512", "server" to "vpn.example.com"))

        val stored = readProfile(prefs, log)

        assertFalse(stored.unreadable)
        assertEquals(VpnProfile().phase1Hash, stored.profile.phase1Hash)
        assertEquals("vpn.example.com", stored.profile.server)
        assertTrue(logged.toString(), logged.any { it.startsWith("WARN") && it.contains("SHA3_512") })
    }

    @Test
    fun `a PPP auth list of only unknown names falls back to the default`() {
        val prefs = FakePreferences(mapOf("ppp_auth" to "EAP_TLS,SPAP"))

        assertEquals(VpnProfile.DEFAULT_PPP_AUTH, readProfile(prefs, log).profile.allowedPppAuth)
    }
}

/** Throws out of every read and every write, the way a store with the wrong keyset does. */
private class ThrowingPreferences : SharedPreferences by FakePreferences() {
    override fun getString(key: String?, defValue: String?): String =
        throw SecurityException("Could not decrypt value")

    override fun getInt(key: String?, defValue: Int): Int =
        throw SecurityException("Could not decrypt value")

    override fun getBoolean(key: String?, defValue: Boolean): Boolean =
        throw SecurityException("Could not decrypt value")

    override fun edit(): SharedPreferences.Editor =
        throw SecurityException("Could not encrypt value")
}

/**
 * An in-memory [SharedPreferences]. [unreadableKeys] throw on read so a partial decryption failure
 * can be exercised.
 */
private class FakePreferences(
    initial: Map<String, Any> = emptyMap(),
    private val unreadableKeys: Set<String> = emptySet(),
) : SharedPreferences {

    private val values = LinkedHashMap<String, Any>(initial)

    private fun guard(key: String?) {
        if (key in unreadableKeys) throw SecurityException("Could not decrypt value for $key")
    }

    override fun getAll(): MutableMap<String, *> = values

    override fun getString(key: String?, defValue: String?): String? {
        guard(key)
        return values[key] as? String ?: defValue
    }

    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
        guard(key)
        @Suppress("UNCHECKED_CAST")
        return values[key] as? MutableSet<String> ?: defValues
    }

    override fun getInt(key: String?, defValue: Int): Int {
        guard(key)
        return values[key] as? Int ?: defValue
    }

    override fun getLong(key: String?, defValue: Long): Long {
        guard(key)
        return values[key] as? Long ?: defValue
    }

    override fun getFloat(key: String?, defValue: Float): Float {
        guard(key)
        return values[key] as? Float ?: defValue
    }

    override fun getBoolean(key: String?, defValue: Boolean): Boolean {
        guard(key)
        return values[key] as? Boolean ?: defValue
    }

    override fun contains(key: String?): Boolean = values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = FakeEditor(values)

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit
}

private class FakeEditor(private val target: MutableMap<String, Any>) : SharedPreferences.Editor {

    private val staged = LinkedHashMap<String, Any?>()
    private var clearRequested = false

    override fun putString(key: String?, value: String?) = apply { staged[key!!] = value }

    override fun putStringSet(key: String?, values: MutableSet<String>?) =
        apply { staged[key!!] = values }

    override fun putInt(key: String?, value: Int) = apply { staged[key!!] = value }
    override fun putLong(key: String?, value: Long) = apply { staged[key!!] = value }
    override fun putFloat(key: String?, value: Float) = apply { staged[key!!] = value }
    override fun putBoolean(key: String?, value: Boolean) = apply { staged[key!!] = value }
    override fun remove(key: String?) = apply { staged[key!!] = null }
    override fun clear() = apply { clearRequested = true }

    override fun commit(): Boolean {
        if (clearRequested) target.clear()
        staged.forEach { (key, value) -> if (value == null) target.remove(key) else target[key] = value }
        return true
    }

    override fun apply() {
        commit()
    }
}
