package com.arcansecurity.vpn.l2tpipsec.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout

/**
 * [PreferenceProfileStore]: multi-profile CRUD, the active-profile rules, the schema-1 migration
 * and the read-failure path, all against a fake [android.content.SharedPreferences] on a plain JVM.
 */
class ProfileStoreTest {

    /** Everything here suspends on a lock or a flow; a regression must fail, not hang. */
    @get:Rule
    val timeout: Timeout = Timeout.seconds(30)

    private val home = VpnProfile(id = "home", name = "Home", server = "home.example.com")
    private val work = VpnProfile(id = "work", name = "Work", server = "work.example.com")
    private val lab = VpnProfile(id = "lab", name = "Lab", server = "lab.example.com")

    // ------------------------------------------------------------------ loading

    @Test
    fun `a fresh install loads to an empty, ready store`() {
        val fixture = StoreFixture()

        assertEquals(ProfileStoreState.READY, fixture.awaitLoaded())
        assertEquals(emptyList<VpnProfile>(), fixture.store.profiles.value)
        assertNull(fixture.store.activeProfileId.value)
        assertTrue(fixture.store.usesEncryptedStorage.value)
    }

    @Test
    fun `the plaintext fallback is reported so the UI can warn about it`() {
        val fixture = StoreFixture(encrypted = false)

        assertEquals(ProfileStoreState.READY, fixture.awaitLoaded())
        assertFalse(fixture.store.usesEncryptedStorage.value)
    }

    // ------------------------------------------------------------------ multiple profiles

    @Test
    fun `profiles are created, edited in place and read back in order`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()

        fixture.upsert(home)
        fixture.upsert(work)
        fixture.upsert(lab)
        fixture.upsert(work.copy(server = "vpn.corp.example.com"))

        assertEquals(listOf("home", "work", "lab"), fixture.store.profiles.value.map { it.id })
        assertEquals(
            "an edit must not move the profile to the end of the list",
            "vpn.corp.example.com",
            fixture.store.profiles.value[1].server,
        )
    }

    @Test
    fun `the order survives a reload`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(lab)
        fixture.upsert(home)
        fixture.upsert(work)
        fixture.setActive("home")

        val reloaded = StoreFixture(fixture.prefs)
        reloaded.awaitLoaded()

        assertEquals(listOf("lab", "home", "work"), reloaded.store.profiles.value.map { it.id })
        assertEquals("home", reloaded.store.activeProfileId.value)
    }

    @Test
    fun `the first profile created becomes the active one`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()

        fixture.upsert(home)
        fixture.upsert(work)

        assertEquals("home", fixture.store.activeProfileId.value)
        assertEquals(home, fixture.store.activeProfile)
    }

    @Test
    fun `editing the active profile does not change which one is active`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)
        fixture.upsert(work)
        fixture.setActive("work")

        fixture.upsert(home.copy(name = "House"))

        assertEquals("work", fixture.store.activeProfileId.value)
    }

    @Test
    fun `an unknown id can neither be activated nor deleted, and neither throws`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)

        fixture.setActive("nope")
        fixture.delete("nope")

        assertEquals(listOf(home), fixture.store.profiles.value)
        assertEquals("home", fixture.store.activeProfileId.value)
    }

    @Test
    fun `a profile with an id that would corrupt the order list is refused`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()

        fixture.upsert(VpnProfile(id = "a,b", name = "Bad"))

        assertEquals(emptyList<VpnProfile>(), fixture.store.profiles.value)
        assertTrue(fixture.logText(), fixture.logged.any { it.startsWith("ERROR") })
    }

    // ------------------------------------------------------------------ deleting

    @Test
    fun `deleting the active profile activates the one that took its place`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)
        fixture.upsert(work)
        fixture.upsert(lab)
        fixture.setActive("work")

        fixture.delete("work")

        assertEquals(listOf("home", "lab"), fixture.store.profiles.value.map { it.id })
        assertEquals("lab", fixture.store.activeProfileId.value)
    }

    @Test
    fun `deleting the last profile in the list falls back to the new last one`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)
        fixture.upsert(work)
        fixture.setActive("work")

        fixture.delete("work")

        assertEquals("home", fixture.store.activeProfileId.value)
    }

    @Test
    fun `deleting an inactive profile leaves the active one alone`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)
        fixture.upsert(work)
        fixture.setActive("work")

        fixture.delete("home")

        assertEquals("work", fixture.store.activeProfileId.value)
    }

    @Test
    fun `deleting the only profile leaves nothing active`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)

        fixture.delete("home")

        assertEquals(emptyList<VpnProfile>(), fixture.store.profiles.value)
        assertNull(fixture.store.activeProfileId.value)
        assertNull(fixture.store.activeProfile)
    }

    /**
     * Ids are never reused, so nothing would inherit them — but leaving a deleted profile's
     * credentials on disk keeps data the user explicitly asked to be rid of, and every extra copy
     * of a pre-shared key is another thing a forensic image can find.
     */
    @Test
    fun `deleting a profile wipes its secrets`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)
        fixture.secrets.store("home", SecretKind.PRESHARED_KEY, "psk".toCharArray())
        fixture.secrets.store("home", SecretKind.PASSWORD, "hunter2".toCharArray())
        fixture.flushSecrets()

        fixture.delete("home")
        fixture.flushSecrets()

        assertFalse(fixture.secrets.isSet("home", SecretKind.PRESHARED_KEY))
        assertFalse(fixture.secrets.isSet("home", SecretKind.PASSWORD))
        assertNull(fixture.reader.read("home", SecretKind.PRESHARED_KEY))
        assertNull(fixture.reader.read("home", SecretKind.PASSWORD))
        assertTrue(
            "credentials left on disk: ${fixture.prefs.values.keys}",
            fixture.prefs.values.keys.none { it.startsWith("secret.") },
        )
    }

    @Test
    fun `deleting a profile leaves the other profiles' secrets alone`() {
        val fixture = StoreFixture()
        fixture.awaitLoaded()
        fixture.upsert(home)
        fixture.upsert(work)
        fixture.secrets.store("home", SecretKind.PRESHARED_KEY, "home-psk".toCharArray())
        fixture.secrets.store("work", SecretKind.PRESHARED_KEY, "work-psk".toCharArray())
        fixture.flushSecrets()

        fixture.delete("home")
        fixture.flushSecrets()

        assertArrayEquals(
            "work-psk".toCharArray(),
            fixture.reader.read("work", SecretKind.PRESHARED_KEY),
        )
    }

    // ------------------------------------------------------------------ a store that fails

    /**
     * The crash this guards against: `EncryptedSharedPreferences` throws `SecurityException` out of
     * every getter once its keyset no longer matches the data, which propagated out of
     * the old profile repository's constructor and killed the app in `Activity.onCreate` — with no way for
     * the user to reach the screen that would let them retype the profile.
     */
    @Test
    fun `a store whose reads throw becomes an empty, usable store instead of an exception`() {
        val fixture = StoreFixture(FakePreferences(readsFail = true))

        assertEquals(ProfileStoreState.UNREADABLE, fixture.awaitLoaded())
        assertEquals(emptyList<VpnProfile>(), fixture.store.profiles.value)
        assertNull(fixture.store.activeProfileId.value)
        assertTrue(fixture.logText(), fixture.logged.any { it.startsWith("ERROR") })
    }

    /**
     * A partial failure discards the readable values too. Pinning it here because the alternative
     * is defensible and someone will be tempted: a list showing the server and user name with a
     * silently missing pre-shared key is worse than an obviously empty one.
     */
    @Test
    fun `one unreadable value discards the whole store, not just that profile`() {
        val disk = FakePreferences(
            mapOf(
                KEY_ORDER to "home,work",
                "profile.home.name" to "Home",
                "profile.work.name" to "Work",
            ),
            unreadableKeys = setOf("profile.work.name"),
        )

        val fixture = StoreFixture(disk)

        assertEquals(ProfileStoreState.UNREADABLE, fixture.awaitLoaded())
        assertEquals(emptyList<VpnProfile>(), fixture.store.profiles.value)
    }

    @Test
    fun `an unreadable store is usable again as soon as a write succeeds`() {
        val disk = FakePreferences(readsFail = true)
        val fixture = StoreFixture(disk)
        assertEquals(ProfileStoreState.UNREADABLE, fixture.awaitLoaded())

        disk.readsFail = false
        fixture.upsert(home)

        assertEquals(ProfileStoreState.READY, fixture.store.state.value)
        assertEquals(listOf(home), fixture.store.profiles.value)
    }

    @Test
    fun `a store that refuses writes keeps the profile in memory and stays quiet about it`() {
        val fixture = StoreFixture(FakePreferences(writesFail = true))
        fixture.awaitLoaded()

        fixture.upsert(home)
        fixture.setActive("home")
        fixture.delete("home")

        // Nothing threw, and the in-memory view followed every call.
        assertEquals(emptyList<VpnProfile>(), fixture.store.profiles.value)
        assertTrue(fixture.logText(), fixture.logged.any { it.startsWith("ERROR") })
    }

    // ------------------------------------------------------------------ migration

    @Test
    fun `a single-profile install comes back as one profile with both its secrets`() {
        val disk = legacyPreferences()
        val fixture = StoreFixture(disk)

        assertEquals(ProfileStoreState.READY, fixture.awaitLoaded())

        val profile = fixture.store.profiles.value.single()
        assertEquals(LEGACY_PROFILE_ID, profile.id)
        assertEquals("Home", profile.name)
        assertEquals("vpn.example.com", profile.server)
        assertEquals("alice", profile.username)
        assertEquals(1380, profile.mtu)
        assertEquals(profile.id, fixture.store.activeProfileId.value)

        assertTrue(fixture.secrets.isSet(profile.id, SecretKind.PRESHARED_KEY))
        assertTrue(fixture.secrets.isSet(profile.id, SecretKind.PASSWORD))
        assertArrayEquals(
            "s3cr3t-psk".toCharArray(),
            fixture.reader.read(profile.id, SecretKind.PRESHARED_KEY),
        )
        assertArrayEquals(
            "hunter2".toCharArray(),
            fixture.reader.read(profile.id, SecretKind.PASSWORD),
        )
    }

    @Test
    fun `migration moves the plaintext credentials out of the old keys`() {
        val disk = legacyPreferences()

        StoreFixture(disk).awaitLoaded()

        assertFalse("psk" in disk.values.keys)
        assertFalse("password" in disk.values.keys)
        assertFalse("server" in disk.values.keys)
        assertTrue(disk.values.containsKey("secret.$LEGACY_PROFILE_ID.psk"))
        assertEquals(SCHEMA_VERSION, disk.values[KEY_SCHEMA])
    }

    @Test
    fun `the migrated profile survives the next start`() {
        val disk = legacyPreferences()
        StoreFixture(disk).awaitLoaded()

        val restarted = StoreFixture(disk)
        assertEquals(ProfileStoreState.READY, restarted.awaitLoaded())

        assertEquals(listOf(LEGACY_PROFILE_ID), restarted.store.profiles.value.map { it.id })
        assertArrayEquals(
            "s3cr3t-psk".toCharArray(),
            restarted.reader.read(LEGACY_PROFILE_ID, SecretKind.PRESHARED_KEY),
        )
    }

    @Test
    fun `migration does not resurrect a profile the user has since deleted`() {
        val disk = legacyPreferences()
        val fixture = StoreFixture(disk)
        fixture.awaitLoaded()
        fixture.delete(LEGACY_PROFILE_ID)

        val restarted = StoreFixture(disk)
        restarted.awaitLoaded()

        assertEquals(emptyList<VpnProfile>(), restarted.store.profiles.value)
    }

    /**
     * The ordering that matters most, isolated: the *credentials* are what has to be durable before
     * the plaintext copies are dropped. Here the profile rows write perfectly well and only the
     * credential does not — so a migration that trusted the profile write alone would delete the
     * user's only copy of their pre-shared key.
     */
    @Test
    fun `the schema-1 keys survive a migration whose credentials would not persist`() {
        val disk = FakePreferences(
            legacyValues(),
            unwritableKeys = setOf("secret.$LEGACY_PROFILE_ID.psk"),
        )

        val fixture = StoreFixture(disk)
        assertEquals(ProfileStoreState.READY, fixture.awaitLoaded())

        assertEquals("s3cr3t-psk", disk.values["psk"])
        assertEquals("hunter2", disk.values["password"])
        assertFalse("the new layout must not claim the migration happened", disk.values.containsKey(KEY_ORDER))
        // …and the session still works from memory.
        assertArrayEquals(
            "s3cr3t-psk".toCharArray(),
            fixture.reader.read(LEGACY_PROFILE_ID, SecretKind.PRESHARED_KEY),
        )
    }

    /**
     * The same guarantee seen from a store that refuses every write: nothing is thrown away, and
     * the next start on a store that works again completes the move.
     */
    @Test
    fun `a migration that cannot persist keeps the old data for the next attempt`() {
        val disk = legacyPreferences()
        disk.writesFail = true

        val fixture = StoreFixture(disk)
        assertEquals(ProfileStoreState.READY, fixture.awaitLoaded())

        // Usable right now…
        assertEquals(LEGACY_PROFILE_ID, fixture.store.profiles.value.single().id)
        assertArrayEquals(
            "s3cr3t-psk".toCharArray(),
            fixture.reader.read(LEGACY_PROFILE_ID, SecretKind.PRESHARED_KEY),
        )
        // …and nothing was thrown away.
        assertEquals("s3cr3t-psk", disk.values["psk"])
        assertEquals("hunter2", disk.values["password"])
        assertFalse(disk.values.containsKey(KEY_ORDER))

        // The next start, on a store that works again, completes the move.
        disk.writesFail = false
        val restarted = StoreFixture(disk)
        restarted.awaitLoaded()

        assertEquals(LEGACY_PROFILE_ID, restarted.store.profiles.value.single().id)
        assertArrayEquals(
            "s3cr3t-psk".toCharArray(),
            restarted.reader.read(LEGACY_PROFILE_ID, SecretKind.PRESHARED_KEY),
        )
        assertFalse("psk" in disk.values.keys)
    }

    /**
     * A device whose keystore was broken kept its profile in the plaintext fallback file. If the
     * keystore has since started working we open an empty encrypted store — and would silently
     * lose the setup unless the old file is looked at once.
     */
    @Test
    fun `a profile left in the plaintext fallback store is brought forward`() {
        val encryptedDisk = FakePreferences()
        val fallback = legacyPreferences()

        val fixture = StoreFixture(encryptedDisk, legacy = fallback)
        assertEquals(ProfileStoreState.READY, fixture.awaitLoaded())

        assertEquals("Home", fixture.store.profiles.value.single().name)
        assertArrayEquals(
            "s3cr3t-psk".toCharArray(),
            fixture.reader.read(LEGACY_PROFILE_ID, SecretKind.PRESHARED_KEY),
        )
        assertTrue("the new store holds it now", encryptedDisk.values.containsKey(KEY_ORDER))
        assertFalse("and the plaintext copy is gone", "psk" in fallback.values.keys)
    }

    @Test
    fun `the fallback store is not consulted once the main one holds profiles`() {
        val encryptedDisk = FakePreferences()
        StoreFixture(encryptedDisk).let {
            it.awaitLoaded()
            it.upsert(work)
        }
        val fallback = legacyPreferences()

        val fixture = StoreFixture(encryptedDisk, legacy = fallback)
        fixture.awaitLoaded()

        assertEquals(listOf("work"), fixture.store.profiles.value.map { it.id })
        assertEquals("s3cr3t-psk", fallback.values["psk"])
    }

    // ------------------------------------------------------------------ redaction

    @Test
    fun `nothing the store logs contains a secret`() {
        val disk = legacyPreferences()
        val fixture = StoreFixture(disk)
        fixture.awaitLoaded()
        fixture.upsert(home)
        fixture.secrets.store("home", SecretKind.PASSWORD, "another-password".toCharArray())
        fixture.flushSecrets()
        fixture.delete("home")

        val text = fixture.logText()
        assertFalse(text, text.contains("s3cr3t-psk"))
        assertFalse(text, text.contains("hunter2"))
        assertFalse(text, text.contains("another-password"))
    }

    private fun legacyPreferences() = FakePreferences(legacyValues())

    private fun legacyValues(): Map<String, Any> = mapOf(
        "name" to "Home",
        "server" to "vpn.example.com",
        "psk" to "s3cr3t-psk",
        "username" to "alice",
        "password" to "hunter2",
        "mtu" to 1380,
    )
}
