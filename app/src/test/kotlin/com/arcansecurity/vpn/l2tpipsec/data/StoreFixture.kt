package com.arcansecurity.vpn.l2tpipsec.data

import android.content.SharedPreferences
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * A [PreferenceProfileStore] and its [PreferenceSecretVault] wired over a [FakePreferences], with
 * every log record captured.
 *
 * [Dispatchers.Unconfined] stands in for `Dispatchers.IO` so the suspending work runs to completion
 * on the calling thread and the tests need no scheduler of their own — the production wiring is the
 * same objects with the real dispatcher. Everything still goes through the real suspend functions,
 * so the ordering guarantees (load before mutate, credentials durable before the schema-1 keys are
 * dropped) are the ones being exercised.
 */
internal class StoreFixture(
    val prefs: FakePreferences = FakePreferences(),
    private val legacy: SharedPreferences? = null,
    /** Simulates a device whose keystore will not open the store at all. */
    private val openFails: Boolean = false,
) {

    val logged = mutableListOf<String>()

    private val logger = VpnLogger { level, _, message, error ->
        logged += "$level $message ${error?.message.orEmpty()}"
    }

    private val log = Log("Test", logger)

    private val scope = CoroutineScope(Dispatchers.Unconfined)

    private val lazyPrefs = LazyPreferences(Dispatchers.Unconfined, log) {
        if (openFails) throw IllegalStateException("keystore unavailable")
        OpenedPreferences(prefs)
    }

    /** The concrete vault; hand out [secrets] or [reader] to say which half is being used. */
    val vault = PreferenceSecretVault(lazyPrefs, scope, Dispatchers.Unconfined, log)

    /** What the UI would be given. */
    val secrets: SecretVault get() = vault

    /** What only the service is given. */
    val reader: SecretReader get() = vault

    val store: ProfileStore = PreferenceProfileStore(
        prefs = lazyPrefs,
        secrets = vault,
        scope = scope,
        io = Dispatchers.Unconfined,
        log = log,
        legacySource = { legacy },
    )

    /** Waits for the one-shot load, then returns the state it settled in. */
    fun awaitLoaded(): ProfileStoreState = runBlocking { store.awaitLoaded() }

    fun upsert(profile: VpnProfile) = runBlocking { store.upsert(profile) }

    fun delete(id: String) = runBlocking { store.delete(id) }

    fun setActive(id: String) = runBlocking { store.setActive(id) }

    fun flushSecrets(): Boolean = runBlocking { vault.flushNow() }

    /** Every log record, joined — for "nothing anywhere mentioned the secret" assertions. */
    fun logText(): String = logged.joinToString("\n")
}
