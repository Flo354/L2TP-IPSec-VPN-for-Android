package com.arcansecurity.vpn.l2tpipsec.data

import android.content.SharedPreferences

/**
 * An in-memory [SharedPreferences] that can be made to fail the way the encrypted one does.
 *
 * `EncryptedSharedPreferences` throws `SecurityException` out of every getter once its keyset no
 * longer matches the data on disk, and out of the editor when it can no longer encrypt. Both are
 * reachable here — per key with [unreadableKeys], wholesale with [readsFail] and [writesFail],
 * which are `var` so a test can let a store come back to life mid-run.
 */
class FakePreferences(
    initial: Map<String, Any> = emptyMap(),
    private val unreadableKeys: Set<String> = emptySet(),
    /** Keys whose write throws, so one half of a two-step operation can be made to fail. */
    private val unwritableKeys: Set<String> = emptySet(),
    @JvmField var readsFail: Boolean = false,
    @JvmField var writesFail: Boolean = false,
) : SharedPreferences {

    /** Directly inspectable so a test can assert on what is *on disk*, not on what was published. */
    val values = LinkedHashMap<String, Any>(initial)

    private fun guard(key: String?) {
        if (readsFail) throw SecurityException("Could not decrypt value")
        if (key in unreadableKeys) throw SecurityException("Could not decrypt value for $key")
    }

    override fun getAll(): MutableMap<String, *> {
        guard(null)
        return values
    }

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

    override fun contains(key: String?): Boolean {
        guard(key)
        return values.containsKey(key)
    }

    override fun edit(): SharedPreferences.Editor {
        if (writesFail) throw SecurityException("Could not encrypt value")
        return FakeEditor(values, unwritableKeys)
    }

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit
}

private class FakeEditor(
    private val target: MutableMap<String, Any>,
    private val unwritableKeys: Set<String>,
) : SharedPreferences.Editor {

    private val staged = LinkedHashMap<String, Any?>()
    private var clearRequested = false

    override fun putString(key: String?, value: String?) = apply {
        if (key in unwritableKeys) throw SecurityException("Could not encrypt value for $key")
        staged[key!!] = value
    }

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
