// androidx.security:security-crypto is deprecated as a whole, with no replacement inside the
// library: the migration Google points at is hand-rolled AES-GCM over an Android Keystore key,
// which means rewriting the credential store and migrating what is already on disk. Until that is
// done properly, the deprecation is confined to this file — which contains nothing else — so the
// suppression can never quietly hide an unrelated one.
@file:Suppress("DEPRECATION")

package com.arcansecurity.vpn.l2tpipsec.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Opens [fileName] as an [EncryptedSharedPreferences] backed by an AES-256-GCM key held in the
 * Android keystore.
 *
 * @throws java.security.GeneralSecurityException or [java.io.IOException] when the keystore is
 *   unavailable; the caller decides what to do about it.
 */
internal fun openEncryptedPreferences(context: Context, fileName: String): SharedPreferences {
    val masterKey = MasterKey.Builder(context.applicationContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    return EncryptedSharedPreferences.create(
        context.applicationContext,
        fileName,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}
