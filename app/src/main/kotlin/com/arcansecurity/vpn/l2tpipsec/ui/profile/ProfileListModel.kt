package com.arcansecurity.vpn.l2tpipsec.ui.profile

import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import java.util.Locale
import java.util.UUID

/** Shown instead of an empty name; also what a blank name is saved as. */
const val UNTITLED_PROFILE: String = "Untitled profile"

// A profile is named by VpnProfile.displayName, which lives with the data. Declaring an extension
// of the same name here would be shadowed by that member and silently never run.

/** What its server line reads when nothing has been typed yet. */
val VpnProfile.displayServer: String get() = server.trim().ifBlank { "No server set" }

/**
 * Display order for the profile list.
 *
 * By name, then by id. Sorting is done on a `Locale.ROOT` lower-casing rather than the device
 * locale so the order cannot change under the user when they travel — and the id tiebreak keeps
 * two identically named profiles from swapping places on every recomposition.
 *
 * The active profile is deliberately *not* hoisted to the top: it is marked with a badge instead.
 * A list that reorders itself the moment you tap a row makes it very easy to activate the wrong
 * profile twice in a row.
 */
fun orderedForDisplay(profiles: List<VpnProfile>): List<VpnProfile> =
    profiles.sortedWith(
        compareBy({ it.displayName.lowercase(Locale.ROOT) }, { it.id }),
    )

/**
 * A name for the copy of [name] that is not already [taken].
 *
 * "Home" becomes "Home (copy)", then "Home (copy 2)", "Home (copy 3)" — copying a copy does not
 * pile up suffixes, because the base is stripped of an existing one first.
 */
fun duplicateNameFor(name: String, taken: Collection<String>): String {
    val base = name.trim().ifBlank { UNTITLED_PROFILE }.removeCopySuffix()
    val existing = taken.map { it.trim() }.toSet()
    val first = "$base (copy)"
    if (first !in existing) return first
    var index = 2
    while ("$base (copy $index)" in existing) index += 1
    return "$base (copy $index)"
}

/** A name for a brand new profile that does not collide with an existing one. */
fun newProfileName(taken: Collection<String>): String {
    val existing = taken.map { it.trim() }.toSet()
    if (VpnProfile.DEFAULT_NAME !in existing) return VpnProfile.DEFAULT_NAME
    var index = 2
    while ("${VpnProfile.DEFAULT_NAME} $index" in existing) index += 1
    return "${VpnProfile.DEFAULT_NAME} $index"
}

/**
 * A copy of [profile] under a fresh id and an unused name.
 *
 * **It carries no secrets, and it cannot**: they are keyed by profile id in a vault with no read
 * path for the UI. The screen says so rather than letting the user find out when the tunnel fails
 * to authenticate.
 */
fun duplicateOf(profile: VpnProfile, taken: Collection<String>, id: String = newProfileId()): VpnProfile =
    profile.copy(id = id, name = duplicateNameFor(profile.name, taken))

/** Identifier for a new profile; also the key its secrets are filed under in the vault. */
fun newProfileId(): String = UUID.randomUUID().toString()

private fun String.removeCopySuffix(): String =
    COPY_SUFFIX.replace(this, "").trim().ifBlank { UNTITLED_PROFILE }

private val COPY_SUFFIX = Regex("\\s*\\(copy(\\s+\\d+)?\\)$")
