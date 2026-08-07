package com.arcansecurity.vpn.l2tpipsec.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.arcansecurity.vpn.l2tpipsec.data.SecretKind
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.ui.components.AdvancedSection
import com.arcansecurity.vpn.l2tpipsec.ui.components.ConnectionSection
import com.arcansecurity.vpn.l2tpipsec.ui.components.SecretField
import com.arcansecurity.vpn.l2tpipsec.ui.profile.ProfileField
import com.arcansecurity.vpn.l2tpipsec.ui.profile.ProfileFormState
import com.arcansecurity.vpn.l2tpipsec.ui.profile.SecretIntent
import com.arcansecurity.vpn.l2tpipsec.ui.profile.edit
import com.arcansecurity.vpn.l2tpipsec.ui.profile.editMtu
import com.arcansecurity.vpn.l2tpipsec.ui.profile.validate
import com.arcansecurity.vpn.l2tpipsec.ui.profile.visibleError
import com.arcansecurity.vpn.l2tpipsec.ui.profile.withSecretIntent
import com.arcansecurity.vpn.l2tpipsec.ui.profile.withTypedSecret

/**
 * The profile form.
 *
 * This composable is the *only* place in the app that holds the characters of a secret, and it
 * holds them under two rules that are worth stating out loud:
 *
 *  1. `remember`, never `rememberSaveable`. A `rememberSaveable` here would write the pre-shared key
 *     the user is typing straight into the saved-instance-state bundle, which the system persists to
 *     disk and hands back after process death — the exact leak this rewrite was asked to close.
 *  2. A `DisposableEffect` drops the references when the screen leaves the composition, so the value
 *     is unreachable the moment the user navigates away rather than whenever the next GC happens.
 *
 * Everything above this screen — the form state, the controller, the store — only ever learns how
 * *many* characters were typed.
 */
@Composable
fun ProfileEditScreen(
    form: ProfileFormState,
    saving: Boolean,
    tunnelIsUp: Boolean,
    onFormChange: ((ProfileFormState) -> ProfileFormState) -> Unit,
    onSave: (typedPresharedKey: CharArray?, typedPassword: CharArray?) -> Unit,
    modifier: Modifier = Modifier,
) {
    var typedPresharedKey by remember { mutableStateOf("") }
    var typedPassword by remember { mutableStateOf("") }
    var pendingClear by remember { mutableStateOf<SecretKind?>(null) }

    DisposableEffect(Unit) {
        onDispose {
            typedPresharedKey = ""
            typedPassword = ""
        }
    }

    val validation = form.validate()
    val errorFor: (ProfileField) -> String? = { field -> form.visibleError(validation, field) }
    val onChange: (ProfileField?, (VpnProfile) -> VpnProfile) -> Unit = { field, transform ->
        onFormChange { it.edit(field, transform) }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
    ) {
        if (tunnelIsUp) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = "The tunnel is up. Changes here take effect the next time you connect.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(8.dp))
        ConnectionSection(
            form = form,
            errorFor = errorFor,
            onChange = onChange,
            presharedKeyField = {
                SecretField(
                    label = "Pre-shared key",
                    model = form.presharedKey,
                    typed = typedPresharedKey,
                    onTyped = { text ->
                        typedPresharedKey = text
                        onFormChange { it.withTypedSecret(SecretKind.PRESHARED_KEY, text.length) }
                    },
                    onIntent = { intent ->
                        if (intent != SecretIntent.REPLACE) typedPresharedKey = ""
                        onFormChange { it.withSecretIntent(SecretKind.PRESHARED_KEY, intent) }
                    },
                    onRequestClear = { pendingClear = SecretKind.PRESHARED_KEY },
                    error = errorFor(ProfileField.PRESHARED_KEY),
                )
            },
            passwordField = {
                SecretField(
                    label = "Password",
                    model = form.password,
                    typed = typedPassword,
                    onTyped = { text ->
                        typedPassword = text
                        onFormChange { it.withTypedSecret(SecretKind.PASSWORD, text.length) }
                    },
                    onIntent = { intent ->
                        if (intent != SecretIntent.REPLACE) typedPassword = ""
                        onFormChange { it.withSecretIntent(SecretKind.PASSWORD, intent) }
                    },
                    onRequestClear = { pendingClear = SecretKind.PASSWORD },
                    error = errorFor(ProfileField.PASSWORD),
                    imeAction = ImeAction.Done,
                )
            },
        )

        Spacer(Modifier.height(16.dp))
        AdvancedSection(
            form = form,
            expanded = form.advancedExpanded,
            onToggle = { onFormChange { it.copy(advancedExpanded = !it.advancedExpanded) } },
            errorFor = errorFor,
            onChange = onChange,
            onMtuChange = { text -> onFormChange { it.editMtu(text) } },
        )

        Spacer(Modifier.height(20.dp))
        Button(
            onClick = {
                onSave(
                    typedPresharedKey.takeIf { it.isNotEmpty() }?.toCharArray(),
                    typedPassword.takeIf { it.isNotEmpty() }?.toCharArray(),
                )
                // The controller wipes the arrays; drop the strings the fields were showing too.
                typedPresharedKey = ""
                typedPassword = ""
            },
            enabled = !saving,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text(if (saving) "Saving…" else "Save")
        }
        Spacer(Modifier.height(32.dp))
    }

    pendingClear?.let { kind ->
        ClearSecretDialog(
            kind = kind,
            onConfirm = {
                onFormChange { it.withSecretIntent(kind, SecretIntent.CLEAR) }
                if (kind == SecretKind.PRESHARED_KEY) typedPresharedKey = "" else typedPassword = ""
                pendingClear = null
            },
            onDismiss = { pendingClear = null },
        )
    }
}

/** Clearing a secret is destructive and unrecoverable, so it is always confirmed. */
@Composable
private fun ClearSecretDialog(
    kind: SecretKind,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val name = if (kind == SecretKind.PRESHARED_KEY) "pre-shared key" else "password"
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Clear the $name?") },
        text = {
            Text(
                "The stored $name is deleted when you save this profile. It cannot be recovered — " +
                    "you will have to type it in again.",
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text("Clear", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
