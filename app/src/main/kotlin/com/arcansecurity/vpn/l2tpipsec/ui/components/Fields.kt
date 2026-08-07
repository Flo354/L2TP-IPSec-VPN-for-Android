package com.arcansecurity.vpn.l2tpipsec.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.arcansecurity.vpn.l2tpipsec.ui.profile.STORED_SECRET_PLACEHOLDER
import com.arcansecurity.vpn.l2tpipsec.ui.profile.SecretFieldModel
import com.arcansecurity.vpn.l2tpipsec.ui.profile.SecretIntent
import com.arcansecurity.vpn.l2tpipsec.ui.profile.isEditable

/** A text field with an inline error message, the workhorse of the profile form. */
@Composable
fun VpnTextField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    error: String? = null,
    supporting: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text,
    imeAction: ImeAction = ImeAction.Next,
    placeholder: String? = null,
) {
    val support = error ?: supporting
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier.fillMaxWidth(),
        label = { Text(label) },
        placeholder = if (placeholder != null) {
            { Text(placeholder) }
        } else {
            null
        },
        isError = error != null,
        singleLine = true,
        supportingText = if (support != null) {
            { Text(support) }
        } else {
            null
        },
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, imeAction = imeAction),
    )
}

/**
 * One secret field, in whichever of its three states applies.
 *
 * This composable is where "a saved secret can never be shown again" is actually enforced:
 *
 *  * a stored secret is drawn by [SavedSecretRow], which has no value to draw — it renders a fixed
 *    placeholder and offers **Replace** and **Clear**. There is no reveal toggle, because there is
 *    nothing in the process to reveal;
 *  * a secret being typed is drawn by [EditableSecretField], which *does* offer a reveal toggle —
 *    the user is looking at characters they just entered — and resets it the moment the field loses
 *    focus;
 *  * a secret marked for removal is drawn by [ClearedSecretRow], with an undo.
 *
 * [typed] is owned by the screen and dies with it; nothing here writes it anywhere.
 */
@Composable
fun SecretField(
    label: String,
    model: SecretFieldModel,
    typed: String,
    onTyped: (String) -> Unit,
    onIntent: (SecretIntent) -> Unit,
    onRequestClear: () -> Unit,
    modifier: Modifier = Modifier,
    error: String? = null,
    supporting: String? = null,
    imeAction: ImeAction = ImeAction.Next,
) {
    when {
        model.intent == SecretIntent.CLEAR -> ClearedSecretRow(
            label = label,
            error = error,
            onUndo = { onIntent(SecretIntent.KEEP) },
            modifier = modifier,
        )

        model.isEditable -> EditableSecretField(
            label = label,
            value = typed,
            onValueChange = onTyped,
            replacingStored = model.stored,
            onCancelReplace = { onIntent(SecretIntent.KEEP) },
            error = error,
            supporting = supporting,
            imeAction = imeAction,
            modifier = modifier,
        )

        else -> SavedSecretRow(
            label = label,
            error = error,
            onReplace = { onIntent(SecretIntent.REPLACE) },
            onClear = onRequestClear,
            modifier = modifier,
        )
    }
}

/**
 * A secret that is in the vault.
 *
 * Built out of a bordered [Row] rather than a read-only `OutlinedTextField` so that there is no
 * text-selection handle, no copy affordance and no `value` at all — only a constant. The
 * accessibility label is set explicitly to the word "saved": reading a row of bullets aloud would
 * be useless, and reading anything else would be a leak.
 */
@Composable
private fun SavedSecretRow(
    label: String,
    error: String?,
    onReplace: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        FieldLabel(label)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(
                    width = 1.dp,
                    color = if (error != null) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.outline
                    },
                    shape = RoundedCornerShape(12.dp),
                )
                .padding(start = 16.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = STORED_SECRET_PLACEHOLDER,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.semantics { contentDescription = "$label: saved" },
            )
            Spacer(Modifier.width(10.dp))
            SavedBadge()
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onReplace) { Text("Replace") }
            TextButton(onClick = onClear) {
                Text("Clear", color = MaterialTheme.colorScheme.error)
            }
        }
        SupportText(error ?: "Stored on this device. It cannot be displayed again.", isError = error != null)
    }
}

@Composable
private fun ClearedSecretRow(
    label: String,
    error: String?,
    onUndo: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        FieldLabel(label)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.errorContainer, RoundedCornerShape(12.dp))
                .padding(start = 16.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "Will be removed when you save",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onUndo) { Text("Undo") }
        }
        if (error != null) SupportText(error, isError = true)
    }
}

/**
 * A secret being typed.
 *
 * The reveal toggle is legitimate here — the user is looking at characters they just entered — but
 * it is `remember`ed rather than `rememberSaveable`d and it is forced back off as soon as the field
 * loses focus, so it can never survive a trip to another screen or a process death.
 */
@Composable
private fun EditableSecretField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    replacingStored: Boolean,
    onCancelReplace: () -> Unit,
    error: String?,
    supporting: String?,
    imeAction: ImeAction,
    modifier: Modifier = Modifier,
) {
    var revealed by remember { mutableStateOf(false) }
    val support = error ?: supporting
        ?: "Replacing the saved value".takeIf { replacingStored }

    Column(modifier = modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { if (!it.isFocused) revealed = false },
            label = { Text(label) },
            isError = error != null,
            singleLine = true,
            visualTransformation = if (revealed) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            supportingText = if (support != null) {
                { Text(support) }
            } else {
                null
            },
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = imeAction,
            ),
            trailingIcon = {
                IconButton(onClick = { revealed = !revealed }) {
                    Icon(
                        imageVector = if (revealed) {
                            Icons.Filled.VisibilityOff
                        } else {
                            Icons.Filled.Visibility
                        },
                        contentDescription = if (revealed) "Hide what you typed" else "Show what you typed",
                    )
                }
            },
        )
        if (replacingStored) {
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                TextButton(onClick = onCancelReplace) { Text("Keep the saved one") }
            }
        }
    }
}

@Composable
private fun SavedBadge() {
    Box(
        modifier = Modifier
            .background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 3.dp),
    ) {
        Text(
            text = "Saved",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
        )
    }
}

@Composable
private fun FieldLabel(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp),
    )
}

@Composable
private fun SupportText(text: String, isError: Boolean) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = if (isError) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
        modifier = Modifier.padding(start = 16.dp, top = 4.dp),
    )
}

/**
 * A read-only dropdown over a fixed set of values, used for every crypto choice.
 *
 * Hand-rolled from a bordered row plus a [DropdownMenu] rather than `ExposedDropdownMenuBox`: the
 * anchoring API of the latter has changed shape across Material 3 releases, and this has exactly
 * the behaviour the form needs.
 */
@Composable
fun <T> EnumDropdown(
    label: String,
    options: List<T>,
    selected: T,
    onSelected: (T) -> Unit,
    labelFor: (T) -> String,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 4.dp, bottom = 4.dp),
        )
        Box {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = 1.dp,
                        color = MaterialTheme.colorScheme.outline,
                        shape = RoundedCornerShape(12.dp),
                    )
                    .clickable { expanded = true }
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = labelFor(selected),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Icon(
                    imageVector = Icons.Filled.KeyboardArrowDown,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(labelFor(option)) },
                        onClick = {
                            onSelected(option)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

/** A labelled switch with an explanatory second line. */
@Composable
fun SwitchRow(
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp),
        ) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

/** A chip-style toggle used for the PPP authentication protocol set. */
@Composable
fun ToggleChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val background = if (selected) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val foreground = if (selected) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    Box(
        modifier = modifier
            .background(background, RoundedCornerShape(50))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelLarge, color = foreground)
    }
}
