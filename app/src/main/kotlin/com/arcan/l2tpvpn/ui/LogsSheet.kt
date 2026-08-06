package com.arcan.l2tpvpn.ui

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.arcan.l2tpvpn.platform.AndroidLogger
import com.arcan.l2tpvpn.ui.theme.MonoTextStyle

/**
 * The live view of [AndroidLogger]'s ring buffer.
 *
 * Copy and share are not a nicety: matching what the client sent against what a router logged is
 * the whole debugging loop, and it happens by e-mailing the trace to yourself.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsSheet(
    logger: AndroidLogger,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val lines by logger.lines.collectAsState()
    val listState = rememberLazyListState()
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    // Follow the tail: a log you have to scroll is a log you stop reading.
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) {
            listState.scrollToItem(lines.lastIndex)
        }
    }

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(modifier = Modifier.fillMaxHeight(0.92f)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 20.dp, end = 8.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column {
                    Text("Logs", style = MaterialTheme.typography.titleLarge)
                    Text(
                        text = "${lines.size} of ${logger.buffer.capacity} lines",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row {
                    IconButton(onClick = { clipboard.setText(AnnotatedString(logger.snapshot())) }) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy the log")
                    }
                    IconButton(onClick = { shareText(context, logger.snapshot()) }) {
                        Icon(Icons.Filled.Share, contentDescription = "Share the log")
                    }
                    IconButton(onClick = { logger.clear() }) {
                        Icon(Icons.Filled.Delete, contentDescription = "Clear the log")
                    }
                }
            }

            if (lines.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(40.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "Nothing logged yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                ) {
                    items(lines) { line ->
                        Text(
                            text = line,
                            style = MonoTextStyle,
                            color = lineColor(line),
                            modifier = Modifier.padding(vertical = 1.dp),
                        )
                    }
                }
            }
        }
    }
}

/** Errors and warnings have to jump out of a wall of monospaced text. */
@Composable
private fun lineColor(line: String) = when {
    line.contains(" E/") -> MaterialTheme.colorScheme.error
    line.contains(" W/") -> MaterialTheme.colorScheme.tertiary
    line.contains(" D/") -> MaterialTheme.colorScheme.onSurfaceVariant
    else -> MaterialTheme.colorScheme.onSurface
}

private fun shareText(context: android.content.Context, text: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "L2TP/IPsec log")
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(
        Intent.createChooser(intent, "Share the log").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
    )
}
