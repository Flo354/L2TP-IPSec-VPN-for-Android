package com.arcansecurity.vpn.l2tpipsec.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/*
 * A fixed palette rather than dynamic colour. This is an instrument: the same state must look the
 * same on every device, and "connected" must never be rendered in whatever tint the wallpaper
 * happens to suggest.
 */

private val Teal = Color(0xFF14B8A6)
private val TealDark = Color(0xFF0F766E)
private val Ink = Color(0xFF0B1016)
private val Slate = Color(0xFF141C26)
private val SlateHigh = Color(0xFF1D2836)
private val Mist = Color(0xFFF4F6F8)
private val Steel = Color(0xFF8FA3B8)
private val Amber = Color(0xFFF59E0B)
private val Crimson = Color(0xFFE5484D)
private val Emerald = Color(0xFF30A46C)

private val DarkColors = darkColorScheme(
    primary = Teal,
    onPrimary = Color(0xFF00201C),
    primaryContainer = TealDark,
    onPrimaryContainer = Color(0xFFCCFBF1),
    secondary = Color(0xFF7DA9FF),
    onSecondary = Color(0xFF00214D),
    secondaryContainer = Color(0xFF1E3A6B),
    onSecondaryContainer = Color(0xFFD8E4FF),
    tertiary = Amber,
    onTertiary = Color(0xFF2B1700),
    background = Ink,
    onBackground = Color(0xFFE6EDF3),
    surface = Slate,
    onSurface = Color(0xFFE6EDF3),
    surfaceVariant = SlateHigh,
    onSurfaceVariant = Steel,
    outline = Color(0xFF3A4859),
    outlineVariant = Color(0xFF27323F),
    error = Crimson,
    onError = Color(0xFF3A0709),
    errorContainer = Color(0xFF5A1518),
    onErrorContainer = Color(0xFFFFDAD6),
)

private val LightColors = lightColorScheme(
    primary = TealDark,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFCCFBF1),
    onPrimaryContainer = Color(0xFF00201C),
    secondary = Color(0xFF2C5FE0),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDCE6FF),
    onSecondaryContainer = Color(0xFF001A46),
    tertiary = Color(0xFFB45309),
    onTertiary = Color.White,
    background = Mist,
    onBackground = Color(0xFF111A22),
    surface = Color.White,
    onSurface = Color(0xFF111A22),
    surfaceVariant = Color(0xFFE7EDF3),
    onSurfaceVariant = Color(0xFF4A5C6E),
    outline = Color(0xFFB6C2CE),
    outlineVariant = Color(0xFFD6DEE6),
    error = Color(0xFFC62A2F),
    onError = Color.White,
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410004),
)

/** Semantic colours for the connection state, independent of the Material roles. */
data class StatusColors(
    val connected: Color,
    val working: Color,
    val failed: Color,
    val idle: Color,
)

val LocalStatusColors = staticCompositionLocalOf {
    StatusColors(Emerald, Amber, Crimson, Steel)
}

/** Numeric readouts are monospaced so addresses and counters stop jittering as they update. */
private val AppTypography = Typography().let { base ->
    base.copy(
        titleLarge = base.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelSmall = base.labelSmall.copy(letterSpacing = 0.8.sp),
    )
}

/** Style for addresses, byte counters and log lines. */
val MonoTextStyle: TextStyle = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontSize = 13.sp,
)

@Composable
fun L2tpVpnTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val statusColors = if (darkTheme) {
        StatusColors(connected = Emerald, working = Amber, failed = Crimson, idle = Steel)
    } else {
        StatusColors(
            connected = Color(0xFF1A7F4B),
            working = Color(0xFFB45309),
            failed = Color(0xFFC62A2F),
            idle = Color(0xFF64748B),
        )
    }
    androidx.compose.runtime.CompositionLocalProvider(LocalStatusColors provides statusColors) {
        MaterialTheme(
            colorScheme = if (darkTheme) DarkColors else LightColors,
            typography = AppTypography,
            content = content,
        )
    }
}

/** Shorthand for the status palette inside composables. */
val statusColors: StatusColors
    @Composable @ReadOnlyComposable get() = LocalStatusColors.current
