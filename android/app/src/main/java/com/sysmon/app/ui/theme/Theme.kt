package com.sysmon.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

object SysmonColors {
    val Ink = Color(0xFF0A0A0A)
    val Paper = Color(0xFFFAFAF7)
    val Subtle = Color(0xFF6B6B6B)
    val Hairline = Color(0xFFE4E2DC)
    val Accent = Color(0xFF111111)
    val Up = Color(0xFF1F8A3F)
    val Down = Color(0xFFC53030)
    val Unknown = Color(0xFFB58900)
    val Acked = Color(0xFF555555)

    // Brighter status variants for dark mode — the light-mode inks go
    // muddy on near-black.
    val UpBright = Color(0xFF4CC38A)
    val DownBright = Color(0xFFFF6369)
    val UnknownBright = Color(0xFFE5C07B)
    val AckedBright = Color(0xFF9A9A9A)
}

private val LightColors = lightColorScheme(
    primary = SysmonColors.Ink,
    onPrimary = SysmonColors.Paper,
    background = SysmonColors.Paper,
    onBackground = SysmonColors.Ink,
    surface = SysmonColors.Paper,
    onSurface = SysmonColors.Ink,
    surfaceVariant = Color(0xFFF1EFE9),
    onSurfaceVariant = SysmonColors.Subtle,
    outline = SysmonColors.Hairline,
    error = SysmonColors.Down
)

private val DarkColors = darkColorScheme(
    primary = SysmonColors.Paper,
    onPrimary = SysmonColors.Ink,
    background = Color(0xFF0E0E0E),
    onBackground = SysmonColors.Paper,
    surface = Color(0xFF161616),
    onSurface = SysmonColors.Paper,
    surfaceVariant = Color(0xFF1E1E1E),
    onSurfaceVariant = Color(0xFFB5B5B5),
    outline = Color(0xFF333333),
    error = SysmonColors.Down
)

private val Serif = FontFamily.Serif
private val Sans = FontFamily.SansSerif
private val Mono = FontFamily.Monospace

val SysmonTypography = Typography(
    displayLarge = TextStyle(fontFamily = Serif, fontSize = 36.sp, fontWeight = FontWeight.Black, letterSpacing = (-0.5).sp),
    displayMedium = TextStyle(fontFamily = Serif, fontSize = 28.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.3).sp),
    headlineMedium = TextStyle(fontFamily = Sans, fontSize = 18.sp, fontWeight = FontWeight.SemiBold),
    titleLarge = TextStyle(fontFamily = Sans, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.2.sp),
    titleMedium = TextStyle(fontFamily = Sans, fontSize = 14.sp, fontWeight = FontWeight.Medium),
    labelLarge = TextStyle(fontFamily = Sans, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.0.sp),
    labelMedium = TextStyle(fontFamily = Sans, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.6.sp),
    bodyLarge = TextStyle(fontFamily = Sans, fontSize = 15.sp, fontWeight = FontWeight.Normal),
    bodyMedium = TextStyle(fontFamily = Sans, fontSize = 13.sp, fontWeight = FontWeight.Normal),
    bodySmall = TextStyle(fontFamily = Sans, fontSize = 12.sp, fontWeight = FontWeight.Normal, color = SysmonColors.Subtle)
)

val MonoSmall = TextStyle(fontFamily = Mono, fontSize = 12.sp, fontWeight = FontWeight.Normal)
val MonoMedium = TextStyle(fontFamily = Mono, fontSize = 14.sp, fontWeight = FontWeight.Medium)
val MonoLarge = TextStyle(fontFamily = Mono, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)

private val SysmonShapes = Shapes(
    extraSmall = RoundedCornerShape(2.dp),
    small = RoundedCornerShape(4.dp),
    medium = RoundedCornerShape(6.dp),
    large = RoundedCornerShape(8.dp)
)

@Composable
fun SysmonTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) DarkColors else LightColors
    MaterialTheme(
        colorScheme = colors,
        typography = SysmonTypography,
        shapes = SysmonShapes,
        content = content
    )
}
