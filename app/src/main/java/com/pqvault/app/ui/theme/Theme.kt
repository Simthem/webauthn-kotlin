package com.pqvault.app.ui.theme

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

/**
 * Palette lifted from the Mantine dark scale, to match share.privcloud.fr.
 *
 * Amber on near-black rather than a blue accent: it reads as "warning, take care" without
 * being alarming, which is the right register for something guarding your logins.
 */
object PqColors {
    val Dark0 = Color(0xFFC1C2C5) // primary text
    val Dark1 = Color(0xFFA6A7AB)
    val Dark2 = Color(0xFF909296) // dimmed text
    val Dark3 = Color(0xFF5C5F66)
    val Dark4 = Color(0xFF373A40) // borders
    val Dark5 = Color(0xFF2C2E33) // raised surface
    val Dark6 = Color(0xFF25262B) // card
    val Dark7 = Color(0xFF141517) // body
    val Dark8 = Color(0xFF111214)

    val Amber300 = Color(0xFFFFD54F)
    val Amber400 = Color(0xFFFFCA28)
    val Amber500 = Color(0xFFFFC107)
    val Amber700 = Color(0xFFFFA000)
    val Amber50 = Color(0xFFFFF8E1)

    val Red = Color(0xFFFF6B6B)
    val Green = Color(0xFF51CF66)
}

private val DarkScheme = darkColorScheme(
    primary = PqColors.Amber500,
    onPrimary = PqColors.Dark8,
    primaryContainer = PqColors.Amber700,
    onPrimaryContainer = PqColors.Dark8,
    secondary = PqColors.Amber300,
    onSecondary = PqColors.Dark8,
    background = PqColors.Dark7,
    onBackground = PqColors.Dark0,
    surface = PqColors.Dark6,
    onSurface = PqColors.Dark0,
    surfaceVariant = PqColors.Dark5,
    onSurfaceVariant = PqColors.Dark2,
    outline = PqColors.Dark4,
    outlineVariant = PqColors.Dark4,
    error = PqColors.Red,
    onError = PqColors.Dark8,
)

/**
 * The light scheme exists only so the app does not look broken for someone who forces
 * light mode; the design is dark-first, as the reference is.
 */
private val LightScheme = lightColorScheme(
    primary = Color(0xFFB28704),
    onPrimary = Color.White,
    background = Color(0xFFF8F9FA),
    onBackground = Color(0xFF212529),
    surface = Color.White,
    onSurface = Color(0xFF212529),
    surfaceVariant = Color(0xFFF1F3F5),
    onSurfaceVariant = Color(0xFF495057),
    outline = Color(0xFFDEE2E6),
    error = Color(0xFFE03131),
)

private val PqShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(6.dp),
    medium = RoundedCornerShape(10.dp),
    large = RoundedCornerShape(14.dp),
    extraLarge = RoundedCornerShape(20.dp),
)

private val PqTypography = Typography(
    headlineMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 26.sp,
        letterSpacing = (-0.4).sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 21.sp,
        letterSpacing = (-0.2).sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
    ),
    bodyLarge = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 15.sp),
    bodyMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 14.sp),
    bodySmall = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 12.5.sp),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
    ),
)

/**
 * Dark by default rather than following the system, because the design is dark-first --
 * the amber-on-near-black palette is the identity, and the light scheme exists only as a
 * fallback for anyone who explicitly asks for it.
 */
@Composable
fun PqVaultTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkScheme else LightScheme,
        typography = PqTypography,
        shapes = PqShapes,
        content = content,
    )
}
