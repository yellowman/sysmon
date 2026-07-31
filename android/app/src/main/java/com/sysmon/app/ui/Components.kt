package com.sysmon.app.ui

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sysmon.app.Host
import com.sysmon.app.Stats
import com.sysmon.app.formatUptime
import com.sysmon.app.ui.theme.MonoLarge
import com.sysmon.app.ui.theme.MonoMedium
import com.sysmon.app.ui.theme.MonoSmall
import com.sysmon.app.ui.theme.SysmonColors

// Status colors, brightened in dark mode so they read on near-black.
@Composable
fun statusColor(status: String): Color {
    val dark = isSystemInDarkTheme()
    return when (status) {
        "OK" -> if (dark) SysmonColors.UpBright else SysmonColors.Up
        "WARNING" -> if (dark) SysmonColors.UnknownBright else SysmonColors.Unknown
        "CRITICAL" -> if (dark) SysmonColors.DownBright else SysmonColors.Down
        else -> if (dark) SysmonColors.AckedBright else SysmonColors.Acked
    }
}

@Composable
fun warnColor(): Color =
    if (isSystemInDarkTheme()) SysmonColors.UnknownBright else SysmonColors.Unknown

@Composable
fun downColor(): Color =
    if (isSystemInDarkTheme()) SysmonColors.DownBright else SysmonColors.Down

@Composable
fun upColor(): Color =
    if (isSystemInDarkTheme()) SysmonColors.UpBright else SysmonColors.Up

@Composable
fun TopHeader(
    title: String,
    subtitle: String,
    refreshing: Boolean = false,
    live: Boolean? = null,
    onRefresh: (() -> Unit)? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 24.dp),
        verticalAlignment = Alignment.Top
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "SYSMON",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f, fill = false)
                )
                if (live != null) {
                    Box(modifier = Modifier.padding(start = 10.dp)) {
                        LivePill(offline = !live)
                    }
                }
            }
            Text(
                text = title,
                style = MaterialTheme.typography.displayMedium,
                color = MaterialTheme.colorScheme.onBackground
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (onRefresh != null) {
            if (refreshing) {
                Box(
                    modifier = Modifier.size(48.dp),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                }
            } else {
                IconButton(onClick = onRefresh) {
                    Icon(
                        imageVector = Icons.Outlined.Refresh,
                        contentDescription = "Refresh",
                        tint = MaterialTheme.colorScheme.onBackground
                    )
                }
            }
        }
    }
}

// Tiny heartbeat indicator: the visible face of the live delta poller.
// Green + pulsing while updates flow, amber when the last poll failed.
@Composable
fun LivePill(offline: Boolean) {
    val transition = rememberInfiniteTransition(label = "live")
    val dotAlpha by transition.animateFloat(
        initialValue = 1f,
        targetValue = 0.25f,
        animationSpec = infiniteRepeatable(
            animation = tween(900, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "liveAlpha"
    )
    val color = if (offline) warnColor() else upColor()
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(50))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .alpha(if (offline) 1f else dotAlpha)
                .clip(CircleShape)
                .background(color)
        )
        Text(
            text = if (offline) "OFFLINE" else "LIVE",
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.2.sp,
            fontFamily = FontFamily.SansSerif,
            color = if (offline) color else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun AlertBadgedIcon(icon: androidx.compose.ui.graphics.vector.ImageVector, count: Int, contentDescription: String) {
    BadgedBox(badge = {
        if (count > 0) {
            Badge { Text(count.toString()) }
        }
    }) {
        Icon(imageVector = icon, contentDescription = contentDescription)
    }
}

@Composable
fun SectionHeader(label: String, accent: String? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label.uppercase(),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onBackground
        )
        if (accent != null) {
            Text(
                text = accent,
                style = MonoSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun Card(content: @Composable () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surface)
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outline,
                shape = RoundedCornerShape(12.dp)
            )
    ) { content() }
}

// Status dot with a soft glow halo; pulses when [pulse] is set so a down
// host is impossible to miss at a glance.
@Composable
fun StatusDot(status: String, pulse: Boolean = false) {
    val color = statusColor(status)
    Box(
        modifier = Modifier.size(16.dp),
        contentAlignment = Alignment.Center
    ) {
        if (pulse) {
            val transition = rememberInfiniteTransition(label = "pulse")
            val scale by transition.animateFloat(
                initialValue = 1f,
                targetValue = 2.4f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1400, easing = FastOutSlowInEasing)
                ),
                label = "pulseScale"
            )
            val fade by transition.animateFloat(
                initialValue = 0.55f,
                targetValue = 0f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1400, easing = LinearEasing)
                ),
                label = "pulseFade"
            )
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .scale(scale)
                    .alpha(fade)
                    .clip(CircleShape)
                    .background(color)
            )
        }
        Box(
            modifier = Modifier
                .size(16.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.18f))
        )
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color)
        )
    }
}

@Composable
fun StatTile(label: String, value: String, accent: Color? = null, dim: Boolean = false) {
    Column(
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
            .padding(12.dp)
            .fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = label.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MonoLarge,
            color = when {
                dim -> MaterialTheme.colorScheme.onSurfaceVariant
                else -> accent ?: MaterialTheme.colorScheme.onBackground
            }
        )
    }
}

@Composable
fun StatsRow(stats: Stats?) {
    val s = stats ?: return
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Box(modifier = Modifier.weight(1f)) {
            StatTile("TOTAL", s.total.toString())
        }
        Box(modifier = Modifier.weight(1f)) {
            StatTile("OK", s.healthy.toString(), upColor(), dim = s.healthy == 0)
        }
        Box(modifier = Modifier.weight(1f)) {
            StatTile("WARN", s.warning.toString(), warnColor(), dim = s.warning == 0)
        }
        Box(modifier = Modifier.weight(1f)) {
            StatTile("CRIT", s.critical.toString(), downColor(), dim = s.critical == 0)
        }
    }
}

@Composable
fun HostRow(host: Host, onClick: (() -> Unit)? = null) {
    Card {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            StatusDot(host.overallStatus, pulse = host.isDown && !host.paused)
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = host.hostname,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    if (host.paused) {
                        Text(
                            text = "PAUSED",
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.5.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier
                                .padding(start = 6.dp)
                                .clip(RoundedCornerShape(50))
                                .background(MaterialTheme.colorScheme.surfaceVariant)
                                .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(50))
                                .padding(horizontal = 5.dp, vertical = 2.dp)
                        )
                    }
                }
                if (host.description.isNotEmpty()) {
                    Text(
                        text = host.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = host.overallStatus,
                        style = MaterialTheme.typography.labelMedium,
                        color = statusColor(host.overallStatus)
                    )
                    if (host.ip.isNotEmpty()) {
                        Text(
                            text = host.ip,
                            style = MonoSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    val duration = when {
                        host.isDown && host.timeFailed > 0 -> "· down ${formatUptime(host.timeFailed)}"
                        host.isOK && host.timeUp > 0 -> "· up ${formatUptime(host.timeUp)}"
                        else -> null
                    }
                    if (duration != null) {
                        Text(
                            text = duration,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (host.isDown) downColor()
                                else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

// The good news, said loudly: shown when zero hosts are alerting.
@Composable
fun AllClearCard(total: Int) {
    Card {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(CircleShape)
                    .background(upColor().copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Outlined.Check,
                    contentDescription = null,
                    tint = upColor(),
                    modifier = Modifier.size(30.dp)
                )
            }
            Text(
                text = "All systems operational",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground
            )
            if (total > 0) {
                Text(
                    text = "$total host${if (total == 1) "" else "s"} monitored · nothing needs you",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun FieldLabel(text: String) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(bottom = 6.dp)
    )
}

@Composable
fun ErrorBanner(message: String) {
    val red = downColor()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(red.copy(alpha = 0.08f))
            .border(1.dp, red.copy(alpha = 0.35f), RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = red
        )
    }
}

@Composable
fun PausedBanner() {
    val amber = warnColor()
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(amber.copy(alpha = 0.1f))
            .border(1.dp, amber.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        Text(
            text = "Monitoring paused — the daemon is not running checks",
            style = MaterialTheme.typography.bodyMedium,
            color = amber
        )
    }
}

// Amber warning with an optional tappable action, e.g. "Notifications are
// turned off — OPEN NOTIFICATION SETTINGS".
@Composable
fun WarningBanner(message: String, actionLabel: String? = null, onAction: (() -> Unit)? = null) {
    val amber = warnColor()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(amber.copy(alpha = 0.1f))
            .border(1.dp, amber.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
            .then(if (onAction != null) Modifier.clickable { onAction() } else Modifier)
            .padding(12.dp)
    ) {
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = amber
        )
        if (actionLabel != null && onAction != null) {
            Text(
                text = actionLabel.uppercase(),
                style = MaterialTheme.typography.labelMedium,
                color = amber,
                modifier = Modifier.padding(top = 6.dp)
            )
        }
    }
}

@Composable
fun CenteredSpinner() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator(
            strokeWidth = 2.dp,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
fun EmptyState(message: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = message,
            style = MonoMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
