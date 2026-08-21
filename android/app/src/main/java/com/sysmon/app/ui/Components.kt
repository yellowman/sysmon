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
import androidx.compose.material.icons.outlined.WarningAmber
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sysmon.app.Host
import com.sysmon.app.PacketLossStats
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
    degraded: Boolean = false,
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
                        LivePill(offline = !live, degraded = degraded)
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
// Green + pulsing while updates flow, amber when the last poll failed
// (OFFLINE) or when polling works but no sysmond is reporting to the
// server (DEGRADED).
@Composable
fun LivePill(offline: Boolean, degraded: Boolean = false) {
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
    val alarmed = offline || degraded
    val color = if (alarmed) warnColor() else upColor()
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
                .alpha(if (alarmed) 1f else dotAlpha)
                .clip(CircleShape)
                .background(color)
        )
        Text(
            text = if (offline) "OFFLINE" else if (degraded) "DEGRADED" else "LIVE",
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.2.sp,
            fontFamily = FontFamily.SansSerif,
            color = if (alarmed) color else MaterialTheme.colorScheme.onSurfaceVariant
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

/**
 * The owning sysmond's name as a small muted pill. Kept deliberately
 * quiet - it is context, not the subject - and absent entirely on a
 * single-box install, where the row looks exactly as it always did.
 */
@Composable
fun SiteTag(name: String) {
    Text(
        text = name,
        fontSize = 9.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = 1,
        modifier = Modifier
            .padding(start = 6.dp)
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(horizontal = 5.dp, vertical = 1.dp)
    )
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
                        color = MaterialTheme.colorScheme.onBackground,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        // A long hostname ellipsizes rather than pushing the
                        // site tag (and PAUSED pill) out of the row.
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    if (host.siteTag.isNotEmpty()) {
                        SiteTag(host.siteTag)
                    }
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
                MetricsRow(host)
            }
        }
    }
}

/**
 * Latency, jitter and loss, for the checks that measure them.
 *
 * Draws nothing at all for an ordinary ping or tcp object, so a list of
 * plain hosts looks exactly as it did. A latency check exists to make
 * numbers, and until now the apps showed only up or down for it.
 */
@Composable
private fun MetricsRow(host: Host) {
    val rtt = host.rtt
    val loss = host.packetLoss
    val snmp = host.snmp
    if (rtt == null && loss == null && snmp == null) return

    Row(
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(top = 2.dp)
    ) {
        if (rtt != null) {
            Text(
                text = "%.2fms".format(rtt.avgMs),
                style = MonoSmall,
                fontWeight = FontWeight.Medium,
                color = metricColor(rtt.avgMs, rtt.thresholdMs, 150.0, 400.0)
            )
            Text(
                text = "±%.2fms".format(rtt.jitterMs),
                style = MonoSmall,
                color = metricColor(rtt.jitterMs, rtt.jitterThresholdMs, 30.0, 100.0)
            )
            // Probes that never came back: the loss the average hides.
            if (rtt.lostProbes > 0) {
                Text(
                    text = "${rtt.replies}/${rtt.probes}",
                    style = MonoSmall,
                    color = downColor()
                )
            }
        }
        if (loss != null) {
            Text(
                text = "%.1f%% loss".format(loss.lossPct),
                style = MonoSmall,
                fontWeight = FontWeight.Medium,
                color = lossColor(loss)
            )
        }
        if (snmp != null && snmp.sysUpTimeTicks > 0) {
            Text(
                text = "up ${formatTicks(snmp.sysUpTimeTicks)}",
                style = MonoSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * How alarming is a measured value?
 *
 * The operator's own threshold decides it when there is one: at or past
 * it is the down colour, and the last 20% of the approach is a warning.
 * With no threshold there is nothing to be relative to, so the absolute
 * fallbacks come from what the numbers mean - 150ms is ITU-T G.114's
 * guidance for voice, 30ms of jitter is where call quality suffers.
 */
@Composable
private fun metricColor(value: Double, threshold: Int, warnAbs: Double, badAbs: Double): Color {
    if (threshold > 0) {
        return when {
            value >= threshold -> downColor()
            value >= threshold * 0.8 -> warnColor()
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        }
    }
    return when {
        value >= badAbs -> downColor()
        value >= warnAbs -> warnColor()
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
}

/** Tolerance is a packet count, so compare like for like. */
@Composable
private fun lossColor(loss: PacketLossStats): Color = when {
    loss.tolerance > 0 && loss.lost > loss.tolerance -> downColor()
    loss.tolerance > 0 && loss.lost == loss.tolerance -> warnColor()
    loss.tolerance > 0 -> MaterialTheme.colorScheme.onSurfaceVariant
    loss.lossPct >= 5.0 -> downColor()
    loss.lossPct >= 1.0 -> warnColor()
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}

/** sysUpTime is TimeTicks: hundredths of a second, which nobody reads. */
private fun formatTicks(ticks: Long): String {
    val secs = ticks / 100
    val d = secs / 86400
    val h = (secs % 86400) / 3600
    val m = (secs % 3600) / 60
    return when {
        d > 0 -> "${d}d ${h}h"
        h > 0 -> "${h}h ${m}m"
        else -> "${m}m"
    }
}

// The good news, said loudly: shown when zero hosts are alerting.
// Unless nothing is reporting - zero alerts from zero daemons is not
// good news, and this card must not dress it as some.
@Composable
fun AllClearCard(total: Int, degraded: Boolean = false) {
    val tone = if (degraded) warnColor() else upColor()
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
                    .background(tone.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = if (degraded) Icons.Outlined.WarningAmber else Icons.Outlined.Check,
                    contentDescription = null,
                    tint = tone,
                    modifier = Modifier.size(30.dp)
                )
            }
            Text(
                text = if (degraded) "No monitoring daemon connected" else "All systems operational",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground
            )
            if (degraded) {
                Text(
                    text = "The server is up, but no sysmond is reporting to it",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else if (total > 0) {
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
            text = "Monitoring paused - the daemon is not running checks",
            style = MaterialTheme.typography.bodyMedium,
            color = amber
        )
    }
}

// Amber warning with an optional tappable action, e.g. "Notifications are
// turned off - OPEN NOTIFICATION SETTINGS".
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
