package com.sysmon.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Single source of truth for live monitoring state.
 *
 * Rather than each screen fetching /api/monitoring/status on its own timer,
 * one poller keeps a host map warm and both the Alerts and Hosts screens
 * observe it. The first fetch pulls the full status; every subsequent poll
 * asks for only what changed via ?since=<rev>, so a steady-state poll
 * transfers a near-empty delta instead of the whole host list.
 */
object StatusStore {
    var hosts by mutableStateOf<List<Host>>(emptyList())
        private set
    var stats by mutableStateOf<Stats?>(null)
        private set
    var daemon by mutableStateOf<DaemonInfo?>(null)
        private set
    var error by mutableStateOf<String?>(null)
        private set
    var loading by mutableStateOf(true)
        private set

    // Debounced connectivity for the LIVE pill: a single failed poll is
    // routine (stale keep-alive sockets, a blip in coverage) and the next
    // poll usually succeeds - flipping the pill on every hiccup made it
    // read OFFLINE half the time on a perfectly healthy connection. Only
    // consecutive failures count.
    var offline by mutableStateOf(false)
        private set

    // The server answered but no sysmond is reporting to it. Nothing is
    // being monitored, which "all good" must not be allowed to claim.
    var degraded by mutableStateOf(false)
        private set
    private var failStreak = 0
    private const val OFFLINE_AFTER_FAILURES = 3

    private const val POLL_MS = 5000L

    private var rev = 0L
    private val index = LinkedHashMap<String, Host>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var pollJob: Job? = null

    val alerts: List<Host> get() = hosts.filter { !it.isOK }
    // The active board: what nobody has claimed yet. Acked alerts are
    // triaged, not gone - screens list them separately.
    val unackedAlerts: List<Host> get() = hosts.filter { !it.isOK && !it.acked }
    val ackedAlerts: List<Host> get() = hosts.filter { !it.isOK && it.acked }

    private fun key(h: Host): String = h.objectName.ifEmpty { h.hostname }

    /** Begin (or resume) polling. Idempotent. */
    fun start() {
        if (pollJob?.isActive == true) return
        pollJob = scope.launch { pollLoop() }
    }

    /** Pause polling (app backgrounded); retains last known state. */
    fun stop() {
        pollJob?.cancel()
        pollJob = null
    }

    /** Force an immediate fetch (pull-to-refresh / manual refresh). */
    suspend fun refreshNow() = fetch()

    private suspend fun pollLoop() {
        fetch()
        while (scope.isActive) {
            delay(POLL_MS)
            fetch()
        }
    }

    private suspend fun fetch() {
        if (!Session.isLoggedIn()) return
        try {
            if (rev == 0L) {
                val status = Api.status()
                applyFull(status.hosts, status.statistics, status.daemon, status.rev)
                degraded = status.sitesReachable == 0
            } else {
                val delta = Api.statusDelta(rev)
                applyDelta(delta)
                degraded = delta.sitesReachable == 0
            }
            error = null
            failStreak = 0
            offline = false
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e // never count a cancelled poll as a network failure
        } catch (e: Exception) {
            error = e.message
            failStreak++
            if (failStreak >= OFFLINE_AFTER_FAILURES) offline = true
        }
        loading = false
        Session.alertCount = unackedAlerts.size
    }

    private fun applyFull(list: List<Host>, s: Stats, d: DaemonInfo, r: Long) {
        index.clear()
        list.forEach { index[key(it)] = it }
        stats = s
        daemon = d
        rev = r
        rebuild()
    }

    private fun applyDelta(d: StatusDelta) {
        if (d.full) {
            applyFull(d.changed, d.statistics, d.daemon, d.rev)
            return
        }
        d.changed.forEach { index[key(it)] = it }
        d.removed.forEach { index.remove(it) }
        stats = d.statistics
        daemon = d.daemon
        rev = d.rev
        rebuild()
    }

    private fun rebuild() {
        hosts = index.values.sortedBy { it.hostname }
    }

    /** Clear all state on logout so the next login starts from a full fetch. */
    fun reset() {
        stop()
        rev = 0L
        index.clear()
        hosts = emptyList()
        stats = null
        daemon = null
        error = null
        failStreak = 0
        offline = false
        degraded = false
        loading = true
    }
}
