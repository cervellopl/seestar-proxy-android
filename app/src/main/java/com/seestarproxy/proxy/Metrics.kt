package com.seestarproxy.proxy

import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.roundToLong

/** One traffic/system log entry shown in the app and on the web dashboard. */
data class LogEntry(
    val seq: Long,
    val timestampMs: Long,
    /** "ctrl-tx", "ctrl-rx", "ctrl-evt", "img", "img-tx", "sys", "err" */
    val channel: String,
    val summary: String,
    val payload: String?,
)

/** Latest telescope state derived from events and get_device_state responses. */
data class TelescopeStatus(
    val battery: Long? = null,
    val temperature: Double? = null,
    val isStacking: Boolean = false,
    val stackCount: Long = 0,
    val isGoto: Boolean = false,
    val isHoming: Boolean = false,
    val tracking: Boolean = false,
    val viewMode: String? = null,
    val chargerStatus: String? = null,
    val lastEvent: String? = null,
    val lastEventTsMs: Long = 0,
)

/** Shared runtime counters, updated by the proxy components and read by UI + dashboard. */
class Metrics {
    val controlRx = AtomicLong()
    val controlTx = AtomicLong()
    val controlEvents = AtomicLong()
    val imagingFrames = AtomicLong()
    val imagingBytes = AtomicLong()
    val controlClients = AtomicInteger()
    val imagingClients = AtomicInteger()

    @Volatile var upstreamControlUp = false
    @Volatile var upstreamImagingUp = false

    val startedAtMs = System.currentTimeMillis()

    private val log = ArrayDeque<LogEntry>(LOG_CAPACITY)
    private val logSeq = AtomicLong()

    @Volatile private var status = TelescopeStatus()
    private val statusLock = Any()

    fun pushLog(channel: String, summary: String, payload: String? = null) {
        val entry = LogEntry(logSeq.getAndIncrement(), System.currentTimeMillis(), channel, summary, payload)
        synchronized(log) {
            if (log.size >= LOG_CAPACITY) log.removeFirst()
            log.addLast(entry)
        }
    }

    fun info(msg: String) = pushLog("sys", msg)
    fun error(msg: String) = pushLog("err", msg)

    /** Entries with seq >= [fromSeq]; all entries when null. */
    fun logSince(fromSeq: Long?): List<LogEntry> = synchronized(log) {
        if (fromSeq == null) log.toList() else log.filter { it.seq >= fromSeq }
    }

    fun telescopeStatus(): TelescopeStatus = status

    fun updateEvent(eventName: String, msg: JSONObject) = synchronized(statusLock) {
        var s = status.copy(lastEvent = eventName, lastEventTsMs = System.currentTimeMillis())
        when (eventName) {
            "PiStatus" -> {
                msg.optNumber("battery_capacity")?.let { s = s.copy(battery = it.toDouble().roundToLong()) }
                msg.optNumber("temp")?.let { s = s.copy(temperature = it.toDouble()) }
            }
            "Stack" -> {
                s = s.copy(isStacking = true)
                (msg.opt("count") as? Number)?.let { s = s.copy(stackCount = it.toLong()) }
            }
            "AutoGoto", "ScopeGoto" -> s = s.copy(isGoto = true)
            "ScopeHome" -> s = s.copy(isHoming = msg.optString("state") == "working")
            "ScopeTrack" -> s = s.copy(tracking = msg.optBoolean("tracking", false))
            "View" -> s = s.copy(viewMode = msg.opt("mode") as? String)
        }
        status = s
    }

    fun updateResponse(msg: JSONObject) = synchronized(statusLock) {
        if (Protocol.methodName(msg) != "get_device_state") return@synchronized
        val pi = msg.optJSONObject("result")?.optJSONObject("pi_status") ?: return@synchronized
        var s = status
        pi.optNumber("battery_capacity")?.let { s = s.copy(battery = it.toDouble().roundToLong()) }
        pi.optNumber("temp")?.let { s = s.copy(temperature = it.toDouble()) }
        (pi.opt("charger_status") as? String)?.let { s = s.copy(chargerStatus = it) }
        status = s
    }

    /** Clear transient state after an upstream reconnect. */
    fun resetTelescopeState() = synchronized(statusLock) {
        status = status.copy(isStacking = false, stackCount = 0, isGoto = false, isHoming = false)
    }

    fun toJson(fromSeq: Long?, extra: JSONObject.() -> Unit = {}): JSONObject {
        val s = status
        return JSONObject().apply {
            put("uptime_s", (System.currentTimeMillis() - startedAtMs) / 1000)
            put("control", JSONObject().apply {
                put("rx", controlRx.get())
                put("tx", controlTx.get())
                put("events", controlEvents.get())
                put("clients", controlClients.get())
                put("upstream_up", upstreamControlUp)
            })
            put("imaging", JSONObject().apply {
                put("frames", imagingFrames.get())
                put("bytes", imagingBytes.get())
                put("clients", imagingClients.get())
                put("upstream_up", upstreamImagingUp)
            })
            put("telescope", JSONObject().apply {
                put("battery", s.battery ?: JSONObject.NULL)
                put("temperature", s.temperature ?: JSONObject.NULL)
                put("is_stacking", s.isStacking)
                put("stack_count", s.stackCount)
                put("is_goto", s.isGoto)
                put("is_homing", s.isHoming)
                put("tracking", s.tracking)
                put("view_mode", s.viewMode ?: JSONObject.NULL)
                put("charger_status", s.chargerStatus ?: JSONObject.NULL)
                put("last_event", s.lastEvent ?: JSONObject.NULL)
                put("last_event_ts_ms", s.lastEventTsMs)
            })
            put("log", JSONArray().apply {
                logSince(fromSeq).forEach { e ->
                    put(JSONObject().apply {
                        put("seq", e.seq)
                        put("ts", e.timestampMs)
                        put("channel", e.channel)
                        put("summary", e.summary)
                        put("payload", e.payload ?: JSONObject.NULL)
                    })
                }
            })
            extra()
        }
    }

    private fun JSONObject.optNumber(key: String): Number? = opt(key) as? Number

    companion object {
        const val LOG_CAPACITY = 200
    }
}
