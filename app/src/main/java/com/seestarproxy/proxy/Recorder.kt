package com.seestarproxy.proxy

import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicInteger

/**
 * Records traffic in the same layout as seestar-proxy's `--record`:
 *
 * ```
 * <session>/manifest.json
 * <session>/control.jsonl       {"timestamp":…, "direction":"client|telescope", "raw":"…"}
 * <session>/frames/frame_0000_preview.bin   (80-byte header + payload)
 * ```
 */
class Recorder(val dir: File) {
    private val framesDir = File(dir, "frames")
    private val controlOut: FileOutputStream
    private val frameCounter = AtomicInteger()
    private val previewCount = AtomicInteger()
    private val stackCount = AtomicInteger()
    private val messageCount = AtomicInteger()
    private val startNanos = System.nanoTime()
    private val startEpoch = System.currentTimeMillis() / 1000.0

    init {
        framesDir.mkdirs()
        controlOut = FileOutputStream(File(dir, "control.jsonl"))
    }

    private fun timestamp() = startEpoch + (System.nanoTime() - startNanos) / 1e9

    fun recordControl(direction: String, raw: String) {
        messageCount.incrementAndGet()
        val line = JSONObject().apply {
            put("timestamp", timestamp())
            put("direction", direction)
            put("raw", raw)
        }.toString() + "\n"
        synchronized(controlOut) {
            try {
                controlOut.write(line.toByteArray(Charsets.UTF_8))
                controlOut.flush()
            } catch (_: Exception) {
            }
        }
    }

    /** [frame] is the complete frame: 80-byte header followed by the payload. */
    fun recordFrame(frame: ByteArray) {
        val parsed = FrameHeader.parse(frame)
        if (!parsed.isImage) return // skip handshake/control frames
        val idx = frameCounter.getAndIncrement()
        val kind = if (parsed.id == 23) {
            stackCount.incrementAndGet(); "stack"
        } else {
            previewCount.incrementAndGet(); "preview"
        }
        try {
            FileOutputStream(File(framesDir, "frame_%04d_%s.bin".format(idx, kind))).use { it.write(frame) }
        } catch (_: Exception) {
        }
    }

    fun finalize(): String {
        val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date())
        val manifest = JSONObject().apply {
            put("capture_date", iso)
            put("telescope_model", JSONObject.NULL)
            put("firmware_version", JSONObject.NULL)
            put("frame_count", frameCounter.get())
            put("preview_frame_count", previewCount.get())
            put("stack_frame_count", stackCount.get())
            put("control_message_count", messageCount.get())
            put("duration_seconds", (System.nanoTime() - startNanos) / 1e9)
            put("source", "seestar-proxy-android")
        }
        File(dir, "manifest.json").writeText(manifest.toString(2))
        synchronized(controlOut) { controlOut.closeQuietly() }
        return "Nagranie zapisane: ${messageCount.get()} wiadomości, ${frameCounter.get()} klatek"
    }
}
