package com.seestarproxy.proxy

import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream

/**
 * Seestar protocol constants and helpers.
 *
 * Port 4700: JSON-RPC over TCP, `\r\n` delimited.
 * Port 4800: binary frames with an 80-byte big-endian header + payload.
 * Port 4720: UDP discovery (`scan_iscope`).
 */
object Protocol {
    const val HEADER_SIZE = 80
    const val CONTROL_PORT = 4700
    const val IMAGING_PORT = 4800
    const val DISCOVERY_PORT = 4720
    const val DASHBOARD_PORT = 4090

    /** Max length of a single JSON line accepted from a client. */
    const val MAX_LINE_BYTES = 1_048_576

    /** Frames larger than this are treated as a corrupt stream. */
    const val MAX_FRAME_BYTES = 50_000_000L

    /** Max requests awaiting a telescope response before new ones are rejected. */
    const val MAX_PENDING_REQUESTS = 1_024

    fun methodName(msg: JSONObject): String? =
        (msg.opt("method") as? String)

    fun isEvent(msg: JSONObject): Boolean = msg.has("Event")

    /** Raw `id` value if present and non-null (any JSON type). */
    fun getId(msg: JSONObject): Any? {
        val v = msg.opt("id")
        return if (v == null || v == JSONObject.NULL) null else v
    }

    /** `id` as a non-negative integer, used to match telescope responses to remapped ids. */
    fun numericId(msg: JSONObject): Long? {
        val v = msg.opt("id")
        return when (v) {
            is Int -> v.toLong().takeIf { it >= 0 }
            is Long -> v.takeIf { it >= 0 }
            is Number -> v.toDouble().let { d ->
                if (d >= 0 && d == Math.floor(d) && d < Long.MAX_VALUE) d.toLong() else null
            }
            else -> null
        }
    }

    fun heartbeat(id: Long): String =
        """{"id":$id,"method":"test_connection","params":"verify"}"""
}

/** Parsed 80-byte frame header. */
data class FrameHeader(
    val size: Long,
    val code: Int,
    val id: Int,
    val width: Int,
    val height: Int,
) {
    /** True if this looks like a real image frame rather than a handshake. */
    val isImage: Boolean get() = width > 0 && height > 0 && size > 1000

    val kind: String
        get() = when (id) {
            20 -> "view"
            21 -> "preview"
            23 -> "stack"
            else -> "frame"
        }

    companion object {
        fun parse(b: ByteArray): FrameHeader {
            require(b.size >= Protocol.HEADER_SIZE)
            fun u8(i: Int) = b[i].toInt() and 0xFF
            val size = (u8(6).toLong() shl 24) or (u8(7).toLong() shl 16) or
                (u8(8).toLong() shl 8) or u8(9).toLong()
            return FrameHeader(
                size = size,
                code = u8(14),
                id = u8(15),
                width = (u8(16) shl 8) or u8(17),
                height = (u8(18) shl 8) or u8(19),
            )
        }
    }
}

class LineTooLongException(len: Int) : IOException("line too long ($len bytes)")

/**
 * Reads `\n`-terminated lines with a hard size limit. Returns null at EOF.
 * A trailing partial line at EOF is returned as a line (matching the Rust proxy).
 */
class LineReader(input: InputStream, private val limit: Int = Protocol.MAX_LINE_BYTES) {
    private val inp = BufferedInputStream(input, 64 * 1024)
    private val buf = ByteArrayOutputStream()

    fun readLine(): String? {
        buf.reset()
        while (true) {
            val c = inp.read()
            if (c < 0) {
                return if (buf.size() == 0) null else String(buf.toByteArray(), Charsets.UTF_8)
            }
            if (c == '\n'.code) return String(buf.toByteArray(), Charsets.UTF_8)
            buf.write(c)
            if (buf.size() > limit) throw LineTooLongException(buf.size())
        }
    }
}

fun Closeable?.closeQuietly() {
    try {
        this?.close()
    } catch (_: Exception) {
    }
}

fun String.clip(n: Int): String = if (length <= n) this else substring(0, n) + "…"
