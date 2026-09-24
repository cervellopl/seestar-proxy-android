package com.seestarproxy.proxy

import org.json.JSONObject
import java.io.IOException
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Minimal HTTP dashboard (port 4090 by default):
 *
 * - `GET /`            HTML page
 * - `GET /api/stats`   JSON snapshot
 * - `GET /api/stream`  Server-Sent Events, stats + new log entries at 1 Hz
 */
class DashboardServer(
    private val port: Int,
    private val html: String,
    private val metrics: Metrics,
    private val extra: JSONObject.() -> Unit,
    /** Additional GET routes: path → (content type, body). */
    private val routes: Map<String, () -> Pair<String, String>> = emptyMap(),
) {
    private val running = AtomicBoolean(true)
    private lateinit var server: ServerSocket

    fun start() {
        server = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(port))
        }
        metrics.info("Dashboard: http://<ip-telefonu>:$port/")
        thread(name = "dash-accept", isDaemon = true) {
            while (running.get()) {
                val s = try {
                    server.accept()
                } catch (_: IOException) {
                    return@thread
                }
                thread(name = "dash-conn", isDaemon = true) { handle(s) }
            }
        }
    }

    fun stop() {
        running.set(false)
        server.closeQuietly()
    }

    private fun handle(s: Socket) = s.use {
        try {
            s.soTimeout = 10_000
            val reader = LineReader(s.getInputStream(), 8_192)
            val requestLine = reader.readLine()?.trim() ?: return
            // Drain headers.
            while (true) {
                val h = reader.readLine() ?: break
                if (h.isBlank()) break
            }
            val parts = requestLine.split(" ")
            val method = parts.getOrNull(0) ?: ""
            val path = parts.getOrNull(1)?.substringBefore('?') ?: "/"
            val out = s.getOutputStream()
            when {
                method != "GET" -> respond(out, 405, "text/plain", "Method Not Allowed")
                path == "/" || path == "/index.html" -> respond(out, 200, "text/html; charset=utf-8", html)
                path == "/api/stats" -> respond(out, 200, "application/json", metrics.toJson(null, extra).toString())
                path == "/api/stream" -> stream(s, out)
                path in routes -> routes.getValue(path)().let { (type, body) -> respond(out, 200, type, body) }
                else -> respond(out, 404, "text/plain", "Not Found")
            }
        } catch (_: IOException) {
        }
    }

    private fun respond(out: OutputStream, code: Int, type: String, body: String) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        val status = when (code) {
            200 -> "OK"; 404 -> "Not Found"; else -> "Method Not Allowed"
        }
        out.write(
            ("HTTP/1.1 $code $status\r\nContent-Type: $type\r\nContent-Length: ${bytes.size}\r\n" +
                "Cache-Control: no-cache\r\nConnection: close\r\n\r\n").toByteArray()
        )
        out.write(bytes)
        out.flush()
    }

    private fun stream(s: Socket, out: OutputStream) {
        s.soTimeout = 0
        out.write(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n"
                .toByteArray()
        )
        var nextSeq: Long? = null
        while (running.get()) {
            val json = metrics.toJson(nextSeq, extra)
            val log = json.getJSONArray("log")
            if (log.length() > 0) nextSeq = log.getJSONObject(log.length() - 1).getLong("seq") + 1
            else if (nextSeq == null) nextSeq = 0
            out.write("data: $json\n\n".toByteArray(Charsets.UTF_8))
            out.flush()
            try {
                Thread.sleep(1_000)
            } catch (_: InterruptedException) {
                return
            }
        }
    }
}
