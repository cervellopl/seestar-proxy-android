package com.seestarproxy.proxy

import org.json.JSONObject
import java.io.IOException
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Port 4700 control proxy: multiplexes JSON-RPC between many clients and a
 * single upstream Seestar connection.
 *
 * - Connects upstream lazily, when the first client connects.
 * - Rewrites request ids to globally unique ones so clients never collide.
 * - Routes each response back to the originating client with its original id.
 * - Broadcasts async events (`"Event"` messages) to every client.
 * - Sends `test_connection` heartbeats once the telescope has answered.
 */
class ControlProxy(
    private val bindPort: Int,
    private val upstream: InetSocketAddress,
    private val metrics: Metrics,
    private val recorder: Recorder?,
    /** Network that carries traffic to the telescope. */
    private val net: NetBinder = NetBinder.DEFAULT,
    /** Notified with each client address (used for discovery announcements). */
    private val onClient: (java.net.InetAddress) -> Unit = {},
) {
    private class Pending(val client: Client, val originalId: Any)

    private val running = AtomicBoolean(true)
    private val nextId = AtomicLong(100_000)
    private val pending = ConcurrentHashMap<Long, Pending>()
    private val heartbeatIds = ConcurrentHashMap.newKeySet<Long>()
    private val clients = CopyOnWriteArrayList<Client>()
    private val upstreamQueue = LinkedBlockingQueue<String>(256)
    private val handshakeDone = AtomicBoolean(false)
    private val upstreamStarted = AtomicBoolean(false)

    private lateinit var server: ServerSocket
    @Volatile private var upstreamSocket: Socket? = null

    fun start() {
        server = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(bindPort))
        }
        metrics.info("Sterowanie: nasłuch na porcie $bindPort")
        thread(name = "ctrl-accept", isDaemon = true) { acceptLoop() }
    }

    val localPort: Int get() = server.localPort

    fun stop() {
        running.set(false)
        server.closeQuietly()
        upstreamSocket.closeQuietly()
        clients.forEach { it.close() }
    }

    private fun acceptLoop() {
        while (running.get()) {
            val sock = try {
                server.accept()
            } catch (e: IOException) {
                if (running.get()) metrics.error("Sterowanie: błąd accept: ${e.message}")
                return
            }
            sock.tcpNoDelay = true
            val addr = sock.remoteSocketAddress.toString().trimStart('/')
            metrics.info("Klient sterowania połączony: $addr")

            if (!upstreamStarted.getAndSet(true)) {
                thread(name = "ctrl-upstream", isDaemon = true) { upstreamLoop() }
                thread(name = "ctrl-heartbeat", isDaemon = true) { heartbeatLoop() }
                // Give the upstream connection a moment to establish.
                Thread.sleep(200)
            }

            val client = Client(sock, addr)
            onClient(sock.inetAddress)
            clients.add(client)
            metrics.controlClients.incrementAndGet()
            thread(name = "ctrl-client-$addr", isDaemon = true) {
                try {
                    handleClient(client)
                } catch (e: Exception) {
                    if (running.get()) metrics.error("Klient sterowania $addr: ${e.message}")
                } finally {
                    client.close()
                    clients.remove(client)
                    metrics.controlClients.decrementAndGet()
                    metrics.info("Klient sterowania rozłączony: $addr")
                }
            }
        }
    }

    // ─── Client side ────────────────────────────────────────────────────────

    /** A connected client with its own outbound queue drained by a writer thread. */
    private inner class Client(val socket: Socket, val addr: String) {
        private val out = LinkedBlockingQueue<String>(1024)
        private val closed = AtomicBoolean(false)
        private val writer = thread(start = false, name = "ctrl-writer-$addr", isDaemon = true) {
            try {
                val os: OutputStream = socket.getOutputStream()
                while (!closed.get()) {
                    val msg = out.take()
                    os.write("$msg\r\n".toByteArray(Charsets.UTF_8))
                    os.flush()
                }
            } catch (_: InterruptedException) {
            } catch (_: IOException) {
            } finally {
                close()
            }
        }

        init {
            writer.start()
        }

        /** Queue a line for this client; returns false if the client is too slow. */
        fun send(msg: String): Boolean = !closed.get() && out.offer(msg)

        fun close() {
            if (closed.getAndSet(true)) return
            socket.closeQuietly()
            writer.interrupt()
        }
    }

    private fun handleClient(client: Client) {
        val reader = LineReader(client.socket.getInputStream())
        while (running.get()) {
            val line = reader.readLine() ?: break
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue

            // Record pre-remap so each client message appears exactly once.
            recorder?.recordControl("client", trimmed)
            metrics.controlTx.incrementAndGet()

            val msg = try {
                JSONObject(trimmed)
            } catch (_: Exception) {
                metrics.error("Niepoprawny JSON od klienta: ${trimmed.clip(100)}")
                continue
            }
            metrics.pushLog("ctrl-tx", Protocol.methodName(msg) ?: "?", trimmed)

            val originalId = Protocol.getId(msg)
            if (originalId != null) {
                val remapped = nextId.getAndIncrement()
                msg.put("id", remapped)
                val forwarded = msg.toString()

                synchronized(pending) {
                    if (pending.size >= Protocol.MAX_PENDING_REQUESTS) {
                        val err = JSONObject().apply {
                            put("id", originalId)
                            put("code", -32000)
                            put("error", "too many pending requests")
                        }
                        client.send(err.toString())
                        null
                    } else {
                        pending[remapped] = Pending(client, originalId)
                        Unit
                    }
                } ?: continue

                if (!upstreamQueue.offer(forwarded, 10, TimeUnit.SECONDS)) {
                    pending.remove(remapped)
                    metrics.error("Kolejka do teleskopu pełna — odrzucono ${Protocol.methodName(msg)}")
                }
            } else {
                // Notification (no id) — forward as-is.
                upstreamQueue.offer(msg.toString(), 10, TimeUnit.SECONDS)
            }
        }
    }

    // ─── Upstream side ──────────────────────────────────────────────────────

    private fun heartbeatLoop() {
        while (running.get()) {
            try {
                Thread.sleep(5_000)
            } catch (_: InterruptedException) {
                return
            }
            if (!handshakeDone.get()) continue
            val id = nextId.getAndIncrement()
            heartbeatIds.add(id)
            upstreamQueue.offer(Protocol.heartbeat(id))
        }
    }

    private fun connectUpstream(): Socket? {
        while (running.get()) {
            metrics.info("Łączenie ze sterowaniem teleskopu $upstream…")
            val s = Socket()
            try {
                net.bind(s)
                s.connect(upstream, 10_000)
                s.tcpNoDelay = true
                s.keepAlive = true
                return s
            } catch (e: IOException) {
                s.closeQuietly()
                metrics.error("Nie można połączyć ze sterowaniem: ${e.message}")
            }
            try {
                Thread.sleep(5_000)
            } catch (_: InterruptedException) {
                return null
            }
        }
        return null
    }

    private fun upstreamLoop() {
        while (running.get()) {
            val sock = connectUpstream() ?: return
            upstreamSocket = sock
            metrics.info("Połączono ze sterowaniem teleskopu $upstream")

            // Reset per-connection state.
            handshakeDone.set(false)
            heartbeatIds.clear()
            metrics.resetTelescopeState()
            // In-flight requests from the previous connection will never be answered.
            val stale = pending.values.toList()
            pending.clear()
            stale.forEach { p ->
                p.client.send(JSONObject().apply {
                    put("id", p.originalId)
                    put("code", -1)
                    put("error", "telescope reconnecting")
                }.toString())
            }

            val readerAlive = AtomicBoolean(true)
            thread(name = "ctrl-upstream-reader", isDaemon = true) {
                try {
                    readUpstream(sock)
                } finally {
                    readerAlive.set(false)
                }
            }

            try {
                val os = sock.getOutputStream()
                while (running.get() && readerAlive.get()) {
                    val msg = upstreamQueue.poll(250, TimeUnit.MILLISECONDS) ?: continue
                    os.write("$msg\r\n".toByteArray(Charsets.UTF_8))
                    os.flush()
                }
            } catch (e: IOException) {
                if (running.get()) metrics.error("Błąd zapisu do teleskopu: ${e.message}")
            } catch (_: InterruptedException) {
            }
            sock.closeQuietly()
            if (!running.get()) return
            metrics.error("Utracono połączenie sterowania, ponowienie za 5 s…")
            try {
                Thread.sleep(5_000)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun readUpstream(sock: Socket) {
        metrics.upstreamControlUp = true
        try {
            val reader = LineReader(sock.getInputStream(), 1_000_000)
            while (running.get()) {
                val line = reader.readLine() ?: break
                val trimmed = line.trim()
                if (trimmed.isEmpty()) continue

                recorder?.recordControl("telescope", trimmed)
                if (!handshakeDone.getAndSet(true)) {
                    metrics.info("Pierwsza odpowiedź teleskopu — handshake zakończony")
                }

                val msg = try {
                    JSONObject(trimmed)
                } catch (_: Exception) {
                    metrics.error("Niepoprawny JSON od teleskopu: ${trimmed.clip(100)}")
                    continue
                }
                routeUpstreamMessage(msg, trimmed)
            }
        } catch (e: LineTooLongException) {
            metrics.error("Przepełnienie bufora od teleskopu, rozłączam")
        } catch (e: IOException) {
            if (running.get()) metrics.error("Błąd odczytu z teleskopu: ${e.message}")
        } finally {
            metrics.upstreamControlUp = false
            sock.closeQuietly()
        }
    }

    private fun routeUpstreamMessage(msg: JSONObject, raw: String) {
        if (Protocol.isEvent(msg)) {
            val name = msg.opt("Event") as? String ?: "?"
            metrics.controlEvents.incrementAndGet()
            metrics.pushLog("ctrl-evt", name, raw)
            metrics.updateEvent(name, msg)
            broadcast(raw)
            return
        }

        val remapped = Protocol.numericId(msg)
        if (remapped == null) {
            broadcast(raw)
            return
        }

        metrics.controlRx.incrementAndGet()
        val p = pending.remove(remapped)
        if (p != null) {
            msg.put("id", p.originalId)
            val response = msg.toString()
            metrics.pushLog("ctrl-rx", Protocol.methodName(msg) ?: "?", response)
            metrics.updateResponse(msg)
            p.client.send(response)
        } else if (heartbeatIds.remove(remapped)) {
            // Response to the proxy's own heartbeat — nobody else asked for it.
        } else {
            broadcast(raw)
        }
    }

    private fun broadcast(raw: String) {
        for (c in clients) {
            if (!c.send(raw)) metrics.error("Klient ${c.addr} nie nadąża — pominięto wiadomość")
        }
    }
}
