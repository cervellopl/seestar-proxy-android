package com.seestarproxy.proxy

import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Port 4800 imaging proxy: fans out binary frames from one upstream Seestar
 * connection to every connected client.
 *
 * Traffic is mostly downstream, but clients also send JSON-RPC text lines
 * (a `test_connection` keepalive, imaging-start commands). Those — plus the
 * proxy's own heartbeat — go through one queue drained by a single upstream
 * writer, so lines are never interleaved.
 */
class ImagingProxy(
    private val bindPort: Int,
    private val upstream: InetSocketAddress,
    private val metrics: Metrics,
    private val recorder: Recorder?,
    /** Network that carries traffic to the telescope. */
    private val net: NetBinder = NetBinder.DEFAULT,
    /** Notified with each client address (used for discovery announcements). */
    private val onClient: (java.net.InetAddress) -> Unit = {},
) {
    private val running = AtomicBoolean(true)
    private val clients = CopyOnWriteArrayList<Client>()
    private val upstreamQueue = LinkedBlockingQueue<String>(256)
    private lateinit var server: ServerSocket
    @Volatile private var upstreamSocket: Socket? = null

    fun start() {
        server = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(bindPort))
        }
        metrics.info("Obraz: nasłuch na porcie $bindPort")
        thread(name = "img-accept", isDaemon = true) { acceptLoop() }
        thread(name = "img-upstream", isDaemon = true) { upstreamLoop() }
        thread(name = "img-heartbeat", isDaemon = true) { heartbeatLoop() }
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
                if (running.get()) metrics.error("Obraz: błąd accept: ${e.message}")
                return
            }
            sock.tcpNoDelay = true
            val addr = sock.remoteSocketAddress.toString().trimStart('/')
            metrics.info("Klient obrazu połączony: $addr")
            val client = Client(sock, addr)
            onClient(sock.inetAddress)
            clients.add(client)
            metrics.imagingClients.incrementAndGet()
            thread(name = "img-client-$addr", isDaemon = true) {
                try {
                    readClient(client)
                } catch (_: Exception) {
                } finally {
                    client.close()
                    clients.remove(client)
                    metrics.imagingClients.decrementAndGet()
                    metrics.info("Klient obrazu rozłączony: $addr")
                }
            }
        }
    }

    /** Client with a bounded frame queue; when it falls behind the oldest frames are dropped. */
    private inner class Client(val socket: Socket, val addr: String) {
        private val frames = ArrayBlockingQueue<ByteArray>(32)
        private val closed = AtomicBoolean(false)
        private val writer = thread(start = false, name = "img-writer-$addr", isDaemon = true) {
            try {
                val os = socket.getOutputStream()
                while (!closed.get()) {
                    os.write(frames.take())
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

        fun offerFrame(frame: ByteArray) {
            if (closed.get()) return
            // Dropping frames is preferable to dropping the client.
            while (!frames.offer(frame)) frames.poll()
        }

        fun close() {
            if (closed.getAndSet(true)) return
            socket.closeQuietly()
            writer.interrupt()
        }
    }

    private fun readClient(client: Client) {
        val reader = LineReader(client.socket.getInputStream())
        while (running.get()) {
            val line = reader.readLine() ?: break
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val method = try {
                Protocol.methodName(org.json.JSONObject(trimmed))
            } catch (_: Exception) {
                null
            }
            metrics.pushLog("img-tx", method ?: "?", trimmed)
            upstreamQueue.offer(trimmed, 10, TimeUnit.SECONDS)
        }
    }

    private fun heartbeatLoop() {
        var id = 1L
        while (running.get()) {
            try {
                Thread.sleep(5_000)
            } catch (_: InterruptedException) {
                return
            }
            upstreamQueue.offer(Protocol.heartbeat(id++))
        }
    }

    private fun upstreamLoop() {
        while (running.get()) {
            metrics.info("Łączenie z obrazem teleskopu $upstream…")
            val sock = Socket()
            try {
                net.bind(sock)
                sock.connect(upstream, 10_000)
                sock.tcpNoDelay = true
                sock.keepAlive = true
                sock.receiveBufferSize = 1 shl 20
                upstreamSocket = sock
                metrics.info("Połączono z obrazem teleskopu $upstream")

                val readerAlive = AtomicBoolean(true)
                thread(name = "img-upstream-reader", isDaemon = true) {
                    try {
                        readFrames(sock)
                    } finally {
                        readerAlive.set(false)
                    }
                }
                val os = sock.getOutputStream()
                while (running.get() && readerAlive.get()) {
                    val msg = upstreamQueue.poll(250, TimeUnit.MILLISECONDS) ?: continue
                    os.write("$msg\r\n".toByteArray(Charsets.UTF_8))
                    os.flush()
                }
                if (running.get()) metrics.error("Utracono połączenie obrazu")
            } catch (e: IOException) {
                if (running.get()) metrics.error("Obraz teleskopu: ${e.message}")
            } catch (_: InterruptedException) {
                return
            } finally {
                sock.closeQuietly()
            }
            if (!running.get()) return
            try {
                Thread.sleep(5_000)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun readFrames(sock: Socket) {
        metrics.upstreamImagingUp = true
        var frameCount = 0L
        try {
            val input = DataInputStream(BufferedInputStream(sock.getInputStream(), 256 * 1024))
            val header = ByteArray(Protocol.HEADER_SIZE)
            while (running.get()) {
                input.readFully(header)
                val h = FrameHeader.parse(header)
                if (h.size > Protocol.MAX_FRAME_BYTES) {
                    metrics.error("Nierealny rozmiar klatki: ${h.size}")
                    break
                }
                // Header + payload in one allocation, shared by all clients.
                val frame = ByteArray(Protocol.HEADER_SIZE + h.size.toInt())
                System.arraycopy(header, 0, frame, 0, Protocol.HEADER_SIZE)
                input.readFully(frame, Protocol.HEADER_SIZE, h.size.toInt())

                recorder?.recordFrame(frame)

                metrics.imagingFrames.incrementAndGet()
                metrics.imagingBytes.addAndGet(frame.size.toLong())
                // Log every 30th frame so the traffic log isn't flooded.
                if (frameCount++ % 30 == 0L) {
                    val summary = if (h.isImage) {
                        "%s %dx%d (%.1f KB)".format(h.kind, h.width, h.height, h.size / 1024.0)
                    } else {
                        "${h.kind} (${h.size} B)"
                    }
                    metrics.pushLog("img", summary)
                }

                for (c in clients) c.offerFrame(frame)
            }
        } catch (e: IOException) {
            if (running.get()) metrics.error("Odczyt obrazu przerwany: ${e.message}")
        } finally {
            metrics.upstreamImagingUp = false
            sock.closeQuietly()
        }
    }
}
