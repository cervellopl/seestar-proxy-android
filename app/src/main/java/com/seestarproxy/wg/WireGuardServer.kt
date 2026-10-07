package com.seestarproxy.wg

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.seestarproxy.proxy.DiscoveryBridge
import com.seestarproxy.proxy.Metrics
import com.seestarproxy.proxy.Protocol
import com.seestarproxy.proxy.closeQuietly
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** Static WireGuard info for the UI / dashboard. */
data class WgInfo(
    val port: Int,
    val endpoint: String,
    val serverPublicKey: String,
    val clientConfig: String,
)

/**
 * Embedded WireGuard endpoint for remote access (port of seestar-proxy's
 * `--wireguard`):
 *
 * ```
 * WireGuard client ──UDP──▶ :51820 ── decrypt ──▶ IPv4 packets
 *                                                  ├─ TCP → TcpStack → 127.0.0.1:{4700,4800,4090}
 *                                                  ├─ UDP 4720 → discovery reply (as the telescope)
 *                                                  ├─ UDP 53 → DNS (seestar names local, rest forwarded)
 *                                                  └─ ICMP echo → reply
 * ```
 *
 * Inside the tunnel the proxy answers on the *telescope's own IP* (and on
 * 10.99.0.1), so the Seestar app can keep using the address it remembers.
 */
class WireGuardServer(
    private val keyDir: File,
    private val port: Int,
    endpointOverride: String?,
    private val fullTunnel: Boolean,
    private val upstreamIp: InetAddress,
    private val telescopeSn: String?,
    private val telescopeModel: String?,
    /** Tunnel TCP port → local proxy port. */
    private val portMap: Map<Int, Int>,
    private val metrics: Metrics,
    /** Network that carries traffic to the telescope. */
    private val net: com.seestarproxy.proxy.NetBinder = com.seestarproxy.proxy.NetBinder.DEFAULT,
) {
    private val running = AtomicBoolean(true)
    private lateinit var socket: DatagramSocket
    private lateinit var tcp: TcpStack
    lateinit var peer: WgPeer
        private set
    lateinit var info: WgInfo
        private set
    @Volatile var peerEndpoint: SocketAddress? = null
        private set
    @Volatile private var lastDataRxMs = 0L
    @Volatile private var deviceInfo: ByteArray = DiscoveryBridge.fallbackResponse().toString().toByteArray()
    private val dnsPool = Executors.newFixedThreadPool(4)

    private val upstreamBytes = upstreamIp.address
    private val endpoint = endpointOverride?.takeIf { it.isNotBlank() }?.let {
        if (it.contains(':')) it else "$it:$port"
    } ?: "${detectLocalIp() ?: "0.0.0.0"}:$port"

    val tunnelConnections: Int get() = if (::tcp.isInitialized) tcp.connectionCount.get() else 0

    fun start() {
        require(upstreamBytes.size == 4) { "WireGuard wymaga adresu IPv4 teleskopu" }
        val serverKeys = WgKeyPair.loadOrGenerate(File(keyDir, "wg.key"))
        val clientKeys = WgKeyPair.loadOrGenerate(File(keyDir, "wg_client.key"))
        peer = WgPeer(serverKeys, clientKeys.publicKey)

        val allowed = if (fullTunnel) "0.0.0.0/0" else "${upstreamIp.hostAddress}/32, 10.99.0.0/24"
        val config = """
            |[Interface]
            |PrivateKey = ${WgCrypto.b64(clientKeys.privateKey)}
            |Address = ${Ip.str(CLIENT_IP)}/32
            |DNS = ${Ip.str(SERVER_IP)}
            |
            |[Peer]
            |PublicKey = ${WgCrypto.b64(serverKeys.publicKey)}
            |Endpoint = $endpoint
            |AllowedIPs = $allowed
            |PersistentKeepalive = 25
            |""".trimMargin()
        info = WgInfo(port, endpoint, WgCrypto.b64(serverKeys.publicKey), config)

        socket = DatagramSocket(null)
        socket.reuseAddress = true
        socket.bind(InetSocketAddress(port))
        tcp = TcpStack(
            acceptIps = setOf(Ip.u32(upstreamBytes, 0), Ip.u32(SERVER_IP, 0)),
            portMap = portMap,
            output = ::sendIp,
            log = metrics::info,
        ).also { it.start() }

        metrics.info("WireGuard: nasłuch UDP $port, endpoint $endpoint")
        thread(name = "wg-rx", isDaemon = true) { receiveLoop() }
        thread(name = "wg-timers", isDaemon = true) { timerLoop() }
        thread(name = "wg-devinfo", isDaemon = true) { loadDeviceInfo() }
    }

    fun stop() {
        running.set(false)
        if (::tcp.isInitialized) tcp.stop()
        if (::socket.isInitialized) socket.closeQuietly()
        dnsPool.shutdownNow()
    }

    /** Discovery answer as seen inside the tunnel: `ip` is the telescope's real address. */
    private fun loadDeviceInfo() {
        val json = if (telescopeSn != null) {
            DiscoveryBridge.buildConfiguredResponse(telescopeSn, telescopeModel, null, upstreamIp.hostAddress!!)
        } else {
            DiscoveryBridge.fetchDeviceInfoTcp(upstreamIp, Protocol.CONTROL_PORT, net) ?: DiscoveryBridge.fallbackResponse()
        }
        json.optJSONObject("result")?.put("ip", upstreamIp.hostAddress)
        deviceInfo = json.toString().toByteArray()
    }

    private fun receiveLoop() {
        val buf = ByteArray(65_535)
        while (running.get()) {
            val p = DatagramPacket(buf, buf.size)
            try {
                socket.receive(p)
            } catch (e: IOException) {
                if (running.get()) metrics.error("WireGuard: błąd odbioru: ${e.message}")
                return
            }
            val hadSession = peer.hasSession
            when (val r = peer.handle(p.data.copyOf(p.length), p.length)) {
                is WgPeer.Result.Reply -> {
                    peerEndpoint = p.socketAddress
                    send(r.data)
                    metrics.info("WireGuard: handshake z ${p.address.hostAddress}:${p.port}")
                }
                is WgPeer.Result.Packet -> {
                    peerEndpoint = p.socketAddress // roaming: follow the peer's latest address
                    if (!hadSession && peer.hasSession) metrics.info("WireGuard: sesja aktywna")
                    if (r.data.isNotEmpty()) {
                        lastDataRxMs = System.currentTimeMillis()
                        try {
                            onIpPacket(r.data)
                        } catch (e: Exception) {
                            metrics.error("WireGuard: błąd pakietu: ${e.message}")
                        }
                    }
                }
                WgPeer.Result.Drop -> {}
            }
        }
    }

    private fun onIpPacket(data: ByteArray) {
        val ip = Ip.V4.parse(data) ?: return
        // Cryptokey routing: the peer may only use its tunnel address.
        if (!ip.src.contentEquals(CLIENT_IP)) return
        when (ip.proto) {
            Ip.PROTO_TCP -> tcp.inject(ip)
            Ip.PROTO_UDP -> onUdp(ip)
            Ip.PROTO_ICMP -> if (isOurs(ip.dst)) Ip.icmpEchoReply(ip)?.let(::sendIp)
        }
    }

    private fun isOurs(a: ByteArray) = a.contentEquals(upstreamBytes) || a.contentEquals(SERVER_IP)

    private fun onUdp(ip: Ip.V4) {
        val o = ip.ihl
        if (ip.payloadLen < 8) return
        val srcPort = Ip.u16(ip.raw, o)
        val dstPort = Ip.u16(ip.raw, o + 2)
        val udpLen = Ip.u16(ip.raw, o + 4)
        if (udpLen < 8 || udpLen > ip.payloadLen) return
        val payload = ip.raw.copyOfRange(o + 8, o + udpLen)
        when (dstPort) {
            Protocol.DISCOVERY_PORT -> {
                val method = try { JSONObject(String(payload)).optString("method") } catch (_: Exception) { "" }
                if (method == "scan_iscope") {
                    metrics.info("WireGuard: zapytanie discovery z tunelu")
                    sendIp(Ip.udp(upstreamBytes, Protocol.DISCOVERY_PORT, ip.src, srcPort, deviceInfo))
                }
            }
            53 -> onDns(ip, srcPort, payload)
        }
    }

    private fun onDns(ip: Ip.V4, srcPort: Int, query: ByteArray) {
        val (name, qEnd) = Dns.queryName(query) ?: return
        if (Dns.isSeestarName(name) && Dns.isTypeA(query, qEnd)) {
            metrics.info("WireGuard DNS: $name → ${upstreamIp.hostAddress}")
            sendIp(Ip.udp(ip.dst, 53, ip.src, srcPort, Dns.answerA(query, qEnd, upstreamBytes)))
            return
        }
        // Everything else is forwarded so the client's DNS keeps working.
        val dst = ip.dst.copyOf()
        val src = ip.src.copyOf()
        try {
            dnsPool.execute {
                for (server in DNS_SERVERS) {
                    try {
                        DatagramSocket().use { s ->
                            s.soTimeout = 2_000
                            s.send(DatagramPacket(query, query.size, InetAddress.getByName(server), 53))
                            val b = ByteArray(4096)
                            val r = DatagramPacket(b, b.size)
                            s.receive(r)
                            sendIp(Ip.udp(dst, 53, src, srcPort, b.copyOf(r.length)))
                        }
                        return@execute
                    } catch (_: IOException) {
                    }
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun timerLoop() {
        var lastAnnounce = 0L
        while (running.get()) {
            try {
                Thread.sleep(1_000)
            } catch (_: InterruptedException) {
                return
            }
            val now = System.currentTimeMillis()
            if (!peer.hasSession || peerEndpoint == null) continue
            // Unsolicited discovery announcements so apps behind the tunnel find the telescope.
            if (now - lastAnnounce >= 3_000 && now - peer.lastReceivedMs < 60_000) {
                lastAnnounce = now
                sendIp(Ip.udp(upstreamBytes, Protocol.DISCOVERY_PORT, CLIENT_IP, Protocol.DISCOVERY_PORT, deviceInfo))
            }
            // Passive keepalive: answer data we haven't replied to within KEEPALIVE_TIMEOUT.
            if (lastDataRxMs > peer.lastSentMs && now - lastDataRxMs >= WgPeer.KEEPALIVE_TIMEOUT_MS) {
                peer.encrypt(ByteArray(0))?.let(::send)
            }
        }
    }

    private fun sendIp(packet: ByteArray) {
        peer.encrypt(packet)?.let(::send)
    }

    private fun send(data: ByteArray) {
        val to = peerEndpoint ?: return
        try {
            socket.send(DatagramPacket(data, data.size, to))
        } catch (_: IOException) {
        }
    }

    fun statusJson(): JSONObject = JSONObject().apply {
        put("port", port)
        put("endpoint", endpoint)
        put("session", peer.hasSession)
        put("peer", peerEndpoint?.toString()?.trimStart('/') ?: JSONObject.NULL)
        put("last_handshake_ms", peer.lastHandshakeMs)
        put("rx_bytes", peer.rxBytes.get())
        put("tx_bytes", peer.txBytes.get())
        put("tunnel_connections", tunnelConnections)
    }

    companion object {
        val SERVER_IP = byteArrayOf(10, 99, 0, 1)
        val CLIENT_IP = byteArrayOf(10, 99, 0, 2)
        private val DNS_SERVERS = listOf("1.1.1.1", "8.8.8.8")

        /** Local IP used for outbound traffic, a sensible default endpoint. */
        fun detectLocalIp(): String? = try {
            DatagramSocket().use {
                it.connect(InetAddress.getByName("8.8.8.8"), 80)
                it.localAddress.hostAddress?.takeUnless { a -> a == "0.0.0.0" || a == "::" }
            }
        } catch (_: Exception) {
            null
        }

        /** Deletes both key files so new keys (and a new QR code) are generated next start. */
        fun resetKeys(keyDir: File) {
            File(keyDir, "wg.key").delete()
            File(keyDir, "wg_client.key").delete()
        }

        fun qrMatrix(text: String): BitMatrix = QRCodeWriter().encode(
            text, BarcodeFormat.QR_CODE, 0, 0,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L, EncodeHintType.MARGIN to 2),
        )

        fun qrSvg(text: String): String {
            val m = qrMatrix(text)
            val sb = StringBuilder()
            sb.append("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 ${m.width} ${m.height}\" shape-rendering=\"crispEdges\">")
            sb.append("<rect width=\"100%\" height=\"100%\" fill=\"#fff\"/><path fill=\"#000\" d=\"")
            for (y in 0 until m.height) for (x in 0 until m.width) if (m[x, y]) sb.append("M$x ${y}h1v1h-1z")
            sb.append("\"/></svg>")
            return sb.toString()
        }
    }
}
