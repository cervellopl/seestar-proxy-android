package com.seestarproxy.proxy

import org.json.JSONObject
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

private val BROADCAST: InetAddress = InetAddress.getByName("255.255.255.255")

/** All non-loopback IPv4 addresses of this device, with their interface names. */
fun localIpv4Addresses(): List<Pair<String, String>> = try {
    NetworkInterface.getNetworkInterfaces().toList()
        .filter { it.isUp && !it.isLoopback }
        .flatMap { nif ->
            nif.inetAddresses.toList().filterIsInstance<Inet4Address>().map { nif.name to it.hostAddress!! }
        }
} catch (_: Exception) {
    emptyList()
}

/** UDP socket bound to [addr] with SO_REUSEADDR and broadcast enabled. */
fun reusableUdpSocket(addr: InetSocketAddress): DatagramSocket =
    DatagramSocket(null).apply {
        reuseAddress = true
        broadcast = true
        bind(addr)
    }

/** The probe the Seestar expects. `name` must not contain dashes; source port must be 4720. */
fun scanProbe(localIp: String): ByteArray = JSONObject().apply {
    put("id", 201)
    put("method", "scan_iscope")
    put("name", "seestarproxy")
    put("ip", localIp)
}.toString().toByteArray()

/**
 * UDP discovery bridge on port 4720.
 *
 * 1. Captures the telescope's device info (UDP probe → TCP `get_device_state`
 *    fallback → minimal stub), or builds it from the configured serial number.
 * 2. Answers client `scan_iscope` probes with that info, with `ip` replaced by
 *    the proxy's address *as seen from the requester* — the Wi‑Fi address for
 *    LAN clients, the VPN address for clients coming through a VPN.
 * 3. Every 3 s sends the same answer unsolicited to [announceTargets] and to
 *    remote clients it has seen, for networks where broadcasts don't arrive
 *    (e.g. routed OpenVPN/SoftEther).
 *
 * Two sockets share the port: [clientSock] (0.0.0.0, normal routing incl.
 * VPN) and [scopeSock] (telescope-side address, pinned to [net]) which talks
 * to the telescope, whose replies are addressed to it.
 */
class DiscoveryBridge(
    private val upstreamIp: InetAddress,
    private val telescopeSn: String?,
    private val telescopeModel: String?,
    private val telescopeBssid: String?,
    private val metrics: Metrics,
    private val net: NetBinder = NetBinder.DEFAULT,
    private val announceTargets: List<InetAddress> = emptyList(),
    private val port: Int = Protocol.DISCOVERY_PORT,
    /** Port the client apps listen on for announcements. */
    private val announcePort: Int = Protocol.DISCOVERY_PORT,
) {
    private val running = AtomicBoolean(true)
    private val sockets = CopyOnWriteArrayList<DatagramSocket>()
    @Volatile private var clientSock: DatagramSocket? = null
    @Volatile private var scopeSock: DatagramSocket? = null
    @Volatile private var deviceInfo: JSONObject = fallbackResponse()
    @Volatile private var haveRealInfo = false
    /** Remote clients (not on the telescope network) that get periodic announcements. */
    private val seenClients = ConcurrentHashMap.newKeySet<InetAddress>()

    fun start() {
        thread(name = "discovery", isDaemon = true) {
            try {
                run()
            } catch (e: Exception) {
                if (running.get()) metrics.error("Discovery: ${e.message}")
            }
        }
    }

    fun stop() {
        running.set(false)
        sockets.forEach { it.closeQuietly() }
    }

    /** Called by the control/imaging proxies so remote clients also get announcements. */
    fun noteClient(addr: InetAddress) {
        if (addr.isLoopbackAddress || addr.isAnyLocalAddress || addr == upstreamIp || net.owns(addr)) return
        if (addr !is Inet4Address || seenClients.size >= MAX_SEEN) return
        seenClients.add(addr)
    }

    private fun run() {
        deviceInfo = if (telescopeSn != null) {
            metrics.info("Discovery: skonfigurowana tożsamość sn=$telescopeSn")
            buildConfiguredResponse(telescopeSn, telescopeModel, telescopeBssid, "0.0.0.0")
        } else {
            probeUpstream()
        }
        if (!running.get()) return
        haveRealInfo = deviceInfo.optJSONObject("result")?.opt("sn").let { it is String && it != "proxy" }
        metrics.info("Discovery: dane urządzenia: ${deviceInfo.toString().clip(200)}")

        val client = reusableUdpSocket(InetSocketAddress(port)).also { sockets.add(it) }
        clientSock = client
        // Telescope-side socket: the telescope only answers probes from port 4720 and
        // sends its reply to the address we probed from, which is this socket.
        scopeSock = try {
            val local = localIpFor(upstreamIp, net)
            if (local.isAnyLocalAddress) null
            else reusableUdpSocket(InetSocketAddress(local, port)).also { net.bind(it); sockets.add(it) }
        } catch (e: IOException) {
            metrics.error("Discovery: gniazdo po stronie teleskopu niedostępne: ${e.message}")
            null
        }
        metrics.info("Discovery: nasłuch UDP na porcie $port")

        scopeSock?.let { s -> thread(name = "discovery-scope", isDaemon = true) { receiveLoop(s) } }
        thread(name = "discovery-announce", isDaemon = true) { announceLoop() }
        receiveLoop(client)
    }

    private fun receiveLoop(sock: DatagramSocket) {
        val buf = ByteArray(16_384)
        while (running.get()) {
            val packet = DatagramPacket(buf, buf.size)
            try {
                sock.receive(packet)
            } catch (e: IOException) {
                if (running.get()) metrics.error("Discovery: błąd odbioru: ${e.message}")
                return
            }
            try {
                handle(packet)
            } catch (e: Exception) {
                metrics.error("Discovery: ${e.message}")
            }
        }
    }

    private fun handle(packet: DatagramPacket) {
        val text = String(packet.data, 0, packet.length, Charsets.UTF_8).trim()
        val request = try {
            JSONObject(text)
        } catch (_: Exception) {
            return
        }
        if (request.optString("method") != "scan_iscope") return

        // A packet with "result"/"code" is a discovery *response*, not a probe.
        if (request.has("result") || request.has("code")) {
            if (packet.address == upstreamIp && !haveRealInfo) {
                deviceInfo = request
                haveRealInfo = true
                metrics.info("Discovery: zaktualizowano dane z teleskopu, sn=${request.optJSONObject("result")?.optString("sn")}")
            }
            return // our own broadcast echoes and other responses
        }

        val src = packet.address
        val proxyIp = localIpFor(src, net).hostAddress!!
        metrics.info("Discovery: zapytanie od ${src.hostAddress} → odpowiadam adresem $proxyIp")
        noteClient(src)
        val response = infoFor(proxyIp)
        val out = replySocketFor(src)
        try {
            // Unicast back to the requester…
            out?.send(DatagramPacket(response, response.size, packet.socketAddress))
            // …and broadcast so apps on this same device see it on the physical interface.
            out?.send(DatagramPacket(response, response.size, BROADCAST, port))
        } catch (e: IOException) {
            metrics.error("Discovery: nie wysłano odpowiedzi: ${e.message}")
        }

        // Still on the fallback? Ask the telescope again; its reply lands on scopeSock.
        if (!haveRealInfo) {
            val s = scopeSock ?: clientSock ?: return
            try {
                val probe = scanProbe(localIpFor(upstreamIp, net).hostAddress!!)
                s.send(DatagramPacket(probe, probe.size, upstreamIp, Protocol.DISCOVERY_PORT))
            } catch (_: IOException) {
            }
        }
    }

    /** Requesters on the telescope's Wi‑Fi must be answered over that Wi‑Fi. */
    private fun replySocketFor(addr: InetAddress) =
        if (net.owns(addr)) scopeSock ?: clientSock else clientSock

    private fun infoFor(proxyIp: String): ByteArray {
        val copy = JSONObject(deviceInfo.toString())
        copy.optJSONObject("result")?.put("ip", proxyIp)
        return copy.toString().toByteArray()
    }

    private fun announceLoop() {
        var lastLogged = emptySet<InetAddress>()
        while (running.get()) {
            try {
                Thread.sleep(ANNOUNCE_INTERVAL_MS)
            } catch (_: InterruptedException) {
                return
            }
            val targets = (announceTargets + seenClients).toSet()
            if (targets != lastLogged && targets.isNotEmpty()) {
                metrics.info("Discovery: ogłaszam teleskop do ${targets.joinToString { it.hostAddress ?: "?" }}")
                lastLogged = targets
            }
            for (t in targets) {
                try {
                    val data = infoFor(localIpFor(t, net).hostAddress!!)
                    replySocketFor(t)?.send(DatagramPacket(data, data.size, t, announcePort))
                } catch (_: IOException) {
                }
            }
        }
    }

    /** UDP probe to the telescope, falling back to TCP `get_device_state`, then a stub. */
    private fun probeUpstream(): JSONObject {
        try {
            val localIp = localIpFor(upstreamIp, net)
            reusableUdpSocket(InetSocketAddress(localIp, port)).use { s ->
                net.bind(s)
                sockets.add(s)
                val probe = scanProbe(localIp.hostAddress!!)
                s.send(DatagramPacket(probe, probe.size, BROADCAST, Protocol.DISCOVERY_PORT))
                metrics.info("Discovery: wysłano sondę scan_iscope, czekam 5 s na teleskop")
                val deadline = System.currentTimeMillis() + 5_000
                val buf = ByteArray(16_384)
                while (running.get()) {
                    val left = deadline - System.currentTimeMillis()
                    if (left <= 0) break
                    s.soTimeout = left.toInt()
                    val p = DatagramPacket(buf, buf.size)
                    try {
                        s.receive(p)
                    } catch (_: SocketTimeoutException) {
                        break
                    }
                    if (p.address != upstreamIp) continue
                    val text = String(p.data, 0, p.length, Charsets.UTF_8).trim()
                    try {
                        return JSONObject(text)
                    } catch (_: Exception) {
                        // Firmware error reply: probe was received, go straight to TCP fallback.
                        if (text.contains("\"code\"") || text.contains("\"error\"")) break
                        // Otherwise an echo of someone else's odd probe — keep waiting.
                    }
                }
                sockets.remove(s)
            }
        } catch (e: IOException) {
            metrics.error("Discovery: sonda UDP nieudana: ${e.message}")
        }

        if (!running.get()) return fallbackResponse()
        metrics.info("Discovery: próba TCP get_device_state…")
        return fetchDeviceInfoTcp(upstreamIp, Protocol.CONTROL_PORT, net) ?: fallbackResponse().also {
            metrics.error("Discovery: brak danych z teleskopu — używam odpowiedzi zastępczej")
        }
    }

    companion object {
        private const val ANNOUNCE_INTERVAL_MS = 3_000L
        private const val MAX_SEEN = 32

        fun fetchDeviceInfoTcp(ip: InetAddress, port: Int, net: NetBinder = NetBinder.DEFAULT): JSONObject? = try {
            connectVia(net, InetSocketAddress(ip, port), 5_000).use { s ->
                s.soTimeout = 5_000
                s.getOutputStream().apply {
                    write("{\"id\":999,\"method\":\"get_device_state\",\"params\":[\"verify\"]}\r\n".toByteArray())
                    flush()
                }
                val reader = LineReader(s.getInputStream())
                val deadline = System.currentTimeMillis() + 5_000
                var result: JSONObject? = null
                while (result == null && System.currentTimeMillis() < deadline) {
                    val line = reader.readLine() ?: break
                    result = try {
                        JSONObject(line.trim()).optJSONObject("result")
                    } catch (_: Exception) {
                        null
                    }
                }
                result?.let { r ->
                    discoveryEnvelope(JSONObject().apply {
                        put("sn", r.optJSONObject("device")?.optString("sn", "unknown") ?: "unknown")
                        put("product_model", r.optJSONObject("device")?.optString("product_model", "Seestar") ?: "Seestar")
                        put("ssid", r.optJSONObject("ap")?.optString("ssid", "") ?: "")
                        put("is_verified", true)
                        put("tcp_client_num", 0)
                    })
                }
            }
        } catch (_: Exception) {
            null
        }

        fun buildConfiguredResponse(sn: String, model: String?, bssid: String?, proxyIp: String): JSONObject =
            discoveryEnvelope(JSONObject().apply {
                put("product_model", model ?: "Seestar S50")
                put("sn", sn)
                put("ssid", "S50_$sn")
                put("ip", proxyIp)
                put("is_verified", true)
                put("tcp_client_num", 0)
                put("can_star_mode_sel_cam", false)
                put("serc", "WPA-PSK")
                if (bssid != null) put("bssid", bssid)
            })

        fun fallbackResponse(): JSONObject = discoveryEnvelope(JSONObject().apply {
            put("product_model", "Seestar (via proxy)")
            put("sn", "proxy")
            put("ssid", "Seestar_proxy")
            put("is_verified", true)
            put("tcp_client_num", 0)
        })

        private fun discoveryEnvelope(result: JSONObject) = JSONObject().apply {
            put("jsonrpc", "2.0")
            put("Timestamp", "0")
            put("method", "scan_iscope")
            put("result", result)
            put("code", 0)
            put("id", 201)
        }
    }
}

/** A telescope found by [TelescopeScanner]. */
data class FoundTelescope(val ip: String, val sn: String, val model: String, val ssid: String)

/** One-shot LAN scan: broadcast `scan_iscope` from port 4720 and collect replies. */
object TelescopeScanner {
    fun scan(timeoutMs: Int = 3_000, net: NetBinder = NetBinder.DEFAULT): List<FoundTelescope> {
        val found = linkedMapOf<String, FoundTelescope>()
        reusableUdpSocket(InetSocketAddress(Protocol.DISCOVERY_PORT)).use { s ->
            net.bind(s)
            val ownIps = localIpv4Addresses().map { it.second }.toSet()
            val probe = scanProbe(ownIps.firstOrNull() ?: "0.0.0.0")
            s.send(DatagramPacket(probe, probe.size, BROADCAST, Protocol.DISCOVERY_PORT))
            val deadline = System.currentTimeMillis() + timeoutMs
            val buf = ByteArray(16_384)
            while (true) {
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) break
                s.soTimeout = left.toInt()
                val p = DatagramPacket(buf, buf.size)
                try {
                    s.receive(p)
                } catch (_: SocketTimeoutException) {
                    break
                }
                val ip = p.address.hostAddress ?: continue
                if (ip in ownIps) continue
                val result = try {
                    JSONObject(String(p.data, 0, p.length, Charsets.UTF_8).trim()).optJSONObject("result")
                } catch (_: Exception) {
                    null
                } ?: continue
                found[ip] = FoundTelescope(
                    ip = ip,
                    sn = result.optString("sn"),
                    model = result.optString("product_model", "Seestar"),
                    ssid = result.optString("ssid"),
                )
            }
        }
        return found.values.toList()
    }
}
