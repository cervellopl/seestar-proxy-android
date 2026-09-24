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
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

private val BROADCAST: InetAddress = InetAddress.getByName("255.255.255.255")

/** Local IPv4 address the OS would use to reach [target]. */
fun localIpFor(target: InetAddress): InetAddress =
    DatagramSocket().use {
        it.connect(target, 1)
        it.localAddress
    }

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
 *    the proxy's own address so apps connect to the proxy.
 */
class DiscoveryBridge(
    private val upstreamIp: InetAddress,
    private val telescopeSn: String?,
    private val telescopeModel: String?,
    private val telescopeBssid: String?,
    private val metrics: Metrics,
) {
    private val running = AtomicBoolean(true)
    @Volatile private var socket: DatagramSocket? = null

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
        socket.closeQuietly()
    }

    private fun run() {
        var deviceInfo = if (telescopeSn != null) {
            metrics.info("Discovery: skonfigurowana tożsamość sn=$telescopeSn")
            buildConfiguredResponse(telescopeSn, telescopeModel, telescopeBssid, "0.0.0.0")
        } else {
            probeUpstream()
        }
        if (!running.get()) return

        val proxyIp = localIpFor(upstreamIp).hostAddress!!
        deviceInfo.optJSONObject("result")?.put("ip", proxyIp)
        var haveRealInfo = deviceInfo.optJSONObject("result")?.opt("sn").let { it is String && it != "proxy" }
        metrics.info("Discovery: dane urządzenia (ip → $proxyIp): ${deviceInfo.toString().clip(200)}")

        val sock = reusableUdpSocket(InetSocketAddress(Protocol.DISCOVERY_PORT))
        socket = sock
        metrics.info("Discovery: nasłuch UDP na porcie ${Protocol.DISCOVERY_PORT}")

        val buf = ByteArray(16_384)
        while (running.get()) {
            val packet = DatagramPacket(buf, buf.size)
            try {
                sock.receive(packet)
            } catch (e: IOException) {
                if (running.get()) metrics.error("Discovery: błąd odbioru: ${e.message}")
                return
            }
            val text = String(packet.data, 0, packet.length, Charsets.UTF_8).trim()
            val request = try {
                JSONObject(text)
            } catch (_: Exception) {
                continue
            }
            if (request.optString("method") != "scan_iscope") continue

            // A packet with "result"/"code" is a discovery *response*, not a probe.
            if (request.has("result") || request.has("code")) {
                if (packet.address == upstreamIp && !haveRealInfo) {
                    request.optJSONObject("result")?.put("ip", proxyIp)
                    deviceInfo = request
                    haveRealInfo = true
                    metrics.info("Discovery: zaktualizowano dane z teleskopu, sn=${request.optJSONObject("result")?.optString("sn")}")
                }
                continue // our own broadcast echoes and other responses
            }

            metrics.info("Discovery: zapytanie od ${packet.address.hostAddress}")
            val response = deviceInfo.toString().toByteArray()
            try {
                // Unicast back to the requester…
                sock.send(DatagramPacket(response, response.size, packet.socketAddress))
                // …and broadcast so apps on this same device see it on the physical interface.
                sock.send(DatagramPacket(response, response.size, BROADCAST, Protocol.DISCOVERY_PORT))
            } catch (e: IOException) {
                metrics.error("Discovery: nie wysłano odpowiedzi: ${e.message}")
            }

            // Still on the fallback? Ask the telescope again; its reply lands on this socket.
            if (!haveRealInfo) {
                val probe = scanProbe(proxyIp)
                try {
                    sock.send(DatagramPacket(probe, probe.size, upstreamIp, Protocol.DISCOVERY_PORT))
                } catch (_: IOException) {
                }
            }
        }
    }

    /** UDP probe to the telescope, falling back to TCP `get_device_state`, then a stub. */
    private fun probeUpstream(): JSONObject {
        val localIp = localIpFor(upstreamIp)
        try {
            reusableUdpSocket(InetSocketAddress(localIp, Protocol.DISCOVERY_PORT)).use { s ->
                socket = s
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
            }
        } catch (e: IOException) {
            metrics.error("Discovery: sonda UDP nieudana: ${e.message}")
        } finally {
            socket = null
        }

        if (!running.get()) return fallbackResponse()
        metrics.info("Discovery: próba TCP get_device_state…")
        return fetchDeviceInfoTcp(upstreamIp, Protocol.CONTROL_PORT) ?: fallbackResponse().also {
            metrics.error("Discovery: brak danych z teleskopu — używam odpowiedzi zastępczej")
        }
    }

    companion object {
        fun fetchDeviceInfoTcp(ip: InetAddress, port: Int): JSONObject? = try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, port), 5_000)
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
    fun scan(timeoutMs: Int = 3_000): List<FoundTelescope> {
        val found = linkedMapOf<String, FoundTelescope>()
        reusableUdpSocket(InetSocketAddress(Protocol.DISCOVERY_PORT)).use { s ->
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
