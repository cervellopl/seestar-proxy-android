package com.seestarproxy.proxy

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class NetworkTest {
    private val lo = InetAddress.getLoopbackAddress()

    private fun freeUdpPort() = DatagramSocket(0).use { it.localPort }

    private fun receiveJson(s: DatagramSocket): JSONObject {
        val b = ByteArray(16_384)
        val p = DatagramPacket(b, b.size)
        s.receive(p)
        return JSONObject(String(b, 0, p.length))
    }

    /** Counts pinning calls, like TelescopeNetwork would make. */
    private class RecordingBinder : NetBinder {
        val tcpBinds = AtomicInteger()
        override fun bind(s: Socket) {
            tcpBinds.incrementAndGet()
        }
    }

    @Test
    fun discovery_replyCarriesProxyAddressFacingRequester() {
        val port = freeUdpPort()
        val bridge = DiscoveryBridge(lo, "4ddb0535", null, null, Metrics(), port = port, announcePort = freeUdpPort())
        bridge.start()
        try {
            Thread.sleep(300)
            DatagramSocket(0, lo).use { s ->
                s.soTimeout = 3_000
                val q = scanProbe("127.0.0.1")
                s.send(DatagramPacket(q, q.size, lo, port))
                val r = receiveJson(s)
                assertEquals("4ddb0535", r.getJSONObject("result").getString("sn"))
                // The requester reached us over loopback, so loopback is the address to advertise.
                assertEquals("127.0.0.1", r.getJSONObject("result").getString("ip"))
            }
        } finally {
            bridge.stop()
        }
    }

    @Test
    fun discovery_announcesToConfiguredTargets() {
        DatagramSocket(0, lo).use { listener ->
            listener.soTimeout = 6_000
            val bridge = DiscoveryBridge(
                lo, "4ddb0535", null, null, Metrics(),
                announceTargets = listOf(lo), port = freeUdpPort(), announcePort = listener.localPort,
            )
            bridge.start()
            try {
                val r = receiveJson(listener)
                assertEquals("scan_iscope", r.getString("method"))
                assertEquals("127.0.0.1", r.getJSONObject("result").getString("ip"))
            } finally {
                bridge.stop()
            }
        }
    }

    @Test
    fun parseAnnounceTargets_acceptsIpsAndReportsGarbage() {
        val bad = CopyOnWriteArrayList<String>()
        val ips = parseAnnounceTargets("192.168.30.255, 10.0.0.5;\nseestar.local", bad::add)
        assertEquals(listOf("192.168.30.255", "10.0.0.5"), ips.map { it.hostAddress })
        assertEquals(listOf("seestar.local"), bad)
    }

    @Test
    fun proxies_pinUpstreamConnectionsAndReportClients() {
        val telescope = ServerSocket(0, 50, lo)
        thread(isDaemon = true) {
            while (true) {
                val s = try { telescope.accept() } catch (_: Exception) { break }
                thread(isDaemon = true) { try { s.getInputStream().readBytes() } catch (_: Exception) {} }
            }
        }
        val binder = RecordingBinder()
        val clients = CopyOnWriteArrayList<InetAddress>()
        val control = ControlProxy(0, InetSocketAddress(lo, telescope.localPort), Metrics(), null, binder, clients::add)
        val imaging = ImagingProxy(0, InetSocketAddress(lo, telescope.localPort), Metrics(), null, binder, clients::add)
        control.start()
        imaging.start()
        try {
            Socket(lo, control.localPort).use {
                Thread.sleep(800)
                // Imaging connects upstream at start, control on its first client.
                assertTrue("upstream sockets must go through the binder", binder.tcpBinds.get() >= 2)
                assertEquals(listOf(lo), clients.toList())
            }
        } finally {
            control.stop()
            imaging.stop()
            telescope.close()
        }
    }
}
