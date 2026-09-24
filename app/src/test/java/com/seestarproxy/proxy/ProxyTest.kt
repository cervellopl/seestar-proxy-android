package com.seestarproxy.proxy

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

class ProxyTest {

    private val localhost = InetAddress.getLoopbackAddress()

    @Test
    fun frameHeader_parse_readsBigEndianFields() {
        val b = ByteArray(80)
        b[6] = 0x00; b[7] = 0x01; b[8] = 0x00; b[9] = 0x00 // size 65536
        b[15] = 23
        b[16] = 0x04; b[17] = 0x38 // 1080
        b[18] = 0x07; b[19] = 0x80.toByte() // 1920
        val h = FrameHeader.parse(b)
        assertEquals(65536L, h.size)
        assertEquals("stack", h.kind)
        assertEquals(1080, h.width)
        assertEquals(1920, h.height)
        assertEquals(true, h.isImage)
    }

    @Test
    fun control_twoClientsSameId_eachGetsOwnResponseWithOriginalId() {
        // Fake telescope: answers every request with result = "r<remapped id>", and emits one event.
        val telescope = ServerSocket(0, 50, localhost)
        thread(isDaemon = true) {
            val s = telescope.accept()
            val r = LineReader(s.getInputStream())
            val out = s.getOutputStream()
            var sentEvent = false
            while (true) {
                val line = r.readLine() ?: break
                val req = JSONObject(line.trim())
                val id = req.getLong("id")
                val resp = JSONObject().put("id", id).put("method", req.optString("method"))
                    .put("result", "r$id").put("code", 0)
                out.write("$resp\r\n".toByteArray())
                if (!sentEvent) {
                    out.write("{\"Event\":\"PiStatus\",\"battery_capacity\":77}\r\n".toByteArray())
                    sentEvent = true
                }
                out.flush()
            }
        }

        val metrics = Metrics()
        val proxy = ControlProxy(0, InetSocketAddress(localhost, telescope.localPort), metrics, null)
        proxy.start()

        val a = Socket(localhost, proxy.localPort)
        val b = Socket(localhost, proxy.localPort)
        Thread.sleep(400)
        a.getOutputStream().write("{\"id\":1,\"method\":\"get_device_state\"}\r\n".toByteArray())
        Thread.sleep(200)
        b.getOutputStream().write("{\"id\":1,\"method\":\"get_view_state\"}\r\n".toByteArray())

        fun readUntilResponse(s: Socket): Pair<JSONObject, Boolean> {
            s.soTimeout = 5_000
            val r = LineReader(s.getInputStream())
            var sawEvent = false
            while (true) {
                val m = JSONObject(r.readLine()!!.trim())
                if (m.has("Event")) sawEvent = true else return m to sawEvent
            }
        }

        val (ra, _) = readUntilResponse(a)
        val (rb, _) = readUntilResponse(b)
        assertEquals(1, ra.getInt("id"))
        assertEquals(1, rb.getInt("id"))
        assertEquals("get_device_state", ra.getString("method"))
        assertEquals("get_view_state", rb.getString("method"))
        // Different remapped ids went upstream.
        assert(ra.getString("result") != rb.getString("result"))
        assertEquals(77L, metrics.telescopeStatus().battery)
        proxy.stop()
        telescope.close()
    }

    @Test
    fun imaging_frameIsFannedOutToAllClients() {
        val payload = ByteArray(5000) { (it % 251).toByte() }
        val header = ByteArray(80).also {
            it[8] = (payload.size shr 8).toByte(); it[9] = payload.size.toByte()
            it[15] = 21; it[17] = 100; it[19] = 50
        }
        val telescope = ServerSocket(0, 50, localhost)
        val clientsReady = java.util.concurrent.CountDownLatch(1)
        thread(isDaemon = true) {
            val s = telescope.accept()
            clientsReady.await()
            s.getOutputStream().apply { write(header); write(payload); flush() }
            Thread.sleep(5_000)
        }

        val proxy = ImagingProxy(0, InetSocketAddress(localhost, telescope.localPort), Metrics(), null)
        proxy.start()
        val clients = List(3) { Socket(localhost, proxy.localPort).apply { soTimeout = 5_000 } }
        Thread.sleep(500)
        clientsReady.countDown()

        for (c in clients) {
            val buf = ByteArray(80 + payload.size)
            DataInputStream(c.getInputStream()).readFully(buf)
            assertArrayEquals(header, buf.copyOfRange(0, 80))
            assertArrayEquals(payload, buf.copyOfRange(80, buf.size))
        }
        proxy.stop()
        telescope.close()
    }
}
