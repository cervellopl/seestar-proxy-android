package com.seestarproxy.wg

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Drives [WgPeer] with an initiator written directly from the WireGuard
 * whitepaper (§5.4.2–5.4.6), then exchanges transport messages both ways.
 */
class WgPeerTest {
    private val server = WgKeyPair.generate()
    private val client = WgKeyPair.generate()

    private class Handshake(val msg: ByteArray, val c: ByteArray, val h: ByteArray, val eph: WgKeyPair, val index: Int)

    private fun initiation(tai64n: ByteArray = tai64n()): Handshake {
        val eph = WgKeyPair.generate()
        val index = 0x11223344
        val m = ByteArray(148)
        m[0] = 1
        m.putIntLE(4, index)
        var c = WgPeer.INITIAL_CHAIN_KEY
        var h = WgCrypto.hash(WgPeer.INITIAL_HASH, server.publicKey)
        System.arraycopy(eph.publicKey, 0, m, 8, 32)
        c = WgCrypto.kdf(1, c, eph.publicKey)[0]
        h = WgCrypto.hash(h, eph.publicKey)
        var k = WgCrypto.kdf(2, c, WgCrypto.dh(eph.privateKey, server.publicKey))
        c = k[0]
        val encStatic = WgCrypto.aeadEncrypt(k[1], 0, client.publicKey, h)
        System.arraycopy(encStatic, 0, m, 40, 48)
        h = WgCrypto.hash(h, encStatic)
        k = WgCrypto.kdf(2, c, WgCrypto.dh(client.privateKey, server.publicKey))
        c = k[0]
        val encTs = WgCrypto.aeadEncrypt(k[1], 0, tai64n, h)
        System.arraycopy(encTs, 0, m, 88, 28)
        h = WgCrypto.hash(h, encTs)
        val mac1 = WgCrypto.mac(WgCrypto.hash(WgPeer.LABEL_MAC1, server.publicKey), m, 116)
        System.arraycopy(mac1, 0, m, 116, 16)
        return Handshake(m, c, h, eph, index)
    }

    private var tsCounter = 1L
    private fun tai64n(): ByteArray {
        val t = ByteArray(12)
        val v = 0x400000000000000AL + tsCounter++
        for (i in 0 until 8) t[i] = (v ushr (56 - 8 * i)).toByte()
        return t
    }

    /** Completes the handshake from the initiator side; returns (sendKey, recvKey, remoteIndex). */
    private fun consumeResponse(hs: Handshake, resp: ByteArray): Triple<ByteArray, ByteArray, Int> {
        assertEquals(92, resp.size)
        assertEquals(2, resp[0].toInt())
        assertEquals(hs.index, resp.getIntLE(8))
        val mac1 = WgCrypto.mac(WgCrypto.hash(WgPeer.LABEL_MAC1, client.publicKey), resp, 60)
        assertArrayEquals(mac1, resp.copyOfRange(60, 76))
        val ephR = resp.copyOfRange(12, 44)
        var c = WgCrypto.kdf(1, hs.c, ephR)[0]
        var h = WgCrypto.hash(hs.h, ephR)
        c = WgCrypto.kdf(1, c, WgCrypto.dh(hs.eph.privateKey, ephR))[0]
        c = WgCrypto.kdf(1, c, WgCrypto.dh(client.privateKey, ephR))[0]
        val k3 = WgCrypto.kdf(3, c, ByteArray(32))
        c = k3[0]
        h = WgCrypto.hash(h, k3[1])
        assertNotNull("empty payload must authenticate", WgCrypto.aeadDecrypt(k3[2], 0, resp.copyOfRange(44, 60), h))
        val t = WgCrypto.kdf(2, c, ByteArray(0))
        return Triple(t[0], t[1], resp.getIntLE(4))
    }

    private fun transport(key: ByteArray, receiver: Int, counter: Long, plain: ByteArray): ByteArray {
        val m = ByteArray(16 + plain.size + 16)
        m[0] = 4
        m.putIntLE(4, receiver)
        m.putLongLE(8, counter)
        val enc = WgCrypto.aeadEncrypt(key, counter, plain, null)
        System.arraycopy(enc, 0, m, 16, enc.size)
        return m
    }

    @Test
    fun handshake_thenTransportBothWays() {
        val peer = WgPeer(server, client.publicKey)
        val hs = initiation()
        val reply = peer.handle(hs.msg, hs.msg.size) as WgPeer.Result.Reply
        val (send, recv, remote) = consumeResponse(hs, reply.data)

        // Responder must not send before key confirmation.
        assertFalse(peer.hasSession)
        val ping = ByteArray(40) { it.toByte() }
        val r = peer.handle(transport(send, remote, 0, ping), 16 + 40 + 16) as WgPeer.Result.Packet
        assertArrayEquals(ping, r.data)
        assertTrue(peer.hasSession)

        val out = peer.encrypt(ByteArray(33) { 7 })!!
        assertEquals(4, out[0].toInt())
        assertEquals(hs.index, out.getIntLE(4))
        val plain = WgCrypto.aeadDecrypt(recv, out.getLongLE(8), out, null, 16, out.size - 16)!!
        assertEquals(48, plain.size) // padded to 16
        assertArrayEquals(ByteArray(33) { 7 }, plain.copyOf(33))
    }

    @Test
    fun transport_replayedCounterIsDropped() {
        val peer = WgPeer(server, client.publicKey)
        val hs = initiation()
        val reply = peer.handle(hs.msg, hs.msg.size) as WgPeer.Result.Reply
        val (send, _, remote) = consumeResponse(hs, reply.data)
        val m = transport(send, remote, 5, ByteArray(0))
        assertTrue(peer.handle(m, m.size) is WgPeer.Result.Packet)
        assertTrue(peer.handle(m, m.size) === WgPeer.Result.Drop)
    }

    @Test
    fun initiation_replayedTimestampIsDropped() {
        val peer = WgPeer(server, client.publicKey)
        val hs = initiation()
        assertTrue(peer.handle(hs.msg, hs.msg.size) is WgPeer.Result.Reply)
        assertTrue(peer.handle(hs.msg, hs.msg.size) === WgPeer.Result.Drop)
    }

    @Test
    fun initiation_badMac1IsDropped() {
        val peer = WgPeer(server, client.publicKey)
        val hs = initiation()
        hs.msg[120] = (hs.msg[120] + 1).toByte()
        assertTrue(peer.handle(hs.msg, hs.msg.size) === WgPeer.Result.Drop)
    }

    @Test
    fun initiation_unknownPeerIsDropped() {
        val peer = WgPeer(server, WgKeyPair.generate().publicKey)
        val hs = initiation()
        assertTrue(peer.handle(hs.msg, hs.msg.size) === WgPeer.Result.Drop)
    }

    /** Reference pair produced by the official `wg genkey | wg pubkey`. */
    @Test
    fun publicKey_matchesWireguardTools() {
        val priv = WgCrypto.unb64("+F8W7xS5e/R0cRDLDxxDnhkxZ7hDkrlf3zmiZ0TFq0w=")
        assertEquals("CWc5RCTFenfP6wEZEVtNaIAVe2UnBX9oik56XhRCtXA=", WgCrypto.b64(WgCrypto.publicKey(priv)))
    }

    @Test
    fun replayWindow_acceptsReorderedButNotOld() {
        val w = ReplayWindow()
        assertTrue(w.accept(10))
        assertTrue(w.accept(8))
        assertFalse(w.accept(8))
        assertTrue(w.accept(3000))
        assertFalse(w.accept(10)) // fell out of the 2048 window
        assertTrue(w.accept(2999))
    }

    @Test
    fun ip_udpPacketHasValidChecksums() {
        val p = Ip.udp(byteArrayOf(10, 99, 0, 1), 4720, byteArrayOf(10, 99, 0, 2), 5000, "hello".toByteArray())
        assertEquals(0, Ip.checksum(p, 0, 20))
        assertEquals(0, Ip.transportChecksum(p, 20, Ip.PROTO_UDP, p.size - 20))
    }

    @Test
    fun dns_answersSeestarLocal() {
        // Query for seestar.local, type A, class IN.
        val q = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            byteArrayOf(7) + "seestar".toByteArray() + byteArrayOf(5) + "local".toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
        val (name, end) = Dns.queryName(q)!!
        assertEquals("seestar.local", name)
        assertTrue(Dns.isSeestarName(name))
        assertFalse(Dns.isSeestarName("api.seestar.com"))
        val r = Dns.answerA(q, end, byteArrayOf(192.toByte(), 168.toByte(), 1, 50))
        assertEquals(0x1234, Ip.u16(r, 0))
        assertEquals(1, Ip.u16(r, 6))
        assertArrayEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 50), r.copyOfRange(r.size - 4, r.size))
    }
}
