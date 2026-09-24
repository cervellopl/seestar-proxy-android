package com.seestarproxy.wg

import java.util.concurrent.atomic.AtomicLong

internal fun ByteArray.getIntLE(off: Int): Int =
    (this[off].toInt() and 0xFF) or ((this[off + 1].toInt() and 0xFF) shl 8) or
        ((this[off + 2].toInt() and 0xFF) shl 16) or ((this[off + 3].toInt() and 0xFF) shl 24)

internal fun ByteArray.putIntLE(off: Int, v: Int) {
    for (i in 0 until 4) this[off + i] = (v ushr (8 * i)).toByte()
}

internal fun ByteArray.getLongLE(off: Int): Long {
    var v = 0L
    for (i in 7 downTo 0) v = (v shl 8) or (this[off + i].toLong() and 0xFF)
    return v
}

internal fun ByteArray.putLongLE(off: Int, v: Long) {
    for (i in 0 until 8) this[off + i] = (v ushr (8 * i)).toByte()
}

/** Anti-replay sliding window (2048 counters), in the spirit of RFC 6479. */
internal class ReplayWindow {
    private val size = 2048
    private val bits = LongArray(size / 64)
    private var max = -1L

    private fun bit(c: Long) = (c % size).toInt()
    private fun isSet(c: Long) = bits[bit(c) / 64] and (1L shl (bit(c) % 64)) != 0L
    private fun set(c: Long) { bits[bit(c) / 64] = bits[bit(c) / 64] or (1L shl (bit(c) % 64)) }
    private fun clear(c: Long) { bits[bit(c) / 64] = bits[bit(c) / 64] and (1L shl (bit(c) % 64)).inv() }

    @Synchronized
    fun canAccept(c: Long): Boolean = when {
        c < 0 || c >= WgPeer.REJECT_AFTER_MESSAGES -> false
        c > max -> true
        max - c >= size -> false
        else -> !isSet(c)
    }

    /** Marks [c] as seen; call only after the packet authenticated. Returns false on replay. */
    @Synchronized
    fun accept(c: Long): Boolean {
        if (!canAccept(c)) return false
        if (c > max) {
            if (c - max >= size) bits.fill(0) else { var i = max + 1; while (i <= c) { clear(i); i++ } }
            max = c
        }
        set(c)
        return true
    }
}

/** One set of transport keys derived from a completed handshake. */
internal class Session(
    val localIndex: Int,
    val remoteIndex: Int,
    val sendKey: ByteArray,
    val recvKey: ByteArray,
) {
    val createdAt = System.currentTimeMillis()
    val sendCounter = AtomicLong(0)
    val replay = ReplayWindow()
    val expired: Boolean get() = System.currentTimeMillis() - createdAt > WgPeer.REJECT_AFTER_TIME_MS
}

/**
 * WireGuard responder for a single peer: processes handshake initiations
 * (Noise_IKpsk2), and encrypts/decrypts transport messages.
 *
 * The proxy only ever *responds* to handshakes; the client (configured with
 * PersistentKeepalive) is responsible for initiating and rekeying.
 */
class WgPeer(
    private val staticKeys: WgKeyPair,
    val peerPublic: ByteArray,
    private val presharedKey: ByteArray = ByteArray(32),
) {
    sealed interface Result {
        /** Send these bytes back to the peer (handshake response). */
        class Reply(val data: ByteArray) : Result
        /** Decrypted IP packet (empty = keepalive). */
        class Packet(val data: ByteArray) : Result
        data object Drop : Result
    }

    private val lock = Any()
    @Volatile private var current: Session? = null
    private var previous: Session? = null
    /** Session created by our last response; promoted once the initiator uses it. */
    private var next: Session? = null
    private var lastTimestamp = ByteArray(12)
    private val mac1KeyOwn = WgCrypto.hash(LABEL_MAC1, staticKeys.publicKey)
    private val mac1KeyPeer = WgCrypto.hash(LABEL_MAC1, peerPublic)

    @Volatile var lastHandshakeMs = 0L
        private set
    @Volatile var lastReceivedMs = 0L
        private set
    @Volatile var lastSentMs = 0L
        private set
    val rxBytes = AtomicLong()
    val txBytes = AtomicLong()

    val hasSession: Boolean get() = current?.expired == false

    fun handle(msg: ByteArray, len: Int): Result {
        if (len < 4) return Result.Drop
        return when (msg[0].toInt()) {
            1 -> if (len == 148) handleInitiation(msg) else Result.Drop
            4 -> if (len >= 32) handleTransport(msg, len) else Result.Drop
            else -> Result.Drop // responses (2) and cookie replies (3) are never sent to a responder
        }
    }

    private fun handleInitiation(msg: ByteArray): Result {
        // mac1 must be valid before doing any expensive crypto.
        val mac1 = WgCrypto.mac(mac1KeyOwn, msg, 116)
        if (!mac1.contentEquals(msg.copyOfRange(116, 132))) return Result.Drop

        val senderIndex = msg.getIntLE(4)
        val ephI = msg.copyOfRange(8, 40)

        var c = INITIAL_CHAIN_KEY
        var h = WgCrypto.hash(INITIAL_HASH, staticKeys.publicKey)
        c = WgCrypto.kdf(1, c, ephI)[0]
        h = WgCrypto.hash(h, ephI)
        var kk = WgCrypto.kdf(2, c, WgCrypto.dh(staticKeys.privateKey, ephI))
        c = kk[0]
        val encStatic = msg.copyOfRange(40, 88)
        val staticI = WgCrypto.aeadDecrypt(kk[1], 0, encStatic, h) ?: return Result.Drop
        h = WgCrypto.hash(h, encStatic)
        if (!staticI.contentEquals(peerPublic)) return Result.Drop // unknown peer

        kk = WgCrypto.kdf(2, c, WgCrypto.dh(staticKeys.privateKey, staticI))
        c = kk[0]
        val encTs = msg.copyOfRange(88, 116)
        val timestamp = WgCrypto.aeadDecrypt(kk[1], 0, encTs, h) ?: return Result.Drop
        h = WgCrypto.hash(h, encTs)

        synchronized(lock) {
            // TAI64N is big-endian: must strictly increase to reject replayed initiations.
            if (compareUnsigned(timestamp, lastTimestamp) <= 0) return Result.Drop
            lastTimestamp = timestamp

            // ── Build the response ──
            val ephR = WgKeyPair.generate()
            val localIndex = WgCrypto.random.nextInt()
            val resp = ByteArray(92)
            resp[0] = 2
            resp.putIntLE(4, localIndex)
            resp.putIntLE(8, senderIndex)
            System.arraycopy(ephR.publicKey, 0, resp, 12, 32)

            c = WgCrypto.kdf(1, c, ephR.publicKey)[0]
            h = WgCrypto.hash(h, ephR.publicKey)
            c = WgCrypto.kdf(1, c, WgCrypto.dh(ephR.privateKey, ephI))[0]
            c = WgCrypto.kdf(1, c, WgCrypto.dh(ephR.privateKey, staticI))[0]
            val k3 = WgCrypto.kdf(3, c, presharedKey)
            c = k3[0]
            h = WgCrypto.hash(h, k3[1])
            val empty = WgCrypto.aeadEncrypt(k3[2], 0, ByteArray(0), h)
            System.arraycopy(empty, 0, resp, 44, 16)
            System.arraycopy(WgCrypto.mac(mac1KeyPeer, resp, 60), 0, resp, 60, 16)
            // mac2 stays zero: we never issue cookies.

            // Transport keys: initiator sends with T1, so the responder receives with T1.
            val t = WgCrypto.kdf(2, c, ByteArray(0))
            next = Session(localIndex, senderIndex, sendKey = t[1], recvKey = t[0])
            lastHandshakeMs = System.currentTimeMillis()
            return Result.Reply(resp)
        }
    }

    private fun handleTransport(msg: ByteArray, len: Int): Result {
        val receiver = msg.getIntLE(4)
        val counter = msg.getLongLE(8)
        val session = synchronized(lock) {
            listOfNotNull(next, current, previous).firstOrNull { it.localIndex == receiver }
        } ?: return Result.Drop
        if (session.expired || !session.replay.canAccept(counter)) return Result.Drop
        val plain = WgCrypto.aeadDecrypt(session.recvKey, counter, msg, null, 16, len - 16) ?: return Result.Drop
        if (!session.replay.accept(counter)) return Result.Drop

        synchronized(lock) {
            // First packet on the new keys confirms the handshake: rotate sessions.
            if (session === next) {
                previous = current
                current = session
                next = null
            }
        }
        lastReceivedMs = System.currentTimeMillis()
        rxBytes.addAndGet(len.toLong())
        return Result.Packet(plain)
    }

    /**
     * Encrypts an IP packet (or an empty keepalive) for the peer.
     * Returns null when there is no usable session.
     */
    fun encrypt(packet: ByteArray): ByteArray? {
        val s = current ?: return null
        if (s.expired) return null
        val counter = s.sendCounter.getAndIncrement()
        if (counter >= REJECT_AFTER_MESSAGES) return null
        // Pad the plaintext to a multiple of 16 bytes.
        val padded = if (packet.isEmpty()) packet else packet.copyOf((packet.size + 15) and 15.inv())
        val out = ByteArray(16 + padded.size + 16)
        out[0] = 4
        out.putIntLE(4, s.remoteIndex)
        out.putLongLE(8, counter)
        val enc = WgCrypto.aeadEncrypt(s.sendKey, counter, padded, null)
        System.arraycopy(enc, 0, out, 16, enc.size)
        lastSentMs = System.currentTimeMillis()
        txBytes.addAndGet(out.size.toLong())
        return out
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return 0
    }

    companion object {
        const val REJECT_AFTER_TIME_MS = 180_000L
        const val REJECT_AFTER_MESSAGES = Long.MAX_VALUE - (1L shl 13)
        const val KEEPALIVE_TIMEOUT_MS = 10_000L

        private val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray()
        private val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()
        internal val LABEL_MAC1 = "mac1----".toByteArray()
        internal val INITIAL_CHAIN_KEY = WgCrypto.hash(CONSTRUCTION)
        internal val INITIAL_HASH = WgCrypto.hash(INITIAL_CHAIN_KEY, IDENTIFIER)
    }
}
