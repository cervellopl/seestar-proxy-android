package com.seestarproxy.wg

import com.seestarproxy.proxy.closeQuietly
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.math.max
import kotlin.math.min

/** Bounded byte FIFO: the local-socket reader blocks when it is full (back-pressure). */
internal class SendBuffer(capacity: Int) {
    private val buf = ByteArray(capacity)
    private var head = 0
    private var size = 0
    private var closed = false
    private val lock = Object()

    fun write(src: ByteArray, len: Int): Boolean {
        var off = 0
        synchronized(lock) {
            while (off < len) {
                while (size == buf.size && !closed) lock.wait()
                if (closed) return false
                val n = min(len - off, buf.size - size)
                val tail = (head + size) % buf.size
                val first = min(n, buf.size - tail)
                System.arraycopy(src, off, buf, tail, first)
                if (n > first) System.arraycopy(src, off + first, buf, 0, n - first)
                size += n
                off += n
            }
        }
        return true
    }

    fun size(): Int = synchronized(lock) { size }

    fun peek(offset: Int, dst: ByteArray, dstOff: Int, n: Int) = synchronized(lock) {
        val start = (head + offset) % buf.size
        val first = min(n, buf.size - start)
        System.arraycopy(buf, start, dst, dstOff, first)
        if (n > first) System.arraycopy(buf, 0, dst, dstOff + first, n - first)
    }

    fun consume(n: Int) = synchronized(lock) {
        val k = min(n, size)
        head = (head + k) % buf.size
        size -= k
        lock.notifyAll()
    }

    fun close() = synchronized(lock) { closed = true; lock.notifyAll() }
}

/**
 * Minimal userspace TCP (server side only) for connections arriving through
 * the WireGuard tunnel. Each accepted connection is bridged to a local port
 * on 127.0.0.1 (the proxy's control / imaging / dashboard listeners).
 *
 * Implemented: 3-way handshake, MSS + window-scale options, in-order receive,
 * retransmission with RTO (RFC 6298), slow start / congestion avoidance,
 * fast retransmit, zero-window probing, FIN/RST handling.
 * Not implemented: SACK, timestamps, out-of-order reassembly (segments are
 * dropped and re-requested via duplicate ACKs).
 *
 * All connection state is owned by a single event-loop thread.
 */
class TcpStack(
    /** Tunnel destination IPs we answer for. */
    private val acceptIps: Set<Int>,
    /** Tunnel destination port → local 127.0.0.1 port. */
    private val portMap: Map<Int, Int>,
    /** Sends an IPv4 packet back into the tunnel. */
    private val output: (ByteArray) -> Unit,
    private val log: (String) -> Unit,
) {
    private data class Key(val rip: Int, val rport: Int, val lip: Int, val lport: Int)

    private val events = LinkedBlockingQueue<Any>()
    private val conns = HashMap<Key, Conn>()
    private val running = AtomicBoolean(true)
    private val wake = Any()
    private lateinit var loop: Thread
    val connectionCount = AtomicInteger()

    fun start() {
        loop = thread(name = "wg-tcp", isDaemon = true) { runLoop() }
    }

    fun stop() {
        running.set(false)
        events.offer(wake)
    }

    /** Called from the WireGuard receive thread with a decrypted TCP packet. */
    fun inject(ip: Ip.V4) {
        events.offer(ip)
    }

    private fun runLoop() {
        while (running.get()) {
            val now = System.currentTimeMillis()
            var timeout = 50L
            for (c in conns.values) if (c.deadline > 0) timeout = min(timeout, max(1, c.deadline - now))
            val ev = try {
                events.poll(timeout, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                break
            }
            var e = ev
            while (e != null) {
                if (e is Ip.V4) try {
                    onSegment(e)
                } catch (ex: Exception) {
                    log("TCP: błąd segmentu: ${ex.message}")
                }
                e = events.poll()
            }
            val t = System.currentTimeMillis()
            for (c in conns.values.toList()) {
                if (c.deadline in 1..t) c.onTimer(t)
                c.pump(t)
                c.checkIdle(t)
            }
        }
        for (c in conns.values.toList()) c.abort(sendRst = true)
    }

    private fun ipInt(b: ByteArray, off: Int = 0) = Ip.u32(b, off)

    private fun onSegment(ip: Ip.V4) {
        val p = ip.raw
        val o = ip.ihl
        if (ip.payloadLen < 20) return
        if (Ip.transportChecksum(p, o, Ip.PROTO_TCP, ip.payloadLen) != 0) return
        val seg = Segment(
            srcPort = Ip.u16(p, o), dstPort = Ip.u16(p, o + 2),
            seq = Ip.u32(p, o + 4), ack = Ip.u32(p, o + 8),
            dataOff = ((Ip.u8(p, o + 12) ushr 4) * 4),
            flags = Ip.u8(p, o + 13), window = Ip.u16(p, o + 14),
            raw = p, tcpOff = o, tcpLen = ip.payloadLen,
        )
        if (seg.dataOff < 20 || seg.dataOff > seg.tcpLen) return
        val key = Key(ipInt(ip.src), seg.srcPort, ipInt(ip.dst), seg.dstPort)
        val c = conns[key]
        if (c != null) {
            c.onSegment(seg)
            return
        }
        if (seg.isRst) return
        val target = portMap[seg.dstPort]
        if (seg.isSyn && !seg.isAck && target != null && key.lip in acceptIps) {
            val conn = Conn(key, ip.src, ip.dst, target, seg)
            conns[key] = conn
            connectionCount.set(conns.size)
            return
        }
        // Refuse: no listener / not our address / stray segment.
        if (seg.isAck) {
            sendRaw(ip.dst, seg.dstPort, ip.src, seg.srcPort, seg.ack, 0, RST, 0, null, 0, 0, null)
        } else {
            val len = seg.payloadLen + (if (seg.isSyn) 1 else 0) + (if (seg.isFin) 1 else 0)
            sendRaw(ip.dst, seg.dstPort, ip.src, seg.srcPort, 0, seg.seq + len, RST or ACK, 0, null, 0, 0, null)
        }
    }

    private class Segment(
        val srcPort: Int, val dstPort: Int, val seq: Int, val ack: Int, val dataOff: Int,
        val flags: Int, val window: Int, val raw: ByteArray, val tcpOff: Int, val tcpLen: Int,
    ) {
        val isSyn get() = flags and SYN != 0
        val isAck get() = flags and ACK != 0
        val isFin get() = flags and FIN != 0
        val isRst get() = flags and RST != 0
        val payloadOff get() = tcpOff + dataOff
        val payloadLen get() = tcpLen - dataOff

        /** Walks the TCP options, calling [f] with (kind, offset of the value, value length). */
        private inline fun forEachOption(f: (Int, Int, Int) -> Unit) {
            var i = tcpOff + 20
            val end = tcpOff + dataOff
            while (i < end) {
                val kind = Ip.u8(raw, i)
                if (kind == 0) break
                if (kind == 1) { i++; continue }
                if (i + 1 >= end) break
                val len = Ip.u8(raw, i + 1)
                if (len < 2 || i + len > end) break
                f(kind, i + 2, len - 2)
                i += len
            }
        }

        /** MSS, window scale and SACK-permitted (only meaningful on SYN). */
        fun synOptions(): SynOptions {
            var mss: Int? = null
            var ws: Int? = null
            var sack = false
            forEachOption { kind, at, len ->
                if (kind == 2 && len == 2) mss = Ip.u16(raw, at)
                if (kind == 3 && len == 1) ws = min(Ip.u8(raw, at), 14)
                if (kind == 4 && len == 0) sack = true
            }
            return SynOptions(mss, ws, sack)
        }

        /** SACK blocks as [left, right) sequence pairs. */
        fun sackBlocks(): List<IntArray> {
            val out = ArrayList<IntArray>(4)
            forEachOption { kind, at, len ->
                if (kind == 5) {
                    var j = at
                    while (j + 8 <= at + len) {
                        out.add(intArrayOf(Ip.u32(raw, j), Ip.u32(raw, j + 4)))
                        j += 8
                    }
                }
            }
            return out
        }
    }

    private fun sendRaw(
        src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int, seq: Int, ack: Int, flags: Int,
        window: Int, data: ByteArray?, dOff: Int, dLen: Int, options: ByteArray?,
    ) {
        val optLen = options?.size ?: 0
        val tcpLen = 20 + optLen + dLen
        val p = Ip.v4(src, dst, Ip.PROTO_TCP, tcpLen)
        Ip.put16(p, 20, srcPort)
        Ip.put16(p, 22, dstPort)
        Ip.put32(p, 24, seq)
        Ip.put32(p, 28, ack)
        p[32] = (((20 + optLen) / 4) shl 4).toByte()
        p[33] = flags.toByte()
        Ip.put16(p, 34, window)
        if (options != null) System.arraycopy(options, 0, p, 40, optLen)
        if (data != null && dLen > 0) System.arraycopy(data, dOff, p, 40 + optLen, dLen)
        Ip.put16(p, 36, Ip.transportChecksum(p, 20, Ip.PROTO_TCP, tcpLen))
        output(p)
    }

    private fun seqLt(a: Int, b: Int) = a - b < 0
    private fun seqLe(a: Int, b: Int) = a - b <= 0
    private fun seqGt(a: Int, b: Int) = a - b > 0
    private fun seqGe(a: Int, b: Int) = a - b >= 0

    private class SynOptions(val mss: Int?, val windowScale: Int?, val sackPermitted: Boolean)

    private inner class Conn(
        val key: Key,
        val remoteIp: ByteArray,
        val localIp: ByteArray,
        val targetPort: Int,
        syn: Segment,
    ) {
        var established = false
        var timeWaitUntil = 0L

        // Receive side.
        var rcvNxt = syn.seq + 1
        var peerFin = false
        val toLocal = LinkedBlockingQueue<ByteArray>()
        val toLocalBytes = AtomicInteger()

        // Send side.
        val iss = WgCrypto.random.nextInt()
        var sndUna = iss
        var sndNxt = iss + 1
        var sndMax = iss + 1
        val sndShift: Int
        val sendWsOption: Boolean
        var sndWnd = syn.window.toLong()
        val mss: Int
        var cwnd: Long
        var ssthresh = Long.MAX_VALUE
        var dupAcks = 0
        var inRecovery = false
        var recoverSeq = 0
        /** SACK (RFC 2018) negotiated. */
        val sackOk: Boolean
        /** Next sequence to consider for retransmission during SACK recovery. */
        var rtxNext = 0
        /** After an RTO, don't start fast recovery until everything sent before it is acked. */
        var afterRto = false
        var rtoRecoverSeq = 0
        val sendBuf = SendBuffer(1 shl 20)
        @Volatile var localEof = false
        /** FIN is in the current transmission window. */
        var finSent = false
        /** finSeq has been assigned (the FIN was sent at least once). */
        var finAssigned = false
        var finSeq = 0
        var finAcked = false
        var removed = false

        // Timers (RFC 6298).
        var srtt = -1.0
        var rttvar = 0.0
        var rto = 1000L
        var deadline = 0L
        var retries = 0
        var rttSeq = 0
        var rttStart = 0L
        var rttValid = false
        var lastRx = System.currentTimeMillis()

        // Diagnostics, logged when the connection closes.
        var segsSent = 0L
        var retransmits = 0L
        var timeouts = 0
        var fastRecoveries = 0

        var socket: Socket? = null
        private val tmp = ByteArray(1500)

        init {
            val o = syn.synOptions()
            mss = min(o.mss ?: 536, OUR_MSS)
            sendWsOption = o.windowScale != null
            sndShift = o.windowScale ?: 0
            sackOk = o.sackPermitted
            cwnd = 10L * mss
            sendSynAck()
        }

        fun advertisedWindow() = max(0, RCV_WINDOW - toLocalBytes.get())

        fun send(seq: Int, flags: Int, data: ByteArray? = null, off: Int = 0, len: Int = 0, opts: ByteArray? = null) {
            if (len > 0) {
                segsSent++
                if (seqLt(seq, sndMax)) retransmits++
            }
            sendRaw(localIp, key.lport, remoteIp, key.rport, seq, rcvNxt, flags, advertisedWindow(), data, off, len, opts)
        }

        fun sendAck() = send(sndNxt, ACK)

        fun sendSynAck() {
            var opts = byteArrayOf(2, 4, (OUR_MSS ushr 8).toByte(), OUR_MSS.toByte())
            if (sendWsOption) opts += byteArrayOf(1, 3, 3, 0) // window scale 0 (we don't scale our window)
            if (sackOk) opts += byteArrayOf(1, 1, 4, 2) // SACK permitted
            send(iss, SYN or ACK, opts = opts)
            deadline = System.currentTimeMillis() + rto
        }

        fun onSegment(seg: Segment) {
            lastRx = System.currentTimeMillis()
            if (seg.isRst) {
                if (established || seqLe(rcvNxt, seg.seq)) abort(sendRst = false)
                return
            }
            if (seg.isSyn) {
                // Retransmitted SYN while we wait for the final ACK.
                if (!established) sendSynAck() else sendAck()
                return
            }
            if (!seg.isAck) return

            if (!established) {
                if (seg.ack != iss + 1) return
                established = true
                sndUna = iss + 1
                deadline = 0
                retries = 0
                rto = 1000
                sndWnd = seg.window.toLong() shl sndShift
                startBridge()
            }

            onAck(seg)
            onData(seg)
        }

        private fun onAck(seg: Segment) {
            val ack = seg.ack
            val newWnd = seg.window.toLong() shl sndShift
            if (seqGt(ack, sndMax)) {
                sendAck()
                return
            }
            val now = System.currentTimeMillis()
            if (sackOk) for (b in seg.sackBlocks()) addSack(b[0], b[1])
            if (seqGt(ack, sndUna)) {
                var acked = ack - sndUna
                if (finAssigned && !finAcked && ack == finSeq + 1) {
                    finAcked = true
                    acked -= 1
                }
                sendBuf.consume(acked)
                sndUna = ack
                if (seqLt(sndNxt, sndUna)) sndNxt = sndUna
                pruneSacks()
                if (afterRto && seqGe(ack, rtoRecoverSeq)) afterRto = false
                // New data acknowledged: drop the exponential backoff (as Linux does).
                if (retries > 0) rto = computedRto()
                retries = 0
                dupAcks = 0
                if (rttValid && seqGt(ack, rttSeq)) {
                    val r = (now - rttStart).toDouble()
                    if (srtt < 0) { srtt = r; rttvar = r / 2 } else {
                        rttvar = 0.75 * rttvar + 0.25 * Math.abs(srtt - r)
                        srtt = 0.875 * srtt + 0.125 * r
                    }
                    rto = computedRto()
                    rttValid = false
                }
                if (inRecovery) {
                    if (seqLe(recoverSeq, ack)) {
                        inRecovery = false
                        cwnd = ssthresh
                    } else if (sackOk) {
                        if (seqLt(rtxNext, sndUna)) rtxNext = sndUna
                    } else {
                        retransmitFirst() // NewReno partial ACK: next hole right away
                    }
                } else if (cwnd < ssthresh) {
                    cwnd += min(acked.toLong(), mss.toLong())
                } else {
                    cwnd += max(1L, mss.toLong() * mss / cwnd)
                }
                cwnd = min(cwnd, MAX_CWND)
                deadline = if (sndUna == sndMax) 0 else now + rto
            } else if (ack == sndUna && seg.payloadLen == 0 && !seg.isFin && sndMax != sndUna) {
                // Duplicate ACK. The window isn't compared: receivers with buffer
                // autotuning (Linux) change it on almost every ACK.
                dupAcks++
                if (!sackOk) {
                    if (dupAcks == 3 && !inRecovery && !afterRto) {
                        enterRecovery()
                        retransmitFirst()
                    } else if (inRecovery && dupAcks > 3) {
                        cwnd += mss
                    }
                }
            }
            // SACK loss detection (RFC 6675): 3 duplicate ACKs or more than 3 segments SACKed.
            if (sackOk && !inRecovery && !afterRto && sndMax != sndUna &&
                (dupAcks >= 3 || sackedBetween(sndUna, sndMax) >= 3L * mss)
            ) {
                enterRecovery()
                rtxNext = sndUna
            }
            sndWnd = newWnd
        }

        private fun enterRecovery() {
            fastRecoveries++
            val flight = (sndMax - sndUna).toLong()
            ssthresh = max(flight / 2, 2L * mss)
            cwnd = if (sackOk) ssthresh else ssthresh + 3L * mss
            inRecovery = true
            recoverSeq = sndMax
            rttValid = false
        }

        private fun computedRto(): Long =
            if (srtt < 0) 1000L else (srtt + max(10.0, 4 * rttvar)).toLong().coerceIn(MIN_RTO, MAX_RTO)

        private fun retransmitFirst() {
            val avail = sendBuf.size()
            val n = min(mss, avail)
            if (n > 0) {
                sendBuf.peek(0, tmp, 0, n)
                send(sndUna, ACK or PSH, tmp, 0, n)
            } else if (finSent && !finAcked) {
                send(finSeq, FIN or ACK)
            }
            rttValid = false
        }

        // ── SACK scoreboard: merged, sorted [start, end) ranges above sndUna ──

        private val sacks = ArrayList<IntArray>()

        private fun addSack(l0: Int, r: Int) {
            var l = l0
            if (!seqLt(l, r) || seqLe(r, sndUna) || seqGt(r, sndMax)) return
            if (seqLt(l, sndUna)) l = sndUna
            sacks.add(intArrayOf(l, r))
            sacks.sortBy { it[0] - sndUna }
            var i = 0
            while (i < sacks.size - 1) {
                val a = sacks[i]
                val b = sacks[i + 1]
                if (seqGe(a[1], b[0])) {
                    if (seqGt(b[1], a[1])) a[1] = b[1]
                    sacks.removeAt(i + 1)
                } else {
                    i++
                }
            }
        }

        private fun pruneSacks() {
            val it = sacks.iterator()
            while (it.hasNext()) {
                val b = it.next()
                if (seqLe(b[1], sndUna)) it.remove() else if (seqLt(b[0], sndUna)) b[0] = sndUna
            }
        }

        private fun sackedBetween(a: Int, b: Int): Long {
            var sum = 0L
            for (blk in sacks) {
                val s = if (seqGt(blk[0], a)) blk[0] else a
                val e = if (seqLt(blk[1], b)) blk[1] else b
                if (seqLt(s, e)) sum += (e - s)
            }
            return sum
        }

        private fun sackAt(seq: Int) = sacks.firstOrNull { seqLe(it[0], seq) && seqLt(seq, it[1]) }
        private fun nextSackStart(seq: Int) = sacks.firstOrNull { seqGt(it[0], seq) }?.get(0)
        private fun highestSacked() = if (sacks.isEmpty()) sndUna else sacks.last()[1]

        /** Un-SACKed bytes in [from, hi): presumed lost during recovery. */
        private fun holeBytes(from: Int, hi: Int): Long {
            val f = if (seqLt(from, sndUna)) sndUna else from
            return if (seqLt(f, hi)) (hi - f) - sackedBetween(f, hi) else 0L
        }

        private fun nextHole(from: Int, hi: Int): IntArray? {
            var p = if (seqLt(from, sndUna)) sndUna else from
            while (seqLt(p, hi)) {
                val blk = sackAt(p)
                if (blk != null) { p = blk[1]; continue }
                return intArrayOf(p, nextSackStart(p) ?: hi)
            }
            return null
        }

        private fun onData(seg: Segment) {
            var off = seg.payloadOff
            var len = seg.payloadLen
            var seq = seg.seq
            if (len == 0 && !seg.isFin) return
            // Trim bytes we already have (overlapping retransmission).
            if (seqLt(seq, rcvNxt)) {
                val dup = rcvNxt - seq
                if (dup >= len + (if (seg.isFin) 1 else 0)) { sendAck(); return }
                val d = min(dup, len)
                off += d; len -= d; seq += d
            }
            if (seq != rcvNxt || peerFin) { sendAck(); return } // out of order: ask again
            if (len > 0) {
                toLocal.offer(seg.raw.copyOfRange(off, off + len))
                toLocalBytes.addAndGet(len)
                rcvNxt += len
            }
            if (seg.isFin) {
                rcvNxt += 1
                peerFin = true
                toLocal.offer(EOF_MARK)
            }
            sendAck()
        }

        /** Sends as much as the windows allow: holes first (SACK recovery), then new data, then FIN. */
        fun pump(now: Long) {
            if (removed || !established || timeWaitUntil > 0) return
            if (inRecovery && sackOk) sackRecovery(now) else sendWindow(now)
            val dataEnd = sndUna + sendBuf.size()
            if (localEof && !finSent && !finAcked && sndNxt == dataEnd) {
                finSeq = dataEnd
                finAssigned = true
                finSent = true
                send(finSeq, FIN or ACK)
                sndNxt = finSeq + 1
                if (seqGt(sndNxt, sndMax)) sndMax = sndNxt
                if (deadline == 0L) deadline = now + rto
            }
            if (finAcked && peerFin && timeWaitUntil == 0L) {
                timeWaitUntil = now + TIME_WAIT_MS
                deadline = timeWaitUntil
            }
        }

        private fun transmit(seq: Int, n: Int, now: Long) {
            sendBuf.peek(seq - sndUna, tmp, 0, n)
            if (!rttValid && seq == sndMax) { rttValid = true; rttSeq = seq; rttStart = now }
            send(seq, ACK or PSH, tmp, 0, n)
            if (deadline == 0L) deadline = now + rto
        }

        /** Normal sending; after an RTO this is go-back-N that skips SACKed ranges. */
        private fun sendWindow(now: Long) {
            while (true) {
                if (seqLt(sndNxt, sndMax)) {
                    val blk = sackAt(sndNxt)
                    if (blk != null) { sndNxt = blk[1]; continue }
                }
                val unsent = sndUna + sendBuf.size() - sndNxt
                if (unsent <= 0) break
                val outstanding = (sndNxt - sndUna).toLong()
                val pipe = outstanding - sackedBetween(sndUna, sndNxt)
                val room = min(cwnd - pipe, sndWnd - outstanding)
                if (room <= 0) {
                    // Zero window with nothing in flight → arm the persist timer.
                    if (outstanding == 0L && deadline == 0L) deadline = now + rto
                    break
                }
                var n = min(min(mss.toLong(), unsent.toLong()), room).toInt()
                if (seqLt(sndNxt, sndMax)) nextSackStart(sndNxt)?.let { n = min(n, it - sndNxt) }
                transmit(sndNxt, n, now)
                sndNxt += n
                if (seqGt(sndNxt, sndMax)) sndMax = sndNxt
            }
        }

        /** RFC 6675-style recovery: keep `pipe` under cwnd, filling holes before sending new data. */
        private fun sackRecovery(now: Long) {
            while (true) {
                val hi = highestSacked()
                val outstanding = (sndMax - sndUna).toLong()
                val pipe = outstanding - sackedBetween(sndUna, sndMax) - holeBytes(rtxNext, hi)
                if (pipe >= cwnd) break
                val hole = nextHole(rtxNext, hi)
                if (hole != null) {
                    val n = min(mss, hole[1] - hole[0])
                    if (n <= 0 || hole[0] - sndUna >= sendBuf.size()) break
                    transmit(hole[0], min(n, sendBuf.size() - (hole[0] - sndUna)), now)
                    rtxNext = hole[0] + n
                    continue
                }
                val unsent = sndUna + sendBuf.size() - sndNxt
                val n = min(min(mss.toLong(), unsent.toLong()), sndWnd - (sndNxt - sndUna)).toInt()
                if (n <= 0) break
                transmit(sndNxt, n, now)
                sndNxt += n
                if (seqGt(sndNxt, sndMax)) sndMax = sndNxt
            }
        }

        fun onTimer(now: Long) {
            if (removed) return
            if (timeWaitUntil > 0) { remove(); return }
            if (!established) {
                if (++retries > MAX_SYN_RETRIES) { remove(); return }
                rto = min(rto * 2, MAX_RTO)
                sendSynAck()
                return
            }
            if (++retries > MAX_RETRIES) {
                log("TCP: ${Ip.str(remoteIp)}:${key.rport} nie odpowiada — przerywam połączenie")
                abort(sendRst = true)
                return
            }
            timeouts++
            val inFlight = sndNxt - sndUna
            val unsent = sndUna + sendBuf.size() - sndNxt
            if (inFlight == 0 && unsent > 0) {
                // Zero-window probe: one byte past the window.
                sendBuf.peek(0, tmp, 0, 1)
                send(sndNxt, ACK, tmp, 0, 1)
                sndNxt += 1
                if (seqGt(sndNxt, sndMax)) sndMax = sndNxt
            } else if (inFlight > 0) {
                ssthresh = max(inFlight / 2L, 2L * mss)
                cwnd = mss.toLong()
                inRecovery = false
                dupAcks = 0
                afterRto = true
                rtoRecoverSeq = sndMax
                // Go back to the oldest unacknowledged byte (SACKed ranges are skipped).
                sndNxt = sndUna
                if (finSent && seqLe(sndNxt, finSeq)) finSent = false
                rttValid = false
            }
            rto = min(rto * 2, MAX_RTO)
            deadline = now + rto
            pump(now)
        }

        fun checkIdle(now: Long) {
            if (removed || timeWaitUntil > 0) return
            val idle = now - lastRx
            if (idle > IDLE_TIMEOUT_MS || (finAcked && !peerFin && idle > FIN_WAIT_TIMEOUT_MS)) {
                abort(sendRst = true)
            }
        }

        private fun startBridge() {
            thread(name = "wg-bridge-${key.rport}", isDaemon = true) {
                val s = Socket()
                try {
                    s.connect(InetSocketAddress("127.0.0.1", targetPort), 3_000)
                    s.tcpNoDelay = true
                } catch (e: IOException) {
                    log("TCP: brak lokalnego portu $targetPort: ${e.message}")
                    localEof = true
                    sendBuf.close()
                    events.offer(wake)
                    return@thread
                }
                socket = s
                log("Tunel: połączenie ${Ip.str(remoteIp)}:${key.rport} → port ${key.lport}")
                thread(name = "wg-bridge-w-${key.rport}", isDaemon = true) { writeLocal(s) }
                val buf = ByteArray(16 * 1024)
                try {
                    val input = s.getInputStream()
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        if (!sendBuf.write(buf, n)) break
                        events.offer(wake)
                    }
                } catch (_: IOException) {
                }
                localEof = true
                events.offer(wake)
            }
        }

        private fun writeLocal(s: Socket) {
            try {
                val out = s.getOutputStream()
                while (true) {
                    val b = toLocal.take()
                    if (b === EOF_MARK) { s.shutdownOutput(); break }
                    out.write(b)
                    out.flush()
                    toLocalBytes.addAndGet(-b.size)
                }
            } catch (_: Exception) {
                s.closeQuietly()
            }
        }

        fun abort(sendRst: Boolean) {
            if (sendRst && established) send(sndNxt, RST or ACK)
            remove()
        }

        fun remove() {
            if (removed) return
            removed = true
            conns.remove(key)
            if (established) {
                log("Tunel: zamknięto ${Ip.str(remoteIp)}:${key.rport} → ${key.lport} " +
                    "(segmenty $segsSent, retransmisje $retransmits, RTO $timeouts, szybkie odzysk. $fastRecoveries, " +
                    "srtt ${srtt.toInt()} ms)")
            }
            connectionCount.set(conns.size)
            sendBuf.close()
            toLocal.offer(EOF_MARK)
            socket.closeQuietly()
        }
    }

    companion object {
        private const val FIN = 0x01
        private const val SYN = 0x02
        private const val RST = 0x04
        private const val PSH = 0x08
        private const val ACK = 0x10

        /** WireGuard MTU 1420 − 40 bytes of IPv4+TCP headers, with some margin. */
        const val OUR_MSS = 1360
        private const val RCV_WINDOW = 65_535
        private const val MIN_RTO = 250L
        private const val MAX_RTO = 30_000L
        private const val MAX_CWND = 8L shl 20
        private const val MAX_RETRIES = 10
        private const val MAX_SYN_RETRIES = 5
        private const val TIME_WAIT_MS = 2_000L
        private const val IDLE_TIMEOUT_MS = 15 * 60_000L
        private const val FIN_WAIT_TIMEOUT_MS = 60_000L
        private val EOF_MARK = ByteArray(0)
    }
}
