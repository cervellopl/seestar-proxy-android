package com.seestarproxy.wg

/** Minimal IPv4 / UDP / TCP / ICMP packet helpers for the in-tunnel network stack. */
object Ip {
    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xFF
    fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)
    fun u32(b: ByteArray, i: Int) = (u16(b, i) shl 16) or u16(b, i + 2)
    fun put16(b: ByteArray, i: Int, v: Int) { b[i] = (v ushr 8).toByte(); b[i + 1] = v.toByte() }
    fun put32(b: ByteArray, i: Int, v: Int) { put16(b, i, v ushr 16); put16(b, i + 2, v) }

    /** RFC 1071 one's-complement sum (not yet inverted), continuing from [start]. */
    fun sum(b: ByteArray, off: Int, len: Int, start: Long = 0): Long {
        var s = start
        var i = off
        val end = off + len
        while (i + 1 < end) { s += u16(b, i); i += 2 }
        if (i < end) s += u8(b, i) shl 8
        return s
    }

    fun fold(s0: Long): Int {
        var s = s0
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }

    fun checksum(b: ByteArray, off: Int, len: Int) = fold(sum(b, off, len))

    /** TCP/UDP checksum over the IPv4 pseudo-header plus the transport segment. */
    fun transportChecksum(pkt: ByteArray, ihl: Int, proto: Int, segLen: Int): Int {
        var s = sum(pkt, 12, 8) // src + dst
        s += proto + segLen
        return fold(sum(pkt, ihl, segLen, s))
    }

    /** Parsed IPv4 header view over a packet. Returns null for non-IPv4 / truncated packets. */
    class V4(val raw: ByteArray) {
        val ihl = (u8(raw, 0) and 0x0F) * 4
        val totalLen = u16(raw, 2)
        val proto = u8(raw, 9)
        val src = raw.copyOfRange(12, 16)
        val dst = raw.copyOfRange(16, 20)
        val payloadOff get() = ihl
        val payloadLen get() = totalLen - ihl

        companion object {
            fun parse(p: ByteArray): V4? {
                if (p.size < 20 || (u8(p, 0) ushr 4) != 4) return null
                val v = V4(p)
                if (v.ihl < 20 || v.totalLen < v.ihl || v.totalLen > p.size) return null
                // Fragments are not supported.
                val frag = u16(p, 6)
                if (frag and 0x2000 != 0 || frag and 0x1FFF != 0) return null
                return v
            }
        }
    }

    /** Builds an IPv4 header (20 bytes) in front of [payloadLen] bytes and returns the packet. */
    fun v4(src: ByteArray, dst: ByteArray, proto: Int, payloadLen: Int): ByteArray {
        val p = ByteArray(20 + payloadLen)
        p[0] = 0x45
        put16(p, 2, p.size)
        put16(p, 6, 0x4000) // DF
        p[8] = 64
        p[9] = proto.toByte()
        System.arraycopy(src, 0, p, 12, 4)
        System.arraycopy(dst, 0, p, 16, 4)
        put16(p, 10, checksum(p, 0, 20))
        return p
    }

    fun udp(src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int, payload: ByteArray): ByteArray {
        val p = v4(src, dst, PROTO_UDP, 8 + payload.size)
        put16(p, 20, srcPort)
        put16(p, 22, dstPort)
        put16(p, 24, 8 + payload.size)
        System.arraycopy(payload, 0, p, 28, payload.size)
        val c = transportChecksum(p, 20, PROTO_UDP, 8 + payload.size)
        put16(p, 26, if (c == 0) 0xFFFF else c)
        return p
    }

    /** Echo reply for an ICMP echo request, or null if [ip] isn't one. */
    fun icmpEchoReply(ip: V4): ByteArray? {
        if (ip.proto != PROTO_ICMP || ip.payloadLen < 8 || u8(ip.raw, ip.ihl) != 8) return null
        val icmp = ip.raw.copyOfRange(ip.ihl, ip.totalLen)
        icmp[0] = 0
        icmp[2] = 0; icmp[3] = 0
        put16(icmp, 2, checksum(icmp, 0, icmp.size))
        val p = v4(ip.dst, ip.src, PROTO_ICMP, icmp.size)
        System.arraycopy(icmp, 0, p, 20, icmp.size)
        return p
    }

    fun str(a: ByteArray) = "${u8(a, 0)}.${u8(a, 1)}.${u8(a, 2)}.${u8(a, 3)}"
}

/** Tiny DNS helpers: parse a query name and answer it with a single A record. */
object Dns {
    /** Returns the lower-cased query name and the offset just past the question, or null. */
    fun queryName(q: ByteArray): Pair<String, Int>? {
        if (q.size < 13) return null
        val sb = StringBuilder()
        var pos = 12
        while (true) {
            if (pos >= q.size) return null
            val l = q[pos].toInt() and 0xFF
            if (l == 0) { pos++; break }
            if (l > 63 || pos + 1 + l > q.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(q, pos + 1, l, Charsets.US_ASCII))
            pos += 1 + l
        }
        if (pos + 4 > q.size) return null
        return sb.toString().lowercase() to pos + 4
    }

    /** Only A (1) / IN (1) queries get a synthetic answer. */
    fun isTypeA(q: ByteArray, questionEnd: Int) =
        Ip.u16(q, questionEnd - 4) == 1 && Ip.u16(q, questionEnd - 2) == 1

    /** Names that should resolve to the local telescope (cloud APIs excluded). */
    fun isSeestarName(n: String): Boolean {
        if (n == "seestar.com" || n.endsWith(".seestar.com")) return false
        return n == "seestar.local" || n.startsWith("s30_") || n.startsWith("s50_") ||
            n.startsWith("s30-") || n.startsWith("s50-") || (n.contains("seestar") && n.endsWith(".local"))
    }

    fun answerA(q: ByteArray, questionEnd: Int, ip: ByteArray): ByteArray {
        val r = ByteArray(questionEnd + 16)
        r[0] = q[0]; r[1] = q[1]
        r[2] = 0x81.toByte(); r[3] = 0x80.toByte() // response, RD, RA
        Ip.put16(r, 4, 1); Ip.put16(r, 6, 1)
        System.arraycopy(q, 12, r, 12, questionEnd - 12)
        var i = questionEnd
        r[i++] = 0xC0.toByte(); r[i++] = 0x0C // pointer to the question name
        Ip.put16(r, i, 1); i += 2 // A
        Ip.put16(r, i, 1); i += 2 // IN
        Ip.put32(r, i, 60); i += 4 // TTL
        Ip.put16(r, i, 4); i += 2
        System.arraycopy(ip, 0, r, i, 4)
        return r
    }
}
