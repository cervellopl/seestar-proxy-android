package com.seestarproxy.proxy

import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

/**
 * Decides which network carries traffic *to the telescope*.
 *
 * On a phone joined to the Seestar's own Wi‑Fi (no internet) Android routes
 * ordinary sockets over mobile data, so telescope-bound sockets must be
 * pinned to that Wi‑Fi. Client-facing sockets (LAN, VPN, WireGuard) are
 * never pinned — they follow normal routing.
 */
interface NetBinder {
    /** Pins [s] to the telescope network. Call before connect(). */
    fun bind(s: Socket) {}

    /** Pins [s] to the telescope network. Call before sending. */
    fun bind(s: DatagramSocket) {}

    /** True when [addr] lives on the telescope network (so replies to it must use that network). */
    fun owns(addr: InetAddress): Boolean = false

    /** Human-readable description for the UI / log. */
    val description: String get() = "domyślna sieć systemu"

    companion object {
        val DEFAULT = object : NetBinder {}
    }
}

/** Local IPv4 address the OS would use to reach [target] (unpinned, normal routing incl. VPN). */
fun localIpFor(target: InetAddress): InetAddress =
    DatagramSocket().use {
        it.broadcast = true
        it.connect(target, 1)
        it.localAddress
    }

/** Local address used to reach [target] over [net] when it owns the target, else normal routing. */
fun localIpFor(target: InetAddress, net: NetBinder): InetAddress =
    if (!net.owns(target)) localIpFor(target) else DatagramSocket().use {
        it.broadcast = true
        net.bind(it)
        it.connect(target, 1)
        it.localAddress
    }

/** Connects a TCP socket pinned to [net]. */
fun connectVia(net: NetBinder, addr: java.net.InetSocketAddress, timeoutMs: Int): Socket {
    val s = Socket()
    try {
        net.bind(s)
        s.connect(addr, timeoutMs)
        return s
    } catch (e: Exception) {
        s.closeQuietly()
        throw e
    }
}
