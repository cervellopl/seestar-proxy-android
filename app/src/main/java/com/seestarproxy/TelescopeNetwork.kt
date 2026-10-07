package com.seestarproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.seestarproxy.proxy.NetBinder
import java.io.IOException
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Pins telescope traffic to the Wi‑Fi network the telescope is on.
 *
 * Holds a Wi‑Fi request *without* the INTERNET capability, which also keeps
 * Android from dropping a Wi‑Fi that has no internet (e.g. the Seestar's own
 * `S50_xxxx` access point) while mobile data stays the default network —
 * and stays the path for a VPN such as OpenVPN/SoftEther.
 *
 * A socket is pinned only when [target] (the telescope) is inside one of the
 * Wi‑Fi's directly connected subnets; otherwise normal routing is used, so a
 * telescope on the phone's own hotspot keeps working.
 *
 * @param target the telescope address, or null to pin to any Wi‑Fi (LAN scan).
 */
class TelescopeNetwork(ctx: Context, private val target: InetAddress?, private val log: (String) -> Unit = {}) : NetBinder {
    private val cm = ctx.getSystemService(ConnectivityManager::class.java)
    @Volatile private var network: Network? = null
    @Volatile private var link: LinkProperties? = null
    @Volatile private var validated = false
    @Volatile private var bindFailedLogged = false
    private val ready = CountDownLatch(1)

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(n: Network) {
            network = n
            link = cm.getLinkProperties(n)
            validated = cm.getNetworkCapabilities(n)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
            ready.countDown()
            log("Sieć teleskopu: $description")
        }

        override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) {
            if (n == network) link = lp
        }

        override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) {
            if (n == network) validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }

        override fun onLost(n: Network) {
            if (n == network) {
                network = null
                link = null
                log("Sieć teleskopu: Wi‑Fi rozłączone — używam domyślnej sieci")
            }
        }
    }

    fun start() {
        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.requestNetwork(req, callback)
    }

    /** Waits briefly for the Wi‑Fi callback so the first connection is already pinned. */
    fun awaitReady(timeoutMs: Long) {
        ready.await(timeoutMs, TimeUnit.MILLISECONDS)
    }

    fun stop() {
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (_: Exception) {
        }
    }

    /** True when [addr] is in a directly connected (non-default) route of the Wi‑Fi. */
    private fun onLink(addr: InetAddress): Boolean {
        val lp = link ?: return false
        return lp.routes.any { !it.isDefaultRoute && it.destination.address is Inet4Address && it.matches(addr) }
    }

    /** The network to pin to right now, or null for normal routing. */
    private fun pinTarget(): Network? {
        val n = network ?: return null
        return if (target == null || onLink(target)) n else null
    }

    override fun owns(addr: InetAddress): Boolean = network != null && onLink(addr)

    override fun bind(s: Socket) {
        val n = pinTarget() ?: return
        try {
            n.bindSocket(s)
        } catch (e: IOException) {
            bindFailed(e)
        }
    }

    override fun bind(s: DatagramSocket) {
        val n = pinTarget() ?: return
        try {
            n.bindSocket(s)
        } catch (e: IOException) {
            bindFailed(e)
        }
    }

    private fun bindFailed(e: IOException) {
        // Typically a full-tunnel VPN that doesn't allow apps to bypass it.
        if (!bindFailedLogged) {
            bindFailedLogged = true
            log("Nie mogę użyć Wi‑Fi teleskopu (${e.message}). Jeśli działa VPN, ustaw w nim split tunnel " +
                "albo pozwól aplikacjom omijać VPN.")
        }
    }

    override val description: String
        get() {
            val lp = link
            if (network == null || lp == null) return "domyślna sieć systemu (brak Wi‑Fi)"
            val ip = lp.linkAddresses.map { it.address }.firstOrNull { it is Inet4Address }?.hostAddress ?: "?"
            val pinned = target == null || onLink(target)
            val inet = if (validated) "z internetem" else "bez internetu"
            return if (pinned) "Wi‑Fi ${lp.interfaceName} $ip ($inet)"
            else "domyślna sieć systemu (teleskop poza podsiecią Wi‑Fi ${lp.interfaceName} $ip)"
        }
}
