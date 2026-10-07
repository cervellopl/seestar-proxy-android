package com.seestarproxy.proxy

import android.content.Context
import com.seestarproxy.TelescopeNetwork
import com.seestarproxy.wg.WireGuardServer
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/** Wires together all proxy components for one run. Call [start] off the main thread. */
class ProxyEngine(private val ctx: Context, val config: ProxyConfig) {
    val metrics = Metrics()
    var recorder: Recorder? = null
        private set

    private var control: ControlProxy? = null
    private var imaging: ImagingProxy? = null
    private var discovery: DiscoveryBridge? = null
    private var dashboard: DashboardServer? = null

    /** Running WireGuard endpoint, if enabled. */
    var wireguard: WireGuardServer? = null
        private set

    private var telescopeNetwork: TelescopeNetwork? = null

    /** Routing for telescope-bound traffic (pinned Wi‑Fi or system default). */
    var net: NetBinder = NetBinder.DEFAULT
        private set

    /** Resolved telescope address, available after [start]. */
    @Volatile var upstreamIp: InetAddress? = null
        private set

    fun start() {
        val host = config.upstreamHost.trim()
        require(host.isNotEmpty()) { "Podaj adres IP teleskopu" }
        val ip = InetAddress.getByName(host)
        upstreamIp = ip
        metrics.info("Teleskop: $host → ${ip.hostAddress}")

        if (config.pinTelescopeWifi) {
            telescopeNetwork = TelescopeNetwork(ctx, ip, metrics::info).also {
                it.start()
                it.awaitReady(1_500)
                net = it
            }
        }
        metrics.info("Ruch do teleskopu przez: ${net.description}")
        checkReachable(ip)

        if (config.record) {
            val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val base = ctx.getExternalFilesDir("recordings") ?: File(ctx.filesDir, "recordings")
            recorder = Recorder(File(base, "session_$stamp")).also {
                metrics.info("Nagrywanie do ${it.dir.absolutePath}")
            }
        }

        try {
            val noteClient: (InetAddress) -> Unit = { discovery?.noteClient(it) }
            control = ControlProxy(
                config.controlPort, InetSocketAddress(ip, config.upstreamControlPort), metrics, recorder, net, noteClient,
            ).also { it.start() }
            imaging = ImagingProxy(
                config.imagingPort, InetSocketAddress(ip, config.upstreamImagingPort), metrics, recorder, net, noteClient,
            ).also { it.start() }
            if (config.discovery) {
                discovery = DiscoveryBridge(
                    ip,
                    config.telescopeSn.trim().ifEmpty { null },
                    config.telescopeModel.trim().ifEmpty { null },
                    config.telescopeBssid.trim().ifEmpty { null },
                    metrics,
                    net,
                    parseAnnounceTargets(config.announceTargets) { metrics.error("Pominięto niepoprawny adres ogłoszeń: $it") },
                ).also { it.start() }
            }
            if (config.wireguard) {
                // Inside the tunnel clients use the telescope's standard ports.
                val ports = buildMap {
                    put(Protocol.CONTROL_PORT, config.controlPort)
                    put(Protocol.IMAGING_PORT, config.imagingPort)
                    if (config.dashboardPort > 0) put(Protocol.DASHBOARD_PORT, config.dashboardPort)
                }
                wireguard = WireGuardServer(
                    keyDir = wgKeyDir(ctx),
                    port = config.wgPort,
                    endpointOverride = config.wgEndpoint,
                    fullTunnel = config.wgFullTunnel,
                    upstreamIp = ip,
                    telescopeSn = config.telescopeSn.trim().ifEmpty { null },
                    telescopeModel = config.telescopeModel.trim().ifEmpty { null },
                    portMap = ports,
                    metrics = metrics,
                    net = net,
                ).also { it.start() }
            }
            if (config.dashboardPort > 0) {
                val html = ctx.assets.open("dashboard.html").bufferedReader().use { it.readText() }
                dashboard = DashboardServer(
                    config.dashboardPort, html, metrics,
                    extra = {
                        put("upstream", ip.hostAddress)
                        put("telescope_network", net.description)
                        put("recording", recorder?.dir?.absolutePath ?: JSONObject.NULL)
                        put("wireguard", wireguard?.statusJson() ?: JSONObject.NULL)
                    },
                    routes = mapOf(
                        "/api/wireguard" to {
                            val wg = wireguard
                            "application/json" to (if (wg == null) JSONObject().put("enabled", false) else JSONObject()
                                .put("enabled", true)
                                .put("endpoint", wg.info.endpoint)
                                .put("public_key", wg.info.serverPublicKey)
                                .put("config", wg.info.clientConfig)
                                .put("qr_svg", WireGuardServer.qrSvg(wg.info.clientConfig))).toString()
                        },
                    ),
                ).also { it.start() }
            }
        } catch (e: Exception) {
            stop()
            throw e
        }
    }

    fun stop() {
        discovery?.stop()
        dashboard?.stop()
        wireguard?.stop()
        control?.stop()
        imaging?.stop()
        recorder?.let { metrics.info(it.finalize()) }
        recorder = null
        telescopeNetwork?.stop()
        telescopeNetwork = null
    }

    /** One quick TCP probe so a wrong network shows up in the log right away. */
    private fun checkReachable(ip: InetAddress) {
        thread(name = "reach-check", isDaemon = true) {
            try {
                connectVia(net, InetSocketAddress(ip, config.upstreamControlPort), 3_000).close()
                metrics.info("Teleskop ${ip.hostAddress} osiągalny")
            } catch (e: Exception) {
                metrics.error(
                    "Teleskop ${ip.hostAddress} nieosiągalny przez ${net.description} (${e.message}). " +
                        "Jeśli jest wyłączony, proxy połączy się, gdy się pojawi.",
                )
            }
        }
    }

    companion object {
        fun wgKeyDir(ctx: Context) = File(ctx.filesDir, "wireguard")
    }
}
