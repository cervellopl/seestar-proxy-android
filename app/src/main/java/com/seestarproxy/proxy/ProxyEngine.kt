package com.seestarproxy.proxy

import android.content.Context
import com.seestarproxy.wg.WireGuardServer
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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

    /** Resolved telescope address, available after [start]. */
    @Volatile var upstreamIp: InetAddress? = null
        private set

    fun start() {
        val host = config.upstreamHost.trim()
        require(host.isNotEmpty()) { "Podaj adres IP teleskopu" }
        val ip = InetAddress.getByName(host)
        upstreamIp = ip
        metrics.info("Teleskop: $host → ${ip.hostAddress}")

        if (config.record) {
            val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val base = ctx.getExternalFilesDir("recordings") ?: File(ctx.filesDir, "recordings")
            recorder = Recorder(File(base, "session_$stamp")).also {
                metrics.info("Nagrywanie do ${it.dir.absolutePath}")
            }
        }

        try {
            control = ControlProxy(config.controlPort, InetSocketAddress(ip, config.upstreamControlPort), metrics, recorder)
                .also { it.start() }
            imaging = ImagingProxy(config.imagingPort, InetSocketAddress(ip, config.upstreamImagingPort), metrics, recorder)
                .also { it.start() }
            if (config.discovery) {
                discovery = DiscoveryBridge(
                    ip,
                    config.telescopeSn.trim().ifEmpty { null },
                    config.telescopeModel.trim().ifEmpty { null },
                    config.telescopeBssid.trim().ifEmpty { null },
                    metrics,
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
                ).also { it.start() }
            }
            if (config.dashboardPort > 0) {
                val html = ctx.assets.open("dashboard.html").bufferedReader().use { it.readText() }
                dashboard = DashboardServer(
                    config.dashboardPort, html, metrics,
                    extra = {
                        put("upstream", ip.hostAddress)
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
    }

    companion object {
        fun wgKeyDir(ctx: Context) = File(ctx.filesDir, "wireguard")
    }
}
