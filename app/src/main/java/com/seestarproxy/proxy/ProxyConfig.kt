package com.seestarproxy.proxy

import android.content.Context

data class ProxyConfig(
    val upstreamHost: String = "",
    val controlPort: Int = Protocol.CONTROL_PORT,
    val imagingPort: Int = Protocol.IMAGING_PORT,
    val upstreamControlPort: Int = Protocol.CONTROL_PORT,
    val upstreamImagingPort: Int = Protocol.IMAGING_PORT,
    val discovery: Boolean = true,
    val telescopeSn: String = "",
    val telescopeModel: String = "",
    val telescopeBssid: String = "",
    val dashboardPort: Int = Protocol.DASHBOARD_PORT,
    val record: Boolean = false,
    val wireguard: Boolean = false,
    val wgPort: Int = 51820,
    /** host[:port] clients use to reach this phone; empty = auto-detect the local IP. */
    val wgEndpoint: String = "",
    /** AllowedIPs = 0.0.0.0/0 (captures broadcasts, but the client loses internet). */
    val wgFullTunnel: Boolean = false,
) {
    fun save(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("upstreamHost", upstreamHost)
            .putInt("controlPort", controlPort)
            .putInt("imagingPort", imagingPort)
            .putInt("upstreamControlPort", upstreamControlPort)
            .putInt("upstreamImagingPort", upstreamImagingPort)
            .putBoolean("discovery", discovery)
            .putString("telescopeSn", telescopeSn)
            .putString("telescopeModel", telescopeModel)
            .putString("telescopeBssid", telescopeBssid)
            .putInt("dashboardPort", dashboardPort)
            .putBoolean("record", record)
            .putBoolean("wireguard", wireguard)
            .putInt("wgPort", wgPort)
            .putString("wgEndpoint", wgEndpoint)
            .putBoolean("wgFullTunnel", wgFullTunnel)
            .apply()
    }

    companion object {
        private const val PREFS = "proxy_config"

        fun load(ctx: Context): ProxyConfig {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val d = ProxyConfig()
            return ProxyConfig(
                upstreamHost = p.getString("upstreamHost", d.upstreamHost)!!,
                controlPort = p.getInt("controlPort", d.controlPort),
                imagingPort = p.getInt("imagingPort", d.imagingPort),
                upstreamControlPort = p.getInt("upstreamControlPort", d.upstreamControlPort),
                upstreamImagingPort = p.getInt("upstreamImagingPort", d.upstreamImagingPort),
                discovery = p.getBoolean("discovery", d.discovery),
                telescopeSn = p.getString("telescopeSn", d.telescopeSn)!!,
                telescopeModel = p.getString("telescopeModel", d.telescopeModel)!!,
                telescopeBssid = p.getString("telescopeBssid", d.telescopeBssid)!!,
                dashboardPort = p.getInt("dashboardPort", d.dashboardPort),
                record = p.getBoolean("record", d.record),
                wireguard = p.getBoolean("wireguard", d.wireguard),
                wgPort = p.getInt("wgPort", d.wgPort),
                wgEndpoint = p.getString("wgEndpoint", d.wgEndpoint)!!,
                wgFullTunnel = p.getBoolean("wgFullTunnel", d.wgFullTunnel),
            )
        }
    }
}
