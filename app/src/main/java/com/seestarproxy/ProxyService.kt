package com.seestarproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.seestarproxy.proxy.ProxyConfig
import com.seestarproxy.proxy.ProxyEngine
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.concurrent.thread

sealed interface ProxyState {
    data object Stopped : ProxyState
    data object Starting : ProxyState
    data class Running(val engine: ProxyEngine) : ProxyState
    data class Failed(val message: String) : ProxyState
}

/**
 * Foreground service hosting the proxy so it keeps running with the screen off.
 * Holds a partial wake lock, a Wi‑Fi lock and a multicast lock (needed to
 * receive UDP broadcast discovery probes on most devices).
 */
class ProxyService : Service() {

    private var engine: ProxyEngine? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        if (engine != null) return START_STICKY

        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification("Uruchamianie…"),
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0,
        )
        acquireLocks()

        val config = ProxyConfig.load(this)
        val eng = ProxyEngine(applicationContext, config)
        engine = eng
        _state.value = ProxyState.Starting
        thread(name = "proxy-start") {
            try {
                eng.start()
                _state.value = ProxyState.Running(eng)
                updateNotification("Teleskop ${config.upstreamHost} • porty ${config.controlPort}/${config.imagingPort}")
            } catch (e: Exception) {
                _state.value = ProxyState.Failed(e.message ?: e.javaClass.simpleName)
                engine = null
                releaseLocks()
                stopSelf()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun shutdown() {
        val eng = engine ?: return
        engine = null
        thread(name = "proxy-stop") { eng.stop() }
        releaseLocks()
        if (_state.value !is ProxyState.Failed) _state.value = ProxyState.Stopped
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    @Suppress("DEPRECATION")
    private fun acquireLocks() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SeestarProxy:proxy").apply {
            setReferenceCounted(false); acquire()
        }
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "SeestarProxy:wifi").apply {
            setReferenceCounted(false); acquire()
        }
        multicastLock = wm.createMulticastLock("SeestarProxy:discovery").apply {
            setReferenceCounted(false); acquire()
        }
    }

    private fun releaseLocks() {
        wakeLock?.takeIf { it.isHeld }?.release()
        wifiLock?.takeIf { it.isHeld }?.release()
        multicastLock?.takeIf { it.isHeld }?.release()
        wakeLock = null; wifiLock = null; multicastLock = null
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Proxy teleskopu", NotificationManager.IMPORTANCE_LOW)
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ProxyService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Seestar Proxy działa")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Zatrzymaj", stop)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))
    }

    companion object {
        const val ACTION_STOP = "com.seestarproxy.STOP"
        private const val CHANNEL_ID = "proxy"
        private const val NOTIFICATION_ID = 1

        private val _state = MutableStateFlow<ProxyState>(ProxyState.Stopped)
        val state: StateFlow<ProxyState> = _state

        fun start(ctx: Context) {
            _state.value = ProxyState.Starting
            ctx.startForegroundService(Intent(ctx, ProxyService::class.java))
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, ProxyService::class.java).setAction(ACTION_STOP))
        }
    }
}
