package com.seestarproxy.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import com.seestarproxy.TelescopeNetwork
import com.seestarproxy.proxy.NetBinder
import com.seestarproxy.proxy.ProxyEngine
import com.seestarproxy.wg.WgInfo
import com.seestarproxy.wg.WireGuardServer
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.seestarproxy.ProxyService
import com.seestarproxy.ProxyState
import com.seestarproxy.proxy.FoundTelescope
import com.seestarproxy.proxy.LogEntry
import com.seestarproxy.proxy.ProxyConfig
import com.seestarproxy.proxy.TelescopeScanner
import com.seestarproxy.proxy.TelescopeStatus
import com.seestarproxy.proxy.localIpv4Addresses
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Snapshot of the engine's metrics, refreshed once per second for the UI. */
private data class Snapshot(
    val controlUp: Boolean = false,
    val imagingUp: Boolean = false,
    val controlClients: Int = 0,
    val imagingClients: Int = 0,
    val controlTx: Long = 0,
    val controlRx: Long = 0,
    val events: Long = 0,
    val frames: Long = 0,
    val bytes: Long = 0,
    val telescope: TelescopeStatus = TelescopeStatus(),
    val log: List<LogEntry> = emptyList(),
    val recordingDir: String? = null,
    val wg: WgSnapshot? = null,
    val telescopeNetwork: String? = null,
)

private data class WgSnapshot(
    val session: Boolean,
    val peer: String?,
    val lastHandshakeMs: Long,
    val rx: Long,
    val tx: Long,
    val tunnelConnections: Int,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProxyScreen(onOpenUrl: (String) -> Unit, onShare: (String) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by ProxyService.state.collectAsStateWithLifecycle()
    var config by remember { mutableStateOf(ProxyConfig.load(ctx)) }
    var snapshot by remember { mutableStateOf(Snapshot()) }
    var localIps by remember { mutableStateOf(localIpv4Addresses()) }
    var scanning by remember { mutableStateOf(false) }
    var scanResults by remember { mutableStateOf<List<FoundTelescope>?>(null) }
    var scanError by remember { mutableStateOf<String?>(null) }
    var confirmResetKeys by remember { mutableStateOf(false) }

    val running = state is ProxyState.Running
    val busy = state is ProxyState.Starting || running

    LaunchedEffect(state) {
        while (true) {
            localIps = withContext(Dispatchers.IO) { localIpv4Addresses() }
            val eng = (state as? ProxyState.Running)?.engine
            if (eng != null) {
                val m = eng.metrics
                snapshot = Snapshot(
                    controlUp = m.upstreamControlUp,
                    imagingUp = m.upstreamImagingUp,
                    controlClients = m.controlClients.get(),
                    imagingClients = m.imagingClients.get(),
                    controlTx = m.controlTx.get(),
                    controlRx = m.controlRx.get(),
                    events = m.controlEvents.get(),
                    frames = m.imagingFrames.get(),
                    bytes = m.imagingBytes.get(),
                    telescope = m.telescopeStatus(),
                    log = m.logSince(null).takeLast(80).reversed(),
                    recordingDir = eng.recorder?.dir?.absolutePath,
                    telescopeNetwork = eng.net.description,
                    wg = eng.wireguard?.let { w ->
                        WgSnapshot(
                            session = w.peer.hasSession,
                            peer = w.peerEndpoint?.toString()?.trimStart('/'),
                            lastHandshakeMs = w.peer.lastHandshakeMs,
                            rx = w.peer.rxBytes.get(),
                            tx = w.peer.txBytes.get(),
                            tunnelConnections = w.tunnelConnections,
                        )
                    },
                )
            }
            delay(1_000)
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Seestar Proxy") }) },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusCard(state, snapshot, localIps, config, onOpenUrl)
            val wgServer = (state as? ProxyState.Running)?.engine?.wireguard
            if (wgServer != null) WireGuardCard(wgServer.info, snapshot.wg, onShare)

            ConfigCard(
                config = config,
                enabled = !busy,
                scanning = scanning,
                onChange = { config = it },
                onScan = {
                    scanning = true
                    scope.launch {
                        try {
                            scanResults = withContext(Dispatchers.IO) {
                                // Scan over the Wi‑Fi even when it has no internet (telescope's own AP).
                                val net = if (config.pinTelescopeWifi) {
                                    TelescopeNetwork(ctx, null).also { it.start(); it.awaitReady(1_500) }
                                } else null
                                try {
                                    TelescopeScanner.scan(net = net ?: NetBinder.DEFAULT)
                                } finally {
                                    net?.stop()
                                }
                            }
                        } catch (e: Exception) {
                            scanError = e.message ?: e.javaClass.simpleName
                        } finally {
                            scanning = false
                        }
                    }
                },
                onResetKeys = { confirmResetKeys = true },
            )

            if (busy) {
                Button(
                    onClick = { ProxyService.stop(ctx) },
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                ) {
                    Icon(Icons.Default.Stop, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Zatrzymaj proxy")
                }
            } else {
                Button(
                    onClick = {
                        config.save(ctx)
                        ProxyService.start(ctx)
                    },
                    enabled = config.upstreamHost.isNotBlank(),
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                ) {
                    Icon(Icons.Default.PlayArrow, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Uruchom proxy")
                }
            }

            if (running) LogCard(snapshot.log)
            Spacer(Modifier.height(24.dp))
        }
    }

    scanResults?.let { results ->
        AlertDialog(
            onDismissRequest = { scanResults = null },
            title = { Text("Znalezione teleskopy") },
            text = {
                if (results.isEmpty()) {
                    Text("Nie znaleziono teleskopu. Upewnij się, że telefon i Seestar są w tej samej sieci Wi‑Fi.")
                } else {
                    Column {
                        results.forEach { t ->
                            Column(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        config = config.copy(upstreamHost = t.ip, telescopeSn = t.sn)
                                        scanResults = null
                                    }
                                    .padding(vertical = 10.dp),
                            ) {
                                Text("${t.model} — ${t.ip}", fontWeight = FontWeight.SemiBold)
                                Text("SN ${t.sn}  •  ${t.ssid}", style = MaterialTheme.typography.bodySmall)
                            }
                            HorizontalDivider()
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { scanResults = null }) { Text("Zamknij") } },
        )
    }
    if (confirmResetKeys) {
        AlertDialog(
            onDismissRequest = { confirmResetKeys = false },
            title = { Text("Nowe klucze WireGuard?") },
            text = { Text("Obecna konfiguracja w aplikacji WireGuard przestanie działać — trzeba będzie ponownie zeskanować kod QR.") },
            confirmButton = {
                TextButton(onClick = {
                    WireGuardServer.resetKeys(ProxyEngine.wgKeyDir(ctx))
                    confirmResetKeys = false
                }) { Text("Wygeneruj") }
            },
            dismissButton = { TextButton(onClick = { confirmResetKeys = false }) { Text("Anuluj") } },
        )
    }
    scanError?.let {
        AlertDialog(
            onDismissRequest = { scanError = null },
            title = { Text("Skanowanie nieudane") },
            text = { Text(it) },
            confirmButton = { TextButton(onClick = { scanError = null }) { Text("OK") } },
        )
    }
}

@Composable
private fun StatusCard(
    state: ProxyState,
    s: Snapshot,
    localIps: List<Pair<String, String>>,
    config: ProxyConfig,
    onOpenUrl: (String) -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            val (label, color) = when (state) {
                is ProxyState.Running -> "Działa" to Color(0xFF2E7D32)
                ProxyState.Starting -> "Uruchamianie…" to Color(0xFFF9A825)
                is ProxyState.Failed -> "Błąd: ${state.message}" to MaterialTheme.colorScheme.error
                ProxyState.Stopped -> "Zatrzymany" to Color.Gray
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Dot(color)
                Spacer(Modifier.width(8.dp))
                Text(label, style = MaterialTheme.typography.titleMedium)
            }

            Text("Adresy tego telefonu (podaj je w aplikacji Seestar / innych klientach):",
                style = MaterialTheme.typography.bodySmall)
            if (localIps.isEmpty()) Text("brak sieci", color = MaterialTheme.colorScheme.error)
            localIps.forEach { (iface, ip) ->
                Text("$ip  ($iface)", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold)
            }

            if (state is ProxyState.Running) {
                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                Row {
                    StatusItem("Sterowanie", s.controlUp, "${s.controlClients} klient.", Modifier.weight(1f))
                    StatusItem("Obraz", s.imagingUp, "${s.imagingClients} klient.", Modifier.weight(1f))
                }
                Text(
                    "Wysłane ${s.controlTx} • odp. ${s.controlRx} • zdarzenia ${s.events}\n" +
                        "Klatki ${s.frames} • ${"%.1f".format(s.bytes / 1_048_576.0)} MB",
                    style = MaterialTheme.typography.bodySmall,
                )
                val t = s.telescope
                val parts = buildList {
                    t.battery?.let { add("Bateria $it%") }
                    t.temperature?.let { add("Temp. ${"%.1f".format(it)}°C") }
                    t.chargerStatus?.let { add(it) }
                    if (t.isStacking) add("Stackowanie (${t.stackCount})")
                    if (t.tracking) add("Śledzenie")
                    t.viewMode?.let { add("Tryb: $it") }
                }
                if (parts.isNotEmpty()) Text(parts.joinToString(" • "), style = MaterialTheme.typography.bodyMedium)
                s.telescopeNetwork?.let { Text("Ruch do teleskopu: $it", style = MaterialTheme.typography.bodySmall) }
                s.recordingDir?.let { Text("Nagrywanie: $it", style = MaterialTheme.typography.bodySmall) }
                if (config.dashboardPort > 0) {
                    OutlinedButton(onClick = { onOpenUrl("http://127.0.0.1:${config.dashboardPort}/") }) {
                        Text("Otwórz dashboard WWW")
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusItem(name: String, up: Boolean, sub: String, modifier: Modifier) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Dot(if (up) Color(0xFF2E7D32) else Color(0xFFC62828))
        Spacer(Modifier.width(6.dp))
        Column {
            Text(name, fontWeight = FontWeight.SemiBold)
            Text((if (up) "teleskop OK" else "brak połączenia") + " • " + sub,
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun Dot(color: Color) {
    Box(Modifier.size(12.dp).background(color, CircleShape))
}

@Composable
private fun ConfigCard(
    config: ProxyConfig,
    enabled: Boolean,
    scanning: Boolean,
    onChange: (ProxyConfig) -> Unit,
    onScan: () -> Unit,
    onResetKeys: () -> Unit,
) {
    var advanced by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Konfiguracja", style = MaterialTheme.typography.titleMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = config.upstreamHost,
                    onValueChange = { onChange(config.copy(upstreamHost = it.trim())) },
                    label = { Text("Adres IP teleskopu") },
                    placeholder = { Text("np. 192.168.1.123") },
                    singleLine = true,
                    enabled = enabled,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                if (scanning) {
                    CircularProgressIndicator(Modifier.size(32.dp))
                } else {
                    IconButton(onClick = onScan, enabled = enabled) {
                        Icon(Icons.Default.Radar, "Skanuj sieć")
                    }
                }
            }
            SwitchRow("Wi‑Fi teleskopu także bez internetu", config.pinTelescopeWifi, enabled) {
                onChange(config.copy(pinTelescopeWifi = it))
            }
            Text(
                "Ruch do teleskopu idzie przez Wi‑Fi, w którego podsieci jest teleskop (np. jego własny hotspot S50_…), " +
                    "nawet gdy internet i VPN działają przez dane komórkowe.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SwitchRow("Mostek discovery (UDP 4720)", config.discovery, enabled) {
                onChange(config.copy(discovery = it))
            }
            if (config.discovery) {
                OutlinedTextField(
                    value = config.announceTargets,
                    onValueChange = { onChange(config.copy(announceTargets = it)) },
                    label = { Text("Ogłaszaj teleskop do adresów (opcjonalnie)") },
                    placeholder = { Text("np. 192.168.30.255, 192.168.30.12") },
                    supportingText = {
                        Text("Dla sieci, w których broadcast nie dociera (VPN, np. SoftEther/OpenVPN): adresy klientów " +
                            "lub adres rozgłoszeniowy podsieci VPN. Co 3 s.")
                    },
                    enabled = enabled, modifier = Modifier.fillMaxWidth(),
                )
            }
            SwitchRow("Nagrywaj ruch (sesja do odtwarzania)", config.record, enabled) {
                onChange(config.copy(record = it))
            }
            SwitchRow("WireGuard — zdalny dostęp", config.wireguard, enabled) {
                onChange(config.copy(wireguard = it))
            }
            if (config.wireguard) {
                OutlinedTextField(
                    value = config.wgEndpoint,
                    onValueChange = { onChange(config.copy(wgEndpoint = it.trim())) },
                    label = { Text("Endpoint (publiczny adres/DDNS[:port])") },
                    placeholder = { Text("puste = lokalny IP telefonu") },
                    supportingText = {
                        Text("Spoza sieci lokalnej potrzebny jest publiczny adres i przekierowanie portu UDP ${config.wgPort} na telefon.")
                    },
                    singleLine = true, enabled = enabled, modifier = Modifier.fillMaxWidth(),
                )
                SwitchRow("Cały ruch przez tunel (0.0.0.0/0, bez internetu u klienta)", config.wgFullTunnel, enabled) {
                    onChange(config.copy(wgFullTunnel = it))
                }
                if (enabled) {
                    TextButton(onClick = onResetKeys) { Text("Wygeneruj nowe klucze WireGuard") }
                }
            }

            Row(
                Modifier.fillMaxWidth().clickable { advanced = !advanced },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Zaawansowane", Modifier.weight(1f), style = MaterialTheme.typography.labelLarge)
                Icon(if (advanced) Icons.Default.ExpandLess else Icons.Default.ExpandMore, null)
            }
            if (advanced) {
                OutlinedTextField(
                    value = config.telescopeSn,
                    onValueChange = { onChange(config.copy(telescopeSn = it.trim())) },
                    label = { Text("Numer seryjny (sufiks SSID S50_xxxx)") },
                    singleLine = true, enabled = enabled, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = config.telescopeModel,
                    onValueChange = { onChange(config.copy(telescopeModel = it)) },
                    label = { Text("Model (domyślnie Seestar S50)") },
                    singleLine = true, enabled = enabled, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = config.telescopeBssid,
                    onValueChange = { onChange(config.copy(telescopeBssid = it.trim())) },
                    label = { Text("BSSID punktu dostępowego teleskopu") },
                    singleLine = true, enabled = enabled, modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PortField("Port sterowania", config.controlPort, enabled, Modifier.weight(1f)) {
                        onChange(config.copy(controlPort = it))
                    }
                    PortField("Port obrazu", config.imagingPort, enabled, Modifier.weight(1f)) {
                        onChange(config.copy(imagingPort = it))
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PortField("Sterowanie teleskopu", config.upstreamControlPort, enabled, Modifier.weight(1f)) {
                        onChange(config.copy(upstreamControlPort = it))
                    }
                    PortField("Obraz teleskopu", config.upstreamImagingPort, enabled, Modifier.weight(1f)) {
                        onChange(config.copy(upstreamImagingPort = it))
                    }
                }
                PortField("Port dashboardu (0 = wyłączony)", config.dashboardPort, enabled, Modifier.fillMaxWidth()) {
                    onChange(config.copy(dashboardPort = it))
                }
                PortField("Port WireGuard (UDP)", config.wgPort, enabled, Modifier.fillMaxWidth()) {
                    onChange(config.copy(wgPort = it))
                }
            }
        }
    }
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}

@Composable
private fun PortField(label: String, value: Int, enabled: Boolean, modifier: Modifier, onChange: (Int) -> Unit) {
    var text by remember(value) { mutableStateOf(value.toString()) }
    OutlinedTextField(
        value = text,
        onValueChange = { v ->
            text = v.filter { it.isDigit() }.take(5)
            text.toIntOrNull()?.takeIf { it in 0..65535 }?.let(onChange)
        },
        label = { Text(label, maxLines = 1) },
        singleLine = true,
        enabled = enabled,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = modifier,
    )
}

@Composable
private fun LogCard(log: List<LogEntry>) {
    val fmt = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("Ruch i zdarzenia", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            log.forEach { e ->
                val color = when (e.channel) {
                    "err" -> MaterialTheme.colorScheme.error
                    "ctrl-tx", "img-tx" -> Color(0xFF1E88E5)
                    "ctrl-rx" -> Color(0xFF43A047)
                    "ctrl-evt" -> Color(0xFFFB8C00)
                    "img" -> Color(0xFF8E24AA)
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                }
                Text(
                    "${fmt.format(Date(e.timestampMs))} ${e.channel.padEnd(8)} ${e.summary}",
                    color = color,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    maxLines = 2,
                )
            }
        }
    }
}

@Composable
private fun WireGuardCard(info: WgInfo, s: WgSnapshot?, onShare: (String) -> Unit) {
    val qr = remember(info.clientConfig) {
        val m = WireGuardServer.qrMatrix(info.clientConfig)
        val bmp = Bitmap.createBitmap(m.width, m.height, Bitmap.Config.RGB_565)
        for (y in 0 until m.height) for (x in 0 until m.width) {
            bmp.setPixel(x, y, if (m[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
        }
        bmp.asImageBitmap()
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Dot(if (s?.session == true) Color(0xFF2E7D32) else Color.Gray)
                Spacer(Modifier.width(8.dp))
                Text("WireGuard", style = MaterialTheme.typography.titleMedium)
            }
            Text("Endpoint: ${info.endpoint}", fontFamily = FontFamily.Monospace)
            if (s != null) {
                val hs = if (s.lastHandshakeMs == 0L) "nigdy"
                else "${(System.currentTimeMillis() - s.lastHandshakeMs) / 1000} s temu"
                Text(
                    "Klient: ${s.peer ?: "brak"} • handshake: $hs\n" +
                        "Odebrano ${"%.1f".format(s.rx / 1_048_576.0)} MB • wysłano ${"%.1f".format(s.tx / 1_048_576.0)} MB • " +
                        "połączenia w tunelu: ${s.tunnelConnections}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text(
                "Zeskanuj kod w aplikacji WireGuard (+ → Skanuj kod QR), włącz tunel i otwórz aplikację Seestar.",
                style = MaterialTheme.typography.bodySmall,
            )
            Image(
                bitmap = qr,
                contentDescription = "Kod QR konfiguracji WireGuard",
                filterQuality = FilterQuality.None,
                modifier = Modifier.fillMaxWidth().aspectRatio(1f),
            )
            OutlinedButton(onClick = { onShare(info.clientConfig) }) { Text("Udostępnij plik konfiguracji") }
        }
    }
}
