# Seestar Proxy for Android

A port of [astrophotograph/seestar-proxy](https://github.com/astrophotograph/seestar-proxy) (Rust) to a native Android app (Kotlin + Jetpack Compose).
It lets several apps use one Seestar telescope at the same time. Your phone acts as the proxy.

## What's included

| Feature | Port | Status |
|---|---|---|
| JSON-RPC multiplexer (ID remapping, response routing, event broadcast, heartbeat, reconnect) | TCP 4700 | ✅ |
| Image frame fan-out (80-byte header + payload, dropping frames for slow clients) | TCP 4800 | ✅ |
| UDP discovery bridge (`scan_iscope`, sends the phone's IP; UDP probe → TCP `get_device_state` → stub) | UDP 4720 | ✅ |
| Web dashboard (`/`, `/api/stats`, `/api/stream` SSE) | TCP 4090 | ✅ |
| Traffic recording (`control.jsonl`, `frames/*.bin`, `manifest.json`, same format as the original) | – | ✅ |
| Telescope scan on the LAN | – | ✅ (Android addition) |
| Telescope on a no-internet Wi‑Fi alongside a VPN (pinning, per-client discovery address, announcements) | – | ✅ (Android addition) |
| Embedded WireGuard endpoint (remote access, QR code, DNS `seestar.local`, discovery, ping in the tunnel) | UDP 51820 | ✅ |
| Tailscale / Lua hooks / NTP / transparent / replay | – | ❌ not ported |

The proxy runs as a foreground service with a notification and holds wake, Wi‑Fi and multicast locks, so it keeps working with the screen off.

## Usage

1. Put the phone and the Seestar on the same Wi‑Fi network, or connect the telescope to the phone's hotspot.
2. Tap the radar icon to scan the network, or type the telescope's IP → **Start proxy**.
3. On other devices, connect the Seestar app or other clients (e.g. ASIAIR-like tools, scripts) to the phone's IP shown at the top of the screen.
   With the discovery bridge on, the Seestar app finds the "telescope" at the phone's address on its own.
   For the first connection, follow the original's order: telescope **off** → proxy on → app → telescope on.
4. Dashboard: `http://<phone-IP>:4090/`.

Recordings go to `Android/data/com.seestarproxy/files/recordings/`.

## Phone on the Seestar's own Wi‑Fi + VPN (e.g. SoftEther)

Setup: the proxy phone joins the telescope's access point (`S50_xxxx`, no internet) while mobile data carries the internet and a VPN (e.g. OpenVPN to a SoftEther server). Remote users on the VPN connect to the phone's VPN address.

- **Telescope Wi‑Fi even without internet** (on by default): Android normally sends traffic over mobile data when the Wi‑Fi has no internet. The proxy keeps that Wi‑Fi up (`requestNetwork`) and pins all telescope‑bound sockets to it, but only when the telescope is inside that Wi‑Fi's subnet, so a telescope on the phone's hotspot still works. The status shows which network is used, and at startup the proxy checks whether the telescope is reachable.
- **Discovery** answers each request with the proxy address **as seen from the requester**: the Wi‑Fi address for LAN clients, the VPN address for clients coming through the VPN.
- **Announce to addresses**: routed VPNs (OpenVPN in tun mode) usually don't carry broadcasts. Enter the VPN clients' addresses or the VPN subnet's broadcast address, and the proxy will announce the telescope there every 3 s. Remote clients it has already seen get announcements automatically.

VPN setup tips:
- SoftEther has no Android client. Export an OpenVPN profile from SoftEther and use the OpenVPN app (Android 12+ dropped the built‑in L2TP).
- Use a **split tunnel**: don't route everything through the VPN (in OpenVPN for Android, untick "Use default route", or don't push a default gateway from SoftEther). With a full tunnel, Android may refuse to send traffic to the telescope Wi‑Fi unless the VPN allows apps to bypass it; the app then shows a message in the log.
- The VPN subnet must not overlap the telescope's subnet.

Tested on the emulator: with the Wi‑Fi marked "no internet" and mobile data as the default network, pinned connections leave from the Wi‑Fi address, while unpinned ones leave from the mobile data address (i.e. the wrong way). Announcements arrive every 3 s with the address seen from the client's side. A real phone + Seestar + SoftEther setup has not been tested yet.

## WireGuard (remote access)

Like the original, the WireGuard endpoint runs inside the app itself (no VpnService, so no system VPN on the proxy phone). It is a Kotlin implementation of the WireGuard protocol (Noise IKpsk2, BouncyCastle) plus a minimal TCP stack with SACK.

1. In the settings turn on **WireGuard — remote access**. For access from outside your home network, enter a public address or DDNS name in **Endpoint** and forward UDP port 51820 on your router to the phone.
2. After you start the proxy, a QR code appears. Scan it in the WireGuard app on the remote device (or share the `.conf` file).
3. Turn on the tunnel and open the Seestar app. Inside the tunnel the proxy answers **at the telescope's own IP** (and at `10.99.0.1`), so the app keeps using the address it remembers. Discovery is announced every 3 s, and `seestar.local` resolves to the telescope.

By default the tunnel carries only the telescope's traffic (`AllowedIPs = <telescope IP>/32, 10.99.0.0/24`), so the remote device keeps its internet. The **all traffic through the tunnel** option sets `0.0.0.0/0`, like the original, but then the client has no internet (DNS only).

Tested against the official `com.wireguard.android:tunnel` library (wireguard-go). A 3 MB frame arrived byte-for-byte intact at 0/1/5% packet loss (≈4 MB/s without loss, ≈190 KB/s at 1% loss with a 65 ms RTT).

## Build

```bash
gradlew.bat assembleRelease
```

APK: `app/build/outputs/apk/release/app-release.apk` (signed with the debug key, ready to sideload).
Tests: `gradlew.bat testDebugUnitTest`.

## License

The original is GPL-3.0-or-later. This port is a derivative work, so if you distribute it, you must do so under GPL-3.0 as well.
