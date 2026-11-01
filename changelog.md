# 🛡️ GKI-Tether-Shield Changelog

## Version 3.8
* **WebUI Button Fixed**: The KernelSU / APatch / MMRL WebUI button now shows live stats and saves settings (it previously could not reach the service).
* **Companion App Rebuilt**: Built from source; it now verifies it is talking to the real service before showing anything, pauses when in the background, opens links in your browser, and only uses plain HTTP for the local dashboard. Updates reinstall it automatically if needed.
* **Command Line**: `ttlshield config get` and `ttlshield config set '<json>'` read and change settings from a root shell.

## Version 3.7
* **Every Chipset**: TTL fixing no longer depends on Qualcomm `rmnet` interface names; MediaTek, Exynos, Tensor, Unisoc and 464XLAT (CLAT) connections are covered too.
* **Settings Kept on Update**: Your configuration now survives module updates. (Updating from 3.5 to 3.6 reset it once; please re-apply your settings if needed.)
* **Self-Healing Daemon**: A watchdog restarts the daemon if it stops, and errors are logged to `daemon.log` (`ttlshield log`).
* **Live Settings**: `TARGET_TTL` and `QUEUE_NUM` are now applied to the firewall rules, and edits to `config.conf` take effect within seconds without a reboot.
* **Security**: Only the companion app (or root / ADB) can change settings; the update banner only accepts this project's release links; the DNS proxy accepts hotspot clients only, on any chipset.
* **IPv6 DNS**: Tethered clients' IPv6 DNS queries are now encrypted through the DoH proxy as well.
* **Smarter DNS Cache**: Honors record lifetimes, never caches failures, and merges identical lookups.
* **Battery**: No more stats file written every 3 seconds; the dashboard stops polling when hidden. `ttlshield status` now shows live numbers.
* **Fixed**: Thread-safety of settings shared between the packet workers and the dashboard.

## Version 3.6
* **Security**: DNS-over-HTTPS now verifies TLS certificates; the WebUI config API rejects cross-site requests, DNS rebinding and config injection; the DNS proxy is no longer reachable from the cellular network; stats moved out of the shell-writable `/data/local/tmp`.
* **Stability**: Malformed packets from hotspot clients can no longer crash the daemon.
* **IPv6 Hop Limit Fix**: Tethered IPv6 traffic is now normalized to hop limit 64.
* **Faster Packet Processing**: Four parallel NFQUEUE workers, fail-open queues, and only the first packets of each web connection go through DPI splitting.
* **Working Toggles**: Bufferbloat QoS, Wi-Fi power-save lock and TCP low-latency settings now take effect within seconds; the QoS loop no longer resets interface queues every 5 seconds.
* **DNS with DoH Off**: Turning DoH off now falls back to plain DNS instead of breaking name resolution for tethered clients.
* **Renamed Daemon**: The daemon binary is now `tether_shield`; old `nfqttl` processes and rules are cleaned up automatically on update.

## Version 3.5
* **HyperOS / MIUI Action Button Launch**: Automatically grants background activity pop-up permissions (`OP_BACKGROUND_START_ACTIVITY` via `cmd appops`) so the native manager opens reliably on Xiaomi and Redmi devices.
* **Dual Asset Release Support**: Packages both `GKI_Tether_Shield_v*.zip` and `GKI_Hotspot_Shield_v*.zip` for backward and forward compatibility.
* **Dynamic Module Path Detection**: Daemon and CLI scripts seamlessly adapt whether the module is installed under `/data/adb/modules/gki_hotspot_shield` or legacy `/data/adb/modules/nfqttl`.
* **Isolated NFQUEUE Web Ports**: BitTorrent and high-throughput P2P packets stay 100% in-kernel, preventing TCP split data corruption.
* **Transparent DoH DNS Fallback**: Automatic UDP fallback to prevent connectivity drops if upstream encrypted DNS times out.
* **Auto-Update Support**: Added native `updateJson` specification for automatic update notifications and 1-click upgrades in Magisk, KernelSU, APatch, and MMRL.

## Version 3.4
* **Selective In-Kernel Port Matching**: Routed ports 80/443 to NFQUEUE for GoodbyeDPI SNI splitting while keeping non-web traffic in-kernel.

## Version 3.3
* **Native Zero-Icon Companion Manager**: Introduced lightweight Android manager APK launched exclusively via the Magisk Action button without cluttering the app drawer.

## Version 3.2
* **BitTorrent Stability Fix**: Fixed port 53545 tracker loop and selective TTL filtering.

## Version 3.1
* **Encrypted DNS-over-HTTPS**: Implemented in-memory caching DoH proxy supporting Cloudflare, Quad9, Google, and AdGuard.

## Version 3.0
* **Initial GKI Architecture**: Pure Go daemon leveraging Netfilter Queue for real-time TTL=64 normalization and anti-bufferbloat QoS on Android 12+.
