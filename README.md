# 🛡️ GKI-Tether-Shield

<p align="center">
  <a href="https://github.com/maozdemir/GKI-Tether-Shield/releases/latest"><img src="https://img.shields.io/github/v/release/maozdemir/GKI-Tether-Shield?style=for-the-badge&color=blue&logo=github" alt="Latest Release" /></a>
  <a href="https://github.com/maozdemir/GKI-Tether-Shield/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/maozdemir/GKI-Tether-Shield/build.yml?branch=main&style=for-the-badge&logo=githubactions" alt="Build Status" /></a>
  <a href="https://github.com/maozdemir/GKI-Tether-Shield/releases"><img src="https://img.shields.io/github/downloads/maozdemir/GKI-Tether-Shield/total?style=for-the-badge&color=blueviolet&logo=github" alt="Total Downloads" /></a>
  <img src="https://img.shields.io/badge/Platform-Android%20GKI%20(12%2B)-2ea44f?style=for-the-badge&logo=android" alt="Platform" />
  <img src="https://img.shields.io/badge/Root-Magisk%20%7C%20KernelSU%20%7C%20APatch-orange?style=for-the-badge&logo=magisk" alt="Root Compatibility" />
  <a href="LICENSE"><img src="https://img.shields.io/github/license/maozdemir/GKI-Tether-Shield?style=for-the-badge" alt="License" /></a>
</p>

<p align="center">
  <b>The definitive all-in-one network engine, tethering bypass suite, and root module for modern Android devices running Generic Kernel Image (GKI) kernels.</b><br>
  <i>Tested and verified on Android 12, 13, 14, 15, and 16 (Snapdragon 8 Gen 2 / Gen 3 / Gen 4 / 8s, MediaTek Dimensity, Google Tensor, and Samsung Exynos).</i>
</p>

---

## 📑 Table of Contents

- [⚡ The Problem: Why Old Modules Broke](#-the-problem-why-old-modules-broke-on-modern-android)
- [📊 Feature Comparison Matrix](#-feature-comparison-matrix)
- [🚀 Key Architectural Features](#-key-architectural-features)
- [📱 Zero-Icon Companion Manager & WebUI](#-zero-icon-companion-manager--webui)
- [⚙️ Configuration (`config.conf`)](#️-configuration-configconf)
- [📥 Installation](#-installation)
- [🔍 Verification & Testing](#-verification--testing)
- [❓ Frequently Asked Questions (FAQ)](#-frequently-asked-questions-faq)
- [🛠️ Building from Source](#️-building-from-source)
- [📄 License](#-license)

---

## ⚡ The Problem: Why Old Modules Broke on Modern Android

On modern Android GKI kernels (kernel versions 5.4, 5.10, 5.15, 6.1, 6.6, 6.12+), Google completely removed the legacy Netfilter kernel targets `CONFIG_IP_NF_TARGET_TTL` and `CONFIG_IP6_NF_TARGET_HL`. As a result, classic iptables commands (`iptables -t mangle -j TTL --ttl-set 64`) fail unconditionally:

```text
Warning: Extension TTL revision 0 not supported, missing kernel module?
iptables: No chain/target/match by that name.
```

Furthermore, legacy C-based modules relied on inspecting standard Linux routing table 254 (`main`). Since Android 12+, mobile data routes reside in dynamic policy routing tables (`table 1000+`), causing older tools to assign gateway index 0, drop packets, or silently leak untamed client TTLs (128 / 127) to mobile carriers.

Lastly, legacy userspace daemons intercept all packets indiscriminately, creating massive CPU context-switch bottlenecks that throttle high-speed 5G tethering and corrupt BitTorrent/P2P transfers.

**GKI-Tether-Shield** solves this natively without requiring custom kernel builds by coupling high-performance in-kernel selective matching with a real-time pure Go engine.

---

## 📊 Feature Comparison Matrix

| Feature | Stock Android / Legacy Modules | With GKI-Tether-Shield |
| :--- | :--- | :--- |
| **Carrier Hotspot Quota** | Consumes separate tethering cap; throttled to 128 Kbps | **Bypassed completely**; treated as phone's native data via real-time TTL=64 |
| **Deep Packet Inspection (DPI)** | ISPs detect desktop OS & throttle/censor websites via SNI | **Bypassed** via GoodbyeDPI / Zapret TLS ClientHello TCP segmentation |
| **DNS Privacy & Hijacking** | ISP snoops, hijacks, or poisons unencrypted port 53 DNS | **100% Encrypted** via TLS 1.3 DNS-over-HTTPS (Cloudflare / Quad9 / AdGuard) |
| **Bufferbloat / Gaming Ping** | Ping spikes to 300+ ms when someone streams video | **Flat 20-30 ms ping** under load via Fair Queueing (`fq_codel` QoS) |
| **Wi-Fi Latency (Screen Off)** | High jitter and packet drops caused by Wi-Fi power saving | **Locked to low latency** during active hotspot; powersave restored on idle |
| **BitTorrent & P2P Speed** | Stalls or drops due to userspace queue saturation | **100% In-kernel line rate acceleration** with enlarged conntrack table |
| **Configuration Interface** | Complex terminal commands or clunky drawer apps | **Zero-Icon Native Manager App** launched directly via Magisk Action button |

---

## 🚀 Key Architectural Features

### 1. ⚡ Real-Time Hardware-Accelerated TTL Normalization
- Normalizes IPv4 TTL and IPv6 Hop Limit to `64` in microseconds.
- Uses selective kernel-level matching (`-m ttl ! --ttl-eq 64`): packets already matching TTL 64 stay **100% in-kernel**, eliminating 95%+ of userspace context-switch overhead.
- Automatically recalculates IPv4 header checksums on modified packets.

### 2. 🛡️ GoodbyeDPI / Zapret TLS ClientHello TCP Segmentation
- Inspects initial HTTPS TLS ClientHello (SNI) and HTTP cleartext requests.
- Splits TCP payloads into segments at byte-level using raw socket injection.
- Evades carrier DPI middleboxes, domain filtering, and passive OS fingerprinting (`p0f`) across all tethered clients (Windows, macOS, iOS, Android, Linux, PlayStation, Xbox).
- **Isolated to Web Ports (80, 443, 8080, 8443):** Non-web protocols (BitTorrent, gaming UDP, custom ports) stay in-kernel, preventing protocol corruption.

### 3. 🔒 Transparent Encrypted DNS-over-HTTPS (DoH Proxy)
- Transparently intercepts unencrypted UDP & TCP port 53 queries from tethered devices.
- Resolves queries over encrypted **TLS 1.3 / HTTPS** (RFC 8484) with direct IP dialing to prevent bootstrap DNS loops.
- Supported providers:
  - **Cloudflare** (`1.1.1.1`)
  - **Quad9 Security** (`9.9.9.9` - malware & phishing protection)
  - **Google DNS** (`8.8.8.8`)
  - **AdGuard DNS** (`94.140.14.14` - network-wide ad & tracker blocking)
- **Ultra-fast In-Memory Cache:** Repeated domain lookups resolve locally in `<0.2 ms`.
- **Automatic Fallback:** Gracefully falls back to UDP 1.1.1.1:53 if upstream DoH fails, ensuring zero connection drops.
- **Zero Configuration:** Tethered devices require no manual DNS setup.

### 4. 🎮 Anti-Bufferbloat Fair Queueing (`fq_codel` QoS)
- Applies Fair Queueing with Controlled Delay (`fq_codel`) on active cellular and Wi-Fi interfaces.
- Dynamically separates latency-sensitive gaming packets (low-payload UDP) from bulk downloads and 4K video streams, preventing ping spikes under heavy load.
- Kernel sysctl network optimizations (`tcp_notsent_lowat=16384`, `tcp_slow_start_after_idle=0`, enlarged `nf_conntrack_max=262144`).

### 5. 🔋 Smart Hotspot-Aware Wi-Fi Battery Guard
- Automatically disables Wi-Fi power saving (`power_save off`) **only** while mobile hotspot is actively transmitting.
- Instantly restores standard battery-saving sleep mode (`power_save on`) when hotspot turns off.

### 6. 📲 Carrier DUN & Entitlement Bypass
- Automatically resets carrier entitlement flags: `tether_dun_required=0`, `net.tethering.noprovisioning=true`, and `tether_entitlement_check_state=0`.
- Enforces kernel default TTL values: `net.ipv4.ip_default_ttl=64` and `net.ipv6.conf.all.hop_limit=64`.

---

## 📱 Zero-Icon Companion Manager & WebUI

GKI-Tether-Shield includes a modern configuration interface designed to never clutter your application drawer:

### 1. Magisk Action Button
- Tapping the **Action** button on the module card inside the Magisk app immediately launches the native Android configuration dashboard.
- Includes automated HyperOS / MIUI background pop-up permission grants (`cmd appops set com.alperozd.hotspotshield 10021 allow`, etc.) to prevent vendor OS launch blocking.

### 2. Zero App Drawer Clutter
- Omits `android.intent.category.LAUNCHER`: no unwanted launcher icon appears on your home screen or app drawer.

### 3. Embedded WebUI (KernelSU / APatch / Browser)
- Embedded HTTP web server running on port `64640`.
- Supported directly via KernelSU / APatch / MMRL WebUI button, or by navigating to `http://127.0.0.1:64640` in your phone browser.

### 4. Command-Line Interface (`ttlshield`)
- Run commands directly as root in Termux or an ADB shell:
  ```bash
  su -c ttlshield status     # View real-time packet counters and active settings
  su -c ttlshield log        # Dump raw JSON statistics
  su -c ttlshield restart    # Restart the background daemon
  ```

---

## ⚙️ Configuration (`config.conf`)

Settings can be toggled in real-time either via the **In-App Manager**, **WebUI**, or by editing `/data/adb/modules/gki_hotspot_shield/config.conf` (or `/data/adb/modules/nfqttl/config.conf`):

```ini
# ==========================================
# GKI-Tether-Shield Configuration
# ==========================================

# Target TTL & Hop Limit (Default: 64)
TARGET_TTL=64

# DPI Evasion / TCP Segmentation (Zapret / GoodbyeDPI mode)
TCP_SPLIT=1
SPLIT_POS=2
QUEUE_NUM=6464

# Transparent Encrypted DNS (DNS-over-HTTPS)
DOH_ENABLED=1
DOH_PROVIDER=cloudflare   # Options: cloudflare, quad9, google, adguard

# Anti-Bufferbloat QoS (fq_codel)
BUFFERBLOAT_QOS=1

# Smart Wi-Fi Battery Guard (Prevents latency jitter when screen is off)
WIFI_POWER_SAVE_LOCK=1

# TCP Low Latency & Fast Buffer Flushing
TCP_LOW_LATENCY=1
```

---

## 📥 Installation

### Method 1: Root Manager App (Recommended)
1. Download the latest release ZIP from [Releases](https://github.com/maozdemir/GKI-Tether-Shield/releases/latest).
2. Open **Magisk**, **KernelSU**, or **APatch**.
3. Go to **Modules** → **Install from storage** → Select the downloaded ZIP.
4. Reboot your phone.

### Method 2: Launching Configuration Manager
* **In Magisk:** Open Magisk → Modules → Tap the **Action** button on `GKI Tether Shield`.
* **In KernelSU / APatch / MMRL:** Tap the **WebUI** button on the module card.
* **In Web Browser:** Navigate to `http://127.0.0.1:64640` on your phone.
* **In Terminal:** Run `su -c ttlshield status` in Termux to inspect live traffic counters.

---

## 🔍 Verification & Testing

Verify that your tethered traffic is completely shielded and masqueraded:

### 1. Check TTL on Connected Devices
Connect your PC, Mac, or secondary phone to your Android hotspot and test:
* **Windows (Command Prompt):**
  ```cmd
  ping 8.8.8.8
  ```
  *Result:* Look for `Reply from 8.8.8.8: bytes=32 time=... TTL=64` (Windows default is `128`; `64` confirms active normalization).
* **macOS / Linux (Terminal):**
  ```bash
  ping -c 4 8.8.8.8
  ```
  *Result:* Look for `ttl=64` (Normally, a routed packet from macOS arrives at `63`; `64` proves the phone rewrites the outgoing hop).

### 2. Verify Encrypted DNS (DoH)
* Visit [BrowserLeaks DNS Leak Test](https://browserleaks.com/dns) on your tethered device.
* *Result:* The detected DNS resolvers should reflect your configured DoH provider (Cloudflare, Quad9, Google, or AdGuard) instead of your mobile carrier's ISP DNS servers.

### 3. Test Bufferbloat & Latency Under Load
* Run the [Waveform Bufferbloat Test](https://www.waveform.com/tools/bufferbloat).
* *Result:* Grade A or A+ rating with minimal ping degradation during active upstream and downstream saturations.

### 4. Check Module Packet Counters
Run in Termux:
```bash
su -c ttlshield status
```
Example output:
```json
{
  "total_packets": 14205,
  "ipv4_packets": 14192,
  "ipv6_packets": 13,
  "ttl_modified": 1284,
  "tcp_split_packets": 312,
  "doh_queries": 84,
  "dns_cache_hits": 29,
  "target_ttl": 64,
  "tcp_split_enabled": true,
  "doh_enabled": true,
  "doh_provider": "cloudflare"
}
```

---

## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><b>Does this hide tethering usage from mobile carriers?</b></summary>
<p>
Yes. Carriers distinguish phone data from tethered hotspot data by inspecting the TTL field of outgoing IP packets (Windows defaults to TTL 128, macOS/iOS to 64 which decrements to 63 crossing the phone). GKI-Tether-Shield sets all outgoing packets to TTL 64, making tethered client traffic indistinguishable from native phone applications. Additionally, carrier DUN checks and entitlement provisioning are disabled.
</p>
</details>

<details>
<summary><b>Does this work with IPv6?</b></summary>
<p>
Yes. GKI-Tether-Shield simultaneously normalizes both IPv4 TTL and IPv6 Hop Limit to 64.
</p>
</details>

<details>
<summary><b>Why doesn't the companion app appear in my app drawer?</b></summary>
<p>
By design, the companion app omits launcher intent categories to keep your home screen and app drawer completely clean. It is launched exclusively via the Magisk "Action" button, the KernelSU WebUI button, or via the local web dashboard.
</p>
</details>

<details>
<summary><b>Will this affect online gaming ping or BitTorrent downloads?</b></summary>
<p>
No. BitTorrent and gaming traffic stay in kernel space at full line-rate speed. Only standard web ports (80, 443, 8080, 8443) are subject to TCP segmentation, and non-64 TTL packets are selectively queued. The built-in <code>fq_codel</code> queue discipline actively stabilizes ping by eliminating bufferbloat.
</p>
</details>

<details>
<summary><b>What happens if the selected DoH provider is unreachable?</b></summary>
<p>
The embedded DNS proxy features an automatic fallback mechanism: if an encrypted DoH query times out or fails, it immediately falls back to standard UDP resolution via <code>1.1.1.1:53</code>, preventing any internet loss.
</p>
</details>

<details>
<summary><b>What kernels and Android versions are supported?</b></summary>
<p>
All Generic Kernel Image (GKI) kernels (5.4, 5.10, 5.15, 6.1, 6.6, 6.12+) running Android 12, 13, 14, 15, and 16. Also fully backwards-compatible with legacy non-GKI kernels that support Netfilter Queues (<code>CONFIG_NETFILTER_NETLINK_QUEUE</code>).
</p>
</details>

---

## 🛠️ Building from Source

### Requirements
- Go 1.22+
- Android SDK (build-tools 34+) for companion APK compilation (optional)
- PowerShell (Windows) or Bash (Linux / macOS)

### Compiling Daemon
```bash
# Windows PowerShell
$env:GOOS="linux"; $env:GOARCH="arm64"; go build -ldflags="-s -w" -o nfqttl main.go

# Linux / macOS
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o nfqttl main.go
```

### Packaging Module ZIP
```bash
# Package the Magisk / KernelSU module
zip -r9 GKI-Tether-Shield.zip module.prop config.conf service.sh customize.sh action.sh uninstall.sh HotspotShieldManager.apk nfqttl system webroot META-INF
```

---

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by **Mustafa Alper ÖZDEMİR** ([@alperozd](https://github.com/maozdemir)).
