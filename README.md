# 🛡️ GKI-Tether-Shield

<p align="center">
  <img src="https://img.shields.io/github/v/release/maozdemir/GKI-Tether-Shield?style=for-the-badge&color=blue&logo=github" alt="Latest Release" />
  <img src="https://img.shields.io/github/actions/workflow/status/maozdemir/GKI-Tether-Shield/build.yml?branch=main&style=for-the-badge&logo=githubactions" alt="Build Status" />
  <img src="https://img.shields.io/badge/Platform-Android%20GKI%20(12%2B)-2ea44f?style=for-the-badge&logo=android" alt="Platform" />
  <img src="https://img.shields.io/badge/Root-Magisk%20%7C%20KernelSU%20%7C%20APatch-orange?style=for-the-badge&logo=magisk" alt="Root Compatibility" />
  <img src="https://img.shields.io/github/license/maozdemir/GKI-Tether-Shield?style=for-the-badge" alt="License" />
</p>

<p align="center">
  <b>The definitive all-in-one network engine, tethering bypass suite, and root module for modern Android devices running Generic Kernel Image (GKI) kernels.</b><br>
  <i>Tested and verified on Android 12, 13, 14, 15, and 16 (Snapdragon 8 Gen 2 / Gen 3 / Gen 4, Dimensity, Tensor, Exynos).</i>
</p>

---

## ⚡ The Problem: Why Old Modules Broke on Modern Android

On modern Android GKI kernels (kernel versions 5.4, 5.10, 5.15, 6.1, 6.6, 6.12+), Google completely stripped the legacy Netfilter kernel target `CONFIG_IP_NF_TARGET_TTL` and `CONFIG_IP6_NF_TARGET_HL`. As a result, classic iptables commands (`iptables -t mangle -j TTL --ttl-set 64`) fail unconditionally:

```text
Warning: Extension TTL revision 0 not supported, missing kernel module?
iptables: No chain/target/match by that name.
```

Furthermore, legacy C-based modules (like older `nfqttl` builds) relied on inspecting standard Linux routing table 254 (`main`). Since Android 12+, mobile data routes reside in dynamic policy routing tables (`table 1000+`), causing older tools to assign gateway index 0 and silently leak untamed client TTLs (128 / 127) to mobile carriers.

**GKI-Tether-Shield** solves this natively without needing custom kernel compilation by coupling high-performance in-kernel selective matching with a real-time pure Go engine.

---

## 📊 Feature Comparison Matrix

| Feature | Without GKI-Tether-Shield | With GKI-Tether-Shield |
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
- Automatically recalculates IPv4 header checksums.

### 2. 🛡️ GoodbyeDPI / Zapret TLS ClientHello TCP Segmentation
- Inspects initial HTTPS TLS ClientHello (SNI) and HTTP cleartext requests.
- Splits TCP payloads into segments at byte-level using raw socket injection.
- Evades carrier DPI middleboxes, domain filtering, and passive OS fingerprinting (`p0f`) across all tethered clients (Windows, macOS, iOS, Android, Linux, PlayStation, Xbox).
- **Isolated to Web Ports (80, 443, 8080, 8443):** Will never interfere with BitTorrent, gaming UDP, or custom application protocols.

### 3. 🔒 Transparent Encrypted DNS-over-HTTPS (DoH Proxy)
- Transparently intercepts unencrypted UDP & TCP port 53 queries from tethered devices.
- Resolves queries over encrypted **TLS 1.3 / HTTPS** (RFC 8484) with direct IP dialing to prevent bootstrap DNS loops.
- Supported providers:
  - **Cloudflare** (`1.1.1.1`)
  - **Quad9 Security** (`9.9.9.9` - malware & phishing protection)
  - **Google DNS** (`8.8.8.8`)
  - **AdGuard DNS** (`94.140.14.14` - network-wide ad & tracker blocking)
- **Ultra-fast In-Memory Cache:** Repeated domain lookups resolve locally in `<0.2 ms`.
- **Zero Configuration:** Tethered devices require no manual DNS setup.

### 4. 📱 Native Zero-Icon Companion Manager (Magisk Action Button)
- **Zero App Drawer Clutter:** Omits `CATEGORY_LAUNCHER`; no launcher icon appears on your home screen or app drawer.
- **Magisk Action Launch:** Tapping the **Action** button on the module card inside Magisk app instantly launches the native configuration dashboard.
- Includes automatic HyperOS / MIUI background pop-up window permission grants (`OP_BACKGROUND_START_ACTIVITY`) to prevent vendor OS launch drops.
- **KernelSU / APatch / MMRL WebUI:** Fully compatible with embedded WebUI via `webroot/index.html`.

### 5. 🎮 Anti-Bufferbloat Fair Queueing (`fq_codel` QoS)
- Applies Fair Queueing with Controlled Delay (`fq_codel`) on active cellular and Wi-Fi interfaces.
- Dynamically separates latency-sensitive gaming packets (low-payload UDP) from bulk downloads and 4K video streams, preventing ping spikes under heavy load.

### 6. 🔋 Smart Hotspot-Aware Wi-Fi Battery Guard
- Automatically disables Wi-Fi power saving (`power_save off`) **only** while mobile hotspot is actively transmitting.
- Instantly restores standard battery-saving sleep mode (`power_save on`) when hotspot turns off.

### 7. 📲 Carrier DUN & Entitlement Bypass
- Automatically resets carrier entitlement flags: `tether_dun_required=0`, `net.tethering.noprovisioning=true`, and `tether_entitlement_check_state=0`.
- Enforces kernel default TTL values: `net.ipv4.ip_default_ttl=64` and `net.ipv6.conf.all.hop_limit=64`.

---

## ⚙️ Configuration (`config.conf`)

Settings can be toggled in real-time either via the **In-App Manager** or by editing `/data/adb/modules/nfqttl/config.conf`:

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
1. Download the latest `GKI_Hotspot_Shield_v*.zip` from [Releases](https://github.com/maozdemir/GKI-Tether-Shield/releases).
2. Open **Magisk**, **KernelSU**, or **APatch**.
3. Go to **Modules** $\rightarrow$ **Install from storage** $\rightarrow$ Select the ZIP.
4. Reboot your phone.

### Method 2: Launching Configuration Manager
* **In Magisk:** Open Magisk $\rightarrow$ Modules $\rightarrow$ Tap the **Action** button on `GKI Hotspot Shield`.
* **In Browser:** Navigate to `http://127.0.0.1:64640` on your phone.
* **In Terminal:** Run `ttlshield status` in Termux (as root) to view live packet statistics.

---

## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><b>Does this hide tethering usage from my mobile carrier?</b></summary>
<p>
Yes. Carriers detect hotspot usage by inspecting the TTL field of outgoing packets (Windows defaults to TTL 128, macOS/iOS to 64 but decrements to 63 across the phone hop). GKI-Tether-Shield forces all outgoing traffic to TTL 64, making tethered traffic indistinguishable from native phone applications. Additionally, carrier DUN checks and entitlement provisioning are disabled.
</p>
</details>

<details>
<summary><b>Does this work with IPv6?</b></summary>
<p>
Yes. GKI-Tether-Shield simultaneously normalizes both IPv4 TTL and IPv6 Hop Limit to 64.
</p>
</details>

<details>
<summary><b>Why doesn't the companion app show up in my app drawer?</b></summary>
<p>
By design, the companion app omits launcher intent categories so your home screen and app drawer stay clean. It is launched exclusively via the Magisk "Action" button or via the local web dashboard.
</p>
</details>

<details>
<summary><b>Will this affect online gaming ping or BitTorrent downloads?</b></summary>
<p>
No. BitTorrent and gaming traffic stay in kernel space at full line-rate speed. The built-in <code>fq_codel</code> queue discipline actively stabilizes ping by eliminating bufferbloat.
</p>
</details>

---

## 🛠️ Building from Source

### Requirements
- Go 1.22+
- Android SDK (build-tools 34+) for companion APK compilation
- PowerShell (Windows) or Bash (Linux / macOS)

### Compiling Daemon
```bash
# Windows PowerShell
$env:GOOS="linux"; $env:GOARCH="arm64"; go build -ldflags="-s -w" -o nfqttl main.go

# Linux / macOS
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o nfqttl main.go
```

---

## 📄 License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
