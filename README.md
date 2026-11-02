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

Lastly, legacy userspace daemons ran a single-threaded queue and modified payloads indiscriminately, throttling high-speed 5G tethering and corrupting BitTorrent/P2P transfers.

**GKI-Tether-Shield** solves this without custom kernel builds: iptables only *selects* packets (`-m ttl` / `-m hl` matches, which GKI still ships) and hands them to NFQUEUE, where a multi-core Go daemon rewrites TTL / Hop Limit and fixes checksums. Since v4.0 it can instead rewrite them in the kernel itself with a small eBPF program (`TTL_ENGINE=ebpf`), which also catches hotspot traffic that Android's tethering offload sends past iptables.

---

## 📊 Feature Comparison Matrix

| Feature | Stock Android / Legacy Modules | With GKI-Tether-Shield |
| :--- | :--- | :--- |
| **Carrier Hotspot Quota** | Consumes separate tethering cap; throttled to 128 Kbps | **Bypassed completely**; treated as phone's native data via real-time TTL=64 |
| **Deep Packet Inspection (DPI)** | ISPs detect desktop OS & throttle/censor websites via SNI | **Bypassed** via GoodbyeDPI / Zapret TLS ClientHello TCP segmentation |
| **DNS Privacy & Hijacking** | ISP snoops, hijacks, or poisons unencrypted port 53 DNS | **Encrypted, certificate-verified** DNS-over-HTTPS for IPv4 and IPv6 clients (Cloudflare / Quad9 / Google / AdGuard) |
| **Bufferbloat / Gaming Ping** | Ping spikes to 300+ ms when someone streams video | **Flat 20-30 ms ping** under load via Fair Queueing (`fq_codel` QoS) |
| **Wi-Fi Latency (Screen Off)** | High jitter and packet drops caused by Wi-Fi power saving | **Locked to low latency** during active hotspot; powersave restored on idle |
| **BitTorrent & P2P Speed** | Stalls or drops due to userspace queue saturation | Payload never touched (only TTL); **4 parallel queue workers** with fail-open queues and an enlarged conntrack table, or **in-kernel eBPF** TTL fixing with no userspace round trip |
| **Tethering Offload** | Offloaded hotspot packets skip iptables, so their TTL leaks | **Fixed in the kernel** by the eBPF engine, after Android's offload has forwarded them |
| **Chipset Support** | Hardcoded to Qualcomm `rmnet` interfaces | **Any modem** (Qualcomm, MediaTek, Exynos, Tensor, Unisoc, 464XLAT/CLAT): rules key off downstream interfaces, not modem names |
| **Configuration Interface** | Complex terminal commands or clunky drawer apps | **Zero-Icon Native Manager App** launched directly via Magisk Action button |
| **Module Updates** | Manual downloading from GitHub & flashing | **1-Click Native Auto-Update** directly in Magisk / KernelSU / APatch / MMRL; your settings are kept |

---

## 🚀 Key Architectural Features

### 1. ⚡ Real-Time TTL / Hop Limit Normalization
- Normalizes IPv4 TTL and IPv6 Hop Limit of outgoing packets to `TARGET_TTL` (default `64`).
- GKI has no `TTL` target, so iptables only selects packets (`-m ttl ! --ttl-eq 64`, `-m hl ! --hl-eq 64`) and NFQUEUE hands them to the daemon. The phone's own traffic already leaves with TTL 64 and stays in-kernel; forwarded hotspot traffic (TTL 63/127 after routing) is rewritten by the daemon.
- Packets are spread over **4 NFQUEUE workers** by flow hash (multi-core, per-flow order preserved), with **fail-open** queues: if the daemon falls behind, packets pass instead of being dropped.
- **Works on every SoC:** instead of guessing the modem's interface name (`rmnet*`, `ccmni*`, `seth_lte*`, `v4-*` CLAT, ...), every egress interface except known hotspot/USB/Ethernet downstreams is treated as upstream.
- Recalculates IPv4 header checksums; a watchdog restarts the daemon if it ever stops.
- **In-kernel eBPF engine (`TTL_ENGINE=ebpf`, chosen at install):** a small eBPF program on each upstream interface's tc egress hook rewrites TTL / hop limit in the kernel, with no copy to userspace; only the first packets of web connections still go to the daemon for DPI splitting.
  - **Faster and lighter:** forwarded traffic no longer makes a round trip through the daemon, which saves CPU and battery on fast hotspot connections.
  - **Covers offloaded hotspot traffic:** Android's tethering BPF offload forwards hotspot packets straight to the mobile interface with `bpf_redirect()`, skipping iptables (and so NFQUEUE). Those packets still pass the tc egress hook, so the eBPF engine fixes them too.
  - **Safe alongside Android:** it never drops or redirects packets, so Android's own tc programs (netd, clatd, tethering offload) keep working; it follows interfaces as they appear and re-attaches if Android resets them.
  - **Automatic fallback:** if the kernel or SELinux refuses it, the daemon logs why and keeps using NFQUEUE; the dashboard shows which engine is running and why. Switching back keeps the eBPF program attached until the NFQUEUE rules are restored, so TTL fixing never pauses.
  - **Verified** on a Magisk phone with Android 16 and a 6.12 GKI kernel (SELinux enforcing), on the live mobile connection and with the offload path rebuilt in tests.
  - **Tested on your phone at install:** every install and update runs a quick self-test (`tether_shield ebpf-selftest`). It loads the program, checks it rewrites IPv4 and IPv6 test packets in the kernel, and attaches it to a throwaway virtual interface pair in a separate network namespace, never touching the real network. The installer then sets `TTL_ENGINE=ebpf` if it passed, or `nfqueue` with the reason if not.

### 2. 🛡️ GoodbyeDPI / Zapret TLS ClientHello TCP Segmentation
- Inspects initial HTTPS TLS ClientHello (SNI) and HTTP cleartext requests.
- Splits the first data segment **inside the server name** (TLS SNI / HTTP Host) using raw socket injection, so no single packet carries the full name; falls back to a fixed byte position (`SPLIT_MODE=fixed`). Works over IPv4 and IPv6.
- Optionally rejects HTTP/3 (QUIC, UDP 443) so browsers fall back to TCP, where splitting applies (`BLOCK_QUIC`, off by default).
- Evades SNI-based DPI middleboxes and domain filtering for all tethered clients (Windows, macOS, iOS, Android, Linux, consoles).
- **Isolated to Web Ports (80, 443, 8080, 8443):** non-web protocols (BitTorrent, gaming UDP, custom ports) are never split, preventing protocol corruption.
- Only the first 6 packets of each web connection are inspected (`connbytes`), so streaming and downloads skip DPI processing.

### 3. 🔒 Transparent Encrypted DNS-over-HTTPS (DoH Proxy)
- Transparently intercepts unencrypted UDP & TCP port 53 queries from tethered devices, over IPv4 and IPv6.
- Resolves queries over **HTTPS (RFC 8484) with verified TLS certificates**, dialing each provider's pinned IP directly to avoid bootstrap DNS loops.
- Only hotspot clients can reach the proxy; it is never exposed on the mobile network.
- Supported providers:
  - **Cloudflare** (`1.1.1.1`)
  - **Quad9 Security** (`9.9.9.9` - malware & phishing protection)
  - **Google DNS** (`8.8.8.8`)
  - **AdGuard DNS** (`94.140.14.14` - network-wide ad & tracker blocking)
- **In-Memory Cache:** honors record TTLs (5 s – 5 min), never caches failures, and merges identical concurrent lookups.
- **Automatic Fallback:** if DoH fails (or DoH is switched off), queries fall back to plain UDP `1.1.1.1:53` so name resolution keeps working. Fallback queries are **not encrypted**; the dashboard counts them and warns while DoH is failing.
- Cached answers report their remaining TTL, so clients never cache longer than the record allows.
- **Zero Configuration:** Tethered devices require no manual DNS setup.

### 4. 🎮 Anti-Bufferbloat Fair Queueing (`fq_codel` QoS)
- Applies Fair Queueing with Controlled Delay (`fq_codel`) on the hotspot interfaces and the actual uplink (taken from Android's tethering NAT rule) while the hotspot is active, and removes it afterwards.
- Dynamically separates latency-sensitive gaming packets (low-payload UDP) from bulk downloads and 4K video streams, preventing ping spikes under heavy load.
- Optional low-latency TCP sysctls (`tcp_notsent_lowat=16384`, `tcp_slow_start_after_idle=0`, `tcp_autocorking=0`; original values restored when disabled) and an enlarged `nf_conntrack_max=262144`.

### 5. 🔋 Smart Hotspot-Aware Wi-Fi Battery Guard
- Automatically disables Wi-Fi power saving (`power_save off`) **only** while mobile hotspot is actively transmitting.
- Instantly restores standard battery-saving sleep mode (`power_save on`) when hotspot turns off.

### 6. 📲 Carrier DUN & Entitlement Bypass
- Automatically resets carrier entitlement flags: `tether_dun_required=0`, `net.tethering.noprovisioning=true`, and `tether_entitlement_check_state=0`.
- Enforces kernel default TTL values (`net.ipv4.ip_default_ttl`, `net.ipv6.conf.all.hop_limit`) to `TARGET_TTL`.

### 7. 🔐 Locked-Down Local Control
- The dashboard API only listens on `127.0.0.1` and rejects cross-site requests and DNS rebinding.
- Settings can only be changed by the companion app, root or ADB shell (checked by the caller's Linux UID); the browser fallback uses a per-boot token. Other apps can read the dashboard but not change it.
- Daemon logs go to a size-capped `daemon.log` in the module directory.

### 8. 🔄 Native 1-Click Auto-Update (`update.json`)
- Fully compliant with **Magisk**, **KernelSU**, **APatch**, and **MMRL** update specifications.
- Automatically checks for updates and renders a 1-click update button inside your root manager app.
- Embedded Companion WebUI and native manager dynamically check for updates and notify you when new releases are published.
- Your `config.conf` is carried over on every update.

---

## 📱 Zero-Icon Companion Manager & WebUI

GKI-Tether-Shield includes a modern configuration interface designed to never clutter your application drawer:

### 1. Magisk Action Button
- Tapping the **Action** button on the module card inside the Magisk app immediately launches the native Android configuration dashboard.
- The app only shows the dashboard after the daemon proves its identity with a per-boot secret, so it must be opened from the Action button.
- Includes automated HyperOS / MIUI background pop-up permission grants (`cmd appops set com.alperozd.hotspotshield 10021 allow`, etc.) to prevent vendor OS launch blocking.

### 2. Zero App Drawer Clutter
- Omits `android.intent.category.LAUNCHER`: no unwanted launcher icon appears on your home screen or app drawer.

### 3. Embedded WebUI (KernelSU / APatch / Browser)
- Embedded HTTP web server running on port `64640`.
- Supported directly via the KernelSU / APatch / MMRL WebUI button (the page talks to the daemon through the manager's root bridge), or by navigating to `http://127.0.0.1:64640` in your phone browser (read-only unless opened from the Action button).

### 4. Command-Line Interface (`ttlshield`)
- Run commands directly as root in Termux or an ADB shell:
  ```bash
  su -c ttlshield status     # Live packet counters, settings and version
  su -c ttlshield log        # Last daemon log lines (and crash output, if any)
  su -c ttlshield restart    # Restart the background daemon
  su -c "ttlshield config get"                       # Current settings as JSON
  su -c "ttlshield config set '{\"DOH_PROVIDER\":\"quad9\"}'"  # Change settings (same as the WebUI)
  su -c "ttlshield ebpf-selftest"   # Can this phone run the eBPF TTL engine? ("ok" or the reason)
  ```

---

## ⚙️ Configuration (`config.conf`)

Settings can be changed in the **In-App Manager** / **WebUI**, or by editing `/data/adb/modules/gki_hotspot_shield/config.conf`. Edits are picked up automatically within ~10 seconds (no reboot). Comments must be on their own line.

```ini
# ==========================================
# GKI-Tether-Shield Configuration
# ==========================================

# Target TTL & Hop Limit (Default: 64, range 1-255)
TARGET_TTL=64
# How TTL is rewritten: nfqueue (userspace, works everywhere) or ebpf
# (in-kernel, faster; falls back to nfqueue if the kernel refuses it).
# Every install and update tests this phone and sets it: ebpf if the test
# passes, nfqueue if not. You can change it until the next update.
TTL_ENGINE=nfqueue

# DPI Evasion / TCP Segmentation (Zapret / GoodbyeDPI mode)
TCP_SPLIT=1
SPLIT_POS=2
# Split inside the TLS SNI / HTTP Host name (auto) or always at SPLIT_POS (fixed)
SPLIT_MODE=auto
# Reject HTTP/3 (QUIC, UDP 443) so browsers fall back to TCP, where splitting applies
BLOCK_QUIC=0
# First of 4 consecutive NFQUEUE numbers (6464-6467); change only on conflicts
QUEUE_NUM=6464

# Transparent Encrypted DNS (DNS-over-HTTPS)
DOH_ENABLED=1
# Options: cloudflare, quad9, google, adguard
DOH_PROVIDER=cloudflare

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

### 1. Check Outgoing TTL
The TTL is rewritten on packets *leaving* the phone, so a `ping` from a client can't show it (the TTL in a ping reply is set by the remote server). Check on the phone instead:
* **Counters:** browse from a tethered device and run `su -c ttlshield status`; `ttl_modified` should keep rising.
* **On the wire** (needs `tcpdump` on the phone):
  ```bash
  su -c 'tcpdump -ni any -v -c 20 "icmp or tcp port 443"'
  ```
  *Result:* packets leaving on the mobile interface show `ttl 64` (`hlim 64` for IPv6), even for Windows clients (default `128`).
* **eBPF engine:** with `TTL_ENGINE=ebpf`, the dashboard's TTL engine note says "eBPF is running", and each mobile interface lists the program:
  ```bash
  su -c 'tc filter show dev rmnet_data0 egress'   # use your mobile interface name
  ```
  *Result:* a line with `tshield_ttl`. If the note says eBPF wasn't allowed, the reason is shown there and in `ttlshield log`, and NFQUEUE keeps fixing TTL.

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
  "dns_fallback_queries": 0,
  "dns_plain_queries": 0,
  "target_ttl": 64,
  "ttl_engine": "ebpf",
  "ttl_engine_setting": "ebpf",
  "ttl_engine_error": "",
  "tcp_split_enabled": true,
  "block_quic": false,
  "doh_enabled": true,
  "doh_provider": "cloudflare",
  "version": "v4.0",
  "version_code": 400
}
```
`ttl_engine` is the engine actually running; it differs from `ttl_engine_setting` only when eBPF was refused, and `ttl_engine_error` then says why. (Trimmed: the full output also has `bufferbloat_qos`, `dns_last_fallback` and `updated_at`.)

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
Yes. IPv4 TTL and IPv6 Hop Limit are both normalized, including IPv4 traffic sent through 464XLAT/CLAT on IPv6-only carriers, and tethered clients' IPv6 DNS queries go through the DoH proxy too (when the kernel supports IPv6 NAT).
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
BitTorrent and gaming payloads are never modified: only web connections (ports 80 and 443) are subject to TCP segmentation. With the NFQUEUE engine, their packets do pass through the daemon so their TTL can be fixed (GKI has no in-kernel TTL target); this is spread over 4 CPU cores and fails open under overload. With <code>TTL_ENGINE=ebpf</code> they never leave the kernel: the TTL is fixed in place. The built-in <code>fq_codel</code> queue discipline stabilizes ping by eliminating bufferbloat.
</p>
</details>

<details>
<summary><b>Which TTL engine should I use, NFQUEUE or eBPF?</b></summary>
<p>
You usually don't have to choose: every install and update tests your phone and picks eBPF if it works there, NFQUEUE if not (the installer log says which and why). eBPF is faster and lighter on the battery, and it also fixes hotspot traffic that Android's tethering offload sends past iptables. NFQUEUE works on every phone. You can switch with <code>TTL_ENGINE</code> or the TTL engine switch in the dashboard; the next update tests and chooses again. If eBPF stops working later, nothing breaks: the shield falls back to NFQUEUE and the dashboard tells you why. TTL fixing never pauses during a switch.
</p>
</details>

<details>
<summary><b>What happens if the selected DoH provider is unreachable?</b></summary>
<p>
The embedded DNS proxy falls back to standard UDP resolution via <code>1.1.1.1:53</code> if an encrypted DoH query times out or fails, so name resolution keeps working. Those fallback queries are not encrypted.
</p>
</details>

<details>
<summary><b>What kernels and Android versions are supported?</b></summary>
<p>
All Generic Kernel Image (GKI) kernels (5.4, 5.10, 5.15, 6.1, 6.6, 6.12+) running Android 12, 13, 14, 15, and 16. Non-GKI kernels work too if they provide Netfilter Queues (<code>CONFIG_NETFILTER_NETLINK_QUEUE</code>, the <code>NFQUEUE</code> target) and the <code>ttl</code>/<code>hl</code> matches (<code>CONFIG_NETFILTER_XT_MATCH_HL</code>). The eBPF engine additionally needs BPF tc classifiers (<code>CONFIG_NET_CLS_BPF</code>, <code>CONFIG_NET_SCH_INGRESS</code>), which every GKI kernel has because Android itself relies on them.
</p>
</details>

---

## 🛠️ Building from Source

### Requirements
- Go 1.26+ (`go.mod` pins the toolchain; `GOTOOLCHAIN=auto` fetches it)
- `zip` and a POSIX shell (Linux / macOS / WSL / Git Bash)
- Only to change `bpf/ttl.c`: clang/LLVM and libbpf headers (`apt install clang llvm libbpf-dev`), then `go generate ./...` and commit the regenerated `ttl_bpfel.go` / `ttl_bpfel.o` (normal builds use the committed object and need no clang)
- For the companion app: JDK 17 and the Android SDK (`ANDROID_HOME`) with `platforms;android-35` and `build-tools;35.0.0`

### Compiling Daemon
```bash
sh scripts/build.sh       # arm64 binary ./tether_shield, version taken from module.prop
sh scripts/build-apk.sh   # ./HotspotShieldManager.apk from app/ (throwaway key unless APK_KEYSTORE_* are set)
```

### Testing
```bash
go vet . && go test -race ./...   # Linux (or WSL) only: the daemon uses Linux syscalls
sudo go test -race ./...          # also runs the eBPF tests: in-kernel BPF_PROG_TEST_RUN and
                                  # real tc attachment in a throwaway network namespace
```

### Packaging Module ZIP
```bash
sh scripts/package.sh dev dist   # writes dist/GKI_Tether_Shield_dev.zip
```

### Releasing
Every push and pull request builds and tests; the module ZIP is attached to
the workflow run as an artifact. A push to `main` also publishes a release
when `module.prop` carries a version that has no release yet:

1. Bump `version` / `versionCode` in `module.prop` and `update.json`, and add
   a `changelog.md` entry. `sh scripts/check-version.sh` verifies they agree;
   the daemon, WebUI and installer read the version from `module.prop`.
2. Merge to `main`. The workflow tags that commit and publishes the release.

The companion APK is built in CI from `app/`. To sign releases with a stable
key, add the repository secrets `APK_KEYSTORE_B64` (base64 of a keystore),
`APK_KEYSTORE_PASSWORD` and `APK_KEY_ALIAS`; without them each build uses a
throwaway key and the installer reinstalls the app on signature changes.

Pushes that don't change the version build and test only; an existing
release is never modified.

---

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by **Mustafa Alper ÖZDEMİR** ([@alperozd](https://github.com/maozdemir)).
