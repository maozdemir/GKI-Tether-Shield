#!/system/bin/sh
MODDIR=${0%/*}

CONF="$MODDIR/config.conf"
LOOP_INTERVAL=10

# conf_enabled KEY DEFAULT: succeeds if KEY is 1/true in config.conf.
conf_enabled() {
    val="$2"
    if [ -f "$CONF" ]; then
        while IFS='=' read -r key value; do
            [ "$key" = "$1" ] && val="$value"
        done < "$CONF"
    fi
    case "$val" in 1|true|TRUE|True) return 0 ;; *) return 1 ;; esac
}

# 1. Android System & DUN Parameters Reset
resetprop tether_dun_required 0
resetprop net.tethering.noprovisioning true
resetprop tether_entitlement_check_state 0
settings put global tether_dun_required 0 2>/dev/null
settings put global tether_entitlement_check_state 0 2>/dev/null

# 2. Kernel Default TTL & Hop Limit
echo 64 > /proc/sys/net/ipv4/ip_default_ttl
echo 64 > /proc/sys/net/ipv6/conf/all/hop_limit

# 3. High-Performance Anti-Bufferbloat & P2P Conntrack Sysctls
conf_enabled BUFFERBLOAT_QOS 1 && sysctl -w net.core.default_qdisc=fq_codel 2>/dev/null
# TCP low-latency sysctls are applied by the loop in section 8 (TCP_LOW_LATENCY)
sysctl -w net.ipv4.tcp_ecn=0 2>/dev/null
sysctl -w net.core.netdev_max_backlog=8192 2>/dev/null
sysctl -w net.ipv4.tcp_fastopen=3 2>/dev/null
sysctl -w net.netfilter.nf_conntrack_max=262144 2>/dev/null
sysctl -w net.netfilter.nf_conntrack_udp_timeout=30 2>/dev/null
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60 2>/dev/null
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200 2>/dev/null

until [ "$(getprop sys.boot_completed)" = 1 ]; do
    sleep 1
done

# Repeat properties after boot completion
resetprop tether_dun_required 0
resetprop net.tethering.noprovisioning true
resetprop tether_entitlement_check_state 0
settings put global tether_dun_required 0 2>/dev/null
settings put global tether_entitlement_check_state 0 2>/dev/null

# 4. Start Go TTL, DPI & DoH Daemon
# Upgrade cleanup: v3.5 and earlier ran the daemon as "nfqttl" with chains
# nfqttli/nfqttlo. Only needed when updating without a reboot; safe to
# remove once nobody upgrades from <= v3.5 in place.
killall -9 nfqttl 2>/dev/null
for hook in PREROUTING OUTPUT; do
    iptables -t mangle -D $hook -j nfqttli 2>/dev/null
    iptables -t mangle -D $hook -j nfqttlo 2>/dev/null
done
for wan in rmnet+ rmnet_data+; do
    iptables -t mangle -D POSTROUTING -o $wan -j nfqttlo 2>/dev/null
done
for chain in nfqttli nfqttlo; do
    iptables -t mangle -F $chain 2>/dev/null
    iptables -t mangle -X $chain 2>/dev/null
done

killall -9 tether_shield 2>/dev/null
nohup "$MODDIR/tether_shield" </dev/null >/dev/null 2>&1 &

# 5. High-Efficiency NFQUEUE Mangle Rules (chain tshield_out)
# 1) Intercept ports 80, 443 for GoodbyeDPI / TLS SNI splitting
# 2) Intercept non-64 TTL packets for real-time TTL normalization
# 3) Completely bypass BitTorrent, gaming UDP, and bulk file downloads
# Packets are spread over 4 queues (6464-6467, one daemon worker per queue,
# NUM_QUEUES in nfqueue.go) by flow hash, so per-flow ordering is preserved.
# Falls back to a single queue if --queue-balance is unsupported.
CHAIN=tshield_out
QUEUE_TARGET="--queue-balance 6464:6467 --queue-bypass"
iptables -t mangle -N $CHAIN 2>/dev/null
iptables -t mangle -F $CHAIN
if ! iptables -t mangle -A $CHAIN -m ttl ! --ttl-eq 64 -j NFQUEUE $QUEUE_TARGET 2>/dev/null; then
    QUEUE_TARGET="--queue-num 6464 --queue-bypass"
    iptables -t mangle -A $CHAIN -m ttl ! --ttl-eq 64 -j NFQUEUE $QUEUE_TARGET
fi
# The TLS ClientHello / HTTP request is within the first few packets of a
# connection, so only those need DPI splitting. Matching just packets 1-6
# keeps bulk HTTPS (streaming, downloads) out of userspace. Packets with a
# non-64 TTL are still queued by the rule below for TTL normalization.
# Falls back to queueing all web packets if xt_connbytes is unavailable.
sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null
iptables -t mangle -I $CHAIN 1 -p tcp -m multiport --dports 80,443 \
    -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 1:6 \
    -j NFQUEUE $QUEUE_TARGET 2>/dev/null ||
    iptables -t mangle -I $CHAIN 1 -p tcp -m multiport --dports 80,443 -j NFQUEUE $QUEUE_TARGET

# Apply in POSTROUTING on outgoing WAN (cellular) interfaces.
# rmnet+ also matches rmnet_data*, so one rule covers both.
iptables -t mangle -C POSTROUTING -o rmnet+ -j $CHAIN 2>/dev/null || iptables -t mangle -A POSTROUTING -o rmnet+ -j $CHAIN

# IPv6: forwarded packets leave with Hop Limit 63 (or 127/254), which is how
# carriers detect tethering on IPv6-only / 464XLAT networks. Queue non-64
# hop limits to the same queues; the daemon rewrites IPv6 Hop Limit too.
# Falls back to queueing all WAN IPv6 if the hl match is unavailable.
ip6tables -t mangle -N $CHAIN 2>/dev/null
ip6tables -t mangle -F $CHAIN
ip6tables -t mangle -A $CHAIN -m hl ! --hl-eq 64 -j NFQUEUE $QUEUE_TARGET 2>/dev/null ||
    ip6tables -t mangle -A $CHAIN -j NFQUEUE $QUEUE_TARGET
ip6tables -t mangle -C POSTROUTING -o rmnet+ -j $CHAIN 2>/dev/null || ip6tables -t mangle -A POSTROUTING -o rmnet+ -j $CHAIN

# 6. TCP MSS Clamping to PMTU
iptables -t mangle -C FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# 7. Transparent DNS-over-HTTPS (DoH) Redirection (Port 53 -> 53545)
# Only tethered/local clients may use the proxy: DNS arriving on the
# cellular WAN is never redirected, and direct access to port 53545 from
# the WAN is dropped, so the phone is not an open resolver / DNS
# amplifier when the carrier assigns a reachable IP.
for proto in udp tcp; do
    # Upgrade cleanup: v3.1-v3.3 redirected to 5353; v3.4-v3.5 redirected
    # without an interface restriction.
    iptables -t nat -D PREROUTING -p $proto --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
    iptables -t nat -D PREROUTING -p $proto --dport 53 -j REDIRECT --to-ports 53545 2>/dev/null

    iptables -t nat -C PREROUTING ! -i rmnet+ -p $proto --dport 53 -j REDIRECT --to-ports 53545 2>/dev/null ||
        iptables -t nat -A PREROUTING ! -i rmnet+ -p $proto --dport 53 -j REDIRECT --to-ports 53545
    iptables -C INPUT -i rmnet+ -p $proto --dport 53545 -j DROP 2>/dev/null ||
        iptables -I INPUT -i rmnet+ -p $proto --dport 53545 -j DROP
done

# 8. Dynamic Hotspot-Aware QoS, Power Saver Guard & Low-Latency Tuning
# Honors BUFFERBLOAT_QOS, WIFI_POWER_SAVE_LOCK and TCP_LOW_LATENCY from
# config.conf (re-read every tick, so WebUI changes apply within seconds).
# Changes are applied only when the hotspot state, the interface set or a
# setting changes, and exactly what was applied is undone. Shell builtins
# only on the hot path, so the loop costs almost nothing while idle.
# TCP low-latency sysctls: "path value" pairs; originals saved for undo.
LL_SETTINGS="net/ipv4/tcp_slow_start_after_idle:0 net/ipv4/tcp_notsent_lowat:16384 net/ipv4/tcp_autocorking:0"
LL_ORIGINALS=""
for kv in $LL_SETTINGS; do
    path="/proc/sys/${kv%%:*}"
    [ -f "$path" ] && read -r orig < "$path" && LL_ORIGINALS="$LL_ORIGINALS ${kv%%:*}:$orig"
done

apply_sysctls() {
    for kv in $1; do
        [ -f "/proc/sys/${kv%%:*}" ] && echo "${kv#*:}" > "/proc/sys/${kv%%:*}" 2>/dev/null
    done
}

# Sets TETHER_IFACES (all tether/WAN links) and WIFI_IFACES (Wi-Fi only).
scan_ifaces() {
    TETHER_IFACES=""
    WIFI_IFACES=""
    for path in /sys/class/net/*; do
        name="${path##*/}"
        case "$name" in
            wlan*|swlan*|ap*|softap*) TETHER_IFACES="$TETHER_IFACES $name"; WIFI_IFACES="$WIFI_IFACES $name" ;;
            rndis*|ncm*|usb*|bt-pan|rmnet*) TETHER_IFACES="$TETHER_IFACES $name" ;;
        esac
    done
}

(
    applied=""      # state fingerprint last applied
    qos_ifaces=""   # interfaces we attached fq_codel to
    psl_ifaces=""   # interfaces we disabled Wi-Fi power save on
    low_latency=""
    while true; do
        if conf_enabled TCP_LOW_LATENCY 1; then want_ll=1; else want_ll=0; fi
        if [ "$want_ll" != "$low_latency" ]; then
            if [ "$want_ll" = 1 ]; then apply_sysctls "$LL_SETTINGS"; else apply_sysctls "$LL_ORIGINALS"; fi
            low_latency="$want_ll"
        fi

        case "$(iptables -t nat -S tetherctrl_nat_POSTROUTING 2>/dev/null)" in
            *MASQUERADE*) active=1 ;;
            *) active=0 ;;
        esac
        if conf_enabled BUFFERBLOAT_QOS 1; then qos=1; else qos=0; fi
        if conf_enabled WIFI_POWER_SAVE_LOCK 1; then psl=1; else psl=0; fi
        scan_ifaces
        state="$active|$qos|$psl|$TETHER_IFACES"

        if [ "$state" != "$applied" ]; then
            for i in $qos_ifaces; do tc qdisc del dev "$i" root 2>/dev/null; done
            for i in $psl_ifaces; do iw dev "$i" set power_save on 2>/dev/null; done
            qos_ifaces=""
            psl_ifaces=""
            if [ "$active" = 1 ]; then
                if [ "$qos" = 1 ]; then
                    for i in $TETHER_IFACES; do
                        tc qdisc replace dev "$i" root fq_codel 2>/dev/null && qos_ifaces="$qos_ifaces $i"
                    done
                fi
                if [ "$psl" = 1 ]; then
                    for i in $WIFI_IFACES; do
                        iw dev "$i" set power_save off 2>/dev/null && psl_ifaces="$psl_ifaces $i"
                    done
                fi
            fi
            applied="$state"
        fi
        sleep "$LOOP_INTERVAL"
    done
) </dev/null >/dev/null 2>&1 &
