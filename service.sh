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

# conf_value KEY DEFAULT: sets CONF_VALUE to KEY's value (or DEFAULT).
conf_value() {
    CONF_VALUE="$2"
    [ -f "$CONF" ] || return 0
    while IFS='=' read -r key value; do
        [ "$key" = "$1" ] && CONF_VALUE="$value"
    done < "$CONF"
}

# read_net_settings: sets TTL and QUEUE/QUEUE_END from config.conf, using the
# same validation as the daemon (config.go) so rules and daemon agree.
read_net_settings() {
    conf_value TARGET_TTL 64
    case "$CONF_VALUE" in ''|*[!0-9]*) TTL=64 ;; *) TTL=$CONF_VALUE ;; esac
    { [ "$TTL" -ge 1 ] && [ "$TTL" -le 255 ]; } || TTL=64

    conf_value QUEUE_NUM 6464
    case "$CONF_VALUE" in ''|*[!0-9]*) QUEUE=6464 ;; *) QUEUE=$CONF_VALUE ;; esac
    # 4 queues (NUM_QUEUES in nfqueue.go) must fit below 65536.
    { [ "$QUEUE" -ge 1 ] && [ "$QUEUE" -le 65531 ]; } || QUEUE=6464
    QUEUE_END=$((QUEUE + 3))
}

# Cellular interface names differ per SoC (Qualcomm rmnet*, MediaTek ccmni*,
# Unisoc seth_lte*/sipa_eth*, 464XLAT v4-*/clat*, ...), so nothing is tied to
# a list of WAN names. TTL rules treat every egress interface as upstream
# EXCEPT these known downstream/local ones (an unexpected modem name is still
# covered; an unexpected downstream name only costs performance), and the DNS
# proxy only accepts traffic FROM them (an unexpected modem name can never
# reach it).
DOWNSTREAM_IFACES="lo wlan+ swlan+ ap+ softap+ p2p+ wigig+ rndis+ ncm+ usb+ bt-pan+ eth+"

apply_default_ttl() {
    echo "$TTL" > /proc/sys/net/ipv4/ip_default_ttl
    echo "$TTL" > /proc/sys/net/ipv6/conf/all/hop_limit
}

read_net_settings

# 1. Android System & DUN Parameters Reset
resetprop tether_dun_required 0
resetprop net.tethering.noprovisioning true
resetprop tether_entitlement_check_state 0
settings put global tether_dun_required 0 2>/dev/null
settings put global tether_entitlement_check_state 0 2>/dev/null

# 2. Kernel Default TTL & Hop Limit
apply_default_ttl

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

# DNS-over-HTTPS redirection (port 53 -> 53545) and proxy protection, for
# IPv4 and IPv6. Allowlist: only DNS from downstream (tethered) interfaces is
# redirected, and the proxy port only accepts loopback and downstream
# traffic, so no modem interface (of any name) can reach the resolver and
# the phone is never an open resolver / DNS amplifier on a carrier IP.
# Runs before the daemon starts, so the dual-stack listener is never exposed.
DNS_NAT_CHAIN=tshield_dns
DNS_IN_CHAIN=tshield_dns_in
setup_dns_rules() {
    for proto in udp tcp; do
        # Upgrade cleanup: v3.1-v3.3 redirected to 5353; v3.4-v3.5 redirected
        # without an interface restriction; v3.6 excluded rmnet+ only.
        iptables -t nat -D PREROUTING -p $proto --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
        iptables -t nat -D PREROUTING -p $proto --dport 53 -j REDIRECT --to-ports 53545 2>/dev/null
        iptables -t nat -D PREROUTING ! -i rmnet+ -p $proto --dport 53 -j REDIRECT --to-ports 53545 2>/dev/null
        iptables -D INPUT -i rmnet+ -p $proto --dport 53545 -j DROP 2>/dev/null
    done

    for ipt in iptables ip6tables; do
        # Protection first and unconditionally: the listener is dual-stack.
        $ipt -N $DNS_IN_CHAIN 2>/dev/null
        $ipt -F $DNS_IN_CHAIN
        for iface in $DOWNSTREAM_IFACES; do
            $ipt -A $DNS_IN_CHAIN -i "$iface" -j RETURN
        done
        $ipt -A $DNS_IN_CHAIN -j DROP
        for proto in udp tcp; do
            $ipt -C INPUT -p $proto --dport 53545 -j $DNS_IN_CHAIN 2>/dev/null ||
                $ipt -I INPUT -p $proto --dport 53545 -j $DNS_IN_CHAIN
        done

        # Redirect. IPv6 NAT may be missing on some kernels; then IPv6 DNS
        # simply isn't redirected (still protected by the rules above).
        $ipt -t nat -N $DNS_NAT_CHAIN 2>/dev/null || $ipt -t nat -L $DNS_NAT_CHAIN -n >/dev/null 2>&1 || continue
        $ipt -t nat -F $DNS_NAT_CHAIN
        for iface in $DOWNSTREAM_IFACES; do
            [ "$iface" = lo ] && continue
            for proto in udp tcp; do
                $ipt -t nat -A $DNS_NAT_CHAIN -i "$iface" -p $proto --dport 53 -j REDIRECT --to-ports 53545
            done
        done
        $ipt -t nat -C PREROUTING -j $DNS_NAT_CHAIN 2>/dev/null ||
            $ipt -t nat -A PREROUTING -j $DNS_NAT_CHAIN
    done
}

# Daemon messages go to $MODDIR/daemon.log (size-capped by the daemon).
# Raw stderr (e.g. a Go crash trace) goes to daemon.stderr, truncated on each
# start so a crash loop cannot fill the disk; it keeps the last run's trace.
start_daemon() {
    nohup "$MODDIR/tether_shield" </dev/null >"$MODDIR/daemon.stderr" 2>&1 &
}

killall -9 tether_shield 2>/dev/null
# New web UI token every boot (the daemon reuses it across watchdog restarts).
rm -f "$MODDIR/.webui_token"
setup_dns_rules
start_daemon

# 5. High-Efficiency NFQUEUE Mangle Rules
# Cellular interface names differ per SoC, so rules are not tied to a list of
# WAN names; see DOWNSTREAM_IFACES at the top.
WAN_CHAIN=tshield_wan   # POSTROUTING -> skip downstream -> tshield_out
CHAIN=tshield_out       # the actual queueing rules

# tshield_out:
# 1) Intercept ports 80, 443 for GoodbyeDPI / TLS SNI splitting
# 2) Intercept packets whose TTL is not TARGET_TTL, for normalization
# 3) Completely bypass BitTorrent, gaming UDP, and bulk file downloads
# Packets are spread over 4 queues (QUEUE_NUM..+3, one daemon worker per
# queue, NUM_QUEUES in nfqueue.go) by flow hash, preserving per-flow order.
# Falls back to a single queue if --queue-balance is unsupported.
setup_queue_rules() {
    QUEUE_TARGET="--queue-balance $QUEUE:$QUEUE_END --queue-bypass"
    iptables -t mangle -N $CHAIN 2>/dev/null
    iptables -t mangle -F $CHAIN
    if ! iptables -t mangle -A $CHAIN -m ttl ! --ttl-eq "$TTL" -j NFQUEUE $QUEUE_TARGET 2>/dev/null; then
        QUEUE_TARGET="--queue-num $QUEUE --queue-bypass"
        iptables -t mangle -A $CHAIN -m ttl ! --ttl-eq "$TTL" -j NFQUEUE $QUEUE_TARGET
    fi
    # The TLS ClientHello / HTTP request is within the first few packets of a
    # connection, so only those need DPI splitting. Matching just packets 1-6
    # keeps bulk HTTPS (streaming, downloads) out of userspace. Packets with
    # another TTL are still queued by the rule above for TTL normalization.
    # Falls back to queueing all web packets if xt_connbytes is unavailable.
    sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null
    iptables -t mangle -I $CHAIN 1 -p tcp -m multiport --dports 80,443 \
        -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 1:6 \
        -j NFQUEUE $QUEUE_TARGET 2>/dev/null ||
        iptables -t mangle -I $CHAIN 1 -p tcp -m multiport --dports 80,443 -j NFQUEUE $QUEUE_TARGET

    # IPv6: forwarded packets leave with Hop Limit 63 (or 127/254), which is
    # how carriers detect tethering on IPv6-only / 464XLAT networks. Queue
    # other hop limits to the same queues; the daemon rewrites IPv6 too.
    # Falls back to queueing all upstream IPv6 if the hl match is unavailable.
    ip6tables -t mangle -N $CHAIN 2>/dev/null
    ip6tables -t mangle -F $CHAIN
    ip6tables -t mangle -A $CHAIN -m hl ! --hl-eq "$TTL" -j NFQUEUE $QUEUE_TARGET 2>/dev/null ||
        ip6tables -t mangle -A $CHAIN -j NFQUEUE $QUEUE_TARGET

    for ipt in iptables ip6tables; do
        $ipt -t mangle -N $WAN_CHAIN 2>/dev/null
        $ipt -t mangle -F $WAN_CHAIN
        for iface in $DOWNSTREAM_IFACES; do
            $ipt -t mangle -A $WAN_CHAIN -o "$iface" -j RETURN
        done
        $ipt -t mangle -A $WAN_CHAIN -j $CHAIN
        $ipt -t mangle -C POSTROUTING -j $WAN_CHAIN 2>/dev/null ||
            $ipt -t mangle -A POSTROUTING -j $WAN_CHAIN
    done
}

# Upgrade cleanup: v3.6 jumped to tshield_out from POSTROUTING for rmnet+
# only; tshield_wan now covers every upstream interface.
for ipt in iptables ip6tables; do
    $ipt -t mangle -D POSTROUTING -o rmnet+ -j $CHAIN 2>/dev/null
done
setup_queue_rules

# 6. TCP MSS Clamping to PMTU
iptables -t mangle -C FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# 7. DNS redirection / proxy protection: set up in section 4, before the
# daemon starts listening (see setup_dns_rules).

# 8. Daemon Watchdog, Hotspot-Aware QoS, Power Saver Guard & Low-Latency Tuning
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

# Sets TETHER_IFACES (downstream links present) and WIFI_IFACES (Wi-Fi only).
scan_ifaces() {
    TETHER_IFACES=""
    WIFI_IFACES=""
    for path in /sys/class/net/*; do
        name="${path##*/}"
        case "$name" in
            wlan*|swlan*|ap*|softap*) TETHER_IFACES="$TETHER_IFACES $name"; WIFI_IFACES="$WIFI_IFACES $name" ;;
            p2p*|wigig*|rndis*|ncm*|usb*|bt-pan*|eth*) TETHER_IFACES="$TETHER_IFACES $name" ;;
        esac
    done
}

# find_upstreams NAT_RULES: sets UPSTREAM_IFACES to the "-o <iface>" of
# Android's tethering MASQUERADE rules, i.e. the real uplink on any SoC.
find_upstreams() {
    UPSTREAM_IFACES=""
    want=0
    set -f
    for word in $1; do
        [ "$want" = 1 ] && UPSTREAM_IFACES="$UPSTREAM_IFACES $word"
        if [ "$word" = "-o" ]; then want=1; else want=0; fi
    done
    set +f
}

CONF_STAMP="$MODDIR/.config_applied"
: > "$CONF_STAMP"

(
    applied=""      # state fingerprint last applied
    qos_ifaces=""   # interfaces we attached fq_codel to
    psl_ifaces=""   # interfaces we disabled Wi-Fi power save on
    low_latency=""
    while true; do
        # Watchdog: the daemon exits on unrecoverable queue errors (and could
        # crash); restart it so TTL fixing and DNS don't silently stop.
        # At most one restart per tick, so a crash loop can't spin the CPU.
        pidof tether_shield >/dev/null || start_daemon

        # config.conf changed (WebUI save or manual edit): keep iptables, the
        # kernel default TTL and the daemon in sync with it.
        if [ "$CONF" -nt "$CONF_STAMP" ]; then
            : > "$CONF_STAMP"
            old_ttl="$TTL"
            old_queue="$QUEUE"
            read_net_settings
            if [ "$TTL" != "$old_ttl" ] || [ "$QUEUE" != "$old_queue" ]; then
                apply_default_ttl
                setup_queue_rules
            fi
            if [ "$QUEUE" != "$old_queue" ]; then
                # Bound queues can't change live; restart onto the new range.
                killall -9 tether_shield 2>/dev/null
                start_daemon
            else
                # Daemon re-reads config.conf; no restart, so no window in
                # which packets bypass TTL fixing.
                for pid in $(pidof tether_shield); do kill -HUP "$pid"; done
            fi
        fi

        if conf_enabled TCP_LOW_LATENCY 1; then want_ll=1; else want_ll=0; fi
        if [ "$want_ll" != "$low_latency" ]; then
            if [ "$want_ll" = 1 ]; then apply_sysctls "$LL_SETTINGS"; else apply_sysctls "$LL_ORIGINALS"; fi
            low_latency="$want_ll"
        fi

        nat_rules="$(iptables -t nat -S tetherctrl_nat_POSTROUTING 2>/dev/null)"
        case "$nat_rules" in
            *MASQUERADE*) active=1 ;;
            *) active=0 ;;
        esac
        find_upstreams "$nat_rules"
        if conf_enabled BUFFERBLOAT_QOS 1; then qos=1; else qos=0; fi
        if conf_enabled WIFI_POWER_SAVE_LOCK 1; then psl=1; else psl=0; fi
        scan_ifaces
        state="$active|$qos|$psl|$TETHER_IFACES|$UPSTREAM_IFACES"

        if [ "$state" != "$applied" ]; then
            for i in $qos_ifaces; do tc qdisc del dev "$i" root 2>/dev/null; done
            for i in $psl_ifaces; do iw dev "$i" set power_save on 2>/dev/null; done
            qos_ifaces=""
            psl_ifaces=""
            if [ "$active" = 1 ]; then
                if [ "$qos" = 1 ]; then
                    for i in $TETHER_IFACES $UPSTREAM_IFACES; do
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
