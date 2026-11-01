#!/system/bin/sh
MODDIR=${0%/*}

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
sysctl -w net.core.default_qdisc=fq_codel 2>/dev/null
sysctl -w net.ipv4.tcp_slow_start_after_idle=0 2>/dev/null
sysctl -w net.ipv4.tcp_notsent_lowat=16384 2>/dev/null
sysctl -w net.ipv4.tcp_ecn=0 2>/dev/null
sysctl -w net.ipv4.tcp_autocorking=0 2>/dev/null
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

# 8. Dynamic Hotspot-Aware QoS & Power Saver Guard
(
    last_state="unknown"
    while true; do
        if iptables -t nat -S tetherctrl_nat_POSTROUTING 2>/dev/null | grep -q "MASQUERADE"; then
            current_state="active"
            if [ "$last_state" != "active" ]; then
                last_state="active"
            fi

            for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -E 'wlan|rmnet|ap|rndis'); do
                clean_iface=$(echo "$iface" | cut -d'@' -f1)
                tc qdisc replace dev "$clean_iface" root fq_codel 2>/dev/null
                iw dev "$clean_iface" set power_save off 2>/dev/null
            done
        else
            current_state="idle"
            if [ "$last_state" = "active" ]; then
                for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -E 'wlan|ap'); do
                    clean_iface=$(echo "$iface" | cut -d'@' -f1)
                    iw dev "$clean_iface" set power_save on 2>/dev/null
                done
                last_state="idle"
            fi
        fi
        sleep 5
    done
) </dev/null >/dev/null 2>&1 &
