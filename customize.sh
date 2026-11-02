SKIPUNZIP=0

VERSION="$(sed -n 's/^version=//p' "$MODPATH/module.prop" | head -n1)"
ui_print "*****************************************"
ui_print "*   GKI Tether Shield & TTL/DPI Fixer   *"
ui_print "*   ${VERSION:-unknown} by maozdemir"
ui_print "*****************************************"

ui_print "- Setting up permissions..."
set_perm "$MODPATH/tether_shield" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/system/bin/ttlshield" 0 0 0755

# Updates are installed as a fresh module directory, which would reset the
# user's settings to the shipped defaults. Carry the live config over; keys
# added in newer versions fall back to their defaults when missing.
OLD_CONF="/data/adb/modules/${MODID:-gki_hotspot_shield}/config.conf"
if [ -f "$OLD_CONF" ] && [ "$OLD_CONF" != "$MODPATH/config.conf" ]; then
    ui_print "- Keeping your existing settings..."
    cp -f "$OLD_CONF" "$MODPATH/config.conf"
    set_perm "$MODPATH/config.conf" 0 0 0644
fi

# set_conf KEY VALUE: set KEY in the new config.conf, adding it if missing.
set_conf() {
    if grep -q "^$1=" "$MODPATH/config.conf"; then
        sed -i "s/^$1=.*/$1=$2/" "$MODPATH/config.conf"
    else
        [ -z "$(tail -c 1 "$MODPATH/config.conf")" ] || echo >> "$MODPATH/config.conf"
        echo "$1=$2" >> "$MODPATH/config.conf"
    fi
}

# Pick the TTL engine for this phone on every install and update. The self
# test never touches the real network: it checks the eBPF program in the
# kernel's test runner and on a throwaway virtual interface pair. The daemon
# still falls back to NFQUEUE on its own if eBPF fails later.
ui_print "- Testing the in-kernel (eBPF) TTL engine..."
if ST="$("$MODPATH/tether_shield" ebpf-selftest 2>&1)"; then
    set_conf TTL_ENGINE ebpf
    ui_print "  Works on this phone: TTL is fixed in the kernel (eBPF)"
else
    set_conf TTL_ENGINE nfqueue
    ui_print "  Not available here, using NFQUEUE:"
    ui_print "  $(echo "$ST" | tail -n 1 | cut -c 1-160)"
fi

ui_print "- Installing mini config companion app (zero drawer icon)..."
if [ -f "$MODPATH/HotspotShieldManager.apk" ]; then
    APK="$MODPATH/HotspotShieldManager.apk"
    if ! pm install -r "$APK" >/dev/null 2>&1; then
        # Usually a signing-key change (builds without the release key are
        # signed with a fresh key): Android refuses the update, so reinstall.
        # The app keeps no data; the daemon re-reads its new UID on its own.
        pm uninstall com.alperozd.hotspotshield >/dev/null 2>&1
        pm install "$APK" >/dev/null 2>&1 ||
            ui_print "! Companion app install failed; use the browser dashboard instead"
    fi
    cmd appops set com.alperozd.hotspotshield 10021 allow 2>/dev/null
    cmd appops set com.alperozd.hotspotshield 10022 allow 2>/dev/null
    cmd appops set com.alperozd.hotspotshield 10008 allow 2>/dev/null
    cmd appops set com.alperozd.hotspotshield SYSTEM_ALERT_WINDOW allow 2>/dev/null
fi

# v3.5 and earlier kept stats in the shell-writable /data/local/tmp
rm -f /data/local/tmp/ttlfixer_stats.json

# On an update the installed version's service.sh loop (started at boot)
# keeps running; starting a second one here would run two loops and two
# daemons fighting over the same ports. Leave it running until the reboot
# that applies the update (a disabled module stays off, as its owner chose).
# Only a fresh install starts right away.
LIVE_MOD="/data/adb/modules/${MODID:-gki_hotspot_shield}"
if [ "$LIVE_MOD" != "$MODPATH" ] && [ -d "$LIVE_MOD" ]; then
    ui_print "- Installation completed! Reboot to apply the update"
    ui_print "  (the installed version stays as it is until then)."
else
    ui_print "- Starting the service..."
    killall -9 nfqttl tether_shield 2>/dev/null
    nohup sh "$MODPATH/service.sh" </dev/null >/dev/null 2>&1 &
    ui_print "- Installation completed successfully!"
fi
