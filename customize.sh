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

ui_print "- Initializing service..."
# v3.5 and earlier kept stats in the shell-writable /data/local/tmp
rm -f /data/local/tmp/ttlfixer_stats.json
killall -9 nfqttl tether_shield 2>/dev/null
nohup sh "$MODPATH/service.sh" </dev/null >/dev/null 2>&1 &

ui_print "- Installation completed successfully!"
