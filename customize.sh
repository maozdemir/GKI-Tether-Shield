SKIPUNZIP=0

ui_print "*****************************************"
ui_print "*   GKI Hotspot Shield & TTL/DPI Fixer  *"
ui_print "*                  v3.6                 *"
ui_print "*             by alperozd               *"
ui_print "*****************************************"

ui_print "- Setting up permissions..."
set_perm "$MODPATH/tether_shield" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/system/bin/ttlshield" 0 0 0755

ui_print "- Installing mini config companion app (zero drawer icon)..."
if [ -f "$MODPATH/HotspotShieldManager.apk" ]; then
    pm install -r "$MODPATH/HotspotShieldManager.apk" >/dev/null 2>&1
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
