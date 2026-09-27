#!/system/bin/sh
MODDIR="/data/adb/modules/gki_hotspot_shield"
[ ! -f "$MODDIR/nfqttl" ] && MODDIR="/data/adb/modules/nfqttl"
[ ! -f "$MODDIR/nfqttl" ] && MODDIR="${0%/*}"

# 1. Ensure daemon is running
if ! ps -A | grep -q nfqttl; then
    nohup "$MODDIR/nfqttl" </dev/null >/dev/null 2>&1 &
    sleep 1
fi

# 2. Grant Xiaomi/HyperOS background popup & window permissions automatically
cmd appops set com.alperozd.hotspotshield 10021 allow 2>/dev/null
cmd appops set com.alperozd.hotspotshield 10022 allow 2>/dev/null
cmd appops set com.alperozd.hotspotshield 10008 allow 2>/dev/null
cmd appops set com.alperozd.hotspotshield SYSTEM_ALERT_WINDOW allow 2>/dev/null

# 3. Launch the zero-icon native config app
if pm list packages 2>/dev/null | grep -q "com.alperozd.hotspotshield"; then
    am start -n com.alperozd.hotspotshield/.MainActivity --user 0 -f 0x14000000 >/dev/null 2>&1
    exit 0
fi

# 4. Fallback: launch default web browser if companion app is not installed
URL="http://127.0.0.1:64640"
BROWSER=$(pm resolve-activity -a android.intent.action.VIEW -d "$URL" 2>/dev/null | grep packageName | head -n1 | cut -d'=' -f2)

if [ -n "$BROWSER" ]; then
    am start -a android.intent.action.VIEW -d "$URL" -p "$BROWSER" --user 0 -f 0x14000000 >/dev/null 2>&1
fi
am start -a android.intent.action.VIEW -d "$URL" --user 0 -f 0x14000000 >/dev/null 2>&1
