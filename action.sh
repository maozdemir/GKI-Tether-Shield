#!/system/bin/sh
MODDIR="/data/adb/modules/gki_hotspot_shield"
[ -d "$MODDIR" ] || MODDIR="${0%/*}"
APP=com.alperozd.hotspotshield

# 1. Ensure daemon is running
if ! pidof tether_shield >/dev/null; then
    nohup "$MODDIR/tether_shield" </dev/null >"$MODDIR/daemon.stderr" 2>&1 &
fi

# The daemon's per-boot token (root-only) lets the app verify it is talking
# to the real daemon and lets the browser fallback save settings. The daemon
# creates it at startup, so wait briefly if it was only just started.
TOKEN=""
tries=0
while [ $tries -lt 10 ]; do
    [ -r "$MODDIR/.webui_token" ] && read -r TOKEN < "$MODDIR/.webui_token"
    [ -n "$TOKEN" ] && break
    tries=$((tries + 1))
    sleep 0.5
done

# 2. Grant Xiaomi/HyperOS background popup & window permissions automatically
cmd appops set $APP 10021 allow 2>/dev/null
cmd appops set $APP 10022 allow 2>/dev/null
cmd appops set $APP 10008 allow 2>/dev/null
cmd appops set $APP SYSTEM_ALERT_WINDOW allow 2>/dev/null

# 3. Launch the zero-icon native config app. The explicit component (-n)
# means only this app can receive the token extra.
if pm list packages 2>/dev/null | grep -qx "package:$APP"; then
    am start -n $APP/.MainActivity --es token "$TOKEN" --user 0 -f 0x14000000 >/dev/null 2>&1
    exit 0
fi

# 4. Fallback: launch the default web browser if the companion app is missing
URL="http://127.0.0.1:64640"
BROWSER=$(pm resolve-activity -a android.intent.action.VIEW -d "$URL" 2>/dev/null | grep packageName | head -n1 | cut -d'=' -f2)

# daemon_owns_dashboard: succeeds if 127.0.0.1:64640 (hex FC80) is listened
# on, and only by root. If another app grabbed the port, its page would read
# the token from the URL, so the browser must not get it.
daemon_owns_dashboard() {
    found=1
    for table in ${PROC_NET_TCP_TABLES:-/proc/net/tcp /proc/net/tcp6}; do
        [ -r "$table" ] || continue
        while read -r _ local _ state _ _ _ uid _; do
            case "$local" in *:FC80) ;; *) continue ;; esac
            [ "$state" = 0A ] || continue   # 0A = LISTEN
            [ "$uid" = 0 ] || return 1
            found=0
        done < "$table"
    done
    return $found
}

if [ -n "$BROWSER" ]; then
    # Saving needs the token (only the companion app is trusted by UID). It
    # is only sent when the daemon really owns the port, pinned to the
    # resolved browser (-p), never as an open intent another app could
    # receive; the URL fragment never leaves the browser.
    [ -n "$TOKEN" ] && daemon_owns_dashboard && URL="$URL/#token=$TOKEN"
    am start -a android.intent.action.VIEW -d "$URL" -p "$BROWSER" --user 0 -f 0x14000000 >/dev/null 2>&1
else
    # No resolvable browser: open the read-only dashboard without a token.
    am start -a android.intent.action.VIEW -d "$URL" --user 0 -f 0x14000000 >/dev/null 2>&1
fi
