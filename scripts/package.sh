#!/bin/sh
# Package the Magisk/KernelSU/APatch module ZIP.
# Usage: scripts/package.sh <version-tag> [output-dir]
# Expects ./tether_shield (scripts/build.sh) and the APK (scripts/build-apk.sh).
set -eu

TAG="${1:?usage: scripts/package.sh <version-tag> [output-dir]}"
OUT_DIR="${2:-.}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[ -f "$ROOT/tether_shield" ] || { echo "error: $ROOT/tether_shield not found; run scripts/build.sh first" >&2; exit 1; }
[ -f "$ROOT/HotspotShieldManager.apk" ] || { echo "error: $ROOT/HotspotShieldManager.apk not found; run scripts/build-apk.sh first" >&2; exit 1; }

for f in module.prop config.conf service.sh customize.sh action.sh uninstall.sh \
         HotspotShieldManager.apk tether_shield update.json changelog.md; do
    cp "$ROOT/$f" "$STAGE/"
done
cp -R "$ROOT/META-INF" "$STAGE/"
mkdir -p "$STAGE/system/bin" "$STAGE/webroot"
cp "$ROOT/scripts/ttlshield" "$STAGE/system/bin/ttlshield"
cp "$ROOT/index.html" "$STAGE/webroot/index.html"
chmod 0755 "$STAGE/tether_shield" "$STAGE"/*.sh "$STAGE/system/bin/ttlshield"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
ZIP="$OUT_DIR/GKI_Tether_Shield_${TAG}.zip"
rm -f "$ZIP"
(cd "$STAGE" && zip -qr9 "$ZIP" .)
# Legacy asset name kept for links to older releases.
cp "$ZIP" "$OUT_DIR/GKI_Hotspot_Shield_${TAG}.zip"
echo "$ZIP"
