#!/bin/sh
# Package the Magisk/KernelSU/APatch module ZIP.
# Usage: scripts/package.sh <version-tag> [output-dir]
# Expects the arm64 daemon binary ./nfqttl to be built already.
set -eu

TAG="${1:?usage: scripts/package.sh <version-tag> [output-dir]}"
OUT_DIR="${2:-.}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[ -f "$ROOT/nfqttl" ] || { echo "error: $ROOT/nfqttl not found; build it first" >&2; exit 1; }

for f in module.prop config.conf service.sh customize.sh action.sh uninstall.sh \
         HotspotShieldManager.apk nfqttl update.json changelog.md; do
    cp "$ROOT/$f" "$STAGE/"
done
cp -R "$ROOT/META-INF" "$STAGE/"
mkdir -p "$STAGE/system/bin" "$STAGE/webroot"
cp "$ROOT/scripts/ttlshield" "$STAGE/system/bin/ttlshield"
cp "$ROOT/index.html" "$STAGE/webroot/index.html"
chmod 0755 "$STAGE/nfqttl" "$STAGE"/*.sh "$STAGE/system/bin/ttlshield"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
ZIP="$OUT_DIR/GKI_Tether_Shield_${TAG}.zip"
rm -f "$ZIP"
(cd "$STAGE" && zip -qr9 "$ZIP" .)
# Legacy asset name kept for links to older releases.
cp "$ZIP" "$OUT_DIR/GKI_Hotspot_Shield_${TAG}.zip"
echo "$ZIP"
