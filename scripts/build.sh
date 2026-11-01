#!/bin/sh
# Build the arm64 daemon with the version from module.prop baked in.
# Usage: scripts/build.sh [output]   (default: ./tether_shield)
# module.prop is the single source of the version; the binary reports it via
# /api/stats and the WebUI shows it from there.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/tether_shield}"
prop() { grep "^$1=" "$ROOT/module.prop" | head -n1 | cut -d= -f2 | tr -d '\r'; }

VERSION="$(prop version)"
CODE="$(prop versionCode)"
[ -n "$VERSION" ] && [ -n "$CODE" ] || { echo "module.prop is missing version/versionCode" >&2; exit 1; }

cd "$ROOT"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.moduleVersion=$VERSION -X main.moduleVersionCode=$CODE" \
    -o "$OUT" .
echo "built $OUT ($VERSION, $CODE)"
