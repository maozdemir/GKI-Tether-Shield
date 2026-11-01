#!/bin/sh
# Verify every place that carries the module version agrees.
# Usage: scripts/check-version.sh [expected-tag]
# With a tag (release builds), the tag must equal module.prop's version.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
prop() { grep "^$1=" "$ROOT/module.prop" | head -n1 | cut -d= -f2 | tr -d '\r'; }

VERSION="$(prop version)"
CODE="$(prop versionCode)"
fail() { echo "version check failed: $*" >&2; exit 1; }

[ -n "$VERSION" ] && [ -n "$CODE" ] || fail "module.prop is missing version/versionCode"
case "$VERSION" in v*) ;; *) fail "module.prop version '$VERSION' must start with 'v'" ;; esac

if [ $# -ge 1 ]; then
    [ "$1" = "$VERSION" ] || fail "tag '$1' does not match module.prop version '$VERSION'"
fi

# update.json is a flat object; read fields without requiring jq.
json() { grep "\"$1\":" "$ROOT/update.json" | head -n1 | sed 's/^[^:]*: *//; s/[",]//g; s/[[:space:]]*$//'; }
[ "$(json version)" = "$VERSION" ] || fail "update.json version '$(json version)' != $VERSION"
[ "$(json versionCode)" = "$CODE" ] || fail "update.json versionCode '$(json versionCode)' != $CODE"
case "$(json zipUrl)" in
    */releases/download/"$VERSION"/GKI_Tether_Shield_"$VERSION".zip) ;;
    *) fail "update.json zipUrl does not point at the $VERSION release asset" ;;
esac

grep -q "MODULE_VERSION *= \"$VERSION\"" "$ROOT/main.go" || fail "main.go MODULE_VERSION != $VERSION"
grep -q "MODULE_VERSION_CODE *= $CODE\$" "$ROOT/main.go" || fail "main.go MODULE_VERSION_CODE != $CODE"

echo "version $VERSION ($CODE) is consistent"
