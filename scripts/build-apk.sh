#!/bin/sh
# Build and sign the companion app (HotspotShieldManager.apk) from app/.
# Usage: scripts/build-apk.sh [output]   (default: ./HotspotShieldManager.apk)
#
# Needs ANDROID_HOME (platform android-$PLATFORM, build-tools $BUILD_TOOLS)
# and a JDK. Signing key, from the environment:
#   APK_KEYSTORE_B64, APK_KEYSTORE_PASSWORD, APK_KEY_ALIAS  - release key
# Without them a throwaway key is generated. That changes the signature on
# every build, which is fine: customize.sh reinstalls the app when Android
# refuses an update signed with a different key (the app keeps no data).
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/HotspotShieldManager.apk}"
PLATFORM="${PLATFORM:-35}"
BUILD_TOOLS="${BUILD_TOOLS:-35.0.0}"
SDK="${ANDROID_HOME:?ANDROID_HOME must point at the Android SDK}"
BT="$SDK/build-tools/$BUILD_TOOLS"
ANDROID_JAR="$SDK/platforms/android-$PLATFORM/android.jar"

# Tools are plain executables on Linux/macOS and .exe/.bat on Windows.
tool() {
    for candidate in "$BT/$1" "$BT/$1.exe" "$BT/$1.bat"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "missing build tool: $1 in $BT" >&2
    exit 1
}
AAPT2="$(tool aapt2)"
D8="$(tool d8)"
ZIPALIGN="$(tool zipalign)"
APKSIGNER="$(tool apksigner)"
[ -f "$ANDROID_JAR" ] || { echo "missing $ANDROID_JAR" >&2; exit 1; }

prop() { grep "^$1=" "$ROOT/module.prop" | head -n1 | cut -d= -f2 | tr -d '\r'; }
VERSION="$(prop version)"
CODE="$(prop versionCode)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/classes" "$WORK/dex"

# 1. Resources + manifest (version injected from module.prop).
"$AAPT2" compile --dir "$ROOT/app/res" -o "$WORK/res.zip"
"$AAPT2" link -I "$ANDROID_JAR" \
    --manifest "$ROOT/app/AndroidManifest.xml" \
    --version-code "$CODE" --version-name "${VERSION#v}" \
    -o "$WORK/unsigned.apk" "$WORK/res.zip"

# 2. Code: Java -> class files -> dex.
javac -source 11 -target 11 -nowarn -encoding UTF-8 \
    -bootclasspath "$ANDROID_JAR" -classpath "$ANDROID_JAR" \
    -d "$WORK/classes" $(find "$ROOT/app/src" -name '*.java')
"$D8" --release --min-api 26 --lib "$ANDROID_JAR" --output "$WORK/dex" \
    $(find "$WORK/classes" -name '*.class')
(cd "$WORK/dex" && jar -u -M -f "$WORK/unsigned.apk" classes.dex)

# 3. Align and sign.
"$ZIPALIGN" -p -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
if [ -n "${APK_KEYSTORE_B64:-}" ]; then
    printf '%s' "$APK_KEYSTORE_B64" | base64 -d > "$WORK/release.jks"
    KS="$WORK/release.jks"
    ALIAS="${APK_KEY_ALIAS:?APK_KEY_ALIAS is required with APK_KEYSTORE_B64}"
    export APK_KS_PASS="${APK_KEYSTORE_PASSWORD:?APK_KEYSTORE_PASSWORD is required}"
    echo "signing with the release key"
else
    KS="$WORK/throwaway.jks"
    ALIAS=throwaway
    APK_KS_PASS="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    export APK_KS_PASS
    keytool -genkeypair -keystore "$KS" -storetype PKCS12 -alias "$ALIAS" \
        -keyalg RSA -keysize 3072 -validity 10000 -dname "CN=GKI Tether Shield" \
        -storepass "$APK_KS_PASS" -keypass "$APK_KS_PASS" >/dev/null 2>&1
    echo "signing with a throwaway key (no APK_KEYSTORE_B64 set)"
fi
"$APKSIGNER" sign --ks "$KS" --ks-key-alias "$ALIAS" --ks-pass env:APK_KS_PASS \
    --key-pass env:APK_KS_PASS --out "$OUT" "$WORK/aligned.apk"
"$APKSIGNER" verify "$OUT"
rm -f "$OUT.idsig"
echo "built $OUT ($VERSION, $CODE)"
