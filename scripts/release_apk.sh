#!/bin/zsh
# Releases a new Android app version: bumps android/version.properties, runs the unit tests,
# builds the debug APK, copies it to ./IntelFeed.apk (gitignored) and installs it on every
# connected device with data kept. Commit the bump and merge it to main: CI then publishes the
# release android-v<version> with the APK attached (see docs/android-app.md).
#
#   scripts/release_apk.sh              # 1.x -> 1.x+1, test, build, install
#   scripts/release_apk.sh --major      # 1.x -> 2.0
#   scripts/release_apk.sh --install    # only install the current ./IntelFeed.apk on connected
#                                       # devices (e.g. a phone plugged in after the build)
#
# Host-side: needs JDK 17 and the Android SDK (ANDROID_HOME or android/local.properties), plus
# adb for installs. Run from anywhere in the checkout.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/android"
APK="$ROOT/IntelFeed.apk"
VERSION_FILE="$APP/version.properties"

ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"

# Installs $APK on every connected device (data kept); prints the device names.
install_all() {
  local out=()
  [[ -x "$ADB" ]] || { echo "adb not found at $ADB" >&2; echo ""; return 0; }
  for serial in $("$ADB" devices | awk 'NR>1 && $2=="device" {print $1}'); do
    local model=$("$ADB" -s "$serial" shell getprop ro.product.model | tr -d '\r')
    if "$ADB" -s "$serial" install -r "$APK" >/dev/null; then
      [[ "$serial" == emulator-* ]] && out+=("emulator") || out+=("$model")
    else
      echo "Install failed on $model ($serial)" >&2
    fi
  done
  echo "${(j:, :)out}"
}

major=0
case "$1" in
  --install)
    [[ -f "$APK" ]] || { echo "No APK at $APK; run $0 first."; exit 1; }
    where=$(install_all)
    [[ -z "$where" ]] && { echo "No device connected."; exit 1; }
    echo "Installed $(grep '^versionName=' "$VERSION_FILE" | cut -d= -f2) on: $where"
    exit 0 ;;
  --major) major=1 ;;
  "") ;;
  *) echo "usage: scripts/release_apk.sh [--major] | --install"; exit 1 ;;
esac

code=$(grep '^versionCode=' "$VERSION_FILE" | cut -d= -f2)
name=$(grep '^versionName=' "$VERSION_FILE" | cut -d= -f2)
new_code=$((code + 1))
if [[ $major -eq 1 ]]; then
  new_name="$(( ${name%%.*} + 1 )).0"
else
  new_name="${name%%.*}.$(( ${name#*.} + 1 ))"
fi
sed -i '' "s/^versionCode=.*/versionCode=$new_code/; s/^versionName=.*/versionName=$new_name/" "$VERSION_FILE"
echo "Version $name ($code) -> $new_name ($new_code)"

if ! (cd "$APP" && ./gradlew :app:testDebugUnitTest :app:assembleDebug -q); then
  # Put the old version back so a failed build doesn't use up a number.
  sed -i '' "s/^versionCode=.*/versionCode=$code/; s/^versionName=.*/versionName=$name/" "$VERSION_FILE"
  echo "Build or tests failed; version left at $name ($code)."
  exit 1
fi

cp "$APP/app/build/outputs/apk/debug/app-debug.apk" "$APK"
sha=$(shasum -a 256 "$APK" | cut -c1-12)

where=$(install_all); [[ -z "$where" ]] && where="not installed (no device connected)"

echo "Built $new_name (build $new_code), SHA-256 $sha, at $APK; installed on: $where"
echo "Next: commit android/version.properties and merge to main; CI publishes android-v$new_name."
