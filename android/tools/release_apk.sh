#!/bin/zsh
# Releases a new APK: bumps version.properties, tests, builds, copies to ../IntelFeed.apk,
# records the release in APK_VERSIONS.md and installs it on every connected device.
#
#   tools/release_apk.sh "What changed" [--by Claude|Gemini] [--major]
#   tools/release_apk.sh --install     # install the current ../IntelFeed.apk on connected devices
#                                      # (e.g. a phone plugged in after the release) and note it
#
# Run from the project root (the folder with version.properties).
set -e
cd "$(dirname "$0")/.."

ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"

# Installs ../IntelFeed.apk on every connected device (data kept); prints the device names.
install_all() {
  local out=()
  for serial in $("$ADB" devices | awk 'NR>1 && $2=="device" {print $1}'); do
    local model=$("$ADB" -s "$serial" shell getprop ro.product.model | tr -d '\r')
    if "$ADB" -s "$serial" install -r ../IntelFeed.apk >/dev/null; then
      [[ "$serial" == emulator-* ]] && out+=("emulator") || out+=("$model")
    else
      echo "Install failed on $model ($serial)" >&2
    fi
  done
  echo "${(j:, :)out}"
}

summary=""; by="Claude"; major=0
if [[ "$1" == "--install" ]]; then
  where=$(install_all)
  [[ -z "$where" ]] && { echo "No device connected."; exit 1; }
  # Add the devices to the newest row's "Installed on" column.
  python3 - "$where" <<'PY'
import sys
new = [d.strip() for d in sys.argv[1].split(",") if d.strip()]
p = "APK_VERSIONS.md"
lines = open(p).read().split("\n")
i = next(i for i, l in enumerate(lines) if l.startswith("|---")) + 1
cells = lines[i].split("|")
had = [] if cells[-2].strip().startswith("not installed") else [d.strip() for d in cells[-2].split(",") if d.strip()]
cells[-2] = " " + ", ".join(had + [d for d in new if d not in had]) + " "
lines[i] = "|".join(cells)
open(p, "w").write("\n".join(lines))
PY
  echo "Installed $(grep '^versionName=' version.properties | cut -d= -f2) on: $where"
  exit 0
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --by) by="$2"; shift 2 ;;
    --major) major=1; shift ;;
    *) summary="$1"; shift ;;
  esac
done
[[ -z "$summary" ]] && { echo "usage: tools/release_apk.sh \"what changed\" [--by Claude|Gemini] [--major]"; exit 1; }

code=$(grep '^versionCode=' version.properties | cut -d= -f2)
name=$(grep '^versionName=' version.properties | cut -d= -f2)
new_code=$((code + 1))
if [[ $major -eq 1 ]]; then
  new_name="$(( ${name%%.*} + 1 )).0"
else
  new_name="${name%%.*}.$(( ${name#*.} + 1 ))"
fi
sed -i '' "s/^versionCode=.*/versionCode=$new_code/; s/^versionName=.*/versionName=$new_name/" version.properties
echo "Version $name ($code) -> $new_name ($new_code)"

if ! ./gradlew :app:testDebugUnitTest :app:assembleDebug -q; then
  # Put the old version back so a failed build doesn't use up a number.
  sed -i '' "s/^versionCode=.*/versionCode=$code/; s/^versionName=.*/versionName=$name/" version.properties
  echo "Build or tests failed; version left at $name ($code)."
  exit 1
fi

cp app/build/outputs/apk/debug/app-debug.apk ../IntelFeed.apk
sha=$(shasum -a 256 ../IntelFeed.apk | cut -c1-12)
when=$(date '+%Y-%m-%d %H:%M')

where=$(install_all); [[ -z "$where" ]] && where="not installed (no device connected)"

# Newest row goes right under the table header.
row="| $new_name | $new_code | $when | $sha | $by | $summary | $where |"
python3 - "$row" <<'PY'
import sys
row = sys.argv[1]
p = "APK_VERSIONS.md"
lines = open(p).read().split("\n")
i = next(i for i, l in enumerate(lines) if l.startswith("|---"))
lines.insert(i + 1, row)
open(p, "w").write("\n".join(lines))
PY
echo "Released $new_name (build $new_code), SHA-256 $sha, installed on: $where"
