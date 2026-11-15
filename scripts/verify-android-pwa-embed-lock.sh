#!/usr/bin/env bash
# Build gate (same-sha-gate.md section 3, item 1 and 3): the Android shell's embedded PWA zip must be
# the one recorded in the lock, and the lock must agree with the freeze manifest when one is shipped.
# The expected SHA-256 that goes into BuildConfig.PWA_ZIP_SHA256 comes from the lock, never from the
# zip itself, so a wrong zip put in at build time fails here instead of passing the startup check.
# Read-only: it never changes the project.
#
#   scripts/verify-android-pwa-embed-lock.sh --app-dir DIR
#
# DIR/pwa-embed.lock (key=value, same format as the iOS lock), required keys:
#   zip_sha256   64 lowercase hex, SHA-256 of DIR/src/main/assets/SilentPassUI.zip
#   zip_ver      equals "ver" in update.json at the zip root
# Optional keys, checked when present:
#   freeze_manifest_sha256, freeze_ver, freeze_zip_sha256
# When DIR/pwa-freeze-manifest.json exists, all three freeze_* keys are required and must match it
# (file SHA-256, "version", "zip_sha256"), its "status" must be "frozen", and freeze_zip_sha256 and
# freeze_ver must equal zip_sha256 and zip_ver.
#
# No skip flag. Exit code: 0 pass, 1 gate failed, 2 usage error. Output: one JSON line.

set -euo pipefail

APP_DIR=""
while [[ $# -gt 0 ]]; do
	case "$1" in
		--app-dir) APP_DIR="${2:-}"; shift 2 ;;
		*) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
	esac
done
[[ -n "$APP_DIR" ]] || { echo "usage: $0 --app-dir DIR" >&2; exit 2; }

fail() {
	printf '{"gate":"android-pwa-embed-lock","result":"FAIL","reason":"%s"}\n' "$1"
	exit 1
}
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

LOCK="$APP_DIR/pwa-embed.lock"
ZIP="$APP_DIR/src/main/assets/SilentPassUI.zip"
MANIFEST="$APP_DIR/pwa-freeze-manifest.json"

[[ -f "$LOCK" ]] || fail "lock missing: pwa-embed.lock"
[[ -f "$ZIP" ]] || fail "embedded zip missing: src/main/assets/SilentPassUI.zip"

# Each key may appear once (checked here, in the main shell, so the failure stops the gate).
for k in zip_sha256 zip_ver freeze_manifest_sha256 freeze_ver freeze_zip_sha256; do
	n="$(grep -cE "^$k=" "$LOCK" || true)"
	[[ "$n" -le 1 ]] || fail "lock key $k appears $n times"
done
lock_get() { grep -E "^$1=" "$LOCK" | head -1 | cut -d= -f2- | tr -d '[:space:]' || true; }

LOCK_SHA="$(lock_get zip_sha256)"
LOCK_VER="$(lock_get zip_ver)"
[[ "$LOCK_SHA" =~ ^[0-9a-f]{64}$ ]] || fail "lock zip_sha256 is not 64 lowercase hex"
[[ -n "$LOCK_VER" ]] || fail "lock zip_ver missing"

ZIP_SHA="$(sha256 "$ZIP")"
[[ "$ZIP_SHA" == "$LOCK_SHA" ]] || fail "embedded zip sha256 $ZIP_SHA is not the lock zip_sha256 $LOCK_SHA"

ZIP_VER="$(unzip -p "$ZIP" update.json 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("ver",""))' 2>/dev/null || true)"
[[ -n "$ZIP_VER" ]] || fail "embedded zip has no readable update.json ver"
[[ "$ZIP_VER" == "$LOCK_VER" ]] || fail "embedded zip ver $ZIP_VER is not the lock zip_ver $LOCK_VER"

F_MSHA="$(lock_get freeze_manifest_sha256)"
F_VER="$(lock_get freeze_ver)"
F_ZSHA="$(lock_get freeze_zip_sha256)"
if [[ -f "$MANIFEST" ]]; then
	[[ -n "$F_MSHA" && -n "$F_VER" && -n "$F_ZSHA" ]] || fail "pwa-freeze-manifest.json present but lock lacks freeze_* keys"
	M_SHA="$(sha256 "$MANIFEST")"
	[[ "$M_SHA" == "$F_MSHA" ]] || fail "pwa-freeze-manifest.json sha256 $M_SHA is not the lock freeze_manifest_sha256 $F_MSHA"
	read -r M_STATUS M_VER M_ZSHA < <(python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); print(m.get("status",""), m.get("version",""), str(m.get("zip_sha256","")).lower())' "$MANIFEST")
	[[ "$M_STATUS" == "frozen" ]] || fail "freeze manifest status is $M_STATUS, not frozen"
	[[ "$M_VER" == "$F_VER" && "$M_ZSHA" == "$F_ZSHA" ]] || fail "freeze manifest version/zip_sha256 do not match the lock"
	[[ "$F_ZSHA" == "$LOCK_SHA" && "$F_VER" == "$LOCK_VER" ]] || fail "lock freeze_* do not equal zip_sha256/zip_ver"
elif [[ -n "$F_MSHA$F_VER$F_ZSHA" ]]; then
	fail "lock names a freeze manifest but pwa-freeze-manifest.json is missing"
fi

printf '{"gate":"android-pwa-embed-lock","result":"PASS","zip_sha256":"%s","zip_ver":"%s","freeze_manifest":%s}\n' \
	"$LOCK_SHA" "$LOCK_VER" "$([[ -f "$MANIFEST" ]] && echo true || echo false)"
