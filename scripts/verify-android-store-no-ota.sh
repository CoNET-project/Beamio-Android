#!/usr/bin/env bash
# Release gate: the Android shell `store` build must contain no remote PWA update path
# (store-build OTA plan A and the shell/PWA protocol, PM decision 2026-11-12).
# Read-only: it never changes the project or the artifacts.
#
#   scripts/verify-android-store-no-ota.sh [--expect-ota] DEX_DIR|FILE.apk|FILE.aab ...
#
# Fails (exit 1) when any dex contains:
#   - the update manifest / bundle URLs (beamio.app/app/update.json, SilentPassUI-<ver>.zip download base)
#   - the update-available event name (embeddedPwaUpdateAvailable)
#   - the capability bit (pwa.embedded-ota.v1, __CT_ANDROID_CAPS__)
#   (A method named applyEmbeddedPwaUpdate is allowed: since N4 the store build has a stub that only answers
#    {ok:false, reason:"ota_disabled"}. The download, staging and daemon code is what this gate rejects.)
#   - the update daemon class or its log text
# --expect-ota inverts the result (control run on a non-store build: must find the markers),
# so a gate that matches nothing cannot pass silently.
#
# There is no skip flag. Missing dexdump, no dex found, or an unreadable input is a failure.
# Exit code: 0 pass, 1 gate failed, 2 usage error.

set -euo pipefail

EXPECT_OTA=0
if [[ "${1:-}" == "--expect-ota" ]]; then
	EXPECT_OTA=1
	shift
fi
[[ $# -ge 1 ]] || { sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }

DEXDUMP="${DEXDUMP:-}"
if [[ -z "$DEXDUMP" ]]; then
	SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
	if [[ -n "$SDK" && -d "$SDK/build-tools" ]]; then
		DEXDUMP="$(ls -1d "$SDK"/build-tools/*/dexdump 2>/dev/null | sort -V | tail -1 || true)"
	fi
fi
if [[ -z "$DEXDUMP" || ! -x "$DEXDUMP" ]]; then
	echo '{"gate":"android-store-no-ota","result":"FAIL","reason":"dexdump not found (set ANDROID_HOME or DEXDUMP)"}'
	exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

DEX_LIST="$WORK/dex.list"
: >"$DEX_LIST"
n=0
for input in "$@"; do
	if [[ -d "$input" ]]; then
		find "$input" -type f -name '*.dex' >>"$DEX_LIST"
	elif [[ -f "$input" ]]; then
		n=$((n + 1))
		out="$WORK/in$n"
		mkdir -p "$out"
		unzip -q -o "$input" '*.dex' -d "$out" || { echo "{\"gate\":\"android-store-no-ota\",\"result\":\"FAIL\",\"reason\":\"cannot read dex from $input\"}"; exit 1; }
		find "$out" -type f -name '*.dex' >>"$DEX_LIST"
	else
		echo "{\"gate\":\"android-store-no-ota\",\"result\":\"FAIL\",\"reason\":\"input not found: $input\"}"
		exit 1
	fi
done
DEX_COUNT="$(wc -l <"$DEX_LIST" | tr -d ' ')"
if [[ "$DEX_COUNT" == "0" ]]; then
	echo '{"gate":"android-store-no-ota","result":"FAIL","reason":"no dex files found"}'
	exit 1
fi

STRINGS=(
	"beamio.app/app/update.json"
	"embeddedPwaUpdateAvailable"
	"pwa.embedded-ota.v1"
	"__CT_ANDROID_CAPS__"
	"EmbeddedPwaUpdateDaemon"
	"OTA daemon"
)
hits=()
while IFS= read -r dex; do
	for s in "${STRINGS[@]}"; do
		if LC_ALL=C grep -a -q -F "$s" "$dex"; then
			hits+=("string:$s@$(basename "$dex")")
		fi
	done
	# Every dex must parse (a corrupt or unreadable dex fails the gate).
	dump="$WORK/dump.txt"
	if ! "$DEXDUMP" "$dex" >"$dump" 2>/dev/null; then
		echo "{\"gate\":\"android-store-no-ota\",\"result\":\"FAIL\",\"reason\":\"dexdump cannot parse $(basename "$dex")\"}"
		exit 1
	fi
done <"$DEX_LIST"

joined="$(printf '%s,' "${hits[@]+"${hits[@]}"}" | sed 's/,$//')"
if [[ "$EXPECT_OTA" == "1" ]]; then
	if [[ ${#hits[@]} -gt 0 ]]; then
		echo "{\"gate\":\"android-store-no-ota\",\"mode\":\"expect-ota\",\"result\":\"PASS\",\"dex\":$DEX_COUNT,\"hits\":\"$joined\"}"
		exit 0
	fi
	echo "{\"gate\":\"android-store-no-ota\",\"mode\":\"expect-ota\",\"result\":\"FAIL\",\"dex\":$DEX_COUNT,\"reason\":\"no OTA markers in a build that should have them\"}"
	exit 1
fi
if [[ ${#hits[@]} -gt 0 ]]; then
	echo "{\"gate\":\"android-store-no-ota\",\"result\":\"FAIL\",\"dex\":$DEX_COUNT,\"hits\":\"$joined\"}"
	exit 1
fi
echo "{\"gate\":\"android-store-no-ota\",\"result\":\"PASS\",\"dex\":$DEX_COUNT}"
