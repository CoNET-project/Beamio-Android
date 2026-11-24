#!/usr/bin/env bash
# Formal-artifact OTA gate (manifest v2): a formal APK/AAB must carry no OTA test key and no QA override.
#   verify-android-ota-formal.sh <artifact.apk|artifact.aab> [--forbid-key <16hex>]... [--forbid-pubkey <base64>]...
# Checks every dex in the artifact for:
#   - the TEST keyIds and raw public keys (base64, as compiled into a key table) of the frozen vectors
#     (250cf19731885996, 633f7e7faa3978cd), plus any --forbid-key / --forbid-pubkey (e.g. a QA stub key);
#   - local stub addresses (10.0.2.2, http://127.0.0.1, localhost:) and the QA override names/labels
#     (OTA_QA_PUBLIC_KEY, otaQaPublicKey, -otaqa).
# A bare "127.0.0.1" is reported but allowed: LegacyBeamioHostGuard's dead proxy (blackhole for retired hosts) is not OTA.
# Prints one JSON line; exit 0 = PASS, 1 = FAIL, 2 = usage.
set -euo pipefail
[[ $# -ge 1 ]] || { echo "usage: $0 <apk|aab> [--forbid-key <16hex>]..." >&2; exit 2; }
ART="$1"; shift
KEYS=(250cf19731885996 633f7e7faa3978cd JytrEcHLssD2XnVRwuHCmC77qzVUd3xwfDPJNTvZbtk= x92U93Q9b7EaY78V3yMSmWoAyt9yFP6k4Y6GSEnyAPI=)
while [[ $# -gt 0 ]]; do
	case "$1" in
		--forbid-key) [[ "${2:-}" =~ ^[0-9a-f]{16}$ ]] || { echo "bad --forbid-key" >&2; exit 2; }; KEYS+=("$2"); shift 2 ;;
		--forbid-pubkey) [[ "${2:-}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "bad --forbid-pubkey" >&2; exit 2; }; KEYS+=("$2"); shift 2 ;;
		*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
done
[[ -f "$ART" ]] || { echo "no such artifact: $ART" >&2; exit 2; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
unzip -q -o "$ART" '*.dex' -d "$TMP" >/dev/null 2>&1 || true
DEX=()
while IFS= read -r f; do DEX+=("$f"); done < <(find "$TMP" -name '*.dex' | sort)
[[ ${#DEX[@]} -gt 0 ]] || { printf '{"gate":"android-ota-formal","result":"FAIL","reason":"no dex in artifact"}\n'; exit 1; }
FORBIDDEN=("${KEYS[@]}" "10.0.2.2" "http://127.0.0.1" "localhost:" "OTA_QA_PUBLIC_KEY" "otaQaPublicKey" "-otaqa")
HITS=()
for s in "${FORBIDDEN[@]}"; do
	n=$(cat "${DEX[@]}" | LC_ALL=C grep -a -F -c -- "$s" || true)
	[[ "$n" == "0" ]] || HITS+=("$s")
done
LOOPBACK=$(cat "${DEX[@]}" | LC_ALL=C grep -a -F -c -- "127.0.0.1" || true)
SHA=$(shasum -a 256 "$ART" | awk '{print $1}')
if [[ ${#HITS[@]} -eq 0 ]]; then
	printf '{"gate":"android-ota-formal","result":"PASS","artifact_sha256":"%s","dex":%d,"forbidden_checked":%d,"bare_loopback_lines":%s}\n' "$SHA" "${#DEX[@]}" "${#FORBIDDEN[@]}" "$LOOPBACK"
	exit 0
fi
printf '{"gate":"android-ota-formal","result":"FAIL","artifact_sha256":"%s","hits":"%s"}\n' "$SHA" "${HITS[*]}"
exit 1
