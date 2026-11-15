#!/usr/bin/env bash
# Copy the approved SilentPassUI release ZIP into ONE Consumer native shell
# (bootstrap bundle), as the one fixed-name file that shell loads:
#   --only ios      src/CashTrees_iOS/CashTrees_iOS/CashTrees_iOS/SilentPassUI.zip
#   --only android  src/CaehTrees/app/src/main/assets/SilentPassUI.zip
# --only is required: the script never writes both shells in one run (project
# owner single-ZIP rule, 2026-11-10: no double write from the sync script).
#
# Single-ZIP rule (.cursor/rules/beamio-native-shell-single-zip.mdc): each
# shell's packaging folder holds exactly one ZIP, SilentPassUI.zip. The iOS
# target is a file-system synchronized folder, so any other ZIP there (an old
# version, a backup, a temp copy) ships inside the app. This script never
# writes a versioned ZIP into a shell folder and never downloads anything: you
# pass the approved ZIP and its SHA-256 explicitly.
#
# Usage:
#   scripts/syncEmbeddedPwaZipToNativeShells.sh --only ios|android --zip PATH --sha256 HEX
#       [--ver X.Y.Z]
#       [--unreleased-test --freeze-manifest FILE | --approved-ver X --approved-sha HEX --approval TEXT]
#       [--archive-dir DIR] [--ios-resources DIR] [--android-app-dir DIR]
#
#   --only           the one shell to write: ios or android (required)
#   --zip            the approved release ZIP (for example the file downloaded
#                    from https://beamio.ca/app/SilentPassUI-<ver>.zip, or a
#                    local candidate the PM approved)
#   --sha256         its approved SHA-256; the copy is refused if it differs
#   --ver            expected update.json "ver" inside the ZIP (optional; when
#                    omitted, the ZIP's own ver is used for the gates)
#   --unreleased-test  the ZIP is a frozen, not-yet-released PWA above the
#                    released version: test shells only (labelled 未发布测试).
#                    Requires --freeze-manifest (PM, 2026-11-11).
#   --freeze-manifest  the PWA integration lead's freeze manifest JSON
#                    (owner freeze rule, PM 2026-11-11; passed in by path). Before anything
#                    is written: status must be "frozen", --sha256 must equal its
#                    zip_sha256, the ZIP's ver must equal its version, and the
#                    shared checker must pass with it. Both shells keep a copy as
#                    pwa-freeze-manifest.json next to pwa-embed.lock.
#   --qa-manifest FILE (PM R509) with --unreleased-test: a QA candidate, NOT FROZEN. Before anything is
#                    written: status must be "qa-candidate", not_frozen true, freeze_kind
#                    "qa-candidate-not-frozen", --sha256 must equal its zip_sha256 and the ZIP's ver its
#                    version. The checker verdict is QA; it never makes a formal package. iOS keeps the copy
#                    in the same declared input file, and the lock carries qa_manifest_* keys.
#   --approved-ver / --approved-sha / --approval
#                    the ZIP is an approved shell release above the released
#                    version (all three required; version and SHA-256 must match)
#   --archive-dir    also keep a copy named SilentPassUI-<ver>.zip in this
#                    existing folder; it must be outside this repository
#   --ios-resources  iOS packaging folder (--only ios; default: the shell's
#                    resource folder; also IOS_RESOURCES_DIR)
#   --android-app-dir Android app module folder holding src/*/assets
#                    (--only android; default: src/CaehTrees/app; also ANDROID_APP_DIR)
#
# Steps: check the ZIP (SHA-256, index.html and update.json at the root, no
# nested ZIP), check the PWA version rule (scripts/verify-shell-pwa-version.sh:
# the released PWA = the exact ZIP the live https://beamio.ca/app/update.json
# names; older, voided, same-version-different-bytes, or higher without a test
# or approval flag are refused), refuse to write when the selected shell's
# packaging folder already holds a ZIP other than SilentPassUI.zip, write the
# fixed-name copy for that shell only, write that shell's declaration
# pwa-embed.lock (key=value; iOS: next to the Xcode project, read by the build
# phase "Verify embedded PWA version"; Android: <app>/pwa-embed.lock, read by
# app/build.gradle.kts and scripts/verify-android-pwa-embed-lock.sh) and the
# freeze manifest copy, then run that shell's pre-build gates
# (verify-ios-single-zip.sh pre, or verify-android-single-zip.sh prebuild and,
# when present, verify-android-pwa-embed-lock.sh). The other shell's files are
# never read for writing or touched.
#
# Freeze manifest copy: iOS always has pwa-freeze-manifest.json (a declared
# Xcode input; {"status": "none"} when unused). Android has it only for a
# frozen ZIP; without --freeze-manifest an older copy is removed, because the
# Android lock gate requires the freeze_* keys whenever the copy exists.
# Exit 0 = written and the gate passes; 1 = refused or gate failed;
# 2 = bad usage (including a missing --only).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
ZIP_NAME="SilentPassUI.zip"

IOS_DIR="${IOS_RESOURCES_DIR:-$REPO_ROOT/src/CashTrees_iOS/CashTrees_iOS/CashTrees_iOS}"
ANDROID_APP="${ANDROID_APP_DIR:-$REPO_ROOT/src/CaehTrees/app}"
SRC_ZIP=""
SHA=""
VER=""
ARCHIVE_DIR=""
UNRELEASED_TEST=0
APPROVED_VER=""
QA=""
APPROVED_SHA=""
APPROVAL=""
ONLY=""
FREEZE=""

usage() { sed -n '2,68p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "REFUSED: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--only) ONLY="${2:?--only needs ios or android}"; shift 2 ;;
		--zip) SRC_ZIP="${2:?--zip needs a value}"; shift 2 ;;
		--sha256) SHA="${2:?--sha256 needs a value}"; shift 2 ;;
		--ver) VER="${2:?--ver needs a value}"; shift 2 ;;
		--archive-dir) ARCHIVE_DIR="${2:?--archive-dir needs a value}"; shift 2 ;;
		--unreleased-test) UNRELEASED_TEST=1; shift ;;
		--freeze-manifest) FREEZE="${2:?--freeze-manifest needs a file}"; shift 2 ;;
		--qa-manifest) QA="${2:?--qa-manifest needs a file}"; shift 2 ;;
		--approved-ver) APPROVED_VER="${2:?--approved-ver needs a value}"; shift 2 ;;
		--approved-sha) APPROVED_SHA="${2:?--approved-sha needs a value}"; shift 2 ;;
		--approval) APPROVAL="${2:?--approval needs a value}"; shift 2 ;;
		--ios-resources) IOS_DIR="${2:?--ios-resources needs a value}"; shift 2 ;;
		--android-app-dir) ANDROID_APP="${2:?--android-app-dir needs a value}"; shift 2 ;;
		-h | --help) usage ;;
		*) echo "unknown argument: $1" >&2; usage ;;
	esac
done

case "$ONLY" in
	ios | android) ;;
	"") echo "error: --only ios|android is required; this script writes exactly one shell per run (no double write)" >&2; exit 2 ;;
	*) echo "error: --only must be ios or android (got '$ONLY')" >&2; exit 2 ;;
esac
[[ -n "$SRC_ZIP" && -n "$SHA" ]] || { echo "--zip and --sha256 are required" >&2; usage; }
if [[ "$UNRELEASED_TEST" == "1" && -z "$FREEZE" && -z "$QA" ]]; then
	echo "error: --unreleased-test requires --freeze-manifest FILE or --qa-manifest FILE (only a frozen PWA, or a QA candidate, may go into a shell before release approval)" >&2; exit 2
fi
if [[ -n "$QA" ]]; then
	[[ "$UNRELEASED_TEST" == "1" ]] || { echo "--qa-manifest needs --unreleased-test (a QA candidate is never a formal package)" >&2; exit 2; }
	[[ -z "$FREEZE" ]] || { echo "use either --freeze-manifest or --qa-manifest, not both" >&2; exit 2; }
	[[ -z "$APPROVED_VER$APPROVED_SHA$APPROVAL" ]] || { echo "--qa-manifest cannot be combined with --approved-*" >&2; exit 2; }
fi
if [[ -n "$FREEZE" && "$UNRELEASED_TEST" != "1" ]]; then
	echo "error: --freeze-manifest is used together with --unreleased-test" >&2; exit 2
fi
[[ "$SHA" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "--sha256 must be 64 hex characters" >&2; exit 2; }
SHA="$(printf '%s' "$SHA" | tr 'A-F' 'a-f')"
[[ -f "$SRC_ZIP" ]] || die "ZIP not found: $SRC_ZIP"
if [[ "$ONLY" == "ios" ]]; then
	[[ -d "$IOS_DIR" ]] || die "iOS resource folder not found: $IOS_DIR"
else
	[[ -d "$ANDROID_APP/src/main/assets" ]] || die "Android assets folder not found: $ANDROID_APP/src/main/assets"
fi
echo "==> Target shell: $ONLY (the other shell is not written)"

# --- 1. The ZIP itself -------------------------------------------------------
GOT_SHA="$(shasum -a 256 "$SRC_ZIP" | awk '{print $1}')"
echo "==> ZIP: $SRC_ZIP"
echo "    sha256: $GOT_SHA"
[[ "$GOT_SHA" == "$SHA" ]] || die "SHA-256 mismatch: got $GOT_SHA, approved $SHA"

LISTING="$(unzip -Z1 "$SRC_ZIP" 2>/dev/null)" || die "not a readable ZIP: $SRC_ZIP"
printf '%s\n' "$LISTING" | grep -qx 'index.html' || die "index.html missing at the ZIP root"
printf '%s\n' "$LISTING" | grep -qx 'update.json' || die "update.json missing at the ZIP root"
if printf '%s\n' "$LISTING" | grep -qi '\.zip$'; then
	die "the ZIP contains nested .zip entries"
fi
INNER_VER="$(unzip -p "$SRC_ZIP" update.json | /usr/bin/python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("ver",""))' 2>/dev/null || true)"
[[ -n "$INNER_VER" ]] || die "update.json inside the ZIP has no ver"
if [[ -n "$VER" && "$INNER_VER" != "$VER" ]]; then
	die "update.json ver $INNER_VER != --ver $VER"
fi
VER="$INNER_VER"
echo "    update.json ver: $VER; index.html present; no nested ZIP"

# --- 1a. Freeze manifest (frozen, not-yet-released PWA) ----------------------
FREEZE_FILE_SHA=""
if [[ -n "$FREEZE" ]]; then
	[[ -f "$FREEZE" ]] || die "freeze manifest not found: $FREEZE"
	FREEZE="$(cd "$(dirname "$FREEZE")" && pwd -P)/$(basename "$FREEZE")"
	FREEZE_FILE_SHA="$(shasum -a 256 "$FREEZE" | awk '{print $1}')"
	FM="$(/usr/bin/python3 -I - "$FREEZE" <<'PYFM'
import json, sys
try:
    m = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print("ERR unreadable: %s" % e); sys.exit(0)
if m.get("status") != "frozen":
    print("ERR status is %r, not 'frozen'" % m.get("status")); sys.exit(0)
v, z = m.get("version"), m.get("zip_sha256")
if not isinstance(v, str) or not v or not isinstance(z, str) or len(z) != 64:
    print("ERR missing or bad version / zip_sha256"); sys.exit(0)
print("OK %s %s" % (v, z.lower()))
PYFM
)"
	case "$FM" in
		OK\ *) read -r _ FM_VER FM_SHA <<< "$FM" ;;
		*) die "freeze manifest $FREEZE: ${FM#ERR }" ;;
	esac
	echo "==> Freeze manifest: $FREEZE (sha256 $FREEZE_FILE_SHA): ver $FM_VER, zip_sha256 $FM_SHA, status frozen"
	[[ "$SHA" == "$FM_SHA" ]] || die "--sha256 $SHA is not the frozen zip_sha256 $FM_SHA"
	[[ "$VER" == "$FM_VER" ]] || die "ZIP ver $VER is not the frozen version $FM_VER"
fi

# --- 1a2. QA candidate manifest (PM R509): NOT FROZEN, hash and single ZIP only ---
QA_FILE_SHA=""; QA_VER=""; QA_SHA=""
if [[ -n "$QA" ]]; then
	[[ -f "$QA" ]] || die "qa manifest not found: $QA"
	QA="$(cd "$(dirname "$QA")" && pwd -P)/$(basename "$QA")"
	QA_FILE_SHA="$(shasum -a 256 "$QA" | awk '{print $1}')"
	QM="$(/usr/bin/python3 -I - "$QA" <<'PYQA'
import json, sys
try:
    m = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print("ERR unreadable: %s" % e); sys.exit(0)
if not isinstance(m, dict) or m.get("status") != "qa-candidate" or m.get("not_frozen") is not True or m.get("freeze_kind") != "qa-candidate-not-frozen":
    print("ERR not a QA candidate manifest (status qa-candidate, not_frozen true, freeze_kind qa-candidate-not-frozen)"); sys.exit(0)
v, z = m.get("version"), m.get("zip_sha256")
if not isinstance(v, str) or not v or not isinstance(z, str) or len(z) != 64:
    print("ERR missing or bad version / zip_sha256"); sys.exit(0)
print("OK %s %s" % (v, z.lower()))
PYQA
)"
	case "$QM" in
		OK\ *) read -r _ QA_VER QA_SHA <<< "$QM" ;;
		*) die "qa manifest $QA: ${QM#ERR }" ;;
	esac
	echo "==> QA manifest: $QA (sha256 $QA_FILE_SHA): ver $QA_VER, zip_sha256 $QA_SHA, NOT FROZEN (QA only)"
	[[ "$SHA" == "$QA_SHA" ]] || die "--sha256 $SHA is not the QA zip_sha256 $QA_SHA"
	[[ "$VER" == "$QA_VER" ]] || die "ZIP ver $VER is not the QA version $QA_VER"
fi

# --- 1b. PWA version rule (shared with the Android shell) -------------------
VERSION_GATE="$SCRIPT_DIR/verify-shell-pwa-version.sh"
[[ -x "$VERSION_GATE" ]] || die "version checker missing: $VERSION_GATE"
VG_ARGS=(zip "$SRC_ZIP")
CLASSIFICATION="released"
if [[ -n "$APPROVED_VER$APPROVED_SHA$APPROVAL" ]]; then
	[[ -n "$APPROVED_VER" && -n "$APPROVED_SHA" && -n "$APPROVAL" ]] || { echo "--approved-ver, --approved-sha and --approval go together" >&2; exit 2; }
	[[ "$UNRELEASED_TEST" == "0" ]] || { echo "use either --unreleased-test or --approved-*, not both" >&2; exit 2; }
	VG_ARGS+=(--approved-ver "$APPROVED_VER" --approved-sha "$APPROVED_SHA" --approval "$APPROVAL")
	CLASSIFICATION="approved"
elif [[ "$UNRELEASED_TEST" == "1" && -n "$QA" ]]; then
	VG_ARGS+=(--unreleased-test --qa-manifest "$QA")
	CLASSIFICATION="qa-candidate"
elif [[ "$UNRELEASED_TEST" == "1" ]]; then
	VG_ARGS+=(--unreleased-test --freeze-manifest "$FREEZE")
	CLASSIFICATION="unreleased-test"
fi
echo "==> PWA version rule: $VERSION_GATE ${VG_ARGS[*]}"
"$VERSION_GATE" "${VG_ARGS[@]}" || die "PWA version rule failed (nothing was written)"

# --- 2. Refuse to write next to a stray ZIP ----------------------------------
is_zip_file() {
	local f="$1" magic
	case "$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')" in
		*.zip) return 0 ;;
	esac
	[[ -f "$f" && ! -L "$f" ]] || return 1
	magic="$(head -c 4 "$f" 2>/dev/null | xxd -p)"
	case "$magic" in
		504b0304 | 504b0506 | 504b0708) return 0 ;;
	esac
	return 1
}

STRAY=""
scan_stray() {
	# $1 = folder to scan, $2 = the one allowed path
	local root="$1" allowed="$2" f
	while IFS= read -r -d '' f; do
		if is_zip_file "$f" && [[ "$f" != "$allowed" ]]; then
			STRAY="${STRAY}    - ${f}"$'\n'
		fi
	done < <(find "$root" \( -type f -o -type l \) -print0)
}
if [[ "$ONLY" == "ios" ]]; then
	scan_stray "$IOS_DIR" "$IOS_DIR/$ZIP_NAME"
else
	for assets in "$ANDROID_APP"/src/*/assets; do
		[[ -d "$assets" ]] || continue
		scan_stray "$assets" "$ANDROID_APP/src/main/assets/$ZIP_NAME"
	done
fi
if [[ -n "$STRAY" ]]; then
	printf 'The %s packaging folder holds other ZIP files; move them outside the repository first:\n%s' "$ONLY" "$STRAY" >&2
	die "stray ZIP files in the $ONLY packaging folder (nothing was written)"
fi

# --- 3. Archive copy (outside the repository only) ---------------------------
if [[ -n "$ARCHIVE_DIR" ]]; then
	[[ -d "$ARCHIVE_DIR" ]] || die "--archive-dir must be an existing folder outside the repository: $ARCHIVE_DIR"
	ARCHIVE_REAL="$(cd "$ARCHIVE_DIR" && pwd -P)"
	case "$ARCHIVE_REAL/" in
		"$REPO_ROOT"/*) die "--archive-dir must be outside the repository: $ARCHIVE_REAL" ;;
	esac
	cp "$SRC_ZIP" "$ARCHIVE_REAL/SilentPassUI-${VER}.zip"
	echo "==> Archived: $ARCHIVE_REAL/SilentPassUI-${VER}.zip"
fi

# --- 4. Write the fixed-name copies ------------------------------------------
# Declaration read by the shell's build (same key=value format for both shells).
write_lock() {
	local lock="$1" tmp
	tmp="$(mktemp "$(dirname "$lock")/.sync-pwa-embed-lock.XXXXXX")"
	TMP_FILES+=("$tmp")
	{
		echo "# Written by scripts/syncEmbeddedPwaZipToNativeShells.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ). Do not edit by hand."
		echo "zip_sha256=$SHA"
		echo "zip_ver=$VER"
		echo "classification=$CLASSIFICATION"
		if [[ -n "$FREEZE" ]]; then
			# File name only (PM R1670): no local absolute path in the lock; the build reads the fixed-name copy.
			echo "freeze_manifest=$(basename "$FREEZE")"
			echo "freeze_manifest_sha256=$FREEZE_FILE_SHA"
			echo "freeze_ver=$FM_VER"
			echo "freeze_zip_sha256=$FM_SHA"
		fi
		if [[ -n "$QA" ]]; then
			# File name only (PM R1670): no local absolute path in the lock; the build reads the fixed-name copy.
			echo "qa_manifest=$(basename "$QA")"
			echo "qa_manifest_sha256=$QA_FILE_SHA"
			echo "qa_ver=$QA_VER"
			echo "qa_zip_sha256=$QA_SHA"
		fi
		if [[ "$CLASSIFICATION" == "approved" ]]; then
			echo "approved_ver=$APPROVED_VER"
			echo "approved_sha256=$(printf '%s' "$APPROVED_SHA" | tr 'A-F' 'a-f')"
			echo "approval_record=$APPROVAL"
		fi
	} > "$tmp"
	chmod 644 "$tmp"
	mv -f "$tmp" "$lock"
	echo "==> Wrote $lock (classification=$CLASSIFICATION)"
}

TMP_FILES=()
cleanup() {
	local t
	for t in "${TMP_FILES[@]+"${TMP_FILES[@]}"}"; do
		[[ -e "$t" ]] && rm -f -- "$t"
	done
	return 0
}
trap cleanup EXIT

write_fixed() {
	local dir="$1" tmp
	tmp="$(mktemp "$dir/.sync-SilentPassUI.XXXXXX")"
	TMP_FILES+=("$tmp")
	cp "$SRC_ZIP" "$tmp"
	chmod 644 "$tmp"
	mv -f "$tmp" "$dir/$ZIP_NAME"
	[[ "$(shasum -a 256 "$dir/$ZIP_NAME" | awk '{print $1}')" == "$SHA" ]] || die "copy check failed: $dir/$ZIP_NAME"
	echo "==> Wrote $dir/$ZIP_NAME"
}
if [[ "$ONLY" == "android" ]]; then
	write_fixed "$ANDROID_APP/src/main/assets"
	# Android declaration and freeze manifest copy: <app>/pwa-embed.lock and <app>/pwa-freeze-manifest.json.
	ANDROID_MANIFEST="$ANDROID_APP/pwa-freeze-manifest.json"
	if [[ -n "$FREEZE" ]]; then
		cp "$FREEZE" "$ANDROID_MANIFEST"
		chmod 644 "$ANDROID_MANIFEST"
		echo "==> Wrote $ANDROID_MANIFEST (copy of $FREEZE)"
	elif [[ -e "$ANDROID_MANIFEST" ]]; then
		rm -f -- "$ANDROID_MANIFEST"
		echo "==> Removed $ANDROID_MANIFEST (no freeze manifest for this ZIP)"
	fi
	write_lock "$ANDROID_APP/pwa-embed.lock"
	echo "==> Gate: Android pre-build"
	"$SCRIPT_DIR/verify-android-single-zip.sh" prebuild --app-dir "$ANDROID_APP" --sha256 "$SHA" --ver "$VER" \
		|| { echo "FAILED: the Android pre-build single-ZIP gate failed; do not build or deliver." >&2; exit 1; }
	if [[ -x "$SCRIPT_DIR/verify-android-pwa-embed-lock.sh" ]]; then
		"$SCRIPT_DIR/verify-android-pwa-embed-lock.sh" --app-dir "$ANDROID_APP" \
			|| { echo "FAILED: the Android pwa-embed.lock gate failed; do not build or deliver." >&2; exit 1; }
	else
		echo "==> Note: scripts/verify-android-pwa-embed-lock.sh is not in this checkout; the Android build runs it (preBuild)."
	fi
	echo "==> Synced Android SilentPassUI.zip ver=${VER} sha256=${SHA} (classification=$CLASSIFICATION); pre-build gate passes."
	echo "==> Next: build the Android shell, then run scripts/verify-android-single-zip.sh artifact on the APK/AAB."
	exit 0
fi

write_fixed "$IOS_DIR"

# iOS declaration for the Xcode build phase (outside the synced resource folder,
# so it is not bundled). The build fails if SilentPassUI.zip changes later
# without re-running this script.
IOS_PROJ="$(cd "$IOS_DIR/.." && pwd)"
IOS_LOCK="$IOS_PROJ/pwa-embed.lock"
# Copy of the freeze manifest for the Xcode build phase (it may read only
# declared inputs inside the project). Always written, so the declared input exists.
if [[ -n "$FREEZE" ]]; then
	cp "$FREEZE" "$IOS_PROJ/pwa-freeze-manifest.json"
elif [[ -n "$QA" ]]; then
	cp "$QA" "$IOS_PROJ/pwa-freeze-manifest.json"  # the QA copy uses the same declared input (NOT FROZEN)
else
	echo '{"status": "none"}' > "$IOS_PROJ/pwa-freeze-manifest.json"
fi
write_lock "$IOS_LOCK"

# --- 5. Pre-build gate (iOS) -------------------------------------------------
echo "==> Gate: iOS pre-build"
"$SCRIPT_DIR/verify-ios-single-zip.sh" pre --resources "$IOS_DIR" --sha256 "$SHA" --ver "$VER" \
	|| { echo "FAILED: the iOS pre-build single-ZIP gate failed; do not build or deliver." >&2; exit 1; }
echo "==> Synced iOS SilentPassUI.zip ver=${VER} sha256=${SHA} (classification=$CLASSIFICATION); pre-build gate passes."
echo "==> Next: build the iOS shell (Xcode build phases check pwa-embed.lock), then run scripts/verify-ios-single-zip.sh post on the archive and .ipa."
