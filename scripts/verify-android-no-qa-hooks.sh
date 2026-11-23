#!/usr/bin/env bash
# Fail-closed check that an APK carries no QA-only hook (2026-11-22). Usage: verify-android-no-qa-hooks.sh APK
# Exit 0 only when every check passes. Exit 1 on any hit, a missing tool (unzip, grep, python3), a missing or unreadable APK,
# a non-APK file, or a usage error. Read-only; not wired into Gradle (wiring into release/store preBuild is a follow-up).
# Checks:
#  (a) no zip entry under qa/hooks or qa/readfault (src/qaHooks and src/qaReadFault are compiled only with -PchatQaHooks);
#  (b) no QA class or command name in any classes*.dex: QaReadFaultImpl, QaReadFaultReceiver, QaNativeEvidenceActivity, simulateReadFailure;
#  (c) the binary AndroidManifest.xml has no QA component or action: QaReadFaultReceiver, qa.readfault, qa.hooks, READ_FAULT
#      (checked as UTF-8 and UTF-16LE strings).
set -uo pipefail
fail() { echo "FAIL: $1" >&2; exit 1; }
[[ $# -eq 1 ]] || fail "usage: verify-android-no-qa-hooks.sh APK"
APK="$1"
for tool in unzip grep python3; do command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"; done
[[ -f "$APK" ]] || fail "APK not found: $APK"
unzip -tq "$APK" >/dev/null 2>&1 || fail "not a readable zip/APK: $APK"

ENTRIES="$(unzip -Z1 "$APK")" || fail "cannot list $APK"
if printf '%s\n' "$ENTRIES" | grep -q 'qa/hooks/\|qa/readfault/'; then
  fail "zip entry under qa/hooks or qa/readfault present"
fi

DEX_LIST="$(printf '%s\n' "$ENTRIES" | grep -E '^classes[0-9]*\.dex$' || true)"
[[ -n "$DEX_LIST" ]] || fail "no classes*.dex in $APK"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/no-qa-hooks.XXXXXX")" || fail "cannot create temp dir"
trap 'rm -rf "$TMP"' EXIT
for dex in $DEX_LIST; do
  unzip -p "$APK" "$dex" >> "$TMP/all.dex" || fail "cannot read $dex"
done
for name in QaReadFaultImpl QaReadFaultReceiver QaNativeEvidenceActivity simulateReadFailure; do
  if grep -q -a "$name" "$TMP/all.dex"; then fail "QA name present in dex: $name"; fi
done

unzip -p "$APK" AndroidManifest.xml > "$TMP/manifest.bin" || fail "cannot read AndroidManifest.xml"
for name in QaReadFaultReceiver qa.readfault qa.hooks READ_FAULT; do
  if python3 -I -c 'import sys
d=open(sys.argv[1],"rb").read(); n=sys.argv[2].encode()
sys.exit(0 if (n in d or n.decode().encode("utf-16le") in d) else 1)' "$TMP/manifest.bin" "$name"; then
    fail "QA component or action present in manifest: $name"
  fi
done
echo "PASS: no QA hook in $APK (no qa/hooks or qa/readfault entries; no QA classes in dex; no QA component or action in manifest)"
exit 0
