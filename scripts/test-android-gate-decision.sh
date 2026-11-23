#!/usr/bin/env bash
# Stub tests for scripts/android-gate-decision.sh (no gate is run; the inputs are the stubbed exit codes).
# Row format: name variant qa frozen gate singlezip expected(0 accept / 1 refuse / 2 usage)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEC="$HERE/android-gate-decision.sh"
pass=0; fail=0
check() {
	local name="$1" v="$2" q="$3" f="$4" g="$5" s="$6" want="$7" got
	"$DEC" --variant "$v" --qa-requested "$q" --frozen-requested "$f" --gate-rc "$g" --singlezip-rc "$s" >/dev/null 2>&1; got=$?
	if [[ "$got" == "$want" ]]; then pass=$((pass+1)); echo "ok   $name (exit $got)"; else fail=$((fail+1)); echo "FAIL $name: want $want got $got"; fi
}
check "debugqa QA gate 4 + single-ZIP pass -> accept"          debugqa 1 0 4 0 0
check "release gate 4 (no QA) -> refuse"                        release 0 0 4 0 1
check "release gate 4 with QA manifest -> refuse"               release 1 0 4 0 1
check "debugqa gate 4 without QA manifest -> refuse"            debugqa 0 0 4 0 1
check "debugqa gate 4 with frozen manifest too -> refuse"       debugqa 1 1 4 0 1
check "debugqa gate 4 but single-ZIP fails -> refuse first"     debugqa 1 0 4 1 1
check "debugqa QA gate 1 -> refuse"                             debugqa 1 0 1 0 1
check "debugqa QA gate 7 unknown -> refuse"                     debugqa 1 0 7 0 1
check "unknown variant gate 4 with QA -> refuse"                unknown 1 0 4 0 1
check "unknown variant gate 0 (no manifest) -> refuse"          unknown 0 0 0 0 1
check "unknown variant gate 0 with frozen -> refuse"            unknown 0 1 0 0 1
check "unknown variant gate 4 -> refuse"                        unknown 0 0 4 0 1
check "release formal gate 0 -> accept"                         release 0 0 0 0 0
check "release formal gate 0 with frozen -> accept"             release 0 1 0 0 0
check "release gate 0 but single-ZIP fails -> refuse"           release 0 0 0 1 1
check "release gate 0 with QA manifest -> refuse"               release 1 0 0 0 1
check "debugqa formal frozen gate 0 -> accept"                  debugqa 0 1 0 0 0
check "debugqa gate 0 without frozen manifest -> refuse"        debugqa 0 0 0 0 1
check "debugqa gate 0 with QA manifest -> refuse"               debugqa 1 0 0 0 1
check "debugqa gate 0 but single-ZIP fails -> refuse"           debugqa 0 1 0 1 1
check "bad variant argument -> usage 2"                         bogus 0 0 0 0 2
check "non-numeric gate rc -> usage 2"                          debugqa 1 0 x 0 2
echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
