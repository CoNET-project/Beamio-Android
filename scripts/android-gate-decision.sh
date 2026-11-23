#!/usr/bin/env bash
# Android shell: decide whether a PWA gate result may build (caller contract, Gradle preBuild).
#   android-gate-decision.sh --variant debugqa|release|unknown --qa-requested 0|1 --frozen-requested 0|1 \
#                            --gate-rc N --singlezip-rc N
# Fail-closed rule: only registered variants may pass; unknown is refused in every case.
#   1. the single-ZIP gate result comes first: singlezip-rc must be 0, else refuse;
#   2. unknown variant: refuse (any gate rc);
#   3. release: accept gate 0 only (no QA manifest); gate 4 and everything else refused;
#   4. debugqa:
#        gate 4 ("QA ONLY - NOT FROZEN") accepted only with a QA manifest bound (qa=1, frozen=0);
#        gate 0 accepted only with a formal frozen manifest (frozen=1, qa=0);
#        gate 0 without a frozen manifest, or any gate 0 with a QA manifest, refused;
#   5. any other exit code, or bad arguments (exit 2): refuse.
# Exit: 0 accept, 1 refuse, 2 usage error.
set -euo pipefail

VARIANT=""; QA=""; FROZEN=""; GRC=""; SZRC=""
while [[ $# -gt 0 ]]; do
	case "$1" in
		--variant) VARIANT="${2:-}"; shift 2 ;;
		--qa-requested) QA="${2:-}"; shift 2 ;;
		--frozen-requested) FROZEN="${2:-}"; shift 2 ;;
		--gate-rc) GRC="${2:-}"; shift 2 ;;
		--singlezip-rc) SZRC="${2:-}"; shift 2 ;;
		*) echo "error: unknown argument $1" >&2; exit 2 ;;
	esac
done
[[ "$VARIANT" == debugqa || "$VARIANT" == release || "$VARIANT" == unknown ]] || { echo "error: --variant must be debugqa, release or unknown" >&2; exit 2; }
[[ "$QA" == 0 || "$QA" == 1 ]] || { echo "error: --qa-requested must be 0 or 1" >&2; exit 2; }
[[ "$FROZEN" == 0 || "$FROZEN" == 1 ]] || { echo "error: --frozen-requested must be 0 or 1" >&2; exit 2; }
[[ "$GRC" =~ ^[0-9]+$ ]] || { echo "error: --gate-rc must be a number" >&2; exit 2; }
[[ "$SZRC" =~ ^[0-9]+$ ]] || { echo "error: --singlezip-rc must be a number" >&2; exit 2; }

# 1. single-ZIP gate first
if [[ "$SZRC" != 0 ]]; then
	echo "REFUSE: single-ZIP gate failed (rc=$SZRC); gate rc=$GRC is not considered" >&2
	exit 1
fi

# 2. unknown variant is never accepted (fail-closed)
if [[ "$VARIANT" == unknown ]]; then
	echo "REFUSE: unregistered variant (build variant must be debugqa or release)" >&2
	exit 1
fi

# 3. release: formal gate 0 only
if [[ "$VARIANT" == release ]]; then
	if [[ "$GRC" == 0 && "$QA" == 0 ]]; then
		echo "ACCEPT: release formal gate pass"
		exit 0
	fi
	echo "REFUSE: release accepts gate 0 only (gate rc=$GRC, qa=$QA)" >&2
	exit 1
fi

# 4. debugqa
if [[ "$GRC" == 4 ]]; then
	if [[ "$QA" == 1 && "$FROZEN" == 0 ]]; then
		echo "ACCEPT: QA ONLY - NOT FROZEN (debugqa, QA manifest bound, single-ZIP gate pass)"
		exit 0
	fi
	echo "REFUSE: gate 4 needs a QA manifest and no frozen manifest (qa=$QA, frozen=$FROZEN)" >&2
	exit 1
fi
if [[ "$GRC" == 0 ]]; then
	if [[ "$FROZEN" == 1 && "$QA" == 0 ]]; then
		echo "ACCEPT: debugqa formal frozen gate pass"
		exit 0
	fi
	echo "REFUSE: debugqa gate 0 needs a formal frozen manifest and no QA manifest (qa=$QA, frozen=$FROZEN)" >&2
	exit 1
fi
echo "REFUSE: gate exit $GRC is not an accepted result" >&2
exit 1
