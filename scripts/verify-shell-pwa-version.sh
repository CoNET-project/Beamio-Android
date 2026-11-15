#!/usr/bin/env bash
# Pre-pack PWA version gate for the Beamio shells (owner rule 2026-11-11).
# A shell must embed the latest RELEASED PWA, or a strictly higher version
# that is either an explicitly approved release or a local unreleased test.
# Read-only: never changes the project, the ZIP, OTA or production.
#
# "Released" = the live OTA manifest (default https://beamio.ca/app/update.json; beamio.app until R1626):
#   its "ver", and the SHA-256 of the ZIP it names (streamed, not saved).
#
# Modes:
#   zip               FILE.zip              check one PWA ZIP before copying it in
#   android-prebuild  [--app-dir DIR]       check the Android shell assets, then run
#                                           verify-android-single-zip.sh prebuild
#   android-artifact  FILE.apk|FILE.aab ... check built artifacts, then run
#                                           verify-android-single-zip.sh artifact
#
# Options:
#   --released-url URL        manifest URL (default above)
#   --released-ver X --released-sha HEX --released-source TEXT
#                             offline override of the released version (all three)
#   --unreleased-test         allow a version above released, labelled
#                             "UNRELEASED TEST / 未发布测试" (local test shells only)
#   --approved-ver X --approved-sha HEX --approval TEXT
#                             allow a version above released when it is exactly this
#                             approved release (version and SHA-256 must both match)
#   --freeze-manifest FILE    freeze manifest JSON, checked against --approval-dir. Accepted only when every
#                             field the gate reads is present and exact: status "frozen"; not_frozen JSON false;
#                             freeze_kind "owner-freeze"; release_state "frozen-owner-approved"; approved_by
#                             "project-owner"; version X.Y.Z; zip_sha256 64 lowercase hex; void a list; and
#                             owner_freeze_approval a bare file name. not_an_official_freeze, not_for_release,
#                             not_for_store and not_for_ota must be absent or JSON false. Duplicate JSON keys
#                             are refused. Then its version+zip_sha256 pass as FROZEN (not yet released) without
#                             --unreleased-test; its "void" list joins the void ZIPs. Same version, other bytes -> FAIL.
#                             QA candidates (status "qa-candidate") never go here: check them with
#                             --unreleased-test and no --freeze-manifest.
#   --approval-dir DIR        the dedicated directory of owner approval records (required with --freeze-manifest).
#                             The record is a separate file here, never the manifest and never outside this
#                             directory; it must hold these whole lines once each: OWNER FREEZE APPROVAL,
#                             version: X, zip_sha256: Y, manifest_sha256: <sha256 of the manifest bytes>,
#                             approved_by: project-owner. Records are written only by the project's PM, from the
#                             project owner's verbatim words. No other session may write or complete one.
#                             Basis (project owner's decision, relayed by the 总 PM, 2026-11-14, words
#                             "PM 记录即可"): the record needs no signature and need not be submitted by the
#                             project owner in person; the 总 PM writes it from the owner's words. The gate
#                             therefore adds no signature check (review 45424276 item 6 is closed on this basis).
#                             Test fixtures are labelled "FIXTURE，非真实批准" and are never approval.
#   --qa-manifest FILE        QA candidate manifest (status "qa-candidate", not_frozen JSON true, not_for_release /
#                             not_for_store / not_for_ota JSON true, freeze_kind "qa-candidate-not-frozen", release_state
#                             saying NOT FROZEN). Needs --unreleased-test; cannot be combined with --freeze-manifest or
#                             --approved-*. It binds ONE ZIP: the ZIP's version and sha256 must equal the manifest's, else
#                             FAIL. The verdict is QA (hash and single-ZIP check only): never FROZEN, never a formal package.
#
# Void ZIPs (withdrawn 0.52.931 30f08316..., 0.52.932 005baca0...) always FAIL.
# The manifest filename must be exactly SilentPassUI-<ver>.zip; any read error FAILs.
# Rules: ver < released -> FAIL. ver == released -> SHA-256 must equal the
# released ZIP. ver > released -> FAIL unless --approved-* matches or
# --unreleased-test is given. Exit: 0 pass, 1 fail, 2 usage error.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() { sed -n '2,57p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[[ $# -ge 1 ]] || usage
MODE="$1"; shift
case "$MODE" in zip|android-prebuild|android-artifact) ;; -h|--help) usage ;; *) echo "error: unknown mode $MODE" >&2; exit 2 ;; esac

URL="https://beamio.ca/app/update.json"  # R1626: domain moved from beamio.app (owner-authorized); strict TLS
RVER="" RSHA="" RSRC="" TEST=0 AVER="" ASHA="" AREF="" FMAN="" APPR="" QMAN=""
APP_DIR="$REPO_ROOT/src/CaehTrees/app"
FILES=()
while [[ $# -gt 0 ]]; do
	case "$1" in
		--released-url) URL="${2:?}"; shift 2 ;;
		--released-ver) RVER="${2:?}"; shift 2 ;;
		--released-sha) RSHA="${2:?}"; shift 2 ;;
		--released-source) RSRC="${2:?}"; shift 2 ;;
		--unreleased-test) TEST=1; shift ;;
		--approved-ver) AVER="${2:?}"; shift 2 ;;
		--approved-sha) ASHA="${2:?}"; shift 2 ;;
		--approval) AREF="${2:?}"; shift 2 ;;
		--freeze-manifest) FMAN="${2:?}"; shift 2 ;;
		--approval-dir) APPR="${2:?}"; shift 2 ;;
		--qa-manifest) QMAN="${2:?}"; shift 2 ;;
		--app-dir) APP_DIR="${2:?}"; shift 2 ;;
		-h|--help) usage ;;
		--*) echo "error: unknown option $1" >&2; exit 2 ;;
		*) FILES+=("$1"); shift ;;
	esac
done
if [[ -n "$RVER$RSHA$RSRC" && ( -z "$RVER" || -z "$RSHA" || -z "$RSRC" ) ]]; then
	echo "error: --released-ver, --released-sha and --released-source go together" >&2; exit 2
fi
if [[ -n "$AVER$ASHA$AREF" && ( -z "$AVER" || -z "$ASHA" || -z "$AREF" ) ]]; then
	echo "error: --approved-ver, --approved-sha and --approval go together" >&2; exit 2
fi
if [[ -n "$QMAN" && "$TEST" != 1 ]]; then echo "FAIL: --qa-manifest needs --unreleased-test: a QA candidate is never a freeze or a formal package" >&2; exit 1; fi
if [[ -n "$QMAN" && -n "$FMAN" ]]; then echo "FAIL: --qa-manifest and --freeze-manifest cannot be combined" >&2; exit 1; fi
if [[ -n "$QMAN" && -n "$AVER$ASHA$AREF" ]]; then echo "FAIL: --qa-manifest cannot be combined with --approved-*" >&2; exit 1; fi
case "$MODE" in
	zip) [[ ${#FILES[@]} -eq 1 ]] || { echo "error: zip mode takes exactly one ZIP" >&2; exit 2; } ;;
	android-artifact) [[ ${#FILES[@]} -ge 1 ]] || { echo "error: give at least one .apk/.aab" >&2; exit 2; } ;;
	android-prebuild) FILES=("$APP_DIR/src/main/assets/SilentPassUI.zip") ;;
esac

set +e
export PWA_FREEZE_MANIFEST="$FMAN"
export PWA_FREEZE_APPROVAL_DIR="$APPR"
export PWA_QA_MANIFEST="$QMAN"
python3 -I - "$MODE" "$URL" "$RVER" "$RSHA" "$RSRC" "$TEST" "$AVER" "$ASHA" "$AREF" "${FILES[@]}" <<'PY'
import hashlib, io, json, os, re, sys, time, urllib.request, zipfile
mode, url, rver, rsha, rsrc, test, aver, asha, aref = sys.argv[1:10]
files = sys.argv[10:]
test = test == "1"
MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
# Withdrawn, never-released PWA ZIPs (PWA release line, 2026-11-11). Reject in any mode.
VOID = {
    "30f08316d43ea4e328ae72642f2cd5fabb44b222c2026b83c9ba14b363338450": "0.52.931 fb97c1f9, withdrawn",
    "005baca0d6992bf4779ff9bef0335a06fdd2ad978c5896c0f8f9db08c1568517": "0.52.932 non-clean build, withdrawn",
}
# Freeze manifest (pwa-version-ledger): the one frozen, not-yet-released build allowed above released.
# Accepted only when every check below passes; each refusal is printed with its reason (PM R495, R498, R503).
#   - every field the gate reads must be present and exactly as written: status "frozen"; not_frozen JSON false;
#     freeze_kind "owner-freeze"; release_state "frozen-owner-approved"; approved_by "project-owner"; version X.Y.Z;
#     zip_sha256 64 lowercase hex; void a list of 64-hex strings; owner_freeze_approval a bare file name.
#   - not_an_official_freeze, not_for_release, not_for_store, not_for_ota: absent or JSON false.
#   - duplicate JSON keys are refused.
#   - the approval record is a separate file inside --approval-dir (resolved). It is never the manifest, never outside that
#     directory, and the directory is never the manifest's own directory. Its lines must contain each of these whole lines
#     (trailing blanks ignored) exactly once:
#       OWNER FREEZE APPROVAL
#       version: <manifest version>
#       zip_sha256: <manifest zip_sha256>
#       manifest_sha256: <sha256 of the manifest file bytes>
#       approved_by: project-owner
FREEZE_KIND = "owner-freeze"
RELEASE_STATE = "frozen-owner-approved"
APPROVED_BY = "project-owner"
FREEZE_FLAGS = ("not_an_official_freeze", "not_for_release", "not_for_store", "not_for_ota")
FROZEN = None
def _no_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out: raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out
def approval_record_refusals(raw, path, approval_dir, name, m, ver_ok, sha_ok):
    why = []
    manifest_real = os.path.realpath(path)
    adir = os.path.realpath(approval_dir)
    if adir == os.path.dirname(manifest_real):
        why.append("the approval record directory is the manifest's own directory; records must be kept apart")
        return why
    rp = os.path.realpath(os.path.join(adir, name))
    if rp == manifest_real:
        why.append("owner_freeze_approval names the manifest itself")
        return why
    if os.path.dirname(rp) != adir:
        why.append(f"approval record {name!r} resolves outside the approval directory")
        return why
    if not os.path.isfile(rp):
        why.append(f"approval record {name!r} is missing from the approval directory")
        return why
    try:
        with open(rp, encoding="utf-8") as rf: text = rf.read()
    except Exception as e:
        why.append(f"approval record {name!r} unreadable: {e}")
        return why
    if not (ver_ok and sha_ok): return why  # the version or sha is already refused
    lines = [ln.rstrip(" \t\r") for ln in text.splitlines()]
    manifest_sha = hashlib.sha256(raw).hexdigest()
    wanted = ["OWNER FREEZE APPROVAL", f"version: {m['version']}", f"zip_sha256: {m['zip_sha256']}",
              f"manifest_sha256: {manifest_sha}", f"approved_by: {APPROVED_BY}"]
    for want in wanted:
        n = sum(1 for ln in lines if ln == want)
        if n != 1: why.append(f"approval record {name!r} must contain the line {want!r} exactly once (found {n})")
    return why
def freeze_manifest_refusals(raw, path, approval_dir):
    """Returns (refusal reasons, parsed manifest). Never raises."""
    why = []
    try:
        m = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except Exception as e:
        return [f"not valid JSON: {e}"], None
    if not isinstance(m, dict):
        return ["not a JSON object"], None
    def need(k):
        if k in m: return True
        why.append(f"{k} is missing")
        return False
    if need("status") and m["status"] != "frozen":
        why.append(f"status is {m['status']!r}, not 'frozen'")
    if need("not_frozen") and m["not_frozen"] is not False:
        why.append(f"not_frozen is {m['not_frozen']!r}, not JSON false: this manifest is not a freeze")
    for k in FREEZE_FLAGS:
        if k in m and m[k] is not False:
            why.append(f"{k} is {m[k]!r}, not JSON false: this is not a freeze")
    if need("freeze_kind") and m["freeze_kind"] != FREEZE_KIND:
        why.append(f"freeze_kind is {m['freeze_kind']!r}, not {FREEZE_KIND!r}")
    if need("release_state") and m["release_state"] != RELEASE_STATE:
        why.append(f"release_state is {m['release_state']!r}, not {RELEASE_STATE!r}")
    if need("approved_by") and m["approved_by"] != APPROVED_BY:
        why.append(f"approved_by is {m['approved_by']!r}, not {APPROVED_BY!r}")
    ver_ok = sha_ok = False
    if need("version"):
        ver_ok = isinstance(m["version"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", m["version"]) is not None
        if not ver_ok: why.append(f"version {m['version']!r} is not X.Y.Z")
    if need("zip_sha256"):
        sha_ok = isinstance(m["zip_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", m["zip_sha256"]) is not None
        if not sha_ok: why.append("zip_sha256 is not 64 lowercase hex characters")
    if need("void"):
        if not isinstance(m["void"], list) or not all(isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h) for h in m["void"]):
            why.append("void must be a list of 64-hex sha256 strings")
    if need("owner_freeze_approval"):
        name = m["owner_freeze_approval"]
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None:
            why.append("owner_freeze_approval must be a bare file name (no directory part)")
        elif not approval_dir:
            why.append("no approval record directory given (--approval-dir)")
        elif not os.path.isdir(approval_dir):
            why.append(f"approval record directory {approval_dir!r} does not exist")
        else:
            why += approval_record_refusals(raw, path, approval_dir, name, m, ver_ok, sha_ok)
    return why, m
_fm = os.environ.get("PWA_FREEZE_MANIFEST", "")
if _fm:
    try:
        with open(_fm, "rb") as _f: _raw = _f.read()
    except Exception as _e:
        print(f"FAIL: freeze manifest {_fm} unreadable: {_e}")
        print("RESULT: FAIL (freeze manifest refused)"); sys.exit(1)
    _why, _m = freeze_manifest_refusals(_raw, _fm, os.environ.get("PWA_FREEZE_APPROVAL_DIR", ""))
    if _why:
        for _w in _why: print(f"FAIL: freeze manifest {os.path.basename(_fm)} refused: {_w}")
        print(f"RESULT: FAIL (freeze manifest refused: {len(_why)} reason(s); not accepted as a freeze)"); sys.exit(1)
    FROZEN = (_m["version"], _m["zip_sha256"])
    for _h in _m["void"]: VOID[_h] = f"voided in {os.path.basename(_fm)}"
    print(f"freeze manifest: ver={FROZEN[0]} sha256={FROZEN[1]} ({os.path.basename(_fm)}) - all freeze conditions met")
# QA candidate manifest (PM R495, R509 option (a)): with --unreleased-test only. It binds ONE ZIP by its version and sha256 and says
# nothing else: the verdict is QA, NOT FROZEN. It is never a freeze, never a formal package, and never read by --freeze-manifest.
QA = None
QA_FREEZE_KIND = "qa-candidate-not-frozen"
def qa_manifest_refusals(raw, path):
    """Returns (reasons, parsed manifest). Never raises."""
    why = []
    try:
        m = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except Exception as e:
        return [f"not valid JSON: {e}"], None
    if not isinstance(m, dict):
        return ["not a JSON object"], None
    def need(k):
        if k in m: return True
        why.append(f"{k} is missing")
        return False
    if need("status") and m["status"] != "qa-candidate":
        why.append(f"status is {m['status']!r}, not 'qa-candidate'")
    if need("not_frozen") and m["not_frozen"] is not True:
        why.append(f"not_frozen is {m['not_frozen']!r}, not JSON true: a QA manifest must say it is not a freeze")
    for k in ("not_for_release", "not_for_store", "not_for_ota"):
        if need(k) and m[k] is not True:
            why.append(f"{k} is {m[k]!r}, not JSON true")
    if need("freeze_kind") and m["freeze_kind"] != QA_FREEZE_KIND:
        why.append(f"freeze_kind is {m['freeze_kind']!r}, not {QA_FREEZE_KIND!r}")
    if need("release_state") and not (isinstance(m["release_state"], str) and "NOT FROZEN" in m["release_state"]):
        why.append("release_state must say NOT FROZEN")
    if need("version"):
        if not (isinstance(m["version"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", m["version"])):
            why.append(f"version {m['version']!r} is not X.Y.Z")
    if need("zip_sha256"):
        if not (isinstance(m["zip_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", m["zip_sha256"])):
            why.append("zip_sha256 is not 64 lowercase hex characters")
    return why, m
_qm = os.environ.get("PWA_QA_MANIFEST", "")
if _qm:
    try:
        with open(_qm, "rb") as _f: _qraw = _f.read()
    except Exception as _e:
        print(f"FAIL: qa manifest {_qm} unreadable: {_e}")
        print("RESULT: FAIL (qa manifest refused)"); sys.exit(1)
    _qwhy, _qobj = qa_manifest_refusals(_qraw, _qm)
    if _qwhy:
        for _w in _qwhy: print(f"FAIL: qa manifest {os.path.basename(_qm)} refused: {_w}")
        print(f"RESULT: FAIL (qa manifest refused: {len(_qwhy)} reason(s); a QA candidate is not a freeze)"); sys.exit(1)
    QA = (_qobj["version"], _qobj["zip_sha256"])
    print(f"qa manifest: ver={QA[0]} sha256={QA[1]} ({os.path.basename(_qm)}) - QA only: hash and single ZIP, NOT FROZEN")
errors = []
def fail(m): errors.append(m); print("FAIL: " + m)
def semver(v):
    try: return tuple(int(x) for x in v.strip().split("."))
    except ValueError: return None
now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
print(f"checked at {now}")

# 1. released version and its source
released_bytes = None
if rver:
    released_ver, released_sha = rver, rsha.lower()
    print(f"released: ver={released_ver} sha256={released_sha} source=override: {rsrc}")
else:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}), timeout=20) as r:
            if r.status != 200: raise RuntimeError(f"HTTP {r.status}")
            man = json.loads(r.read()); mlm, metag = r.headers.get("Last-Modified"), r.headers.get("ETag")
        released_ver, fname = str(man["ver"]), str(man["filename"])
        if fname != f"SilentPassUI-{released_ver}.zip":
            raise RuntimeError(f"manifest filename {fname!r} is not SilentPassUI-{released_ver}.zip")
        zurl = url.rsplit("/", 1)[0] + "/" + fname
        with urllib.request.urlopen(urllib.request.Request(zurl, headers={"Cache-Control": "no-cache"}), timeout=120) as r:
            if r.status != 200: raise RuntimeError(f"ZIP HTTP {r.status}")
            zlm, zetag = r.headers.get("Last-Modified"), r.headers.get("ETag")
            released_bytes = r.read()  # kept in memory only, for the same-version diagnosis
        n = len(released_bytes)
        released_sha = hashlib.sha256(released_bytes).hexdigest()
        print(f"released: ver={released_ver} sha256={released_sha} size={n} source={url} -> {zurl}")
        print(f"  manifest Last-Modified={mlm} ETag={metag}; ZIP Last-Modified={zlm} ETag={zetag}")
    except Exception as e:
        print(f"FAIL: cannot read the released version from {url}: {e}")
        print("RESULT: FAIL (released version unknown; use --released-* only with a recorded source)")
        sys.exit(1)
if semver(released_ver) is None:
    print(f"FAIL: released ver {released_ver!r} is not X.Y.Z"); sys.exit(1)

# 2. find the embedded ZIP(s)
def zips_in(path):
    low = path.lower()
    if low.endswith(".zip"):
        return [(path, open(path, "rb").read())]
    z = zipfile.ZipFile(path); out = []
    for i in z.infolist():
        if i.is_dir(): continue
        with z.open(i) as f: head = f.read(4)
        if i.filename.lower().endswith(".zip") or head in MAGIC:
            out.append((i.filename, z.read(i)))
    return out

def same_ver_diff(data):
    """Short content diff against the released ZIP (only when its bytes were read)."""
    if released_bytes is None: return ""
    try:
        def files(b):
            z = zipfile.ZipFile(io.BytesIO(b))
            return {i.filename: hashlib.sha256(z.read(i)).hexdigest() for i in z.infolist() if not i.is_dir()}
        e, r = files(data), files(released_bytes)
        main = lambda m: ",".join(sorted(k.rsplit("/", 1)[1] for k in m if k.startswith("static/js/main.") and k.endswith(".js"))) or "?"
        only_e, only_r = len(set(e) - set(r)), len(set(r) - set(e))
        changed = sum(1 for k in set(e) & set(r) if e[k] != r[k])
        return (f"; main script: embedded {main(e)} vs released {main(r)}; "
                f"files only in embedded/released: {only_e}/{only_r}; same path, different content: {changed}")
    except Exception as ex:
        return f"; diff unavailable ({ex})"

def check_zip(label, data):
    sha = hashlib.sha256(data).hexdigest()
    try:
        zz = zipfile.ZipFile(io.BytesIO(data))
        ver = str(json.loads(zz.read("update.json")).get("ver", ""))
        has_index = "index.html" in zz.namelist()
    except Exception as e:
        fail(f"{label}: unreadable PWA ZIP ({e})"); return
    print(f"  embedded: {label} ver={ver} sha256={sha} index.html={'yes' if has_index else 'NO'}")
    if sha in VOID:
        fail(f"{label}: sha256 {sha} is a VOID PWA ZIP ({VOID[sha]}); never embed it"); return
    if not has_index: fail(f"{label}: no index.html at the ZIP root")
    if QA and (ver != QA[0] or sha != QA[1]):
        fail(f"{label}: ver {ver}/sha {sha} is not the qa manifest {QA[0]}/{QA[1]} (a QA manifest binds one ZIP)"); return
    sv, rv = semver(ver), semver(released_ver)
    if sv is None: fail(f"{label}: update.json ver {ver!r} is not X.Y.Z"); return
    if sv < rv:
        fail(f"{label}: ver {ver} is LOWER than released {released_ver} (stale PWA; embed {released_ver} or a newer version)")
    elif sv == rv:
        if sha != released_sha:
            fail(f"{label}: ver {ver} equals released but sha256 {sha} != released {released_sha} (not the released ZIP) "
                 f"— 同号不同包 / same version, different package{same_ver_diff(data)}")
        else:
            print(f"  verdict: OK, embeds the released PWA {ver}")
    else:
        if QA:
            print(f"  verdict: QA {ver} - qa-candidate manifest: hash and single ZIP checked only; NOT FROZEN (not a freeze, not a formal package; test shells only)")
        elif aver and ver == aver and sha == asha.lower():
            print(f"  verdict: OK, {ver} is above released {released_ver} and is the approved release (approval: {aref})")
        elif aver and (ver != aver or sha != asha.lower()):
            fail(f"{label}: ver {ver}/sha {sha} does not match approved {aver}/{asha.lower()}")
        elif FROZEN and ver == FROZEN[0] and sha == FROZEN[1]:
            print(f"  verdict: FROZEN {ver} — the frozen build in the ledger (not yet released; the frozen release candidate)")
        elif FROZEN and ver == FROZEN[0]:
            fail(f"{label}: ver {ver} is the frozen version but sha256 {sha} != frozen {FROZEN[1]} (同号不同包 / same version, different package)")
        elif test:
            print(f"  verdict: UNRELEASED TEST / 未发布测试 — {ver} > released {released_ver}; local test shell only, do not ship")
        else:
            fail(f"{label}: ver {ver} is above released {released_ver}; pass --approved-ver/--approved-sha/--approval for an approved release, or --unreleased-test for a local test shell")

for f in files:
    print(f"input: {f}")
    try:
        found = zips_in(f)
    except FileNotFoundError:
        fail(f"{f}: not found"); continue
    except zipfile.BadZipFile:
        fail(f"{f}: not a ZIP/APK/AAB"); continue
    if len(found) != 1:
        fail(f"{f}: {len(found)} ZIPs found ({', '.join(n for n, _ in found) or 'none'}); exactly one is required")
    for name, data in found:
        check_zip(name, data)

print(("RESULT: FAIL (%d problem(s))" % len(errors)) if errors else "RESULT: PASS (version gate)")
sys.exit(1 if errors else 0)
PY
rc=$?
set -e
[[ $rc -eq 0 ]] || exit $rc

# 3. chain into the existing single-ZIP gate with the embedded ZIP's own hash
if [[ "$MODE" != zip ]]; then
	ZSHA="$(python3 -I - "${FILES[0]}" <<'PY'
import hashlib, sys, zipfile
p = sys.argv[1]
if p.lower().endswith(".zip"):
    print(hashlib.sha256(open(p, "rb").read()).hexdigest())
else:
    z = zipfile.ZipFile(p); n = "base/assets/SilentPassUI.zip" if p.lower().endswith(".aab") else "assets/SilentPassUI.zip"
    # Not at the load path: hand a dummy hash on, the single-ZIP gate reports the location.
    print(hashlib.sha256(z.read(n)).hexdigest() if n in z.namelist() else "0" * 64)
PY
)"
	echo "==> single-ZIP gate (verify-android-single-zip.sh) with embedded sha256 $ZSHA"
	if [[ ! -x "$SCRIPT_DIR/verify-android-single-zip.sh" ]]; then
		echo "FAIL: single-ZIP gate missing: $SCRIPT_DIR/verify-android-single-zip.sh (build refused)" >&2
		echo "RESULT: FAIL (gate script missing)" >&2
		exit 1
	fi
	if [[ "$MODE" == android-prebuild ]]; then
		exec "$SCRIPT_DIR/verify-android-single-zip.sh" prebuild --app-dir "$APP_DIR" --sha256 "$ZSHA"
	else
		exec "$SCRIPT_DIR/verify-android-single-zip.sh" artifact --sha256 "$ZSHA" "${FILES[@]}"
	fi
fi
