#!/usr/bin/env bash
#
# WRITE ONE REPOSITORY'S .github/guard-pins.sha256, BY FETCHING.
#
#   bash fleet/guard_pins.sh <target-repo-dir> [guard-ref]
#
# for example
#
#   bash fleet/guard_pins.sh ~/Desktop/repos/capa_url
#   bash fleet/guard_pins.sh ~/Desktop/repos/capa_url 2db0070
#
# With no ref, the revision is read from the target's
# .github/workflows/release.yml, which is the only correct default: the
# record has to describe the revision that repository's release actually
# runs, and release.yml is where that is stated.
#
# WHY THIS EXISTS, and it is the same reason fleet/adopt.sh does.
#
# guard-pins.sha256 records the SHA-256 of every file the shared release
# guards execute, at the revision release.yml pins. Until now there was
# no template for it and nothing that produced it, while the adoption
# checklist said to copy it "from the template repository". No such
# thing existed, so the only place a first-timer could get one was
# another adopter. Copying it produces a fully green run, 14 passed and
# 0 failed, having audited nothing: the digests are genuinely the pinned
# revision's bytes, so every check passes correctly. THE HOLE IS NOT IN
# THE DIGESTS. It is in what the file CLAIMS about how it came to exist.
#
# capa_hex's record says, in prose a copy carries verbatim:
#
#   "That record was deliberately NOT copied: each digest below was
#    recomputed here by re-fetching the file at the pin"
#   "ALL FIVE FILES WERE READ AT THIS REVISION, not accepted on their
#    digests."
#
# Both false in the receiving repository, and no layer can falsify them.
# That is the same class as the incident this fleet deleted two branches
# over: a record asserting the opposite of how it was produced. The
# general form, which is worth stating once and obeying everywhere:
#
#   A RECORD SHOULD NEVER CARRY A PRE-WRITTEN SENTENCE DESCRIBING WORK A
#   HUMAN DID, BECAUSE COPIES CARRY THE SENTENCE AND NOT THE WORK.
#
# So this writes the digests, which is mechanical and belongs to a
# machine, and leaves the audit note as a BLANK the human must fill.
# tests/test_guard_pins.sh refuses the record while the blank is still
# there, which turns "a copy carries the claim without the work" into a
# red test rather than a sentence nobody can check.
#
# WHY IT IS NOT PART OF fleet/adopt.sh. The guard pin and the
# shared-region revision are deliberately independent: one shared
# revision would make every guard bump force a wiring re-audit and every
# wiring bump force a guard re-audit, and that friction is the likeliest
# reason for either to be skipped. adopt.sh takes the compiler revision
# whose TEMPLATES you are adopting; this takes the guard revision your
# release.yml PINS. Folding them together would either conflate the two
# numbers or require adopt.sh to read a release.yml that does not exist
# yet on a first adoption.
#
# WHAT IT DOES NOT DO: read the diff between the old and new guard
# revisions for you. That is the whole point of the exercise and the one
# part no tool can perform. It prints the compare URL and stops.

set -uo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: bash fleet/guard_pins.sh <target-repo-dir> [guard-ref]

  <target-repo-dir>  the repository whose .github/guard-pins.sha256 to write
  [guard-ref]        the guard revision. Defaults to whatever the target's
                     .github/workflows/release.yml pins, which is the only
                     revision the record can correctly describe. Any ref is
                     accepted and RESOLVED to a full commit SHA.
USAGE
  exit 2
}

GUARD_REPO="nelsonduarte/capa-language"
GUARD_WORKFLOW=".github/workflows/release-guards.yml"
RECORD_REL=".github/guard-pins.sha256"
AUDIT_BLANK="REPLACE-THIS-AUDIT-NOTE"

TARGET=""
REF=""
for arg in "$@"; do
  case "${arg}" in
    -h|--help) usage ;;
    -*)        echo "unknown option: ${arg}" >&2; usage ;;
    *)
      if   [ -z "${TARGET}" ]; then TARGET="${arg}"
      elif [ -z "${REF}" ];    then REF="${arg}"
      else echo "unexpected argument: ${arg}" >&2; usage
      fi
      ;;
  esac
done
[ -n "${TARGET}" ] || usage

STEP=0
say()  { STEP=$((STEP + 1)); printf '\n[%d] %s\n' "${STEP}" "$1"; }
info() { printf '    %s\n' "$1"; }
die()  { printf '\nREFUSED: %s\n' "$1" >&2; shift; for l in "$@"; do printf '         %s\n' "$l" >&2; done; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# ---------------------------------------------------------------------
say "Checking preconditions"

command -v gh >/dev/null 2>&1 || die "gh is not installed" \
  "Every digest here is computed from bytes fetched at the pinned" \
  "revision. Without gh there is no way to get them, and copying them" \
  "from another repository is the failure this script exists to prevent."
gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run: gh auth login)"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is not available"

[ -d "${TARGET}" ] || die "no such directory: ${TARGET}"
TARGET="$(cd "${TARGET}" && pwd)"
[ -d "${TARGET}/.git" ] || die "${TARGET} is not a git repository"

WORKFLOW="${TARGET}/.github/workflows/release.yml"
[ -f "${WORKFLOW}" ] || die "${TARGET} has no .github/workflows/release.yml" \
  "The record describes the guard revision that workflow pins, so the" \
  "workflow has to exist first. Copy release.yml and guard-selftest.yml" \
  "from an existing adopter and adapt their consumer flow to this" \
  "package, then run this again. tests/test_release_wiring.sh checks" \
  "that adaptation in detail; this script does not."
info "target: ${TARGET}"

# ---------------------------------------------------------------------
say "Determining the guard revision"

if [ -z "${REF}" ]; then
  REF="$(sed -n 's|^[[:space:]]*uses:[[:space:]]*'"${GUARD_REPO}"'/\.github/workflows/release-guards\.yml@||p' "${WORKFLOW}")"
  REF="${REF%%[[:space:]]*}"
  [ -n "${REF}" ] || die "release.yml does not call the shared release guards" \
    "Expected a line of the form:" \
    "    uses: ${GUARD_REPO}/${GUARD_WORKFLOW}@<sha>" \
    "Pass the revision explicitly if you are writing the record first."
  info "release.yml pins ${REF}"
fi

REV="$(gh api "repos/${GUARD_REPO}/commits/${REF}" --jq .sha 2>/dev/null)"
# A here-string, not `printf | grep -q`: see the note in fleet/adopt.sh.
grep -qE '^[0-9a-f]{40}$' <<< "${REV}" \
  || die "could not resolve '${REF}' to a commit in ${GUARD_REPO}"
info "recording ${REV}"

if [ "${REV}" != "${REF}" ]; then
  info "NOTE: release.yml pins '${REF}', which is not a full commit SHA."
  info "      Update it to ${REV}, or tests/test_guard_pins.sh will refuse"
  info "      the mismatch. A moving ref lets the guards change under you."
fi

# ---------------------------------------------------------------------
# WHICH FILES TO RECORD.
#
# Two sources, unioned, and neither is hardcoded here:
#
#   * every path the pinned workflow INVOKES, read out of the workflow
#     itself. This is the same derivation tests/test_guard_pins.sh
#     performs online, so the record and the check agree by construction
#     rather than by two people remembering the same list.
#   * every path that check REQUIRES, read out of the installed copy of
#     it. The check keeps a hardcoded floor because a regex over YAML
#     could miss an invocation written some other way, and an
#     under-approximation is the one thing that must not ship. Recording
#     the union means the record can only be a superset.
#
# A third copy of the list here would be the drift problem one level up,
# which is the whole subject of this directory.
# ---------------------------------------------------------------------
say "Deriving which files the guards execute"

fetch() {
  gh api "repos/${GUARD_REPO}/contents/$1?ref=${REV}" --jq .content 2>/dev/null \
    | base64 -d > "$2" 2>/dev/null
  [ -s "$2" ]
}

fetch "${GUARD_WORKFLOW}" "${WORK}/guards.yml" \
  || die "${REV} does not carry ${GUARD_WORKFLOW}" \
         "That revision is not a commit of ${GUARD_REPO}, or predates the" \
         "shared release guards."

{
  printf '%s\n' "${GUARD_WORKFLOW}"
  grep -v '^[[:space:]]*#' "${WORK}/guards.yml" \
    | grep -oE 'bash [^ ]*/tools/[A-Za-z0-9_.-]+\.(sh|py)' \
    | sed 's|.*/tools/|tools/|'
} > "${WORK}/paths"

CHECK="${TARGET}/tests/test_guard_pins.sh"
if [ -f "${CHECK}" ]; then
  awk '
    /^for required in/ { inside = 1; next }
    inside && /^do/    { exit }
    inside {
      line = $0
      gsub(/[\\"]/, "", line)
      gsub(/\$\{GUARD_WORKFLOW\}/, "'"${GUARD_WORKFLOW}"'", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "${CHECK}" >> "${WORK}/paths"
else
  info "NOTE: tests/test_guard_pins.sh is not installed here yet, so only the"
  info "      workflow's own invocations were derived. Run fleet/adopt.sh"
  info "      first and then re-run this, so the check's required list is"
  info "      unioned in as well."
fi

sort -u "${WORK}/paths" > "${WORK}/files"
[ -s "${WORK}/files" ] || die "no guard files could be derived at ${REV}"
while read -r p; do info "${p}"; done < "${WORK}/files"

# ---------------------------------------------------------------------
say "Fetching and digesting"

: > "${WORK}/digests"
while read -r path; do
  [ -n "${path}" ] || continue
  fetch "${path}" "${WORK}/blob" \
    || die "${REV} does not carry ${path}" \
           "It is invoked by ${GUARD_WORKFLOW} at that revision, or required" \
           "by tests/test_guard_pins.sh, but cannot be fetched. Recording a" \
           "file that is not there would be recording a fiction."
  printf '%s  %s\n' "$(sha256sum < "${WORK}/blob" | cut -d' ' -f1)" "${path}" \
    >> "${WORK}/digests"
  info "$(sha256sum < "${WORK}/blob" | cut -d' ' -f1)  ${path}"
done < "${WORK}/files"

# ---------------------------------------------------------------------
say "Writing ${RECORD_REL}"

HAD=""
[ -f "${TARGET}/${RECORD_REL}" ] && HAD=1

mkdir -p "${TARGET}/.github" || die "could not create .github in ${TARGET}"
cat > "${TARGET}/${RECORD_REL}" <<EOF
# THE GUARD REVISION THIS REPOSITORY AUDITED, BY CONTENT.
#
# .github/workflows/release.yml pins the shared release guards by commit
# SHA. A SHA is content-addressed and therefore immutable, so the pin
# cannot be edited under us. What a SHA does NOT do is tell a reader what
# is in it, and nothing states which BYTES were looked at before pinning
# them. That is what this file is for.
#
# Every file the guards execute is recorded below by SHA-256, taken at
# the pinned revision. tests/test_guard_pins.sh re-fetches each one and
# refuses any difference, so:
#
#   * bumping the pin without re-auditing goes RED, because the digests
#     below describe a revision the workflow no longer names;
#   * a pin that resolves to bytes other than the audited ones goes RED,
#     which is the falsifiable form of "we ran what we pinned";
#   * the check runs offline of any claim the guards make about
#     themselves, before a tag is ever pushed.
#
# WHAT REMAINS TRUSTED, stated plainly rather than papered over: that
# GitHub runs the workflow file living at the pinned SHA. A workflow
# cannot establish its own identity from inside itself, because a
# substituted file could simply print the expected answer. That is the
# platform's guarantee and the reason \`uses:@<sha>\` is written by SHA.
# Everything downstream of it is checked here by content.
#
# THE DIGESTS BELOW WERE WRITTEN BY \`bash fleet/guard_pins.sh\`, which
# fetched each file at ${REV} and hashed it. Do not
# hand-edit them, and do not copy this file from another repository: a
# copied record passes every check while having audited nothing, because
# the digests are genuinely the pinned revision's bytes. What a copy
# cannot carry is the reading.
#
# TO RE-AUDIT AFTER A PIN BUMP: read the diff, then re-run
# \`bash fleet/guard_pins.sh <this repository>\` and rewrite the note below.
#
#   https://github.com/${GUARD_REPO}/compare/<old>...${REV}

# ---------------------------------------------------------------------
# AUDIT NOTE. ${AUDIT_BLANK}
#
# REPLACE THIS BLOCK. tests/test_guard_pins.sh REFUSES this record while
# the marker above is still present, on purpose: a pre-written sentence
# describing work a human did is carried by every copy, and the work is
# not. So there is nothing pre-written here to carry.
#
# Write what you actually read at ${REV}:
# what the revision is, what changed since the one it replaces, and
# which of the files below you opened rather than accepted on their
# digest. If you did not read them, say that instead. An honest short
# note is worth more than a thorough-sounding one nobody can check.
# ---------------------------------------------------------------------

revision ${REV}

EOF
cat "${WORK}/digests" >> "${TARGET}/${RECORD_REL}"

info "${RECORD_REL}  (revision ${REV})"
if [ -n "${HAD}" ]; then
  info "  replaced the record that was here"
fi

echo
echo "WRITTEN, NOT YET AUDITED: ${TARGET}/${RECORD_REL}"
echo
echo "The digests are done. The audit is not, and it is the part that matters."
echo
echo "  1. Read the guard files at ${REV}. At minimum"
echo "     tools/capa_floor.sh, which chooses which released compiler the"
echo "     clean room downloads, and tools/clean_room_build.sh, which runs"
echo "     the consumer commands this repository supplies."
echo "  2. If you are bumping an existing pin, read the diff:"
echo "     https://github.com/${GUARD_REPO}/compare/<old>...${REV}"
echo "  3. Replace the AUDIT NOTE block with what you found."
echo "  4. bash ${TARGET}/tests/test_guard_pins.sh"
echo
echo "Step 4 fails until step 3 is done. That is deliberate: this script"
echo "can fetch bytes, and it cannot read them for you."
