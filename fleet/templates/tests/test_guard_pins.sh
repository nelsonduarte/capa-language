#!/usr/bin/env bash
#
# THE PIN, AUDITED BY CONTENT.
#
# release.yml pins the shared release guards by commit SHA, and the
# question that pin is supposed to answer is "which bytes will run".
# Until .github/guard-pins.sha256 existed, that question was answered by
# a value the platform handed the guards rather than by anything
# observable about the files: the guards read a revision from the job
# context and then checked that `actions/checkout` had fetched that same
# revision, which is one number compared with itself. Two revisions that
# are byte-identical are indistinguishable by such a check, and two that
# are NOT identical are exactly the case that must be caught.
#
# So .github/guard-pins.sha256 records the digest of every guard file at
# the revision this repository audited, and this test re-fetches each one
# and compares. A pin bumped without re-auditing goes red on the revision
# line; a pin whose bytes are not the audited bytes goes red on a digest.
# Neither outcome depends on anything the guards say about themselves.
#
# Run it directly:
#
#   bash tests/test_guard_pins.sh
#
# `capa test` runs the .capa files in tests/ and ignores this one.
#
# It reports SKIP rather than failing when `gh` is missing or
# unauthenticated, matching tests/test_release_wiring.sh: an offline
# machine cannot fetch the canonical bytes, and a test that guesses at
# them is the failure mode this file is about. The pin itself is still
# checked offline, because a malformed pin means there is no canonical
# revision to compare against and that is knowable without the network.
#
# CONTROL FLOW, deliberately: FAIL FAST ON PRECONDITIONS, EXHAUSTIVE ON
# SUBSTANCE. A missing workflow, a malformed pin, a missing record, an
# absent revision or a revision that is not the pinned one each end the
# run, because every assertion after them would be comparing against
# nothing and would report a shape of failure that hides the cause. Once
# the revision is settled, every file is checked and every mismatch is
# reported, because "which of them drifted" is the answer worth having.
# capa_authgate's ancestor of this file kept going after a revision
# mismatch instead; that was measured and yields no extra diagnostic on
# any reachable path, since it skips the digest loop in that state too.
#
# WHY THERE IS NO LOCAL COPY OF ANY GUARD, and why capa_authgate's
# tools/check_tag_version.sh was deleted rather than copied out here.
# That file existed so the guard could be rehearsed offline, and it was
# a second copy of a security control inside the very fleet whose drift
# apparatus exists because copies drift. Its own header recorded that it
# had ALREADY drifted once, having been forked before the shared guard
# gained its third argument, so the two accepted different arguments and
# printed different messages while looking interchangeable. The guard is
# now tested once, in the compiler repository, against the file the
# release actually runs. The acknowledged cost is that a contributor
# with only an adopter checked out can no longer rehearse that guard
# offline; that was weighed and accepted, because a rehearsable copy
# that lies is worse than a canonical one that is out of reach.
#
# THIS FILE HAS NO REPO-SPECIFIC CONFIGURATION and is copied verbatim
# into every adopter. That is not left as an assertion: it is a
# WHOLE-FILE entry in .github/shared-regions.sha256, so
# tests/test_shared_regions.sh digests all of it and layer 2 compares
# that digest against the canonical copy upstream. Having no config
# region is the point rather than an omission; the config region is the
# only part of a shared file that nothing digests, so a file that needs
# none should have none.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/release.yml"
PINS="${REPO_ROOT}/.github/guard-pins.sha256"

GUARD_REPO="nelsonduarte/capa-language"
GUARD_WORKFLOW=".github/workflows/release-guards.yml"

PASS=0
FAIL=0
SKIP=0

ok()   { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
no()   { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf 'skip %s\n' "$1"; }

finish() {
  printf '\n%s passed, %s failed, %s skipped\n' "${PASS}" "${FAIL}" "${SKIP}"
  [ "${FAIL}" = "0" ]
}

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [ ! -f "${WORKFLOW}" ]; then
  echo "FAIL: ${WORKFLOW} not found" >&2
  exit 1
fi

# The revision to compare against is not a constant in this file: it is
# whatever release.yml pins, so bumping the pin retargets the comparison
# and a stale audit record goes red at the bump rather than silently
# later.
PIN="$(sed -n 's|^[[:space:]]*uses:[[:space:]]*'"${GUARD_REPO}"'/\.github/workflows/release-guards\.yml@||p' "${WORKFLOW}")"
PIN="${PIN%%[[:space:]]*}"

if printf '%s' "${PIN}" | grep -qE '^[0-9a-f]{40}$'; then
  ok "release.yml pins a full 40-character guard revision (${PIN})"
else
  no "release.yml does not pin a full 40-character guard revision (got '${PIN}')"
  finish
  exit 1
fi

if [ ! -f "${PINS}" ]; then
  no "the audited guard digests are recorded (.github/guard-pins.sha256)"
  finish
  exit 1
fi
ok "the audited guard digests are recorded (.github/guard-pins.sha256)"

AUDITED_REV="$(awk '{ sub(/\r$/, "") } $1 == "revision" { print $2; exit }' "${PINS}")"

if [ -z "${AUDITED_REV}" ]; then
  no "guard-pins.sha256 names no revision; it cannot describe anything"
  finish
  exit 1
fi

if [ "${AUDITED_REV}" != "${PIN}" ]; then
  no "the audited revision is not the pinned one"
  echo "     release.yml pins        ${PIN}"
  echo "     guard-pins.sha256 names ${AUDITED_REV}"
  echo "     re-read the diff between them, then re-record the digests"
  finish
  exit 1
fi
ok "the audited revision is the one release.yml pins"

# One digest line per guard file: "<sha256>  <path>", and nothing else
# on the line. The same shape tests/test_shared_regions.sh accepts for
# its own record, so the two records are read by one rule rather than by
# two that nearly agree. `\r` is stripped, because a record written on a
# Windows checkout without `* text eol=lf` in .gitattributes would
# otherwise fail with a diagnostic about missing entries rather than
# about line endings.
ENTRIES="$(awk '
  { sub(/\r$/, "") }
  /^[0-9a-f]+[ \t]+[^ \t]+$/ && length($1) == 64 { print }
' "${PINS}")"

if [ -z "${ENTRIES}" ]; then
  no "guard-pins.sha256 records no digests; it would pass having checked nothing"
  finish
  exit 1
fi

# ---------------------------------------------------------------------
# COMPLETENESS, OFFLINE FLOOR. The record must cover every file the
# guards actually EXECUTE. Recording four of five files still produces a
# fully green log while one script runs unaudited, and the file most
# likely to be forgotten is the newest one, which is also the one nobody
# has read before.
#
# This list is hardcoded, and being hardcoded it is a fleet fact
# replicated into every copy: a sixth guard file upstream means every
# adopter's copy of this file has to change in lockstep, which is the
# drift problem one level down. The ONLINE derivation further below
# exists because of that. This list stays as the floor, because it is
# the only completeness statement available on a machine with no `gh`,
# and because a regex over a workflow is a heuristic that could miss an
# invocation written some other way. An under-approximation is the one
# thing this must not become.
#
# THE MATCH IS ON THE PARSED PATH FIELD, not a substring of the line. It
# was a substring test, and a record naming tools/capa_floor.sh.orig
# therefore satisfied the requirement for tools/capa_floor.sh: the
# offline half reported `ok the audit record covers tools/capa_floor.sh`
# while the online half, fifty lines below, reported that
# tools/capa_floor.sh.orig is NOT the audited file. One log, two answers,
# and the offline one was the under-approximation this paragraph says it
# must not become.
# ---------------------------------------------------------------------
covers() {
  # ENTRIES has already been filtered to exactly two fields, so $2 IS
  # the path and equality is the whole test.
  printf '%s\n' "${ENTRIES}" | awk -v p="$1" '$2 == p { hit = 1 } END { exit !hit }'
}

for required in \
  "${GUARD_WORKFLOW}" \
  tools/check_tag_version.sh \
  tools/clean_room_build.sh \
  tools/capa_floor.sh \
  tools/verify_guard_digests.sh
do
  if covers "${required}"; then
    ok "the audit record covers ${required}"
  else
    no "the audit record omits ${required}, which the guards execute"
  fi
done

# verify_guard_digests.sh IS in that list unconditionally, and used not
# to be: it was required only when release.yml passes `guard-digests`,
# on the reasoning that the script does nothing without it. The step
# that calls it is NOT conditional, though, so the derived check below
# requires it in every repository, and an adopter that passes no
# guard-digests would go green offline and red in CI with a diagnostic
# contradicting the conditional check above it. One log must not give
# two answers. Requiring it always is the stricter of the two and costs
# a repository that does not use the input exactly one recorded digest.

if ! command -v gh >/dev/null 2>&1; then
  skip "every guard file matches its audited digest (gh not installed)"
  skip "the audit record covers every file the pinned workflow invokes (gh not installed)"
  finish
  exit $?
elif ! gh auth status >/dev/null 2>&1; then
  skip "every guard file matches its audited digest (gh not authenticated)"
  skip "the audit record covers every file the pinned workflow invokes (gh not authenticated)"
  finish
  exit $?
fi

while read -r want path; do
  [ -z "${path}" ] && continue
  got="$(gh api "repos/${GUARD_REPO}/contents/${path}?ref=${PIN}" \
           --jq .content 2>/dev/null | base64 -d | sha256sum | cut -d' ' -f1)"
  if [ -z "${got}" ]; then
    no "${path} could not be fetched at ${PIN}; the pin may not carry it"
  elif [ "${got}" = "${want}" ]; then
    ok "${path} matches its audited digest"
  else
    no "${path} at ${PIN} is NOT the audited file"
    echo "     audited ${want}"
    echo "     fetched ${got}"
  fi
done <<< "${ENTRIES}"

# ---------------------------------------------------------------------
# COMPLETENESS, DERIVED ONLINE. The list above is a copy of a fleet fact
# and will go stale the day a sixth guard file appears upstream, in all
# twenty-two copies at once and silently in every one of them. The
# pinned workflow is already being fetched here, so the set of files it
# invokes can be read out of it rather than remembered.
#
# THIS IS ADDITIVE AND NEVER A REPLACEMENT. It is a regex over YAML: an
# invocation written some other way (an interpolated path, a `script:`
# indirection, a different runner) would not be seen, so on its own it
# would be an under-approximation of what runs, which is precisely the
# failure this whole file exists to abolish. Used alongside the
# hardcoded floor it can only ADD requirements, and a divergence between
# the two lists is itself worth reading: either upstream grew a file, or
# it stopped invoking one.
#
# Comment lines are stripped before matching, which is what keeps
# `python tools/nest_vendor.py` (documentation inside the workflow's own
# header, not an invocation) out of the derived set.
# ---------------------------------------------------------------------
if gh api "repos/${GUARD_REPO}/contents/${GUARD_WORKFLOW}?ref=${PIN}" \
     --jq .content 2>/dev/null | base64 -d > "${WORK}/guards.yml" 2>/dev/null \
   && [ -s "${WORK}/guards.yml" ]; then

  # The workflow file is invoked by definition; everything else is read
  # out of it.
  {
    printf '%s\n' "${GUARD_WORKFLOW}"
    grep -v '^[[:space:]]*#' "${WORK}/guards.yml" \
      | grep -oE 'bash [^ ]*/tools/[A-Za-z0-9_.-]+\.(sh|py)' \
      | sed 's|.*/tools/|tools/|'
  } | sort -u > "${WORK}/derived"

  if [ ! -s "${WORK}/derived" ]; then
    no "no invocations could be derived from ${GUARD_WORKFLOW} at ${PIN}"
    echo "     the workflow was fetched but nothing matched; the derivation"
    echo "     has gone stale and is silently requiring nothing"
  else
    missing=""
    while read -r path; do
      covers "${path}" || missing="${missing} ${path}"
    done < "${WORK}/derived"

    if [ -z "${missing}" ]; then
      ok "the audit record covers every file ${GUARD_WORKFLOW}@${PIN} invokes ($(wc -l < "${WORK}/derived" | tr -d ' ') derived)"
    else
      no "the audit record omits file(s) the pinned workflow invokes:${missing}"
      echo "     derived from ${GUARD_WORKFLOW} at ${PIN}, which is the workflow"
      echo "     your release runs; record a digest for each, or establish that"
      echo "     upstream no longer invokes it"
    fi
  fi
else
  no "${GUARD_WORKFLOW} could not be fetched at ${PIN} to derive what it invokes"
fi

finish
