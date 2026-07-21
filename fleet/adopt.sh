#!/usr/bin/env bash
#
# ADOPT THE SHARED RELEASE-GUARD APPARATUS INTO ONE REPOSITORY.
#
#   bash fleet/adopt.sh <target-repo-dir> <compiler-ref>
#
# for example
#
#   bash fleet/adopt.sh ~/Desktop/repos/capa_hex ddf452e
#   bash fleet/adopt.sh ~/Desktop/repos/capa_url main
#
# WHY THIS EXISTS. Adoption was an eight-step prose checklist, and every
# defect this apparatus has found so far was in the MECHANISM rather than
# in the act of adopting, because there had only been two adoptions and
# both were done by hand by someone holding the whole design in their
# head. Fifteen more will not be like that.
#
# Two of those steps could go wrong QUIETLY. The dangerous one is
# transcribing the five digests. The natural shortcut is to copy
# .github/shared-regions.sha256 from a sibling repository rather than
# from the compiler revision being adopted. If that sibling is one
# revision stale, layer 1 goes GREEN, because the test files were copied
# from the same stale place and genuinely match, while layer 2 goes red.
# The obvious response to that is to bump the revision line until it
# passes, and that is precisely the "update the digests without
# re-copying" fork the record's own header warns against. It is the one
# place in the whole design where the obvious way to make it green is
# the wrong action. Everywhere else, the wrong move looks wrong.
#
# THIS SCRIPT MAKES THAT PATH NOT EXIST rather than discouraging it.
# Every byte it installs, the five shared files and all five digests,
# is fetched from the named compiler revision. It never reads a sibling
# repository, and it never reads the target's existing record for
# anything except reporting what the revision used to be. A human does
# not transcribe a digest at any point. Re-running it over a hand-edited
# record simply overwrites the edit with the canonical numbers, which is
# the desired outcome and not something to refuse.
#
# The other quiet step is .gitattributes, which is asserted below.
#
# WHY IT IS NOT ITSELF IN THE SHARED-REGION RECORD. The record exists
# because files are COPIED into every adopter and copies drift. This
# file is not copied anywhere: it lives in the compiler repository, is
# run from there against a target directory, and has exactly one
# instance, so there is nothing for it to drift from. Putting it in the
# record would require shipping it into seventeen repositories in order
# to check that seventeen copies agree, which would manufacture the
# problem the record exists to solve. It is held honest the same way
# tools/check_tag_version.sh is: one copy, tested where it lives, by
# tests/test_fleet_adopt.py.
#
# WHAT IT DOES NOT REACH, stated plainly and not padded: whether Actions
# is enabled for the repository, whether branch protection requires
# these checks, and what the required-check configuration says. Those
# live in GitHub settings rather than in git, so no file-based tool
# touches them. After adopting, confirm in the repository settings that
# the `checks` workflow is required on the default branch. Nothing here
# can confirm that for you, and nothing here pretends to.

set -uo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: bash fleet/adopt.sh <target-repo-dir> <compiler-ref> [--allow-dirty]

  <target-repo-dir>  the repository adopting the apparatus
  <compiler-ref>     any ref of the compiler repository (a commit SHA, a
                     tag, or a branch). It is RESOLVED to a full commit
                     SHA and that SHA is what gets pinned, because a
                     moving ref in the record would defeat the audit.

  --allow-dirty      proceed even though the target has uncommitted
                     changes. Refused by default so that
                     `git checkout -- . && git clean -fd` in the target
                     undoes exactly what this wrote and nothing else.
                     Both commands: a first adoption writes files that
                     are untracked, which `checkout` does not touch.

  --allow-template-mismatch
                     proceed even though this checkout's fleet/templates/
                     differs from the resolved revision. Refused by
                     default: every byte is installed from the revision,
                     not from here, so a mismatch means installing files
                     nobody has read and describing them from files that
                     were not installed.
USAGE
  exit 2
}

CANON_REPO="nelsonduarte/capa-language"
CANON_PREFIX="fleet/templates/"
RECORD_REL=".github/shared-regions.sha256"
GITATTRIBUTES_RULE='* text eol=lf'

BEGIN_MARK='# ================== CONFIG: the only repo-specific part =================='
END_MARK='# ======================= END CONFIG; shared body ========================='

TARGET=""
REF=""
ALLOW_DIRTY=""
ALLOW_MISMATCH=""

for arg in "$@"; do
  case "${arg}" in
    --allow-dirty)             ALLOW_DIRTY=1 ;;
    --allow-template-mismatch) ALLOW_MISMATCH=1 ;;
    -h|--help)     usage ;;
    -*)            echo "unknown option: ${arg}" >&2; usage ;;
    *)
      if   [ -z "${TARGET}" ]; then TARGET="${arg}"
      elif [ -z "${REF}" ];    then REF="${arg}"
      else echo "unexpected argument: ${arg}" >&2; usage
      fi
      ;;
  esac
done

[ -n "${TARGET}" ] && [ -n "${REF}" ] || usage

STEP=0
say()  { STEP=$((STEP + 1)); printf '\n[%d] %s\n' "${STEP}" "$1"; }
info() { printf '    %s\n' "$1"; }
die()  { printf '\nREFUSED: %s\n' "$1" >&2; shift; for l in "$@"; do printf '         %s\n' "$l" >&2; done; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# ---------------------------------------------------------------------
# Preconditions. Every one of these is a way of not knowing, and a tool
# that half-adopts leaves a repository in a state no test describes.
# ---------------------------------------------------------------------
say "Checking preconditions"

command -v gh >/dev/null 2>&1 \
  || die "gh is not installed" \
         "Every byte installed here is fetched from the compiler revision" \
         "you named. Without gh there is no way to get it, and reading it" \
         "from a sibling repository is the failure this script exists to" \
         "prevent."
gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run: gh auth login)"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is not available"

[ -d "${TARGET}" ] || die "no such directory: ${TARGET}"
TARGET="$(cd "${TARGET}" && pwd)"
[ -d "${TARGET}/.git" ] || die "${TARGET} is not a git repository" \
  "This writes several files. Refusing outside version control, because" \
  "there would be no way to review or undo what it did."

if [ -z "${ALLOW_DIRTY}" ] && [ -n "$(git -C "${TARGET}" status --porcelain)" ]; then
  die "${TARGET} has uncommitted changes" \
      "Commit or stash them first, so that the undo below is exactly what" \
      "this script wrote and nothing else. Pass --allow-dirty to proceed."
fi

# .gitattributes is ASSERTED HERE, with the other preconditions, and not
# after installing. It needs no network and no fetched bytes, and the
# refusal used to fire at step 6 with six files already written and no
# mention that anything had been, which is the "half-adopts and leaves a
# state no test describes" failure this block's own comment names.
#
# CREATING a missing one is a write, so that part waits for the install
# step below. Only the refusal lives here.
ATTRS="${TARGET}/.gitattributes"
if [ -f "${ATTRS}" ] \
   && ! grep -qE '^\*[[:space:]]+text([[:space:]]*=[[:space:]]*auto)?[[:space:]]+eol=lf[[:space:]]*$' "${ATTRS}"; then
  die ".gitattributes exists but does not pin LF for every file" \
      "Add this line to ${ATTRS}:" \
      "  ${GITATTRIBUTES_RULE}" \
      "It is not appended automatically because editing a file you wrote is" \
      "a decision about your repository. Without it a Windows checkout" \
      "produces different bytes from a Linux one, and the digests this" \
      "installs would depend on who committed last." \
      "NOTHING HAS BEEN WRITTEN."
fi
info "target: ${TARGET}"

# ---------------------------------------------------------------------
# Resolve the ref. A branch or tag is accepted for convenience and is
# resolved HERE; what gets pinned is always the full commit SHA, because
# a record pinning a moving ref would let the canonical bytes change
# under an audit that still reported green.
# ---------------------------------------------------------------------
say "Resolving ${REF} in ${CANON_REPO}"

REV="$(gh api "repos/${CANON_REPO}/commits/${REF}" --jq .sha 2>/dev/null)"
printf '%s' "${REV}" | grep -qE '^[0-9a-f]{40}$' \
  || die "could not resolve '${REF}' to a commit in ${CANON_REPO}" \
         "Check the ref exists and has been pushed. An unpublished commit" \
         "cannot be adopted, which is deliberate: the audit compares" \
         "against bytes anyone can fetch."

if [ "${REV}" != "${REF}" ]; then
  info "${REF} resolves to ${REV}"
else
  info "${REV}"
fi
info "this SHA is what the record will pin"

# ---------------------------------------------------------------------
# Fetch everything, before touching the target.
# ---------------------------------------------------------------------
say "Fetching the canonical files at ${REV}"

fetch() {
  # fetch <path-in-compiler-repo> <destination>
  gh api "repos/${CANON_REPO}/contents/$1?ref=${REV}" --jq .content 2>/dev/null \
    | base64 -d > "$2" 2>/dev/null
  [ -s "$2" ]
}

fetch "${CANON_PREFIX}${RECORD_REL}" "${WORK}/record" \
  || die "${REV} does not carry ${CANON_PREFIX}${RECORD_REL}" \
         "That revision predates this apparatus, or is not a commit of" \
         "the compiler repository."

# The set of files to install, and the CONFIG names each region file
# may declare, are DERIVED from the canonical check at this revision
# rather than hardcoded here. A hardcoded copy would be a fleet fact in
# a second place, which is the drift problem this whole apparatus is
# about, one level up.
fetch "${CANON_PREFIX}tests/test_shared_regions.sh" "${WORK}/check.sh" \
  || die "${REV} does not carry the adopter check"

ENTRIES="$(awk '
  /^SHARED_FILES=\(/ { inside = 1; next }
  inside && /^\)/    { exit }
  inside {
    line = $0
    sub(/^[[:space:]]*"/, "", line)
    sub(/"[[:space:]]*$/, "", line)
    if (line != "") print line
  }
' "${WORK}/check.sh")"

[ -n "${ENTRIES}" ] || die "could not read the file table out of the canonical check" \
  "Its SHARED_FILES table is not in the shape this script parses. That is" \
  "a change to the apparatus, and this script must be updated with it" \
  "rather than guessing."

COUNT=0
while IFS= read -r entry; do
  [ -n "${entry}" ] || continue
  rel="${entry#*:}"; rel="${rel%%:*}"
  mkdir -p "${WORK}/new/$(dirname "${rel}")"
  fetch "${CANON_PREFIX}${rel}" "${WORK}/new/${rel}" \
    || die "${REV} does not carry ${CANON_PREFIX}${rel}"
  COUNT=$((COUNT + 1))
  info "${rel}"
done <<< "${ENTRIES}"
info "${COUNT} shared file(s), and the audit record"

# ---------------------------------------------------------------------
# BIND THIS CHECKOUT TO THE REVISION BEING INSTALLED.
#
# Everything above came from the API at ${REV}, which is what closes the
# stale-sibling hole. It opens a different one, and this script produced
# it on its first real use.
#
# The operator reads fleet/templates/ in their own checkout, forms a
# belief about what they are installing, runs this, and writes a commit
# message describing THEIR CHECKOUT. What lands is ${REV}. When the two
# differ, every one of those commit messages is false, and the record is
# the one file no digest covers, so no layer catches it.
#
# That is not hypothetical. Adopting ddf452e from a branch that had
# reworded the record's placeholder comment installed ddf452e's older
# wording, with zero warnings and 33 passed / 0 failed / 0 skipped, and
# produced two commit messages in two repositories asserting the
# opposite of what they contained. At two repositories that gets
# noticed. At fifteen it is fifteen stale stampings and fifteen false
# messages.
#
# The canonical bytes are already in ${WORK} from the step above, so
# this comparison is free. It is the same class of guard as the
# .gitattributes assertion: cheap, and it refuses before anything is
# written rather than explaining afterwards.
# ---------------------------------------------------------------------
say "Binding this checkout to ${REV}"

FLEET_DIR="$(cd "$(dirname "$0")" && pwd)"

MISMATCH=""
compare_local() {
  # compare_local <path-as-adopter-sees-it> <fetched-file>
  local here="${FLEET_DIR}/templates/$1"
  if [ ! -f "${here}" ] || ! cmp -s "${here}" "$2"; then
    MISMATCH="${MISMATCH}
           ${1}"
  fi
}

while IFS= read -r entry; do
  [ -n "${entry}" ] || continue
  rel="${entry#*:}"; rel="${rel%%:*}"
  compare_local "${rel}" "${WORK}/new/${rel}"
done <<< "${ENTRIES}"
compare_local "${RECORD_REL}" "${WORK}/record"

if [ -z "${MISMATCH}" ]; then
  info "fleet/templates/ here is byte-identical to ${REV}"
  info "what you have read is what will be installed"
elif [ -n "${ALLOW_MISMATCH}" ]; then
  echo
  echo "    ############################################################"
  echo "    # WARNING: INSTALLING BYTES YOU HAVE NOT READ.             #"
  echo "    ############################################################"
  echo "    Your fleet/templates/ differs from ${REV} in:${MISMATCH}"
  echo
  echo "    ${REV} is what gets installed and pinned. Your checkout is"
  echo "    NOT. Any commit message you write from what you can see here"
  echo "    will describe files that were not installed."
  echo
else
  die "your fleet/templates/ is not the revision you are adopting" \
      "These files differ between this checkout and ${REV}:${MISMATCH}" \
      "" \
      "${REV} is what gets installed and pinned; this checkout is not read" \
      "for any byte. So whatever you have reviewed locally, and whatever" \
      "commit message you write from it, would describe files that were" \
      "never installed. This script has already produced exactly that, in" \
      "two repositories, on its first real use." \
      "" \
      "Either check out the revision you mean to adopt:" \
      "    git -C ${FLEET_DIR%/fleet} checkout ${REV}" \
      "or adopt the revision you have:" \
      "    push this checkout, then pass the resulting commit" \
      "or, if you genuinely mean to install bytes you have not read," \
      "pass --allow-template-mismatch." \
      "" \
      "NOTHING HAS BEEN WRITTEN."
fi

# ---------------------------------------------------------------------
# CONFIG PRESERVATION, which is the hard part and the reason this
# refuses more often than it repairs.
#
# Adoption is not one-shot. Every revision bump re-runs this against a
# repository whose CONFIG block is already correct and must survive
# verbatim. So for each region file that already exists in the target,
# the local CONFIG region is lifted out and spliced into the freshly
# fetched body.
#
# "CANNOT PRESERVE" MEANS, CONCRETELY, one of:
#
#   * the local file's CONFIG markers are missing, duplicated or out of
#     order, so there is no region to lift and any guess about where it
#     starts would be a guess about which lines are exempt from the
#     digest;
#   * the local CONFIG assigns a name the new template does not declare,
#     which means the template dropped a dimension this repository is
#     still using;
#   * the local CONFIG does not assign a name the new template does
#     declare, which means the template GAINED a dimension and this
#     repository has no value for it.
#
# The last two are the real re-adoption hazard, and both are refusals
# rather than repairs on purpose: either one is a question about what
# this repository means, and a script that answers it invents a value
# nobody chose. The refusal names the file and the exact names.
# ---------------------------------------------------------------------
say "Preserving local CONFIG blocks"

config_names() {
  # The names actually assigned inside a file's CONFIG region.
  awk -v b="${BEGIN_MARK}" -v e="${END_MARK}" '
    { sub(/\r$/, "") }
    $0 == e { inside = 0 }
    inside && /^[A-Za-z_][A-Za-z0-9_]*=/ { sub(/=.*/, ""); print }
    $0 == b { inside = 1 }
  ' "$1" | sort -u
}

marker_shape() {
  awk -v b="${BEGIN_MARK}" -v e="${END_MARK}" '
    { sub(/\r$/, "") }
    $0 == b { nb++; if (nb == 1) bl = NR }
    $0 == e { ne++; if (ne == 1) el = NR }
    END { printf("%d %d %d %d\n", nb + 0, ne + 0, bl + 0, el + 0) }
  ' "$1"
}

FRESH=""
while IFS= read -r entry; do
  [ -n "${entry}" ] || continue
  kind="${entry%%:*}"
  rel="${entry#*:}"; rel="${rel%%:*}"
  [ "${kind}" = "region" ] || continue

  local_file="${TARGET}/${rel}"
  if [ ! -f "${local_file}" ]; then
    FRESH="${FRESH} ${rel}"
    info "${rel}: new here, keeping the template's placeholder CONFIG"
    continue
  fi

  read -r nb ne bl el <<< "$(marker_shape "${local_file}")"
  if [ "${nb}" != "1" ] || [ "${ne}" != "1" ] || [ "${bl}" -gt "${el}" ]; then
    die "cannot preserve the CONFIG block of ${rel}" \
        "Its markers are malformed: the begin marker occurs ${nb} time(s)," \
        "the end marker ${ne} time(s), at lines ${bl} and ${el}." \
        "There is no region to lift out, and guessing where it starts would" \
        "be guessing which lines are exempt from the digest." \
        "Fix the markers in ${local_file}, or delete the file to adopt the" \
        "template's placeholder CONFIG and fill it in by hand."
  fi

  want="$(config_names "${WORK}/new/${rel}")"
  have="$(config_names "${local_file}")"
  if [ "${want}" != "${have}" ]; then
    added="$(comm -13 <(printf '%s\n' "${have}") <(printf '%s\n' "${want}") | tr '\n' ' ')"
    gone="$(comm -23 <(printf '%s\n' "${have}") <(printf '%s\n' "${want}") | tr '\n' ' ')"
    die "cannot preserve the CONFIG block of ${rel}" \
        "The template at ${REV} declares a different set of config names" \
        "than this repository's copy assigns." \
        "  gained upstream, and this repository has no value for: ${added:-(none)}" \
        "  assigned here, but no longer declared upstream:       ${gone:-(none)}" \
        "This is a question about what this repository means, and a script" \
        "that answered it would invent a value nobody chose. Read the diff" \
        "between the two revisions, reconcile ${rel} by hand, then re-run."
  fi

  # Splice: the new body's header up to and including BEGIN, the LOCAL
  # config region, then the new body from END to the end of the file.
  awk -v b="${BEGIN_MARK}" 'NR == FNR { print; if ($0 == b) exit }' \
    "${WORK}/new/${rel}" > "${WORK}/spliced"
  awk -v b="${BEGIN_MARK}" -v e="${END_MARK}" '
    { sub(/\r$/, "") }
    $0 == e { inside = 0 }
    inside  { print }
    $0 == b { inside = 1 }
  ' "${local_file}" >> "${WORK}/spliced"
  awk -v e="${END_MARK}" '$0 == e { on = 1 } on { print }' \
    "${WORK}/new/${rel}" >> "${WORK}/spliced"
  mv "${WORK}/spliced" "${WORK}/new/${rel}"
  info "${rel}: local CONFIG preserved ($(printf '%s' "${have}" | wc -w | tr -d ' ') names)"
done <<< "${ENTRIES}"

# ---------------------------------------------------------------------
# Install. Only now is anything in the target touched.
# ---------------------------------------------------------------------
say "Installing into ${TARGET}"

HAD_RECORD=""
OLD_REV=""
if [ -f "${TARGET}/${RECORD_REL}" ]; then
  HAD_RECORD=1
  OLD_REV="$(awk '{ sub(/\r$/, "") } $1 == "revision" { print $2; exit }' \
    "${TARGET}/${RECORD_REL}")"
fi

# `set -e` is deliberately NOT on, because several branches here read a
# command's status rather than trusting it, so these two writes are
# checked by hand. An unchecked mkdir or cp would leave a partially
# installed tree that only step 8 would notice, and it would notice it
# as DRIFT rather than as a failed copy, which is a diagnosis pointing
# at the wrong thing entirely.
while IFS= read -r entry; do
  [ -n "${entry}" ] || continue
  rel="${entry#*:}"; rel="${rel%%:*}"
  mkdir -p "${TARGET}/$(dirname "${rel}")" \
    || die "could not create $(dirname "${rel}") in ${TARGET}" \
           "The tree is now PARTIALLY INSTALLED. Undo with:" \
           "    git -C ${TARGET} checkout -- . && git -C ${TARGET} clean -fd"
  cp "${WORK}/new/${rel}" "${TARGET}/${rel}" \
    || die "could not write ${rel} into ${TARGET}" \
           "The tree is now PARTIALLY INSTALLED. Undo with:" \
           "    git -C ${TARGET} checkout -- . && git -C ${TARGET} clean -fd"
  info "${rel}"
done <<< "${ENTRIES}"

# The record, with the resolved revision substituted for the template's
# deliberately unusable placeholder. The DIGESTS are the template's own,
# untouched, straight from ${REV}. This is the whole point: no human
# transcribes a digest and no sibling repository is ever read.
mkdir -p "${TARGET}/$(dirname "${RECORD_REL}")" \
  || die "could not create $(dirname "${RECORD_REL}") in ${TARGET}"
awk -v rev="${REV}" '
  { sub(/\r$/, "") }
  $1 == "revision" { print "revision " rev; next }
  { print }
' "${WORK}/record" > "${TARGET}/${RECORD_REL}" \
  || die "could not write ${RECORD_REL} into ${TARGET}" \
         "The tree is now PARTIALLY INSTALLED. Undo with:" \
         "    git -C ${TARGET} checkout -- . && git -C ${TARGET} clean -fd"
info "${RECORD_REL}  (revision ${REV})"

# REPORTED UNCONDITIONALLY, not only when the revision moved. Gating it
# on a changed revision left the single case the record's own header
# warns about, digests transcribed forward with the revision ALREADY
# bumped, as the one case that printed nothing at all about five digests
# and four files having just been replaced.
if [ -n "${HAD_RECORD}" ]; then
  info "  replaced the record that was here (pinned ${OLD_REV:-nothing usable})"
fi

# ---------------------------------------------------------------------
# .gitattributes. Step 3 of the old prose checklist, asserted by nothing
# until this script existed, in an apparatus whose every CRLF handler is
# there because that has bitten repeatedly. On the sixteenth repository
# someone was going to skip it.
#
# The REFUSAL, for a file that exists and does not pin LF, is in the
# preconditions block: it needs no network and no fetched bytes, and
# refusing here would leave six files written. Only the CREATION of a
# missing file is left, because that is a write and writes belong here.
# ---------------------------------------------------------------------
say "Ensuring .gitattributes pins LF"

if [ ! -f "${ATTRS}" ]; then
  {
    echo "# Keep every committed file LF-terminated on every platform. The"
    echo "# shared checks match marker lines by whole-line equality and digest"
    echo "# the result, so a checkout that flips line endings per platform"
    echo "# produces digests that depend on who committed last."
    echo "${GITATTRIBUTES_RULE}"
  } > "${ATTRS}"
  info "created .gitattributes with \`${GITATTRIBUTES_RULE}\`"
elif grep -qE '^\*[[:space:]]+text([[:space:]]*=[[:space:]]*auto)?[[:space:]]+eol=lf[[:space:]]*$' "${ATTRS}"; then
  info "already pins LF"
else
  die ".gitattributes exists but does not pin LF for every file" \
      "Add this line to ${ATTRS}:" \
      "  ${GITATTRIBUTES_RULE}" \
      "It is not appended automatically because editing a file you wrote is" \
      "a decision about your repository. Without it, a Windows checkout" \
      "produces different bytes from a Linux one and the digests above" \
      "depend on who committed last."
fi

# ---------------------------------------------------------------------
# Prove it, with the installed check rather than with a claim.
#
# This is why the script itself stays thin. It could recompute the five
# digests and compare, but that would be a fourth implementation of the
# extraction rule, and two implementations already exist precisely so
# that they can be held against each other. The authority on whether an
# adoption is correct is the check the adoption installs.
# ---------------------------------------------------------------------
say "Running the installed drift check"

if bash "${TARGET}/tests/test_shared_regions.sh" 2>&1 | sed 's/^/    /'; then
  ADOPTION_OK=1
else
  ADOPTION_OK=""
fi

echo
if [ -n "${ADOPTION_OK}" ]; then
  echo "ADOPTED: ${TARGET} at ${REV}"
else
  echo "INSTALLED, BUT THE CHECK IS RED. Read the failures above." >&2
  echo "Nothing outside ${TARGET} was changed. To undo everything:" >&2
  echo "    git -C ${TARGET} checkout -- . && git -C ${TARGET} clean -fd" >&2
  echo "BOTH commands are needed. On a first adoption every file this wrote" >&2
  echo "is UNTRACKED, and \`git checkout -- .\` does not touch untracked files," >&2
  echo "so on its own it would leave the whole installation in place." >&2
fi

echo
echo "STILL YOURS TO DO:"
if [ -n "${FRESH}" ]; then
  echo "  * Fill in the CONFIG block of:${FRESH}"
  echo "    Every value in them is a placeholder. Run"
  echo "        bash ${TARGET}/tests/test_release_wiring.sh"
  echo "    and fix what it reddens; it will name every top-level module you"
  echo "    have not accounted for."
fi
echo "  * Follow the adoption checklist in tests/test_release_wiring.sh's own"
echo "    header, which covers the release workflows, the manifest floor and"
echo "    the clean-room rehearsal. This script does not write those."
echo "  * In the repository's SETTINGS, require the \`checks\` workflow on the"
echo "    default branch, and confirm Actions is enabled. Those live outside"
echo "    git; no file here reaches them and nothing here has checked them."

[ -n "${ADOPTION_OK}" ]
