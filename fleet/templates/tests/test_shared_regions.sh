#!/usr/bin/env bash
#
# DRIFT CHECK FOR THE FLEET'S COPIED TEST FILES.
#
# WHY THIS EXISTS. tests/test_release_wiring.sh and
# tests/test_wiring_mutations.sh are ~1300 lines of security-checking
# logic that is COPIED into every repository that adopts the shared
# release guards. Copies drift, and a drifted copy still reports
# success. That is not a hypothetical: a capability tuple hand-copied at
# 21 sites in the compiler had already drifted before anyone looked, and
# capa_authgate's check_tag_version.sh became a second copy whose two
# versions immediately printed different messages while looking
# interchangeable.
#
# TWO KINDS OF ENTRY, because the fleet's copied files are of two kinds.
#
#   REGION. tests/test_release_wiring.sh and
#   tests/test_wiring_mutations.sh must say repo-specific things, so
#   each is split by two marker lines into a CONFIG region, which is
#   repo-specific by design, and everything else, which is meant to be
#   byte-identical across the fleet. Only the part outside the markers
#   is digested, and the config region is checked separately by grammar.
#
#   WHOLE. tests/test_shared_regions.sh (this file),
#   tests/test_guard_pins.sh and .github/workflows/checks.yml have NO
#   repo-specific content at all, so the whole file is digested and
#   there is no config region, no markers, no marker-shape failure
#   modes, no grammar and no allowlist.
#
# THE SECOND KIND IS NOT A CONVENIENCE. The config region is the only
# part of a shared file that nothing digests, which makes it the
# un-digested attack surface (see the grammar note below for what one
# line placed there can do). A file that has no config region has none
# of that surface. Giving one to a zero-config file, to carry some
# future flag used in one repository out of twenty-two, would
# manufacture exactly the bypass class the grammar below exists to
# police. Zero-config files stay whole-file entries.
#
# THIS FILE IS ITSELF A WHOLE-FILE ENTRY, which is the point. Before it
# was, it policed the other files and nothing policed it: deleting one
# row from the SHARED_FILES table below removed a file from the check
# entirely, and both this check and the wiring test then reported
# success with the release gate gone. Measured on a scratch copy of a
# real adopter, before the change:
#
#   delete the wiring-test row, then neutralise the wiring test
#     drift check : exit=0   FAILs=0
#     wiring test : exit=0
#
# A self-digesting check would not have closed that, since whoever
# edits the table can regenerate the number. Layer 2 does close it,
# because the number it compares against is UPSTREAM's.
#
# THE MARKERS ARE INSIDE THE DIGESTED REGION, for region entries. That
# is deliberate. If they were outside it, the marker text itself could
# be edited to move the boundary and enlarge the un-digested region,
# which is the same defect one level up.
#
# WHY THE CONFIG REGION IS ALSO GRAMMAR-CHECKED, which is the part that
# is easy to leave out and is the reason this file was rewritten. A
# digest over everything-but-the-config says nothing about the config,
# and the config is shell that the file SOURCES. Measured on a scratch
# copy of a real adopter:
#
#   baseline                            53 passed, 0 failed    EXIT=0
#   delete `needs: guards`              FAIL ...  1 failed     EXIT=1
#   + `trap 'exit 0' EXIT` in CONFIG    FAIL ...  1 failed     EXIT=0
#
# The release gate is gone, the failure is still printed, CI is green
# because the exit status is 0, and a digest-only drift check reports no
# drift because the shared region did not change. So the config region
# is required to consist of nothing but blank lines, comments, and one
# single-line assignment to each of an ALLOWLIST of names. Anything else
# is refused, including a trailing comment on an assignment's line.
#
# WHY A TRAILING COMMENT IS REFUSED, stated accurately because the wrong
# reason was recorded here once. It is NOT that recognising one would
# need quote-state tracking; it would not, since every value alternative
# below is self-delimiting and a `#` after one is unambiguous. It is
# that the value of this grammar is that it is small enough to read in
# one sitting and argue about exhaustively. A comment suffix adds a
# second lexical context to every alternative for no gain: no template
# uses one, and an adopter who wants to explain a value has the whole
# rest of the region to do it in.
#
# AND THE WORKFLOW THAT RUNS THEM IS ITSELF AN ENTRY. A drift check
# that nothing executes reports nothing. All of these files once
# appeared in both adopters' YAML only inside comments, so they ran zero
# times per push across a fleet of seventeen repositories.
#
# .github/workflows/checks.yml is therefore a WHOLE-FILE entry too. It
# was briefly left out, on the premise that workflows differ per
# repository so byte-identity would force forks. The fleet had already
# falsified that: the most structurally complex adopter's copy is
# byte-identical to the simplest one's, because every repo-specific fact
# is absorbed by the CONFIG region one layer down and this workflow only
# invokes four fixed script paths. Repositories with extra CI put it in
# a separate workflow, every time. Leaving it out also left a one-line
# bypass, a job-level `if: false`, which every step-level refusal in
# this file missed and which reported 30 passed, 0 failed, EXIT=0.
#
# WHAT NO FILE-BASED MECHANISM CAN COVER, stated plainly rather than
# left for someone to discover: Actions being disabled for the
# repository, branch protection not requiring these checks, and the
# required-check configuration itself. Those live in GitHub settings,
# not in git, so nothing here reaches them and nothing here should be
# read as covering them.
#
# TWO LAYERS, because layer 1 alone is self-certifying:
#
#   1. OFFLINE. Each file's digest is compared to the digest recorded in
#      .github/shared-regions.sha256. This layer NEVER skips. It catches
#      the ordinary case, an edit below the line.
#   2. ONLINE. The canonical file is fetched from the compiler
#      repository at the revision the audit record pins, digested by
#      THIS SAME CODE, and compared to the recorded one. This is what
#      stops someone who edits a body from simply regenerating the
#      number. It reports SKIP without `gh`, matching
#      tests/test_release_wiring.sh: an offline machine cannot answer
#      the question and a test that guesses is the failure mode this
#      whole file is about.
#
# Run it directly:
#
#   bash tests/test_shared_regions.sh
#
# `capa test` runs the .capa files in tests/ and ignores this one.
#
# Set SHARED_REGIONS_SKIP_FETCH=1 to force layer 2 to SKIP.
# tests/test_wiring_mutations.sh does this, because its mutations are
# about layer 1 and a control that reddens because a laptop is offline
# proves nothing about the mutations under it. The variable cannot
# weaken layer 1, which has no network path and no skip branch.
#
# THIS FILE HAS NO REPO-SPECIFIC CONFIGURATION. It is copied verbatim
# into every adopter and the fleet's own record covers it, so that
# claim is checked rather than asserted.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECORD="${REPO_ROOT}/.github/shared-regions.sha256"
WORKFLOW_DIR="${REPO_ROOT}/.github/workflows"

CANON_REPO="nelsonduarte/capa-language"

# The canonical files are stored as COMPLETE files, not as headerless
# fragments, so the extraction below is the identical code on both sides
# of the comparison. A fragment would need its own assembly rules, and
# two implementations of a boundary is how the boundary moves.
CANON_PREFIX="fleet/templates/"

# The files to check, as `<kind>:<path>:<config names>`.
#
#   region  digest everything outside the CONFIG markers, and hold the
#           region between them to the grammar. The names listed are the
#           only assignments its config region may make; every one must
#           appear exactly once and anything else is refused.
#   whole   digest the entire file. No markers, no config, no names.
#
# This table describes the SHARED files and is therefore the same in
# every adopter. It is inside a whole-file entry, so shrinking it is a
# change to bytes that layer 2 compares against upstream.
SHARED_FILES=(
  "region:tests/test_release_wiring.sh:ENTRY_POINTS CEILING_ENTRIES NEGATIVE_CEILING_ENTRIES COMPILER_REJECTS UNCHECKED_MODULES NEEDS_NEST_VENDOR"
  "region:tests/test_wiring_mutations.sh:PRIMARY_MODULE SECOND_MODULE CEILING_LINE_WIDE CEILING_NAME"
  "whole:tests/test_shared_regions.sh:"
  "whole:tests/test_guard_pins.sh:"
  "whole:.github/workflows/checks.yml:"
)

# How many files the table above must yield a verdict for. A count is
# not a substitute for layer 2 and is not offered as one; it is what
# makes a shrunk table loud on a machine where layer 2 skipped, instead
# of silent. It is cross-checked against the record's own entry count
# below as well, so the table and the record cannot quietly disagree.
EXPECTED_SHARED_FILES=5

BEGIN_MARK='# ================== CONFIG: the only repo-specific part =================='
END_MARK='# ======================= END CONFIG; shared body ========================='

# The grammar for a config value. A positive allowlist of characters
# rather than a denylist: `$`, a backtick, `;`, `&`, `|`, `<`, `>`, a
# backslash and a newline are simply not in any of these classes, so
# there is no command substitution, no second statement and no
# redirection to be had. Parentheses appear only as the array form's own
# delimiters, which is why `NAME=(a) && exit 0` does not parse.
_BARE='[][A-Za-z0-9._/=+@%^!?~#*:,-]+'
_DQ='"[][A-Za-z0-9._/=+@%^!?~#*:,'"'"' -]*"'
_SQ="'[][A-Za-z0-9._/=+@%^!?~#*:,\" -]*'"
_ITEM="(${_BARE}|${_DQ})"
_ARRAY="\\((${_ITEM}( ${_ITEM})*)?\\)"
# A bare double-quoted scalar is accepted as well as a single-quoted
# one. It was refused until now purely because `_DQ` was reachable only
# as an array item, which is an accident of how the grammar was built
# rather than a decision: `NAME="a b"` is the most natural thing a new
# adopter writes, and the class inside `_DQ` admits no expansion, no
# second statement and no redirection, so admitting it widens nothing.
CONFIG_VALUE="(${_BARE}|${_SQ}|${_DQ}|${_ARRAY})"

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

# ---------------------------------------------------------------------
# Extraction. FAILS CLOSED: it prints one diagnostic to stderr and exits
# non-zero unless each marker occurs EXACTLY once and the begin marker
# precedes the end marker. It must never fall through to digesting the
# whole file, because a file with no markers would then produce a stable
# digest that says nothing about any boundary.
#
# `\r` IS STRIPPED, EXPLICITLY, everywhere a line of one of these files
# or of the record is compared. Do not remove this on the evidence that
# a CRLF fixture behaves locally: MSYS gawk strips `\r` on its own and
# MSYS grep is CR-tolerant, so a CRLF copy digests identically HERE and
# would not on a Linux runner, where the markers would not match at all.
# ---------------------------------------------------------------------
extract_shared_region() {
  awk -v b="${BEGIN_MARK}" -v e="${END_MARK}" '
    { sub(/\r$/, ""); line[NR] = $0 }
    $0 == b { nb++; if (nb == 1) bl = NR }
    $0 == e { ne++; if (ne == 1) el = NR }
    END {
      if (nb != 1) {
        printf("the CONFIG begin marker occurs %d time(s), expected exactly 1\n", nb + 0) > "/dev/stderr"
        exit 3
      }
      if (ne != 1) {
        printf("the CONFIG end marker occurs %d time(s), expected exactly 1\n", ne + 0) > "/dev/stderr"
        exit 4
      }
      if (bl > el) {
        printf("the CONFIG end marker (line %d) precedes the begin marker (line %d)\n", el, bl) > "/dev/stderr"
        exit 5
      }
      # `<=` and `>=` keep BOTH markers in the digested output.
      for (i = 1; i <= NR; i++) if (i <= bl || i >= el) print line[i]
    }
  ' "$1"
}

# The whole file, `\r` stripped, for a whole-file entry. Written as an
# awk pass rather than `cat` so that a CRLF checkout digests identically
# to an LF one, exactly as it does for a region entry, and so that both
# kinds go through one normalisation rather than two.
whole_file() {
  awk '{ sub(/\r$/, ""); print }' "$1"
}

# The config region, exclusive of both markers, one line per line as
# `<file line number>:<text>`. Marker validity is established by
# extract_shared_region before this is ever called.
#
# The line number is carried in the output rather than reconstructed
# later so that both consumers below match against the same anchored
# shape, and so that a diagnostic names a line of the real file. The
# grammar is applied with `grep -E` and never with a regex handed to
# awk through `-v`: awk processes escape sequences in a `-v` assignment,
# so the escaped parentheses of the array form would arrive as grouping
# parentheses and quietly widen the grammar.
config_lines() {
  awk -v b="${BEGIN_MARK}" -v e="${END_MARK}" '
    { sub(/\r$/, "") }
    $0 == e { inside = 0 }
    inside  { printf("%d:%s\n", NR, $0) }
    $0 == b { inside = 1 }
  ' "$1"
}

# Read a workflow on stdin and report how it names "$1":
#
#   live                    at least one step names it with no disabling
#                           marker on that step;
#   <reason>                every step naming it carries one, and the
#                           reason names the first such marker;
#   (empty)                 nothing outside a comment names it.
#
# Steps are delimited by a line beginning with `-` at any indentation,
# which is what a YAML sequence item is, so a marker anywhere in the
# same item is attributed to the step that names the file whether it
# appears above or below the naming line. That is an approximation of
# YAML, not a parse of it: a job-level `if:` sits outside every item and
# is NOT seen. See the note at the call site for what this does and does
# not establish.
naming_status() {
  awk -v target="$1" '
    # Strip a YAML comment: a `#` at the start of the line, or one
    # preceded by whitespace. Over-stripping is the SAFE direction here,
    # since it can only make this report that nothing names the file.
    function decomment(s,   i, c, p) {
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c != "#") continue
        if (i == 1) return ""
        p = substr(s, i - 1, 1)
        if (p == " " || p == "\t") return substr(s, 1, i - 1)
      }
      return s
    }

    function close_step() {
      if (names) {
        if (marker == "") live = 1
        else if (dead == "") dead = marker
      }
      names = 0
      marker = ""
    }

    /^[[:space:]]*-[[:space:]]/ { close_step() }

    {
      line = decomment($0)
      if (index(line, target)) names = 1
      if (line ~ /\|\|[[:space:]]*true/ && marker == "")
        marker = "`|| true` on the line that names it"
      if (line ~ /^[[:space:]]*if:[[:space:]]*("|\x27)?false("|\x27)?[[:space:]]*$/ && marker == "")
        marker = "`if: false` on the step"
      if (line ~ /^[[:space:]]*continue-on-error:[[:space:]]*("|\x27)?true("|\x27)?[[:space:]]*$/ && marker == "")
        marker = "`continue-on-error: true` on the step"
    }

    END {
      close_step()
      if (live) print "live"
      else if (dead != "") print dead
    }
  '
}

# ---------------------------------------------------------------------
# The record parser.
#
# A record line is EXACTLY a 64-character lowercase hex digest, one or
# more spaces or tabs, and a path: nothing before it, nothing after it.
# The regex below is deliberately the same shape
# tests/test_fleet_templates.py enforces in Python
# (`^([0-9a-f]{64})[ \t]+([^ \t]+)$`), because the stated value of
# running two implementations is that they AGREE. They did not: this one
# used to accept trailing junk, leading indentation and trailing
# whitespace that Python rejected, so a malformed record could be read
# two ways by the two halves of one check. Written without an interval
# expression, which not every awk supports, so the 64 is asserted with
# `length` instead.
#
# The first field must BE a digest. Matching on the path alone is not
# enough and was a real defect here: the record's own header contains
# the line `# tests/test_release_wiring.sh and`, whose second field is
# the path, so a path-only lookup returned `#` and reported drift
# against a comment.
#
# `\r` is stripped here too. Without it a CRLF record fails closed with
# "the audit record has no digest for it", which sends a reader looking
# for a missing entry when the entry is present and the line ending is
# the defect. Both current adopters happen to carry `* text eol=lf` in
# .gitattributes; a new one may not, and a diagnostic that names the
# wrong cause is worse than a slower one that names the right one.
# ---------------------------------------------------------------------
# The shape is written out literally in both functions rather than
# passed through `awk -v`, for the reason config_lines gives: awk
# processes escape sequences in a `-v` assignment, so a regex handed
# over that way is not the regex that was written.
recorded_digest() {
  awk -v p="$1" '
    { sub(/\r$/, "") }
    /^[0-9a-f]+[ \t]+[^ \t]+$/ && length($1) == 64 && $2 == p { print $1; exit }
  ' "${RECORD}"
}

recorded_entry_count() {
  awk '
    { sub(/\r$/, "") }
    /^[0-9a-f]+[ \t]+[^ \t]+$/ && length($1) == 64 { n++ }
    END { print n + 0 }
  ' "${RECORD}"
}

# Digest of a file's shared region, or empty with a diagnostic on
# stderr. Written through a temporary file rather than a pipeline so
# that extraction's exit status is not swallowed by `sha256sum`:
# `awk | sha256sum` yields the digest of the EMPTY STRING when awk bails
# out, which is a perfectly well-formed 64-character answer to a
# question that failed.
region_digest() {
  local src="$1" out="$2"
  if ! extract_shared_region "${src}" > "${out}.region" 2> "${out}.err"; then
    return 1
  fi
  sha256sum < "${out}.region" | cut -d' ' -f1
}

whole_digest() {
  local src="$1" out="$2"
  if ! whole_file "${src}" > "${out}.region" 2> "${out}.err"; then
    return 1
  fi
  sha256sum < "${out}.region" | cut -d' ' -f1
}

# Dispatch on the entry kind. An unknown kind is an error rather than a
# default, because defaulting to `whole` would digest a region file's
# config block and defaulting to `region` would demand markers of a file
# that has none; either way a typo in the table would change what is
# checked instead of saying so.
digest_for_kind() {
  case "$1" in
    region) region_digest "$2" "$3" ;;
    whole)  whole_digest  "$2" "$3" ;;
    *)      printf 'unknown entry kind %s\n' "$1" > "$3.err"; return 1 ;;
  esac
}

# ---------------------------------------------------------------------
# The audit record.
# ---------------------------------------------------------------------
if [ ! -f "${RECORD}" ]; then
  no "the shared-region audit record exists (.github/shared-regions.sha256)"
  finish
  exit 1
fi
ok "the shared-region audit record exists (.github/shared-regions.sha256)"

# ITS OWN REVISION LINE, deliberately not the guard pin from
# .github/guard-pins.sha256. Sharing one revision would make every guard
# bump force a wiring re-audit and every wiring bump force a guard
# re-audit, and that friction is the likeliest reason for the whole
# exercise to be skipped.
CANON_REV="$(awk '{ sub(/\r$/, "") } $1 == "revision" { print $2; exit }' "${RECORD}")"

if printf '%s' "${CANON_REV}" | grep -qE '^[0-9a-f]{40}$'; then
  ok "the audit record pins a full 40-character canonical revision (${CANON_REV})"
else
  no "the audit record pins no usable canonical revision (got '${CANON_REV}')"
  finish
  exit 1
fi

CHECKED=0

for entry in "${SHARED_FILES[@]}"; do
  kind="${entry%%:*}"
  rest="${entry#*:}"
  rel="${rest%%:*}"
  names="${rest#*:}"
  abs="${REPO_ROOT}/${rel}"

  CHECKED=$((CHECKED + 1))

  if [ ! -f "${abs}" ]; then
    no "${rel} exists"
    continue
  fi

  # --- layer 1, offline, never skips ---------------------------------

  got="$(digest_for_kind "${kind}" "${abs}" "${WORK}/local")"
  if [ -z "${got}" ]; then
    # The diagnostic goes ON the FAIL line, not under it. Anything that
    # reads these logs by grepping for `^FAIL ` (the mutation harness
    # does) would otherwise report the assertion's name and drop the
    # reason, which for a boundary defect is the only informative part.
    no "${rel}: it could not be digested: $(tr '\n' ' ' < "${WORK}/local.err")"
    continue
  fi
  if [ "${kind}" = "region" ]; then
    ok "${rel}: the CONFIG markers are well formed"
  fi

  want="$(recorded_digest "${rel}")"
  if [ -z "${want}" ]; then
    no "${rel}: the audit record has no digest for it"
    continue
  fi

  if [ "${got}" = "${want}" ]; then
    if [ "${kind}" = "whole" ]; then
      ok "${rel}: the file matches the audited digest"
    else
      ok "${rel}: the shared region matches the audited digest"
    fi
  else
    if [ "${kind}" = "whole" ]; then
      no "${rel}: the file has DRIFTED from the audited digest"
    else
      no "${rel}: the shared region has DRIFTED from the audited digest"
    fi
    echo "     audited ${want}"
    echo "     local   ${got}"
    if [ "${kind}" = "whole" ]; then
      echo "     this file carries no repo-specific configuration; re-copy"
      echo "     it whole from ${CANON_PREFIX}${rel}"
    else
      echo "     everything outside the CONFIG markers is meant to be identical"
      echo "     across the fleet; re-copy it from ${CANON_PREFIX}${rel}"
    fi
  fi

  # --- is anything actually RUNNING it? ------------------------------
  #
  # Every one of these files is a control whose purpose is noticing
  # silent divergence, and until this assertion existed all four of them
  # appeared in both adopters' YAML only inside comments. They executed
  # zero times per push. A control that runs when a human remembers to
  # run it reports the state of that human's memory.
  #
  # THE PRIMARY ANSWER IS NOW THE DIGEST, not this. .github/workflows/
  # checks.yml is a whole-file entry above, so the workflow that runs
  # these four is compared against the canonical bytes like everything
  # else, and any edit to it reddens.
  #
  # That replaced a weaker design and a false premise. The premise was
  # that "workflows genuinely differ per repository", so demanding
  # byte-identity would force forks. The fleet has falsified it:
  # capa_authgate is exactly the shape predicted to need variation, with
  # five entry points, a negative ceiling entry, a compiler-rejects
  # fixture and nested vendoring, and its checks.yml is byte-identical
  # to a pure library's. That is structural, not luck. Every
  # repo-specific fact is absorbed by the CONFIG region one layer down,
  # and this workflow only ever invokes four fixed script paths. Where
  # repositories DO have extra CI, they put it in a separate workflow,
  # which is what the fleet has actually done every time.
  #
  # And the weaker design leaked. Naming plus the three step-level
  # refusals below missed a one-line job-level disable:
  #
  #   wiring:
  #     runs-on: ubuntu-latest
  #     if: false          # 30 passed, 0 failed, 0 skipped, EXIT=0
  #
  # which is the line a person writes to park a job, so it was the
  # accident case as much as the attack case. The digest catches it.
  #
  # WHY THIS CHECK STAYS ANYWAY, in a smaller role. It is cheap, and it
  # covers two states the digest does not: a repository mid-adoption
  # whose record does not yet carry checks.yml, and a repository that
  # invokes the shared files from some OTHER workflow, which is not
  # digested and never will be. It is no longer the mechanism, and this
  # comment does not present it as one.
  #
  # Comments are stripped first, and NOT only whole-line ones. A
  # trailing `# was: bash tests/test_release_wiring.sh` is exactly what
  # a person writes when temporarily disabling a step, so accepting it
  # reproduces the original defect BY ACCIDENT, which is likelier than
  # anyone attacking this.
  #
  # The result is captured rather than tested with `grep -q`. `pipefail`
  # is set, and `grep -q` exits at the first match and closes the pipe,
  # which can leave the upstream stage killed by SIGPIPE and the whole
  # pipeline non-zero on a SUCCESSFUL search. A glob that matches
  # nothing does the same thing through `cat`, which is how the first
  # version of this reported that nothing ran four files a workflow
  # visibly ran.
  status=""
  if [ -d "${WORKFLOW_DIR}" ]; then
    status="$(find "${WORKFLOW_DIR}" -maxdepth 1 -type f \
                \( -name '*.yml' -o -name '*.yaml' \) -exec cat {} + 2>/dev/null \
              | naming_status "${rel}" || true)"
  fi

  case "${rel}" in
    .github/workflows/*)
      # A workflow is not named by another file and does not need to
      # be: the platform runs it because it is there and its `on:`
      # block matches. Asking whether something names it would be
      # asking the wrong question and would redden every adoption. Its
      # `on:` block, its jobs and its steps are all inside its digest.
      ok "${rel}: run by the platform on its own triggers, not named by another file"
      ;;
    *)
      if [ ! -d "${WORKFLOW_DIR}" ]; then
        no "${rel}: .github/workflows/ does not exist, so nothing runs it"
      elif [ "${status}" = "live" ]; then
        ok "${rel}: a workflow step names it, with no disabling marker on it"
      elif [ -n "${status}" ]; then
        no "${rel}: the only workflow step naming it is disabled (${status})"
        echo "     a step that is named and never runs is the same green log as"
        echo "     one that is absent, and this check is one of the steps, so a"
        echo "     disabled run of it prints nothing for anyone to notice"
      else
        no "${rel}: no workflow names it, so it runs zero times per push"
        echo "     a drift check nothing executes reports nothing; add a step"
        echo "     running it to a workflow that fires on push and pull_request"
        echo "     (a mention inside a YAML comment does not count, trailing"
        echo "     comments included, and was the state both original adopters"
        echo "     were in)"
      fi
      ;;
  esac

  # --- the config region, by grammar ---------------------------------
  #
  # A digest over everything-but-the-config is silent about the config,
  # and the config is shell this file sources. A whole-file entry has no
  # such region and therefore nothing to check here.

  [ "${kind}" = "region" ] || continue

  config_lines "${abs}" > "${WORK}/cfg"

  alt=""
  for name in ${names}; do alt="${alt}|${name}"; done
  alt="${alt#|}"

  bad="$(grep -vE '^[0-9]+:[[:space:]]*(#.*)?$' "${WORK}/cfg" \
         | grep -vE "^[0-9]+:(${alt})=${CONFIG_VALUE}\$" || true)"

  if [ -z "${bad}" ]; then
    ok "${rel}: the CONFIG region is comments and allowlisted assignments only"
  else
    no "${rel}: the CONFIG region contains something that is not a comment"
    echo "     or a single-line assignment to one of: ${names}"
    printf '%s\n' "${bad}" | sed 's/^/     /'
    echo "     this region is NOT digested, so arbitrary shell here is"
    echo "     invisible to the drift check and can neutralise the file"
  fi

  for name in ${names}; do
    n="$(grep -cE "^[0-9]+:${name}=" "${WORK}/cfg")"
    if [ "${n}" = "1" ]; then
      ok "${rel}: ${name} is assigned exactly once"
    else
      no "${rel}: ${name} is assigned ${n} time(s), expected exactly 1"
    fi
  done
done

# ---------------------------------------------------------------------
# THE TABLE ITSELF, counted two ways.
#
# Deleting one row from SHARED_FILES removes a file from this check
# entirely, and every remaining assertion still passes: a check that
# covers three of four files prints exactly the log of one that covers
# four. Layer 2 is the real answer, because this file is a whole-file
# entry and a shrunk table is a digest change upstream would refuse.
# These two counts are what make the same edit loud OFFLINE as well,
# which is the state a machine without `gh` is in.
# ---------------------------------------------------------------------
if [ "${CHECKED}" = "${EXPECTED_SHARED_FILES}" ]; then
  ok "all ${EXPECTED_SHARED_FILES} shared files were reached"
else
  no "${CHECKED} shared file(s) were reached, expected ${EXPECTED_SHARED_FILES}"
  echo "     a row has been removed from SHARED_FILES, or the loop exited early"
  echo "     a file dropped from that table is a file this check no longer covers"
fi

RECORD_ENTRIES="$(recorded_entry_count)"
if [ "${RECORD_ENTRIES}" = "${CHECKED}" ]; then
  ok "the audit record has one entry per checked file (${RECORD_ENTRIES})"
else
  no "the audit record has ${RECORD_ENTRIES} entr(ies) but ${CHECKED} file(s) were checked"
  echo "     the record and the SHARED_FILES table describe different sets;"
  echo "     one of them has been edited without the other"
fi

# ---------------------------------------------------------------------
# Layer 2, online. Layer 1 compares against a number in a file in this
# repository, so anyone who edits a body can regenerate it and go green.
# This is the layer that makes the number honest, and since this file is
# itself one of the entries, it is also what stops the table above from
# being quietly shortened.
# ---------------------------------------------------------------------
if [ -n "${SHARED_REGIONS_SKIP_FETCH:-}" ]; then
  skip "the audited digests are the canonical files' (SHARED_REGIONS_SKIP_FETCH set)"
elif ! command -v gh >/dev/null 2>&1; then
  skip "the audited digests are the canonical files' (gh not installed)"
elif ! gh auth status >/dev/null 2>&1; then
  skip "the audited digests are the canonical files' (gh not authenticated)"
else
  for entry in "${SHARED_FILES[@]}"; do
    kind="${entry%%:*}"
    rest="${entry#*:}"
    rel="${rest%%:*}"
    canon="${CANON_PREFIX}${rel}"

    if ! gh api "repos/${CANON_REPO}/contents/${canon}?ref=${CANON_REV}" \
           --jq .content 2>/dev/null | base64 -d > "${WORK}/canon" 2>/dev/null \
       || [ ! -s "${WORK}/canon" ]; then
      no "${canon} could not be fetched at ${CANON_REV}"
      echo "     either the revision is not published yet or it does not carry the file"
      continue
    fi

    canon_digest="$(digest_for_kind "${kind}" "${WORK}/canon" "${WORK}/remote")"
    if [ -z "${canon_digest}" ]; then
      no "${canon}: the canonical file could not be digested"
      sed 's/^/     /' "${WORK}/remote.err"
      continue
    fi

    want="$(recorded_digest "${rel}")"
    if [ "${canon_digest}" = "${want}" ]; then
      ok "${rel}: the audited digest is the canonical file's at ${CANON_REV}"
    else
      no "${rel}: the audited digest is NOT the canonical file's"
      echo "     canonical ${canon_digest}  (${canon} at ${CANON_REV})"
      echo "     audited   ${want}"
      echo "     the recorded number describes bytes that are not upstream's"
    fi
  done
fi

finish
