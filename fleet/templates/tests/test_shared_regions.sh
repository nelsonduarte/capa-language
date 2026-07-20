#!/usr/bin/env bash
#
# DRIFT CHECK FOR THE SHARED REGIONS OF THE FLEET'S WIRING TESTS.
#
# WHY THIS EXISTS. tests/test_release_wiring.sh and
# tests/test_wiring_mutations.sh are ~770 lines of security-checking
# logic that is COPIED into every repository that adopts the shared
# release guards. Copies drift, and a drifted copy still reports
# success. That is not a hypothetical: a capability tuple hand-copied at
# 21 sites in the compiler had already drifted before anyone looked, and
# capa_authgate's check_tag_version.sh became a second copy whose two
# versions immediately printed different messages while looking
# interchangeable.
#
# So each of those files is split by two marker lines into a CONFIG
# region, which is repo-specific by design, and everything else, which
# is meant to be byte-identical across the fleet. This test digests
# everything OUTSIDE the config region and compares that digest to the
# canonical template's, recorded in .github/shared-regions.sha256.
#
# THE MARKERS ARE INSIDE THE DIGESTED REGION. That is deliberate. If
# they were outside it, the marker text itself could be edited to move
# the boundary and enlarge the un-digested region, which is the same
# defect one level up.
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
# is refused, including a second statement on an assignment's line.
#
# TWO LAYERS, because layer 1 alone is self-certifying:
#
#   1. OFFLINE. The shared region is digested and compared to the digest
#      recorded in .github/shared-regions.sha256. This layer NEVER
#      skips. It catches the ordinary case, an edit below the line.
#   2. ONLINE. The canonical template is fetched from the compiler
#      repository at the revision the audit record pins, its shared
#      region extracted by THIS SAME CODE, and its digest compared to
#      the recorded one. This is what stops someone who edits the body
#      from simply regenerating the number. It reports SKIP without
#      `gh`, matching tests/test_release_wiring.sh: an offline machine
#      cannot answer the question and a test that guesses is the
#      failure mode this whole file is about.
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
# THIS FILE HAS NO REPO-SPECIFIC CONFIGURATION and is intended to be
# byte-identical across every adopter. The one table it carries, of
# files and the config names each may declare, describes the SHARED
# templates and is therefore the same everywhere.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECORD="${REPO_ROOT}/.github/shared-regions.sha256"

CANON_REPO="nelsonduarte/capa-language"

# The canonical templates are stored as COMPLETE files, not as headerless
# fragments, so the extraction below is the identical code on both sides
# of the comparison. A fragment would need its own assembly rules, and
# two implementations of a boundary is how the boundary moves.
CANON_PREFIX="fleet/templates/"

# The files to check, and the config names each one's config region may
# declare. Every name listed must appear exactly once; any name not
# listed is refused.
SHARED_FILES=(
  "tests/test_release_wiring.sh:ENTRY_POINTS CEILING_ENTRIES NEGATIVE_CEILING_ENTRIES COMPILER_REJECTS UNCHECKED_MODULES NEEDS_NEST_VENDOR"
  "tests/test_wiring_mutations.sh:PRIMARY_MODULE SECOND_MODULE CEILING_LINE_WIDE CEILING_NAME"
)

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
CONFIG_VALUE="(${_BARE}|${_SQ}|${_ARRAY})"

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
# `\r` IS STRIPPED, EXPLICITLY, on both sides of every comparison. Do
# not remove this on the evidence that a CRLF fixture behaves locally:
# MSYS gawk strips `\r` on its own and MSYS grep is CR-tolerant, so a
# CRLF copy digests identically HERE and would not on a Linux runner,
# where the markers would not match at all.
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

# Digest of a file's shared region, or empty with a diagnostic on
# stderr. Written through a temporary file rather than a pipeline so
# that extraction's exit status is not swallowed by `sha256sum`.
# The digest the record holds for one path, or empty.
#
# The first field must BE a digest. Matching on the path alone is not
# enough and was a real defect here: the record's own header contains
# the line `# tests/test_release_wiring.sh and`, whose second field is
# the path, so a path-only lookup returned `#` and reported drift
# against a comment.
recorded_digest() {
  awk -v p="$1" '
    $2 == p && length($1) == 64 && $1 ~ /^[0-9a-f]+$/ { print $1; exit }
  ' "${RECORD}"
}

shared_digest() {
  local src="$1" out="$2"
  if ! extract_shared_region "${src}" > "${out}.region" 2> "${out}.err"; then
    return 1
  fi
  sha256sum < "${out}.region" | cut -d' ' -f1
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
CANON_REV="$(awk '$1 == "revision" { print $2; exit }' "${RECORD}")"

if printf '%s' "${CANON_REV}" | grep -qE '^[0-9a-f]{40}$'; then
  ok "the audit record pins a full 40-character canonical revision (${CANON_REV})"
else
  no "the audit record pins no usable canonical revision (got '${CANON_REV}')"
  finish
  exit 1
fi

for entry in "${SHARED_FILES[@]}"; do
  rel="${entry%%:*}"
  names="${entry#*:}"
  abs="${REPO_ROOT}/${rel}"

  if [ ! -f "${abs}" ]; then
    no "${rel} exists"
    continue
  fi

  # --- layer 1, offline, never skips ---------------------------------

  got="$(shared_digest "${abs}" "${WORK}/local")"
  if [ -z "${got}" ]; then
    # The diagnostic goes ON the FAIL line, not under it. Anything that
    # reads these logs by grepping for `^FAIL ` (the mutation harness
    # does) would otherwise report the assertion's name and drop the
    # reason, which for a boundary defect is the only informative part.
    no "${rel}: the CONFIG markers are malformed: $(tr '\n' ' ' < "${WORK}/local.err")"
    continue
  fi
  ok "${rel}: the CONFIG markers are well formed"

  want="$(recorded_digest "${rel}")"
  if [ -z "${want}" ]; then
    no "${rel}: the audit record has no digest for it"
    continue
  fi

  if [ "${got}" = "${want}" ]; then
    ok "${rel}: the shared region matches the audited digest"
  else
    no "${rel}: the shared region has DRIFTED from the audited digest"
    echo "     audited ${want}"
    echo "     local   ${got}"
    echo "     everything outside the CONFIG markers is meant to be identical"
    echo "     across the fleet; re-copy it from ${CANON_PREFIX}${rel}"
  fi

  # --- the config region, by grammar ---------------------------------
  #
  # A digest over everything-but-the-config is silent about the config,
  # and the config is shell this file sources.

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
# Layer 2, online. Layer 1 compares against a number in a file in this
# repository, so anyone who edits the body can regenerate it and go
# green. This is the layer that makes the number honest.
# ---------------------------------------------------------------------
if [ -n "${SHARED_REGIONS_SKIP_FETCH:-}" ]; then
  skip "the audited digests are the canonical template's (SHARED_REGIONS_SKIP_FETCH set)"
elif ! command -v gh >/dev/null 2>&1; then
  skip "the audited digests are the canonical template's (gh not installed)"
elif ! gh auth status >/dev/null 2>&1; then
  skip "the audited digests are the canonical template's (gh not authenticated)"
else
  for entry in "${SHARED_FILES[@]}"; do
    rel="${entry%%:*}"
    canon="${CANON_PREFIX}${rel}"

    if ! gh api "repos/${CANON_REPO}/contents/${canon}?ref=${CANON_REV}" \
           --jq .content 2>/dev/null | base64 -d > "${WORK}/canon" 2>/dev/null \
       || [ ! -s "${WORK}/canon" ]; then
      no "${canon} could not be fetched at ${CANON_REV}"
      echo "     either the revision is not published yet or it does not carry the template"
      continue
    fi

    canon_digest="$(shared_digest "${WORK}/canon" "${WORK}/remote")"
    if [ -z "${canon_digest}" ]; then
      no "${canon}: the canonical template's own CONFIG markers are malformed"
      sed 's/^/     /' "${WORK}/remote.err"
      continue
    fi

    want="$(recorded_digest "${rel}")"
    if [ "${canon_digest}" = "${want}" ]; then
      ok "${rel}: the audited digest is the canonical template's at ${CANON_REV}"
    else
      no "${rel}: the audited digest is NOT the canonical template's"
      echo "     canonical ${canon_digest}  (${canon} at ${CANON_REV})"
      echo "     audited   ${want}"
      echo "     the recorded number describes bytes that are not upstream's"
    fi
  done
fi

finish
