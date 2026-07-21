#!/usr/bin/env bash
#
# Regression test for how .github/workflows/release.yml CALLS the shared
# release guards, and for whether what it calls them with covers this
# package.
#
# WHY THIS EXISTS. The guards themselves are tested where they live, in
# the compiler repository. What is NOT tested there, and cannot be, is
# whether a consumer wired them up in a way that actually gates
# anything. A `guards:` job that runs and reports failure while the
# release publishes anyway is worse than no guard at all: it produces a
# green-looking gate, a red job nobody reads, and a published artefact.
# That is the same shape as the defects the guards exist to catch,
# verification that proves nothing about the thing it appears to cover.
#
# The wiring can break in ways that no YAML parser and no linter calls
# an error, because every one of them is a VALID workflow:
#
#   * pinning a tag or a branch instead of a commit, so the guard can be
#     edited under us;
#   * pinning a well-formed SHA that does not exist, so every release
#     fails at dispatch, or worse, resolves to something unintended;
#   * dropping `needs: guards`, so the two jobs race and the release can
#     publish before the guards finish;
#   * `continue-on-error` or a job-level `if: always()`, so the guards
#     run, fail, and block nothing;
#   * naming a module in the flow that does not exist, so the step is a
#     no-op that nothing notices;
#   * leaving a module out of the flow entirely, so it is never checked
#     and the log looks complete.
#
# Run it directly:
#
#   bash tests/test_release_wiring.sh
#
# `capa test` runs the .capa files in tests/ and ignores this one.
#
# Deliberately grep and awk based: it needs nothing installed and runs
# anywhere the release runs. The one check that needs the network (does
# the pinned commit exist, and does it carry the workflow file) reports
# SKIP rather than failing when `gh` is unavailable or unauthenticated,
# because an offline machine cannot answer that question and a test that
# guesses is the failure mode this whole file is about.
#
# ------------------------------------------------------------------
# WHAT `--check-capabilities` ACTUALLY COVERS, because the answer is not
# what this repository used to claim and the claim is what made the
# mistake likely.
#
# It covers the IMPORT CLOSURE OF THE ENTRY POINT IT IS GIVEN. It does
# not cover "the package". A module that is not an entry point and is
# not imported, directly or transitively, by an entry point is never
# opened, and the command exits 0 having never seen it. Measured on the
# released 1.18.1 against the published capa_hex v0.2.0 tarball with an
# `Fs`-taking `extra.capa` added at the top level:
#
#   capa --check-capabilities hex.capa      -> exit 0, "OK"
#   capa --check-capabilities example.capa  -> exit 0, "OK"
#   capa --check-capabilities extra.capa    -> exit 1, introduces 'Fs'
#
# So the ceiling is only as wide as the set of entry points the release
# hands it, and a package whose release checks two of its five top-level
# modules has a ceiling over two of its five top-level modules.
#
# THIS FILE CLOSES THAT LOOP AGAINST THE FILESYSTEM. It reads the
# top-level `*.capa` files off disk and requires the config below to
# account for every one of them: checked, checked-as-a-negative, or
# explicitly declared unchecked WITH A REASON. Adding a module to the
# repository and forgetting the flow is then a red test rather than a
# silent hole.
#
# WHY TOTAL COVERAGE RATHER THAN CLOSURE ANALYSIS. The alternative was
# to parse the `import` lines and prove each module lies inside some
# entry point's closure. That was rejected: it re-implements the
# compiler's module resolver in shell, and when the two drift, the shell
# version reports "covered" for a module that is not, which is the
# UNSAFE direction and precisely the class of defect this file exists to
# abolish. Requiring every module to be an entry point costs one line
# per module in the consumer flow and a few seconds of clean-room time,
# and it is strictly stronger: it proves each module stays under the
# ceiling IN ISOLATION, so a later refactor that drops a module out of
# the closure does not silently drop its check with it.
# ------------------------------------------------------------------
#
# ------------------------------------------------------------------
# THIS FILE IS MEANT TO BE SHARED ACROSS REPOSITORIES.
#
# It was derived from capa_authgate's copy, which hardcoded that
# repository's own shape: `main.capa`, `service.capa` and
# `tools/nest_vendor.py`. Copied verbatim into any other package those
# three assertions are false, and the nest_vendor one is false in EVERY
# other repository in the fleet, because no other package has a
# two-level dependency graph. A shared test whose assertions have to be
# edited per repository is a shared test that will be edited wrongly.
#
# So everything repo-specific has been lifted into the CONFIG block
# below and everything under it is intended to be byte-identical
# everywhere. Adopting this file in a new package means editing the
# config block and nothing else. If you find yourself editing below the
# line, that is a signal the config block is missing a dimension, and
# the fix is to add one rather than to fork the body.
#
# ADOPTION CHECKLIST. In order, and none of the steps are optional:
#
#   1. Run, from a checkout of the compiler repository,
#      `bash fleet/adopt.sh <this repository> <compiler revision>`.
#      That installs this file, the mutation test, the two zero-config
#      checks and the checks.yml workflow, and writes
#      .github/shared-regions.sha256 from that revision. Do not copy any
#      of them by hand.
#   1a. Copy .github/workflows/{release,guard-selftest}.yml from an
#      existing adopter and adapt their consumer flow to this package.
#      There is no template for these two because they are genuinely
#      repo-specific; this file checks the adaptation in detail, which is
#      what makes copying them safe.
#   1b. Run `bash fleet/guard_pins.sh <this repository>` to write
#      .github/guard-pins.sha256 from the revision release.yml pins, then
#      READ the guard files and replace the audit note it leaves blank.
#      DO NOT COPY THAT FILE FROM ANOTHER ADOPTER. A copied one passes
#      every check while having audited nothing, because its digests
#      genuinely are the pinned revision's bytes. It used to be the only
#      way to obtain one, and the copy then asserted in its new
#      repository that a human had recomputed and read everything.
#   2. Edit ONLY the CONFIG block below. Run
#      `bash tests/test_release_wiring.sh` and fix what it reddens; the
#      body will tell you about every top-level module you have not
#      accounted for.
#   3. Make the consumer flow in BOTH workflows match the config. They
#      are compared to each other, so edit them together.
#   4. Set `capa = ">=..."` in capa.toml to at least the fleet floor
#      asserted below. Do NOT re-measure it per repository: the floor is
#      analytically derivable and the body enforces it.
#   5. DISPATCH guard-selftest.yml AGAINST THE PREVIOUS TAG BEFORE YOU
#      TAG ANYTHING. This is the step people skip and it is the one that
#      pays. Everything in this file is a STATIC check of the wiring; it
#      cannot run a compiler, so it cannot tell you that the declared
#      floor is false, that a vendored dependency is missing from the
#      manifest, or that a documented command does not work in a
#      directory with no siblings. Only the clean room can, and the
#      self-test is the clean room without the cost of a tag. A green
#      run of this file on a repository still declaring a false floor is
#      exactly what an adoption looks like the moment before it burns a
#      tag.
#   6. Only then push the signed tag.
# ------------------------------------------------------------------

set -uo pipefail

# ================== CONFIG: the only repo-specific part ==================

# EVERY VALUE BELOW IS A PLACEHOLDER. Replace all six, then run
# `bash tests/test_release_wiring.sh` and fix what it reddens.
#
# THIS BLOCK IS THE ONLY PART OF THIS FILE THAT IS NOT DIGESTED, so it is
# also the only part an adopter may touch. tests/test_shared_regions.sh
# digests everything outside it and refuses any difference from the
# canonical template, and it additionally requires this block to consist
# of nothing but blank lines, comments and one single-line assignment to
# each of the six names below. That second rule is not tidiness: an
# un-digested region accepts arbitrary shell, and a single line reading
# `trap 'exit 0' EXIT` placed here makes this whole file exit 0 while
# still printing its failures, which is a green CI run over a release
# gate that is no longer there.

# Entry points the clean room must COMPILE, in the order the flow runs
# them. For a library this is the library module plus any documented
# runnable example; for an application it is each executable entry.
ENTRY_POINTS=(main.capa example.capa)

# Entry points whose CAPABILITY CEILING the clean room must check.
#
# Because the ceiling covers only the import closure of the entry it is
# given (see the note above), this list must account for EVERY top-level
# `.capa` file in the repository, together with the three lists that
# follow it. The body reads the directory and refuses any module that
# appears in none of them.
#
# Leave this EMPTY for a package that declares no `[capabilities]` table
# in capa.toml, and the body below will then require that the flow does
# NOT run `--check-capabilities` at all. That is not pedantry: with no
# ceiling declared the command prints
#
#   capa: --check-capabilities: no package declares a [capabilities]
#         ceiling; nothing to verify.
#
# and exits 0. A step that always passes having inspected nothing is
# precisely the class of defect the release guards exist to abolish, and
# it is worse than omitting the step, because the log looks like
# evidence. The body cross-checks this list against capa.toml so the two
# cannot disagree.
CEILING_ENTRIES=(main.capa example.capa)

# Modules the clean room must prove the CEILING REFUSES.
#
# A repository that documents "this file is what the ceiling catches"
# is making a claim about the compiler, and an undemonstrated claim
# about a security control is the thing this whole pilot keeps finding.
# Each entry here obliges the consumer flow to carry a line that runs
# the check and requires it to fail FOR THE STATED REASON, so a module
# that starts passing (or that stops existing) reddens the release.
NEGATIVE_CEILING_ENTRIES=()

# Modules the clean room must prove the COMPILER REFUSES, as
# `file.capa=substring of the expected error`. The substring is
# mandatory: a bare "it failed" passes for a missing file, a syntax
# error, or any other reason, and a negative that passes for the wrong
# reason is not a negative.
COMPILER_REJECTS=()

# Top-level modules deliberately left out of the release checks, as
# `file.capa=why`. The reason is mandatory and is the whole point: this
# is the one place a module can be uncovered, and it costs a written
# justification that a reviewer reads.
UNCHECKED_MODULES=()

# Does the consumer flow need `python tools/nest_vendor.py`?
#
# Only for a package with a TWO-LEVEL dependency graph: the ceiling gate
# looks for a dependency's own dependencies under `vendor/<dep>/vendor/`
# while `capa install` vendors flat. At the time of writing exactly one
# repository in the fleet needs it (capa_authgate). Set to "yes" there
# and "no" everywhere else; when it is "no" the body REQUIRES the line
# to be absent, so a copy-paste of someone else's flow is caught rather
# than silently carried along.
NEEDS_NEST_VENDOR=no

# ======================= END CONFIG; shared body =========================

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/release.yml"
MANIFEST="${REPO_ROOT}/capa.toml"

GUARD_REPO="nelsonduarte/capa-language"
GUARD_PATH=".github/workflows/release-guards.yml"

# THE FLEET COMPILER FLOOR. Deliberately below the config line, because
# it is NOT a per-repository measurement and an adopter must not be able
# to lower it by editing a config block.
#
# It is analytically derivable rather than measured per package. capa
# 1.18.0 (PR #85) changed the module resolver so `[package].name` maps
# to the project root. Every seed library self-imports
# `capa_<name>.<module>` while its tarball extracts to
# `capa_<name>-v<tag>`, so on every release below 1.18.0 that
# self-import resolves to nothing and the package does not build at all.
# 1.18.1 is then the first release whose binary can run `capa test`,
# which every consumer flow does. That gives >=1.18.1 uniformly, and it
# was confirmed 3 for 3 against the released binaries on capa_base64,
# capa_url and capa_uuid.
#
# WHY THIS ASSERTION EARNS ITS PLACE. An adoption performed exactly as
# the checklist above instructs produced 52 green assertions on a
# repository still declaring `capa = ">=1.1.0"`, a floor that is not
# merely untested but FALSE: that compiler cannot build the package at
# all. Nothing static caught it, and the clean room only speaks at tag
# time, so the defect the pilot existed to find survived a by-the-book
# adoption and would have cost a tag to discover.
#
# Over-declaring is a usability cost and under-declaring is a soundness
# one, so this is a floor and not an equality: a package may declare
# HIGHER (capa_authgate needs Serve, which shipped in 1.17.0) and never
# lower.
FLEET_FLOOR_MIN="1.18.1"

# The capability names capa accepts in `[capabilities].max`, verbatim
# from the compiler's own rejection message on 1.18.1. `Unsafe` is
# deliberately absent: the compiler does not accept it in a ceiling.
KNOWN_CAPABILITIES="Clock Db Env Fs Net Proc Random Serve Stdio"

PASS=0
FAIL=0
SKIP=0

ok()   { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
no()   { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf 'skip %s\n' "$1"; }

check() {
  local desc="$1" condition="$2"
  if eval "${condition}"; then ok "${desc}"; else no "${desc}"; fi
}

if [ ! -f "${WORKFLOW}" ]; then
  echo "FAIL: ${WORKFLOW} not found" >&2
  exit 1
fi

# `file.capa=reason` splitting, for the two lists that carry a reason.
pair_key()    { printf '%s' "${1%%=*}"; }
pair_reason() { case "$1" in *=*) printf '%s' "${1#*=}" ;; *) printf '' ;; esac; }

# Extract one job's block: from `  <name>:` at two-space indent up to the
# next line at that same indent level. Job-level keys sit at four spaces
# and steps deeper, so this captures the whole job and nothing after it.
job_block() {
  awk -v job="$1" '
    BEGIN { header = "^  " job ":[[:space:]]*$" }
    $0 ~ header { in_job = 1; next }
    in_job && /^  [A-Za-z_-]+:/ { in_job = 0 }
    in_job { print }
  ' "${WORKFLOW}"
}

GUARDS="$(job_block guards)"
RELEASE="$(job_block release)"

check "a guards job exists" '[ -n "${GUARDS}" ]'
check "a release job exists" '[ -n "${RELEASE}" ]'

# --- the guards are the shared ones, at a pinned commit ----------------

USES="$(printf '%s\n' "${GUARDS}" | sed -n 's/^[[:space:]]*uses:[[:space:]]*//p')"

check "the guards job calls a reusable workflow" '[ -n "${USES}" ]'

check "it calls the shared guards, not a local copy" \
  'printf "%s" "${USES}" | grep -qF "${GUARD_REPO}/${GUARD_PATH}@"'

# The pin itself. A tag is mutable and a branch more so, so anything
# that is not a full 40-hex commit SHA is refused. An abbreviated SHA is
# refused too: abbreviations can become ambiguous as a repository grows.
PIN="${USES##*@}"
check "the guards are pinned by a full 40-character commit SHA (got '${PIN}')" \
  'printf "%s" "${PIN}" | grep -qE "^[0-9a-f]{40}$"'

# --- the guards actually gate the release ------------------------------

check "the release job declares needs: guards" \
  'printf "%s" "${RELEASE}" | grep -qE "^[[:space:]]*needs:[[:space:]]*(guards|\[[[:space:]]*guards[[:space:]]*\])[[:space:]]*$"'

# `continue-on-error` on the guards job turns a failing gate into a
# passing one, which is the single most dangerous edit possible here.
check "the guards job does not set continue-on-error" \
  '! printf "%s" "${GUARDS}" | grep -qE "^[[:space:]]*continue-on-error:"'

check "the release job does not set continue-on-error" \
  '! printf "%s" "${RELEASE}" | grep -qE "^[[:space:]]*continue-on-error:"'

# A job-level `if:` on the release job can defeat `needs:` entirely:
# `if: always()` and `if: !cancelled()` both run the job after the
# guards have failed. Step-level `if:` keys sit deeper than four spaces
# and are not matched here.
check "the release job has no job-level if: that could bypass the guards" \
  '! printf "%s" "${RELEASE}" | grep -qE "^    if:"'

check "the guards job has no job-level if: that could skip it" \
  '! printf "%s" "${GUARDS}" | grep -qE "^    if:"'

# --- the declared compiler floor ---------------------------------------
#
# tools/capa_floor.sh in the release guards reads this key to decide
# which RELEASED compiler the clean room downloads, so it is not
# documentation: it selects the binary the artefact is proven against. A
# floor naming a compiler that cannot build the package makes the whole
# clean room a statement about the wrong toolchain.

package_block() {
  awk '
    /^[[:space:]]*\[package\][[:space:]]*$/ { in_p = 1; next }
    in_p && /^[[:space:]]*\[/ { in_p = 0 }
    in_p { print }
  ' "${MANIFEST}"
}

if [ ! -f "${MANIFEST}" ]; then
  no "capa.toml exists"
  FLOOR_RAW=""
else
  ok "capa.toml exists"
  FLOOR_RAW="$(package_block | sed -n 's/^[[:space:]]*capa[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
fi

check "capa.toml [package] declares a compiler floor (got '${FLOOR_RAW}')" \
  '[ -n "${FLOOR_RAW}" ]'

# The guard parses this key, so the form is load-bearing too: anything
# other than a plain `>=X.Y.Z` is refused rather than interpreted.
check "the floor is written as >=X.Y.Z" \
  'printf "%s" "${FLOOR_RAW}" | grep -qE "^>=[0-9]+\.[0-9]+\.[0-9]+$"'

FLOOR_VER="${FLOOR_RAW#>=}"

# `sort -V` is GNU and BSD-portable enough for the runners and dev
# machines this runs on, but a shell that cannot do version ordering
# must say so rather than guess an answer.
if ! printf '1.2.3\n1.2.4\n' | sort -V >/dev/null 2>&1; then
  skip "the declared floor is at least the fleet floor ${FLEET_FLOOR_MIN} (sort -V unavailable)"
elif ! printf "%s" "${FLOOR_VER}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  no "the declared floor is at least the fleet floor ${FLEET_FLOOR_MIN} (unparseable floor '${FLOOR_RAW}')"
elif [ "$(printf '%s\n%s\n' "${FLOOR_VER}" "${FLEET_FLOOR_MIN}" | sort -V | head -1)" = "${FLEET_FLOOR_MIN}" ]; then
  ok "the declared floor ${FLOOR_RAW} is at least the fleet floor ${FLEET_FLOOR_MIN}"
else
  no "the declared floor ${FLOOR_RAW} is BELOW the fleet floor ${FLEET_FLOOR_MIN}; every package self-imports capa_<name>.<module> and no release below 1.18.0 can resolve that in an extracted tarball"
fi

# --- the guards are given enough to prove something --------------------

# An empty consumer-commands makes the clean room report success having
# run nothing. The shared guard refuses that itself; this asserts the
# caller never gets there, and that the flow covers what this package
# actually claims.
COMMANDS="$(printf '%s\n' "${GUARDS}" | awk '
  /^[[:space:]]*consumer-commands:[[:space:]]*\|/ { in_cmds = 1; next }
  in_cmds && /^[[:space:]]{0,8}[a-zA-Z_-]+:/ { in_cmds = 0 }
  in_cmds { print }
' | grep -vE '^[[:space:]]*(#.*)?$')"

# Compared as whole trimmed lines from here on. The previous form
# interpolated a filename into a `grep -qE` pattern, where `.` matches
# any character, so a flow saying `hexXcapa` satisfied a config saying
# `hex.capa`. Fixed-string, whole-line matching has no such reading.
COMMANDS_TRIMMED="$(printf '%s\n' "${COMMANDS}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

flow_has() { printf '%s\n' "${COMMANDS_TRIMMED}" | grep -qxF "$1"; }

check "the clean room is given consumer commands" '[ -n "${COMMANDS}" ]'

check "the consumer flow imports the publisher key first" \
  '[ "$(printf "%s\n" "${COMMANDS}" | head -1 | tr -d "[:space:]")" = "gpg--importpublisher.asc" ]'

check "the consumer flow installs dependencies" 'flow_has "capa install"'

# The nested-vendor step, required or forbidden according to the config.
# Both directions are asserted: a package that needs it and lost it has
# an unrunnable ceiling check, and a package that does not need it but
# carries the line inherited a command that will fail in its clean room
# because it ships no tools/ directory.
if [ "${NEEDS_NEST_VENDOR}" = "yes" ]; then
  check "the consumer flow builds the nested vendor layout" \
    'flow_has "python tools/nest_vendor.py"'
else
  check "the consumer flow does NOT carry a nest_vendor step it has no tools/ for" \
    '! printf "%s" "${COMMANDS}" | grep -qF "nest_vendor"'
fi

# --- every configured module names a file that is really there ---------
#
# A module named in both the config and the flow but absent from disk is
# a step that cannot do anything, and an identical typo in both places
# is the easiest mistake in the whole adoption to make. Only the
# filesystem can settle it.

for entry in ${ENTRY_POINTS[@]+"${ENTRY_POINTS[@]}"}; do
  check "the configured entry point ${entry} exists on disk" \
    '[ -f "${REPO_ROOT}/${entry}" ]'
done

for entry in ${CEILING_ENTRIES[@]+"${CEILING_ENTRIES[@]}"}; do
  check "the configured ceiling entry ${entry} exists on disk" \
    '[ -f "${REPO_ROOT}/${entry}" ]'
done

for entry in ${NEGATIVE_CEILING_ENTRIES[@]+"${NEGATIVE_CEILING_ENTRIES[@]}"}; do
  check "the configured ceiling negative ${entry} exists on disk" \
    '[ -f "${REPO_ROOT}/${entry}" ]'
done

for pair in ${COMPILER_REJECTS[@]+"${COMPILER_REJECTS[@]}"}; do
  key="$(pair_key "${pair}")"
  check "the configured compiler-rejects module ${key} exists on disk" \
    '[ -f "${REPO_ROOT}/${key}" ]'
  check "the compiler-rejects entry ${key} states the error it expects" \
    '[ -n "$(pair_reason "${pair}")" ]'
done

for pair in ${UNCHECKED_MODULES[@]+"${UNCHECKED_MODULES[@]}"}; do
  key="$(pair_key "${pair}")"
  check "the deliberately unchecked module ${key} exists on disk" \
    '[ -f "${REPO_ROOT}/${key}" ]'
  check "the unchecked module ${key} states a reason" \
    '[ -n "$(pair_reason "${pair}")" ]'
done

# --- every module on disk is accounted for ------------------------------
#
# The ceiling covers the import closure of the entry it is handed, so
# coverage is exactly the set of entries the flow names, and a module
# nobody named is a module nobody checked. This is the assertion that
# turns that from an invisible property of the import graph into a
# property of a directory listing.

top_level_modules() {
  local f
  for f in "${REPO_ROOT}"/*.capa; do
    [ -e "${f}" ] || continue
    printf '%s\n' "${f##*/}"
  done | sort
}

accounted_modules() {
  local e pair
  for e in ${CEILING_ENTRIES[@]+"${CEILING_ENTRIES[@]}"}; do printf '%s\n' "${e}"; done
  for e in ${NEGATIVE_CEILING_ENTRIES[@]+"${NEGATIVE_CEILING_ENTRIES[@]}"}; do printf '%s\n' "${e}"; done
  for pair in ${COMPILER_REJECTS[@]+"${COMPILER_REJECTS[@]}"}; do pair_key "${pair}"; printf '\n'; done
  for pair in ${UNCHECKED_MODULES[@]+"${UNCHECKED_MODULES[@]}"}; do pair_key "${pair}"; printf '\n'; done
}

ON_DISK="$(top_level_modules)"
ACCOUNTED="$(accounted_modules | sort)"

UNACCOUNTED="$(comm -23 <(printf '%s\n' "${ON_DISK}") <(printf '%s\n' "${ACCOUNTED}" | uniq) | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
check "every top-level .capa is accounted for by the config${UNACCOUNTED:+ (unaccounted: ${UNACCOUNTED})}" \
  '[ -z "${UNACCOUNTED}" ]'

# A module listed twice says two things about itself, and one of them is
# that it is both checked and deliberately not checked.
DUPLICATED="$(printf '%s\n' "${ACCOUNTED}" | uniq -d | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
check "no module is claimed by two config lists${DUPLICATED:+ (duplicated: ${DUPLICATED})}" \
  '[ -z "${DUPLICATED}" ]'

# A ceiling entry the clean room never compiles is a ceiling entry whose
# compile failure would surface as a confusing ceiling failure.
MISSING_COMPILE=""
for entry in ${CEILING_ENTRIES[@]+"${CEILING_ENTRIES[@]}"}; do
  found=no
  for e in ${ENTRY_POINTS[@]+"${ENTRY_POINTS[@]}"}; do
    [ "${e}" = "${entry}" ] && found=yes
  done
  [ "${found}" = "yes" ] || MISSING_COMPILE="${MISSING_COMPILE}${entry} "
done
MISSING_COMPILE="${MISSING_COMPILE% }"
check "every ceiling entry is also compiled${MISSING_COMPILE:+ (not compiled: ${MISSING_COMPILE})}" \
  '[ -z "${MISSING_COMPILE}" ]'

# --- the flow runs what the config says ---------------------------------

check "at least one entry point is configured" '[ "${#ENTRY_POINTS[@]}" -gt 0 ]'

for entry in ${ENTRY_POINTS[@]+"${ENTRY_POINTS[@]}"}; do
  check "the consumer flow compiles ${entry}" 'flow_has "capa --check ${entry}"'
done

# The ceiling, in whichever direction this package declares.
#
# The config and the manifest must agree. A CEILING_ENTRIES list with no
# `[capabilities]` table means the flow runs a command that inspects
# nothing and exits 0; a `[capabilities]` table with an empty list means
# the package declares a bound that no release ever checks. Both are
# verification theatre, in opposite directions, so both are refused.
if [ -f "${MANIFEST}" ] && grep -qE '^[[:space:]]*\[capabilities\][[:space:]]*$' "${MANIFEST}"; then
  DECLARES_CEILING=yes
else
  DECLARES_CEILING=no
fi

if [ "${#CEILING_ENTRIES[@]}" -gt 0 ]; then
  check "capa.toml declares the [capabilities] ceiling this flow checks" \
    '[ "${DECLARES_CEILING}" = "yes" ]'
  for entry in "${CEILING_ENTRIES[@]}"; do
    check "the consumer flow checks the capability ceiling of ${entry}" \
      'flow_has "capa --check-capabilities ${entry}"'
  done
else
  check "capa.toml declares no ceiling, matching an empty CEILING_ENTRIES" \
    '[ "${DECLARES_CEILING}" = "no" ]'
  # Without a ceiling the command prints "nothing to verify" and exits
  # 0, so its presence would be a green step that inspected nothing.
  check "the consumer flow does NOT run a --check-capabilities that would verify nothing" \
    '! printf "%s" "${COMMANDS}" | grep -qF -- "--check-capabilities"'
fi

# The negatives. Each is asserted in the flow in a form that requires
# the command to fail FOR THE STATED REASON: `grep -q` over the combined
# output makes a pass impossible unless the expected message appeared,
# so a renamed file, a syntax error, or a ceiling that quietly starts
# accepting the module all redden.
for entry in ${NEGATIVE_CEILING_ENTRIES[@]+"${NEGATIVE_CEILING_ENTRIES[@]}"}; do
  check "the consumer flow proves the ceiling REFUSES ${entry}" \
    'flow_has "capa --check-capabilities ${entry} 2>&1 | grep -q '"'"'ceiling violation'"'"'"'
done

for pair in ${COMPILER_REJECTS[@]+"${COMPILER_REJECTS[@]}"}; do
  key="$(pair_key "${pair}")"
  msg="$(pair_reason "${pair}")"
  check "the consumer flow proves the compiler REFUSES ${key}" \
    'flow_has "capa --check ${key} 2>&1 | grep -q \"${msg}\""'
done

check "the consumer flow runs the tests" 'flow_has "capa test"'

# --- a ceiling that bounds something ------------------------------------
#
# `max` is only worth checking if it excludes something. A ceiling
# naming every capability the language has passes every entry point in
# every package and proves precisely nothing, while producing the same
# reassuring "OK - every declared capability ceiling holds" as a tight
# one.
#
# The spelling check is here for a second reason. capa refuses an
# unknown name in `max`, but on 1.18.1 it refuses it by DISCARDING THE
# WHOLE MANIFEST with a warning and then, depending on the subcommand,
# either exiting 0, dying with a Python traceback, or reporting an
# unrelated unresolved-import error. A lowercase `stdio` is the likeliest
# typo in this exercise and this is the cheapest place to catch it.

if [ "${DECLARES_CEILING}" = "yes" ]; then
  ceiling_names() {
    awk '
      /^[[:space:]]*\[capabilities\][[:space:]]*$/ { in_c = 1; next }
      in_c && /^[[:space:]]*\[/ { in_c = 0 }
      in_c { print }
    ' "${MANIFEST}" \
      | sed -n 's/^[[:space:]]*max[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p' \
      | tr ',' '\n' \
      | sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//' \
      | grep -v '^[[:space:]]*$'
  }

  CEILING_MAX="$(ceiling_names)"

  # An unparseable `max` (a multi-line array, a missing key) must not be
  # read as an empty one, which would silently pass every check below.
  check "capa.toml's [capabilities].max parses as a single-line array" \
    'printf "%s\n" "$(awk "/^[[:space:]]*\[capabilities\][[:space:]]*\$/ { in_c = 1; next } in_c && /^[[:space:]]*\[/ { in_c = 0 } in_c { print }" "${MANIFEST}")" | grep -qE "^[[:space:]]*max[[:space:]]*=[[:space:]]*\[.*\][[:space:]]*$"'

  UNKNOWN=""
  while IFS= read -r name; do
    [ -n "${name}" ] || continue
    case " ${KNOWN_CAPABILITIES} " in
      *" ${name} "*) ;;
      *) UNKNOWN="${UNKNOWN}'${name}' " ;;
    esac
  done <<EOF
${CEILING_MAX}
EOF
  UNKNOWN="${UNKNOWN% }"
  check "every name in [capabilities].max is a capability capa knows${UNKNOWN:+ (unknown: ${UNKNOWN})}" \
    '[ -z "${UNKNOWN}" ]'

  EXCLUDED=""
  for cap in ${KNOWN_CAPABILITIES}; do
    printf '%s\n' "${CEILING_MAX}" | grep -qxF "${cap}" || EXCLUDED="${EXCLUDED}${cap} "
  done
  EXCLUDED="${EXCLUDED% }"
  check "the ceiling excludes at least one capability, so it bounds something${EXCLUDED:+ (excluded: ${EXCLUDED})}" \
    '[ -n "${EXCLUDED}" ]'
fi

# --- the guards hold no credential they could publish with -------------

GUARD_PERMS="$(printf '%s\n' "${GUARDS}" | awk '
  /^[[:space:]]*permissions:[[:space:]]*$/ { in_perms = 1; next }
  in_perms && /^    [a-zA-Z_-]+:/ { in_perms = 0 }
  in_perms { print }
' | grep -vE '^[[:space:]]*(#.*)?$')"

check "the guards job states its own permissions" '[ -n "${GUARD_PERMS}" ]'

# The workflow-level grant is write-heavy (contents, id-token,
# attestations) and a job that says nothing inherits all of it. The
# guards read; `id-token: write` in particular is the token that SIGNS
# attestations, and a guard must not be able to sign anything.
check "the guards job grants itself no write permission" \
  '! printf "%s" "${GUARD_PERMS}" | grep -qE ":[[:space:]]*write[[:space:]]*$"'

check "the guards job does not take id-token" \
  '! printf "%s" "${GUARD_PERMS}" | grep -qE "^[[:space:]]*id-token:"'

# --- the caller closes the gap the guards cannot ------------------------

# Guard 2 verifies a tarball it rebuilt from the tag, not the bytes this
# workflow uploads, because it has to run before publication. Only the
# release job holds the artefact it is about to publish, so only it can
# assert the two are the same.
check "the release job compares its tarball to the digest the guards verified" \
  'printf "%s" "${RELEASE}" | grep -qF "needs.guards.outputs.tarball-sha256"'

# --- what already existed here must not be weakened ---------------------
#
# Adopting the guards ADDS a gate; it must never cost one. These three
# were in this repository's release workflow before the guards existed,
# and a refactor that quietly drops any of them would still look like a
# working release.

check "the release job still verifies the tag's GPG signature" \
  'printf "%s" "${RELEASE}" | grep -qF "git verify-tag"'

check "the tag signature is still anchored to a pinned fingerprint" \
  'grep -qE "^[[:space:]]*PINNED_FPR:" "${WORKFLOW}"'

# Every third-party action must be pinned by full commit SHA. A `@v4`
# tag is repointable by its owner, which in a workflow holding
# `id-token: write` means someone else can sign as us.
UNPINNED="$(grep -nE '^[[:space:]]*uses:[[:space:]]*[^ ]+@' "${WORKFLOW}" \
  | grep -vE '@[0-9a-f]{40}([[:space:]]|$)' || true)"
check "every action is pinned by full commit SHA${UNPINNED:+ (offenders: ${UNPINNED})}" \
  '[ -z "${UNPINNED}" ]'

# --- the rehearsal predicts the release ---------------------------------

# guard-selftest.yml exists so the plumbing can be exercised on demand
# instead of one data point per tag. It is only worth having if it
# rehearses the SAME thing the release runs: a self-test pinned to a
# different guard revision, or handed a different consumer flow, reports
# success about a pipeline that is not the one which will publish.

SELFTEST="${REPO_ROOT}/.github/workflows/guard-selftest.yml"

if [ ! -f "${SELFTEST}" ]; then
  no "a dispatchable guard self-test exists (guard-selftest.yml)"
else
  ok "a dispatchable guard self-test exists (guard-selftest.yml)"

  SELF_USES="$(sed -n 's/^[[:space:]]*uses:[[:space:]]*//p' "${SELFTEST}" \
    | grep -F "${GUARD_REPO}/${GUARD_PATH}@" || true)"
  SELF_PIN="${SELF_USES##*@}"

  check "the self-test pins the SAME guard revision as the release (got '${SELF_PIN}')" \
    '[ -n "${SELF_PIN}" ] && [ "${SELF_PIN}" = "${PIN}" ]'

  # The commands are the whole substance of guard 2. Compared as a set
  # of non-blank, non-comment lines, so indentation cannot make two
  # identical flows look different.
  self_commands() {
    awk '
      /^[[:space:]]*consumer-commands:[[:space:]]*\|/ { in_cmds = 1; next }
      in_cmds && /^[[:space:]]{0,8}[a-zA-Z_-]+:/ { in_cmds = 0 }
      in_cmds { print }
    ' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -vE '^(#.*)?$'
  }

  check "the self-test runs the same consumer flow as the release" \
    '[ "$(self_commands "${SELFTEST}")" = "$(self_commands "${WORKFLOW}")" ]'

  # The guard digests are written in THREE places: the audit record, and
  # both workflows. Three copies of one security constant is how they
  # drift, and a drifted copy still reports success, so they are tied
  # together here rather than trusted to stay equal.
  yaml_digests() {
    awk '
      /^[[:space:]]*guard-digests:[[:space:]]*\|/ { in_d = 1; next }
      in_d && /^[[:space:]]{0,6}[a-zA-Z_-]+:/ { in_d = 0 }
      in_d { print }
    ' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
      | grep -E '^[0-9a-f]{64}' | sed 's/[[:space:]]\{1,\}/  /' | sort
  }

  audited_digests() {
    grep -E '^[0-9a-f]{64}' "${REPO_ROOT}/.github/guard-pins.sha256" \
      | sed 's/[[:space:]]\{1,\}/  /' | sort
  }

  check "the release passes guard digests at all" \
    '[ -n "$(yaml_digests "${WORKFLOW}")" ]'

  check "the self-test verifies the same guard digests as the release" \
    '[ "$(yaml_digests "${SELFTEST}")" = "$(yaml_digests "${WORKFLOW}")" ]'

  # The run-time check and the pre-flight audit must describe one set of
  # bytes. If they diverge, one of them is verifying a revision nobody
  # audited, and which one is anybody's guess.
  check "the digests the release passes are the ones it audited" \
    '[ "$(yaml_digests "${WORKFLOW}")" = "$(audited_digests)" ]'

  # A rehearsal that can publish is not a rehearsal. It must hold no
  # write scope at all, and above all no id-token, which is the token
  # that signs attestations.
  check "the self-test grants no write permission anywhere" \
    '! grep -qE "^[[:space:]]*[a-z-]+:[[:space:]]*write[[:space:]]*$" "${SELFTEST}"'

  check "the self-test never takes id-token" \
    '! grep -qE "^[[:space:]]*id-token:" "${SELFTEST}"'

  # It must not be reachable from a tag push, or it becomes a second
  # release path with none of the release path's checks.
  check "the self-test is dispatch-only" \
    'grep -qE "^[[:space:]]*workflow_dispatch:" "${SELFTEST}" && ! grep -qE "^[[:space:]]*(push|release):" "${SELFTEST}"'
fi

# --- does the pin actually exist (network) ------------------------------

if ! command -v gh >/dev/null 2>&1; then
  skip "the pinned commit exists and carries ${GUARD_PATH} (gh not installed)"
elif ! gh auth status >/dev/null 2>&1; then
  skip "the pinned commit exists and carries ${GUARD_PATH} (gh not authenticated)"
elif ! printf "%s" "${PIN}" | grep -qE "^[0-9a-f]{40}$"; then
  skip "the pinned commit exists and carries ${GUARD_PATH} (no valid SHA to look up)"
else
  # Two separate facts. A commit can exist without containing the file,
  # which would be a pin that resolves and guards nothing.
  if gh api "repos/${GUARD_REPO}/commits/${PIN}" --jq .sha >/dev/null 2>&1; then
    ok "the pinned commit ${PIN} exists in ${GUARD_REPO}"
  else
    no "the pinned commit ${PIN} does not exist in ${GUARD_REPO}"
  fi

  if gh api "repos/${GUARD_REPO}/contents/${GUARD_PATH}?ref=${PIN}" --jq .sha >/dev/null 2>&1; then
    ok "${GUARD_PATH} exists at the pinned commit"
  else
    no "${GUARD_PATH} is absent at the pinned commit; the pin guards nothing"
  fi
fi

printf '\n%s passed, %s failed, %s skipped\n' "${PASS}" "${FAIL}" "${SKIP}"
[ "${FAIL}" = "0" ]
