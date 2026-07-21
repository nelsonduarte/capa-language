#!/usr/bin/env bash
#
# Mutation test for tests/test_release_wiring.sh and, from S onwards,
# for tests/test_shared_regions.sh.
#
# WHY THIS EXISTS. The wiring test reports "53 passed, 0 failed", and
# that number says how many assertions RAN. It says nothing about how
# many of them BITE. An adversarial audit of this repository applied
# three edits by hand, each of which leaves a release checking less than
# it claims, and all three passed green:
#
#   * an entry point typo'd identically in the config and in the flow,
#     so both agree about a file that does not exist;
#   * a ceiling entry dropped from both, so a module is silently no
#     longer covered;
#   * an entry point dropped entirely, same effect, no trace.
#
# Separately, an adoption of the shared body onto capa_base64 performed
# exactly as the checklist instructs produced 52 green assertions on a
# repository still declaring `capa = ">=1.1.0"`, a floor that CANNOT
# build the package at all.
#
# A guard nobody has ever seen fail is a guard nobody has evidence
# about. So each mutation below is applied to a scratch copy of this
# repository, the relevant test is run there, and it is required to
# FAIL. The unmutated control is required to PASS, which is what rules
# out the harness reporting success because the test errored for its own
# reasons.
#
# MUTATIONS S THROUGH Y TARGET A DIFFERENT CHECK. Everything up to R
# mutates what this repository DECLARES about itself, and the wiring
# test catches it. S onwards mutates the ~770 lines of shared body that
# were COPIED into this repository from the compiler's templates, which
# the wiring test cannot see, because it is the file being edited. Those
# run tests/test_shared_regions.sh instead. W is the odd one out and
# must stay GREEN: it edits the config region, which is repo-specific by
# design, and a drift check that reddens there is one that gets turned
# off. X is the one that matters most, and the reason the drift check is
# not a digest alone: the config region is not digested, so a single
# line of shell placed in it can neutralise the whole file while the
# digest reports no drift.
#
# Run it directly:
#
#   bash tests/test_wiring_mutations.sh
#
# `capa test` runs the .capa files in tests/ and ignores this one.

set -uo pipefail

# ================== CONFIG: the only repo-specific part ==================

# Two top-level modules this repository's release actually checks. The
# mutations rename the first and delete the second, so both must be real
# entries in tests/test_release_wiring.sh and in both workflows.
# PRIMARY_MODULE must be the FIRST name in ENTRY_POINTS and
# CEILING_ENTRIES; SECOND_MODULE must be any name that is not the first.
PRIMARY_MODULE=main.capa
SECOND_MODULE=example.capa

# A `max = [...]` line naming every capability capa accepts, which
# replaces capa.toml's own. A ceiling that excludes nothing bounds
# nothing.
CEILING_LINE_WIDE='max = ["Clock", "Db", "Env", "Fs", "Net", "Proc", "Random", "Serve", "Stdio"]'

# One capability the real ceiling names, to misspell.
CEILING_NAME=Stdio

# ======================= END CONFIG; shared body =========================

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIRING_TEST=tests/test_release_wiring.sh

# THE TWO WORKFLOWS MUST EXIST BEFORE ANY MUTATION RUNS. Every mutation
# below edits both of them with `sed -i`, so on a repository that has
# only just been adopted and has not copied them yet, sed printed
# `can't read .github/workflows/guard-selftest.yml` into the middle of
# the output and the harness carried on producing meaningless verdicts.
# A missing precondition should say so once, not leak a tool's error
# once per mutation.
for _wf in .github/workflows/release.yml .github/workflows/guard-selftest.yml; do
  if [ ! -f "${REPO_ROOT}/${_wf}" ]; then
    echo "FAIL: ${_wf} not found" >&2
    echo "      Every mutation here edits both release.yml and" >&2
    echo "      guard-selftest.yml, so there is nothing to mutate and any" >&2
    echo "      verdict would be meaningless. Copy both from an existing" >&2
    echo "      adopter and adapt their consumer flow to this package; see" >&2
    echo "      the adoption checklist in tests/test_release_wiring.sh." >&2
    exit 1
  fi
done
SHARED_TEST=tests/test_shared_regions.sh
MUTATIONS_TEST=tests/test_wiring_mutations.sh

PASS=0
FAIL=0
SKIP=0

# The two negative dimensions are optional (a pure library declares
# neither), so the mutations that exercise them read the names out of
# the wiring test's own config and report SKIP where the dimension is
# unused, rather than asserting something about a list that is empty.
NEG_MODULE="$(sed -n 's/^NEGATIVE_CEILING_ENTRIES=(\([^ )]*\).*/\1/p' \
  "$(cd "$(dirname "$0")/.." && pwd)/tests/test_release_wiring.sh" | head -1)"
REJECT_MODULE="$(sed -n 's/^COMPILER_REJECTS=("\([^=]*\)=.*/\1/p' \
  "$(cd "$(dirname "$0")/.." && pwd)/tests/test_release_wiring.sh" | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# A scratch copy of the working tree, without .git (so a mutation can
# never be committed by accident) and without vendor/ (large, and no
# assertion reads it).
seed_copy() {
  local dest="$1"
  rm -rf "${dest}"
  mkdir -p "${dest}"
  (cd "${REPO_ROOT}" && tar cf - --exclude=.git --exclude=vendor .) | (cd "${dest}" && tar xf -)
}

# Run one of this repository's shell tests inside a copy and report its
# exit status.
#
# SHARED_REGIONS_SKIP_FETCH forces layer 2 of the shared-region check,
# the one that fetches the canonical template, to SKIP. That layer needs
# the network and is allowed to skip; running it once per mutation would
# make this file's verdicts depend on whether a laptop is online, and a
# control that reddens for that reason proves nothing about the
# mutations below it. Layer 1, the offline digest comparison, has no
# skip branch and is unaffected.
run_test() {
  (cd "$1" && SHARED_REGIONS_SKIP_FETCH=1 bash "$2" >"$1/.wiring.out" 2>&1)
}

run_wiring() { run_test "$1" "${WIRING_TEST}"; }
run_shared() { run_test "$1" "${SHARED_TEST}"; }

# A digest over every file in a copy, so a mutator that silently edits
# nothing can be told apart from one whose edit the wiring test caught.
# That distinction is not hypothetical: the ceiling-widening mutator
# first written here embedded `["Stdio"]` in a sed pattern, where the
# brackets are a character class, so it matched nothing, changed
# nothing, and reported an honest but useless "missed".
tree_digest() {
  (cd "$1" && find . -type f ! -name '.wiring.out' -exec sha256sum {} + | sort | sha256sum)
}

# expect_red <id> <description> <mutator function> [runner function]
#
# The runner defaults to run_wiring, which is what every mutation up to R
# targets. The shared-region mutations pass run_shared instead: their
# point is that a copy of the shared body has been edited, which the
# wiring test cannot see because it is the file being edited.
expect_red() {
  # Assigned one per statement: bash expands every word of a `local`
  # command before performing any of its assignments, so a later
  # initialiser referring to an earlier name reads it as unset, and
  # under `set -u` that is a hard error rather than an empty string.
  local id="$1"
  local desc="$2"
  local mutate="$3"
  local runner="${4:-run_wiring}"
  local dir="${WORK}/${id}"
  seed_copy "${dir}"
  local before
  before="$(tree_digest "${dir}")"
  ( cd "${dir}" && "${mutate}" ) || { FAIL=$((FAIL + 1)); printf 'FAIL %s: mutator errored\n' "${id}"; return; }
  if [ "$(tree_digest "${dir}")" = "${before}" ]; then
    FAIL=$((FAIL + 1))
    printf 'FAIL %s: the mutator changed nothing, so this proves nothing\n' "${id}"
    return
  fi
  if "${runner}" "${dir}"; then
    FAIL=$((FAIL + 1))
    printf 'FAIL %s: %s\n' "${id}" "${desc}"
    printf '     the test stayed GREEN under this mutation\n'
  else
    PASS=$((PASS + 1))
    printf 'ok   %s: %s\n' "${id}" "${desc}"
    sed -n 's/^FAIL /       caught: /p' "${dir}/.wiring.out" | head -4
  fi
}

# expect_green <id> <description> <mutator function> [runner function]
#
# The inverse, and it earns its place: a drift check that reddens on an
# edit to the region that is repo-specific BY DESIGN is a check every
# adopter learns to ignore, and the whole design rests on the config
# region being freely editable. A false positive here is as much a
# defect as a missed mutation, so it is tested rather than assumed.
expect_green() {
  local id="$1"
  local desc="$2"
  local mutate="$3"
  local runner="${4:-run_wiring}"
  local dir="${WORK}/${id}"
  seed_copy "${dir}"
  local before
  before="$(tree_digest "${dir}")"
  ( cd "${dir}" && "${mutate}" ) || { FAIL=$((FAIL + 1)); printf 'FAIL %s: mutator errored\n' "${id}"; return; }
  if [ "$(tree_digest "${dir}")" = "${before}" ]; then
    FAIL=$((FAIL + 1))
    printf 'FAIL %s: the mutator changed nothing, so this proves nothing\n' "${id}"
    return
  fi
  if "${runner}" "${dir}"; then
    PASS=$((PASS + 1))
    printf 'ok   %s: %s\n' "${id}" "${desc}"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL %s: %s\n' "${id}" "${desc}"
    printf '     the test went RED on an edit it is supposed to permit\n'
    sed -n 's/^FAIL /       said: /p' "${dir}/.wiring.out" | head -4
  fi
}

# expect_red_if <guard value> <id> <description> <mutator function>
# Reports SKIP when the config dimension the mutation targets is unused
# in this repository, so an empty list cannot be read as a caught
# mutation.
expect_red_if() {
  local guard="$1"
  shift
  if [ -z "${guard}" ]; then
    SKIP=$((SKIP + 1))
    printf 'skip %s: %s (this repository declares none)\n' "$1" "$2"
    return
  fi
  expect_red "$@"
}

# ------------------------------- control -------------------------------

seed_copy "${WORK}/control"
if run_wiring "${WORK}/control"; then
  PASS=$((PASS + 1))
  printf 'ok   control: the unmutated tree passes the wiring test (%s)\n' \
    "$(tail -1 "${WORK}/control/.wiring.out")"
else
  FAIL=$((FAIL + 1))
  printf 'FAIL control: the UNMUTATED tree already fails; every result below is meaningless\n'
  sed -n 's/^FAIL /       /p' "${WORK}/control/.wiring.out"
fi

# A second control, for the second runner. Without it, every
# shared-region mutation below could be "caught" by a check that reddens
# on the unmutated tree too, which is the harness reporting its own
# breakage as evidence.
seed_copy "${WORK}/control-shared"
if run_shared "${WORK}/control-shared"; then
  PASS=$((PASS + 1))
  printf 'ok   control: the unmutated tree passes the shared-region check (%s)\n' \
    "$(tail -1 "${WORK}/control-shared/.wiring.out")"
else
  FAIL=$((FAIL + 1))
  printf 'FAIL control: the UNMUTATED tree already fails the shared-region check\n'
  sed -n 's/^FAIL /       /p' "${WORK}/control-shared/.wiring.out"
fi

# ------------------------------ mutations ------------------------------

# D. The config and the flow disagree, and the old body could not tell.
#    It interpolated the filename into a `grep -qE` pattern, where `.`
#    matches any character, so a flow saying `hexXcapa` satisfied a
#    config saying `hex.capa`. This is the regression test for that.
mutate_d() {
  sed -i "s|^\([[:space:]]*\)capa --check ${PRIMARY_MODULE}\$|\1capa --check ${PRIMARY_MODULE%.*}Xcapa|" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
  sed -i "s|^\([[:space:]]*\)capa --check-capabilities ${PRIMARY_MODULE}\$|\1capa --check-capabilities ${PRIMARY_MODULE%.*}Xcapa|" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
}
expect_red D "the flow's module name differs from the config's by one character" mutate_d

# E. The audit's mutation E: the SAME typo in the config and in both
#    flows, so nothing internal disagrees. Only the filesystem knows.
mutate_e() {
  local bad="${PRIMARY_MODULE%.*}Xcapa"
  sed -i "s|^ENTRY_POINTS=(${PRIMARY_MODULE} |ENTRY_POINTS=(${bad} |" "${WIRING_TEST}"
  sed -i "s|^CEILING_ENTRIES=(${PRIMARY_MODULE} |CEILING_ENTRIES=(${bad} |" "${WIRING_TEST}"
  sed -i "s|^\([[:space:]]*\)capa --check ${PRIMARY_MODULE}\$|\1capa --check ${bad}|" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
  sed -i "s|^\([[:space:]]*\)capa --check-capabilities ${PRIMARY_MODULE}\$|\1capa --check-capabilities ${bad}|" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
}
expect_red E "an entry point typo'd identically in the config and the flow" mutate_e

# F. The audit's mutation F: a ceiling entry dropped from the config and
#    from both flows. The module still exists and is still shipped; it
#    is simply no longer covered by anything.
mutate_f() {
  # Removed from wherever it sits in the array, not by rewriting the
  # whole array, so this works for a two-name list and a five-name one.
  sed -i "s|^\(CEILING_ENTRIES=(.*\) ${SECOND_MODULE}\(.*)\)\$|\1\2|" "${WIRING_TEST}"
  sed -i "/^[[:space:]]*capa --check-capabilities ${SECOND_MODULE}\$/d" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
}
expect_red F "a ceiling entry dropped from both the config and the flow" mutate_f

# G. The audit's mutation G: an entry point dropped entirely, compile
#    and ceiling alike, from the config and from both flows.
mutate_g() {
  sed -i "s|^\(ENTRY_POINTS=(.*\) ${SECOND_MODULE}\(.*)\)\$|\1\2|" "${WIRING_TEST}"
  sed -i "s|^\(CEILING_ENTRIES=(.*\) ${SECOND_MODULE}\(.*)\)\$|\1\2|" "${WIRING_TEST}"
  sed -i "/^[[:space:]]*capa --check ${SECOND_MODULE}\$/d" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
  sed -i "/^[[:space:]]*capa --check-capabilities ${SECOND_MODULE}\$/d" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
}
expect_red G "an entry point dropped entirely from the config and the flow" mutate_g

# H. A new module appears in the repository and nobody adds it to the
#    flow. This is the live shape of the defect: the ceiling covers the
#    import closure of the entries it is given, so an unimported module
#    is never opened and `--check-capabilities` exits 0 having never
#    seen it. Nothing here compiles the file, so its contents only have
#    to be a plausible module.
mutate_h() {
  cat > zz_unreferenced.capa <<'CAPA'
pub fun leak(fs: Fs, path: String, data: String)
    let _ = fs.write(path, data)
CAPA
}
expect_red H "a new top-level module lands and no flow line covers it" mutate_h

# I. The false floor, the defect that survived a by-the-book adoption
#    of this template onto capa_base64 with 52 green assertions.
mutate_i() {
  sed -i 's|^capa = ">=.*"|capa = ">=1.1.0"|' capa.toml
}
expect_red I "capa.toml declares a floor below the fleet floor" mutate_i

# J. The floor written in a form tools/capa_floor.sh cannot parse. The
#    guard reads this key to choose the compiler the clean room
#    downloads, so an uninterpretable value is not a style question.
mutate_j() {
  sed -i 's|^capa = ">=\(.*\)"|capa = "^\1"|' capa.toml
}
expect_red J "the floor is written in a form the guard cannot parse" mutate_j

# K. A ceiling naming every capability. It passes every entry point in
#    every package, and prints the same reassuring "OK - every declared
#    capability ceiling holds" as a tight one.
mutate_k() {
  sed -i "s|^max = .*\$|${CEILING_LINE_WIDE}|" capa.toml
}
expect_red K "the ceiling names every capability and therefore bounds nothing" mutate_k

# L. A lowercase capability name, the likeliest typo when fifteen
#    adopters hand-write this table. capa refuses it, but it refuses it
#    by discarding the WHOLE manifest with a warning and then either
#    exiting 0, dying with a traceback, or reporting an unrelated
#    unresolved-import error, depending on the subcommand.
mutate_l() {
  local lower
  lower="$(printf '%s' "${CEILING_NAME}" | tr 'A-Z' 'a-z')"
  sed -i "s|\"${CEILING_NAME}\"|\"${lower}\"|" capa.toml
}
expect_red L "a capability name in the ceiling is misspelled" mutate_l

# M. The gate stops gating. Re-proved here because the mutation is one
#    word and the workflow stays valid YAML.
mutate_m() {
  sed -i 's|^    uses: nelsonduarte/capa-language|    continue-on-error: true\n    uses: nelsonduarte/capa-language|' \
    .github/workflows/release.yml
}
expect_red M "the guards job is made continue-on-error" mutate_m

# N. The rehearsal stops rehearsing the thing that will publish.
mutate_n() {
  sed -i "/^[[:space:]]*capa test\$/d" .github/workflows/guard-selftest.yml
}
expect_red N "the self-test's consumer flow drifts from the release's" mutate_n

# O. An action repointed to a mutable tag, in a workflow that holds
#    id-token: write.
mutate_o() {
  sed -i '0,/^\([[:space:]]*\)uses: \(actions\/[a-z-]\{1,\}\)@[0-9a-f]\{40\}/s//\1uses: \2@v6/' \
    .github/workflows/release.yml
}
expect_red O "a third-party action is pinned by tag instead of commit" mutate_o

# P. A documented counter-example quietly stops being demonstrated: the
#    module is dropped from the config and from both flows. It is still
#    in the tarball and the README still points at it, and nothing runs
#    it. This is the shape the counter-examples were in before the
#    negatives existed.
mutate_p() {
  sed -i "s|^\(NEGATIVE_CEILING_ENTRIES=(.*\)${NEG_MODULE}\(.*)\)\$|\1\2|" "${WIRING_TEST}"
  sed -i "/^[[:space:]]*capa --check-capabilities ${NEG_MODULE} /d" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
}
expect_red_if "${NEG_MODULE}" P "a documented ceiling counter-example is dropped from config and flow" mutate_p

# Q. The config still claims the counter-example is demonstrated and the
#    flow no longer runs it. The claim and the evidence part company,
#    which is the failure mode the whole file is about.
mutate_q() {
  sed -i "/^[[:space:]]*capa --check-capabilities ${NEG_MODULE} /d" \
    .github/workflows/release.yml .github/workflows/guard-selftest.yml
}
expect_red_if "${NEG_MODULE}" Q "the flow stops running a counter-example the config still claims" mutate_q

# R. The negative is kept but loses the reason it must fail for, so it
#    would pass for a missing file or an unrelated error. A negative
#    that passes for the wrong reason is not a negative.
mutate_r() {
  sed -i "s|^COMPILER_REJECTS=(\"${REJECT_MODULE}=.*\")\$|COMPILER_REJECTS=(\"${REJECT_MODULE}=\")|" "${WIRING_TEST}"
}
expect_red_if "${REJECT_MODULE}" R "a compiler-rejects negative loses the error it must fail with" mutate_r

# ------------------- the shared regions, S through Y --------------------
#
# Everything above mutates what this repository DECLARES. What follows
# mutates the ~770 lines of shared body that were COPIED here, which
# nothing above can see: the wiring test cannot detect an edit to the
# wiring test. These target tests/test_shared_regions.sh instead.

BEGIN_MARK='# ================== CONFIG: the only repo-specific part =================='
END_MARK='# ======================= END CONFIG; shared body ========================='

# Insert TEXT before line N of FILE. Deliberately not sed's `i\`
# command: implementations disagree about how they treat an escape
# sequence in the inserted text, and one of these mutations inserts a
# line beginning with `t`.
insert_before() {
  awk -v n="$1" -v t="$3" 'NR == n { print t } { print }' "$2" > "$2.tmp" \
    && mv "$2.tmp" "$2"
}

# The line number of a marker, matched whole-line and literally.
marker_line() {
  awk -v m="$2" '{ sub(/\r$/, "") } $0 == m { print NR; exit }' "$1"
}

# S. The ordinary case. One line of the shared body is edited, below the
#    end marker, where an adopter "just fixing something locally" edits.
#    A comment is used rather than code so that the wiring test still
#    passes: the point is that ONLY the drift check can see this.
mutate_s() {
  sed -i '0,/^# --- the guards are the shared ones, at a pinned commit ---*$/s//# --- locally tweaked, surely harmless ---/' \
    "${WIRING_TEST}"
}
expect_red S "one line of the shared body is edited below the marker" mutate_s run_shared

# T. The end marker is moved DOWN, so lines that were shared body are
#    now inside the un-digested config region. This is the boundary
#    attack: no line changes, and yet the region that accepts arbitrary
#    shell has grown. It must be caught by the digest, because those
#    lines have left the digested surface.
mutate_t() {
  local ln
  ln="$(marker_line "${WIRING_TEST}" "${END_MARK}")"
  sed -i "${ln}d" "${WIRING_TEST}"
  insert_before "$((ln + 8))" "${WIRING_TEST}" "${END_MARK}"
}
expect_red T "the end marker is moved down, swallowing body lines into the config region" mutate_t run_shared

# U. A marker is deleted outright. Extraction must FAIL CLOSED here: a
#    file with one marker has no boundary, and a check that fell through
#    to digesting the whole file would produce a stable number that
#    describes nothing.
mutate_u() {
  local ln
  ln="$(marker_line "${WIRING_TEST}" "${BEGIN_MARK}")"
  sed -i "${ln}d" "${WIRING_TEST}"
}
expect_red U "the begin marker is deleted, leaving no boundary at all" mutate_u run_shared

# V. A marker is duplicated. Two begin markers mean two candidate
#    boundaries, and picking either one silently is how the un-digested
#    region gets chosen by whoever edits the file.
mutate_v() {
  local ln
  ln="$(marker_line "${WIRING_TEST}" "${BEGIN_MARK}")"
  insert_before "$((ln + 4))" "${WIRING_TEST}" "${BEGIN_MARK}"
}
expect_red V "the begin marker is duplicated" mutate_v run_shared

# W. The false-positive control, and the one that must stay GREEN. The
#    config region is what every adopter edits, on purpose, on adoption.
#    A drift check that reddens here is one that gets switched off.
mutate_w() {
  # Both shapes of legitimate config edit: a comment, and an assignment
  # rewritten wholesale. The assignment is matched on its NAME rather
  # than its current value, so this works whatever the adopter declares.
  local ln
  ln="$(marker_line "${WIRING_TEST}" "${BEGIN_MARK}")"
  insert_before "$((ln + 1))" "${WIRING_TEST}" "# A note an adopter might reasonably add."
  sed -i "s|^UNCHECKED_MODULES=.*\$|UNCHECKED_MODULES=(zz_scratch.capa=a-note-for-the-reviewer)|" \
    "${WIRING_TEST}"
}
expect_green W "a config-only edit does NOT trigger the drift check" mutate_w run_shared

# X. THE REASON THE DIGEST ALONE WAS NOT ENOUGH, and the mutation this
#    whole design changed for. One line of shell in the un-digested
#    config region makes the wiring test exit 0 while still printing
#    every failure it found. Measured before the grammar check existed:
#    a release with `needs: guards` deleted reported "1 failed" and
#    exited 0, so CI was green over a missing release gate, and the
#    shared-region digest was UNCHANGED because the config region is not
#    digested. If this one does not redden, the work is not done.
mutate_x() {
  local ln
  ln="$(marker_line "${WIRING_TEST}" "${END_MARK}")"
  insert_before "${ln}" "${WIRING_TEST}" "trap 'exit 0' EXIT"
}
expect_red X "a statement is injected into the un-digested config region" mutate_x run_shared

# Y. The same check, applied to the OTHER shared file. This file is
#    itself ~300 lines of copied body, and a drift check that covered
#    only its sibling would leave it to rot.
mutate_y() {
  sed -i '0,/^# ------------------------------- control ---*$/s//# ------------------------------- ctrl ---/' \
    "${MUTATIONS_TEST}"
}
expect_red Y "the shared body of this file is edited" mutate_y run_shared

printf '\n%s mutation(s) caught, %s missed, %s skipped\n' "${PASS}" "${FAIL}" "${SKIP}"
[ "${FAIL}" = "0" ]
