#!/usr/bin/env bash
#
# RELEASE GUARD 2: prove the released artefact builds somewhere that is
# not our machine.
#
# WHY THIS EXISTS. capa_authgate v0.1.0 was published, GPG-signed,
# SLSA-attested and CI-green, and did not compile for anyone who
# downloaded it. Its capa.toml omitted a transitive dependency
# (capa_hash), and our own ~/Desktop/repos layout, with every library
# checked out side by side, silently satisfied the unresolved import
# through the module resolver's parent-directory fallback. Every check
# we ran passed. The defect surfaced only when the published tarball was
# extracted somewhere without those siblings.
#
# The same repository then shipped a tarball whose .gitattributes
# export-ignored tools/, so the README told downloaders to run
# `python tools/nest_vendor.py` and the tarball did not contain it. The
# single command demonstrating the product's central claim was
# unrunnable by everyone except us.
#
# Both defects are one shape: verification that runs WHERE WE ARE,
# proving nothing about where the USER is. This guard runs the consumer
# flow in a directory that has no siblings, from the artefact bytes, with
# a RELEASED compiler. It catches the first defect because there is
# nothing next door to resolve against, and the second because it runs
# the documented commands against the artefact's own contents rather
# than the working tree's.
#
# Note that the first defect's specific mechanism (the parent-directory
# search root) was closed in the compiler itself. This guard is not
# redundant with that fix: it is the layer that does not depend on which
# compiler version the user has, and the released compilers a consumer
# actually runs today still carry the old fallback.
#
# USAGE
#
#   tools/clean_room_build.sh \
#       --tarball dist/capa_authgate-v0.2.1.tar.gz \
#       --room    /tmp/cleanroom \
#       --run     'gpg --import publisher.asc' \
#       --run     'capa install' \
#       --run     'python tools/nest_vendor.py' \
#       --run     'capa --check main.capa' \
#       --run     'capa test'
#
# The --run commands are the CONSUMER flow, in order, executed inside
# the extracted package. They are given by the caller because they are
# genuinely repository-specific (which modules to check, whether a
# vendor layout step is needed); what is NOT repository-specific, and so
# lives here in one auditable place, is the isolation, the extraction,
# and the fail-closed rules.
#
# IT FAILS CLOSED. Every way of not knowing is an error: no tarball, an
# unreadable tarball, a room that is not an absolute path, a room that
# already has anything in it, a tarball that does not extract to exactly
# one top-level directory, an empty --run command, and above all ZERO
# --run commands. A clean room that runs nothing proves nothing while
# reporting success, which is precisely the failure this whole guard
# exists to prevent.

set -euo pipefail

TARBALL=""
ROOM=""
SHA256_OUT=""
COMMANDS=()

usage() {
  cat >&2 <<'EOF'
usage: clean_room_build.sh --tarball <file> --room <abs-dir> --run <cmd> [--run <cmd> ...]
                           [--sha256-out <file>]
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --tarball)
      [ "$#" -ge 2 ] || { echo "ERROR: --tarball needs a value" >&2; exit 1; }
      TARBALL="$2"; shift 2 ;;
    --room)
      [ "$#" -ge 2 ] || { echo "ERROR: --room needs a value" >&2; exit 1; }
      ROOM="$2"; shift 2 ;;
    --sha256-out)
      [ "$#" -ge 2 ] || { echo "ERROR: --sha256-out needs a value" >&2; exit 1; }
      SHA256_OUT="$2"; shift 2 ;;
    --run)
      [ "$#" -ge 2 ] || { echo "ERROR: --run needs a value" >&2; exit 1; }
      if [ -z "${2//[[:space:]]/}" ]; then
        echo "ERROR: --run was given an empty command; refusing to pretend it ran" >&2
        exit 1
      fi
      COMMANDS+=("$2"); shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument '$1'" >&2
      usage
      exit 1 ;;
  esac
done

if [ -z "${TARBALL}" ]; then
  echo "ERROR: no --tarball given; there is no artefact to verify" >&2
  exit 1
fi

if [ ! -f "${TARBALL}" ]; then
  echo "ERROR: tarball '${TARBALL}' not found; cannot verify an artefact that is not there" >&2
  exit 1
fi

if [ -z "${ROOM}" ]; then
  echo "ERROR: no --room given; a clean room needs an explicit location" >&2
  exit 1
fi

# An absolute path only. A relative room is resolved against whatever
# directory the caller happens to be in, which in a release workflow is
# the source checkout, which is exactly the tree whose neighbours we are
# trying not to be able to see.
case "${ROOM}" in
  /*) ;;
  *)
    echo "ERROR: --room '${ROOM}' must be an absolute path" >&2
    exit 1 ;;
esac

if [ "${#COMMANDS[@]}" -eq 0 ]; then
  echo "ERROR: no --run commands given; a clean room that runs nothing proves nothing" >&2
  exit 1
fi

# The room must be empty. Anything already sitting in it becomes a
# sibling of the extracted package, which is the exact condition that
# hid the capa_authgate v0.1.0 defect for months.
if [ -e "${ROOM}" ]; then
  if [ ! -d "${ROOM}" ]; then
    echo "ERROR: --room '${ROOM}' exists and is not a directory" >&2
    exit 1
  fi
  if [ -n "$(ls -A "${ROOM}")" ]; then
    echo "ERROR: --room '${ROOM}' is not empty; it would give the artefact siblings" >&2
    ls -A "${ROOM}" >&2
    exit 1
  fi
else
  mkdir -p "${ROOM}"
fi

# Record the digest of the exact bytes verified, so a caller can assert
# that what it publishes is what this guard built. See the reusable
# workflow for why that assertion is the caller's job and not this
# script's.
if command -v sha256sum >/dev/null 2>&1; then
  DIGEST="$(sha256sum "${TARBALL}" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  DIGEST="$(shasum -a 256 "${TARBALL}" | cut -d' ' -f1)"
else
  echo "ERROR: neither sha256sum nor shasum is available; cannot record what was verified" >&2
  exit 1
fi
echo "clean room: verifying ${TARBALL}"
echo "clean room: sha256 ${DIGEST}"
if [ -n "${SHA256_OUT}" ]; then
  printf '%s\n' "${DIGEST}" > "${SHA256_OUT}"
fi

tar -xzf "${TARBALL}" -C "${ROOM}"

# Exactly one top-level directory, which is the project root. More than
# one means the extracted files are siblings of each other; zero means
# the tarball was empty. Both are unverifiable, so both are errors.
ENTRIES=()
while IFS= read -r entry; do
  [ -n "${entry}" ] && ENTRIES+=("${entry}")
done < <(ls -A "${ROOM}")

if [ "${#ENTRIES[@]}" -ne 1 ]; then
  echo "ERROR: tarball extracted to ${#ENTRIES[@]} top-level entries; expected exactly 1" >&2
  printf '  %s\n' "${ENTRIES[@]}" >&2
  exit 1
fi

PROJECT="${ROOM}/${ENTRIES[0]}"
if [ ! -d "${PROJECT}" ]; then
  echo "ERROR: '${PROJECT}' is not a directory; the tarball has no project root" >&2
  exit 1
fi

echo "clean room: project root ${PROJECT} (siblings: none)"

# CAPA_PATH is an explicit list of module search roots, so inheriting it
# would let the clean room reach straight back into the tree we are
# isolating from. Unset it rather than trusting it to be unset.
unset CAPA_PATH

cd "${PROJECT}"

STEP=0
for cmd in "${COMMANDS[@]}"; do
  STEP=$((STEP + 1))
  echo ""
  echo "clean room: step ${STEP}/${#COMMANDS[@]}: ${cmd}"
  # Run it with `set -e` off and read the status explicitly. Inside an
  # `if ! cmd` the `$?` seen by the body is the status of the NEGATION,
  # so a failing step gets reported as "exit 0", which is a guard
  # printing a reassuring number about a failure. It fired correctly
  # either way, but a diagnostic nobody can trust is how the next defect
  # gets waved through.
  set +e
  bash -c "${cmd}"
  status=$?
  set -e
  if [ "${status}" -ne 0 ]; then
    echo "" >&2
    echo "ERROR: clean-room step ${STEP} failed (exit ${status}): ${cmd}" >&2
    echo "       the published artefact does not build outside the development tree" >&2
    exit 1
  fi
done

echo ""
echo "OK: ${TARBALL} builds from a clean location (${STEP} step(s))"
