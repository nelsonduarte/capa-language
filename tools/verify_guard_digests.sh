#!/usr/bin/env bash
#
# Verify the fetched guard scripts against digests the ADOPTER pinned.
#
# WHY THIS EXISTS, AND WHAT IT HONESTLY BUYS.
#
# The step this replaces was called "Confirm the guards are the revision
# the caller pinned" and it did not do that. It compared the checked-out
# SHA against the value it had just used as the checkout ref, so both
# sides came from one variable and it agreed with itself. Handed the
# wrong revision it would have said OK. It detected exactly one thing,
# an empty ref silently taking the default branch, which is worth having
# and is now checked where it belongs, before the checkout.
#
# So be exact about what a workflow can establish about ITSELF from the
# inside: nothing. The `uses:` pin is resolved by the platform, and a
# substituted workflow substitutes its own verification step along with
# everything else. Identity is irreducibly the platform's guarantee.
# This script cannot change that and does not claim to. It would be
# verifying itself.
#
# What it does buy is real and narrower. The reusable workflow FILE is
# pinned by the caller's `uses:` line, but the guard SCRIPTS are fetched
# at run time by ref, and an adopter who pins `@main` or `@v1.18.1`
# rather than a commit SHA gets no immutability from the platform at
# all: the ref resolves to whatever it points at today. `guard-digests`
# is the adopter's own record of the bytes they audited, written in
# THEIR repository, so it is the one input here that does not come from
# ours. If the guards change under them, this fails and names the file.
#
# It is optional because forcing every adopter to compute digests before
# they can release would push repositories away from having guards at
# all. When it is absent the workflow says so in the log rather than
# implying an anchor it does not have.
#
# USAGE
#
#   tools/verify_guard_digests.sh <root> <digests-file>
#
# Each non-blank, non-comment line of the digests file is
#
#   <64-hex-sha256>  <path relative to root>
#
# which is `sha256sum` output, so an adopter produces the list with
#
#   sha256sum tools/check_tag_version.sh tools/clean_room_build.sh
#
# IT FAILS CLOSED. A missing root, a missing or empty digests file, a
# malformed line, a listed file that is not there, a digest that does
# not match, or a file that parses to zero entries are all errors. In
# particular an EMPTY digests file is an error rather than a pass:
# "verified nothing" must never render as "verified".

set -euo pipefail

ROOT="${1-}"
DIGESTS="${2-}"

if [ -z "${ROOT}" ] || [ -z "${DIGESTS}" ]; then
  echo "ERROR: usage: $0 <root> <digests-file>" >&2
  exit 1
fi

if [ ! -d "${ROOT}" ]; then
  echo "ERROR: guard root '${ROOT}' is not a directory; nothing to verify" >&2
  exit 1
fi

if [ ! -f "${DIGESTS}" ]; then
  echo "ERROR: digests file '${DIGESTS}' not found" >&2
  exit 1
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    echo "ERROR: neither sha256sum nor shasum is available" >&2
    exit 1
  fi
}

CHECKED=0
while IFS= read -r line || [ -n "${line}" ]; do
  # Trim, then skip blanks and comments.
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [ -z "${line}" ] && continue
  case "${line}" in \#*) continue ;; esac

  WANT="${line%%[[:space:]]*}"
  REST="${line#"${WANT}"}"
  # `sha256sum` writes two spaces, or a space and a `*` in binary mode.
  REST="${REST#"${REST%%[![:space:]]*}"}"
  REST="${REST#\*}"
  PATH_REL="${REST}"

  case "${WANT}" in
    [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])
      ;;
    *)
      echo "ERROR: malformed digest line (want '<64-hex>  <path>'): ${line}" >&2
      exit 1 ;;
  esac

  if [ -z "${PATH_REL}" ]; then
    echo "ERROR: digest line names no path: ${line}" >&2
    exit 1
  fi

  # A listed path must stay inside the fetched guard tree. `..` would
  # let a digests file point the check at some other file that happens
  # to match, which is a check passing about the wrong bytes.
  case "${PATH_REL}" in
    /* | *..*)
      echo "ERROR: digest path must be relative and inside the guard tree: ${PATH_REL}" >&2
      exit 1 ;;
  esac

  TARGET="${ROOT}/${PATH_REL}"
  if [ ! -f "${TARGET}" ]; then
    echo "ERROR: pinned guard file '${PATH_REL}' is not present in the fetched guards" >&2
    exit 1
  fi

  GOT="$(sha256_of "${TARGET}")"
  # Compare case-insensitively; sha256sum lowercases, adopters may not.
  if [ "$(printf '%s' "${GOT}" | tr 'A-F' 'a-f')" != "$(printf '%s' "${WANT}" | tr 'A-F' 'a-f')" ]; then
    echo "ERROR: ${PATH_REL} does not match the digest you pinned" >&2
    echo "       pinned   ${WANT}" >&2
    echo "       fetched  ${GOT}" >&2
    echo "       the guards changed since you audited them; re-audit and re-pin," >&2
    echo "       or pin the reusable workflow to a commit SHA instead of a moving ref" >&2
    exit 1
  fi

  echo "  ok  ${PATH_REL}"
  CHECKED=$((CHECKED + 1))
done < "${DIGESTS}"

if [ "${CHECKED}" -eq 0 ]; then
  echo "ERROR: the digests file lists no files; 'verified nothing' is not 'verified'" >&2
  exit 1
fi

echo "OK: ${CHECKED} guard file(s) match the digests you pinned"
