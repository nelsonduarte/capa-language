#!/usr/bin/env bash
#
# Print the compiler version a package DECLARES it needs, taken from the
# `capa` key of its manifest's [package] table:
#
#   [package]
#   capa = ">=1.17.0"      ->  1.17.0
#
# This exists for release guard 2. That guard must build the published
# artefact with a RELEASED compiler rather than the working tree, and
# the honest choice of which release is the FLOOR the package itself
# advertises: it is the oldest compiler a consumer could obey the
# manifest with, so it is the version whose failure the package would be
# blamed for. Deriving it here rather than hardcoding it in each
# caller's workflow is the point; a pinned copy of a version number in a
# second place is the same defect as the tag/manifest drift that guard 1
# now catches.
#
# Since compiler 1.19.0 the field is also ENFORCED at build time by
# `capa/pkg/_floor.py`: a root manifest whose floor the running compiler
# is below is a hard error. The grammar here and the grammar there are
# deliberately IDENTICAL, whitespace included, so that a manifest which
# passes this guard cannot be one the compiler refuses. If you change
# either regex, change both, and extend the differential corpus in
# `tests/test_capa_floor.py` that feeds one case list to both.
#
# IT FAILS CLOSED. No manifest, no [package] table, no `capa` key, more
# than one, or a constraint in a form this script does not recognise are
# all errors. It prints nothing and exits non-zero rather than guessing
# a version, because guessing here means guard 2 silently tests a
# compiler no consumer is required to have.
#
#   tools/capa_floor.sh capa.toml    # -> 1.17.0

set -euo pipefail

MANIFEST="${1-capa.toml}"

if [ ! -f "${MANIFEST}" ]; then
  echo "ERROR: manifest '${MANIFEST}' not found; cannot determine the compiler floor" >&2
  exit 1
fi

# Same table-scoped read as check_tag_version.sh: a bare grep would also
# match a dependency's own `capa` pin.
RAW="$(awk '
  /^[[:space:]]*\[/ { in_package = ($0 ~ /^[[:space:]]*\[package\][[:space:]]*$/); next }
  in_package && /^[[:space:]]*capa[[:space:]]*=/ {
    line = $0
    sub(/^[^=]*=[[:space:]]*/, "", line)
    sub(/[[:space:]]*(#.*)?$/, "", line)
    gsub(/^["\x27]|["\x27]$/, "", line)
    print line
  }
' "${MANIFEST}")"

if [ -z "${RAW}" ]; then
  echo "ERROR: ${MANIFEST} declares no [package] capa requirement; cannot pick a released compiler" >&2
  echo "       add e.g. capa = \">=1.17.0\", or pass capa-version to the guard explicitly" >&2
  exit 1
fi

COUNT="$(printf '%s\n' "${RAW}" | wc -l | tr -d '[:space:]')"
if [ "${COUNT}" != "1" ]; then
  echo "ERROR: ${MANIFEST} declares ${COUNT} [package] capa requirements; expected exactly 1" >&2
  printf '%s\n' "${RAW}" >&2
  exit 1
fi

# Accept only an exact version or a `>=` floor, both of which name one
# unambiguous release. Ranges, carets and wildcards do not, so they are
# refused rather than approximated.
#
# Exactly three numeric components. The previous `[0-9][0-9.]*[0-9]`
# also matched `1.17`, `1.2.3.4` and `1..2`, none of which is a release
# this project has ever published; it would have handed guard 2 a
# version string that resolves to no tag, and it disagreed with the
# compiler-side parser, which is the one divergence that must not exist.
FLOOR="$(printf '%s\n' "${RAW}" | sed -n 's/^[[:space:]]*\(>=[[:space:]]*\)\{0,1\}\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)[[:space:]]*$/\2/p')"

if [ -z "${FLOOR}" ]; then
  echo "ERROR: cannot read a single release out of capa = \"${RAW}\" in ${MANIFEST}" >&2
  echo "       supported forms are \"1.17.0\" and \">=1.17.0\"" >&2
  exit 1
fi

printf '%s\n' "${FLOOR}"
