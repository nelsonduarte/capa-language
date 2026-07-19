#!/usr/bin/env bash
#
# RELEASE GUARD 1: fail the release unless the pushed tag matches the
# version declared in the manifest.
#
# WHY THIS EXISTS. capa_authgate v0.2.0 was tagged, built, attested and
# published while its capa.toml still said version = "0.1.0". Everything
# downstream of the tag was correct: the signature, the tarball digest,
# the Rekor entry. The artefact simply carried the wrong label, so
# `capa install` on the v0.2.0 tarball reported `capa_authgate 0.1.0`.
# Nothing in that release workflow had ever compared the two, so nothing
# could catch it. A tag is not rewritable without destroying the
# provenance it anchors, so v0.2.0 stays published with the incorrect
# label and this guard exists so that no later tag can repeat it.
#
# WHY IT LIVES HERE. This repository is the trust anchor every Capa
# package already pins its compiler version to, and where the publisher
# key policy lives. `.github/workflows/release-guards.yml` calls this
# file, and every repository that adopts that reusable workflow runs
# THIS copy, not a fork of it. N copies of a security guard are N copies
# that drift.
#
# THIS SCRIPT IS THE GUARD, not a description of one. What CI runs is
# what you can run here:
#
#   tools/check_tag_version.sh v1.17.0 pyproject.toml project   # passes
#   tools/check_tag_version.sh v9.9.9  pyproject.toml project   # fails
#   tools/check_tag_version.sh v0.2.1  capa.toml                # a Capa package
#
# IT FAILS CLOSED. A guard that succeeds when it cannot do its job is
# worse than no guard, because it manufactures false confidence. Every
# way of not knowing is an error: no tag argument, no manifest, a table
# name that is not a plain identifier, no version key in the requested
# table, an empty parse, or more than one candidate version line. Only
# an exact match exits 0.

set -euo pipefail

TAG="${1-}"
MANIFEST="${2-capa.toml}"
# The TOML table holding the authoritative version. `capa.toml` uses
# [package]; this repository's own pyproject.toml uses [project]. This
# is the one input the repo-local capa_authgate original did not have,
# and it is what lets a single guard serve both manifest dialects
# instead of being copied and edited per repository.
TABLE="${3-package}"

if [ -z "${TAG}" ]; then
  echo "ERROR: no tag given; usage: $0 <tag> [manifest] [table]" >&2
  exit 1
fi

if [ ! -f "${MANIFEST}" ]; then
  echo "ERROR: manifest '${MANIFEST}' not found; cannot compare against tag ${TAG}" >&2
  exit 1
fi

# The table name is interpolated into an awk regex below, so restrict it
# to a plain identifier. A table name carrying regex metacharacters
# could otherwise widen the match and let the guard read a version from
# a table nobody asked about, which is a guard passing for the wrong
# reason.
case "${TABLE}" in
  *[!A-Za-z0-9_-]* | '')
    echo "ERROR: table name '${TABLE}' is not a plain identifier ([A-Za-z0-9_-]+)" >&2
    exit 1
    ;;
esac

# Read `version` from the requested table ONLY. A bare grep would also
# match a [dependencies.*] or [project.optional-dependencies] version
# line and could compare the tag against a dependency's pin, which would
# be a guard passing for the wrong reason. Any other table header, hence
# also a sub-table such as [project.urls], closes the region.
VERSIONS="$(awk -v table="${TABLE}" '
  BEGIN { header = "^[[:space:]]*\\[" table "\\][[:space:]]*$" }
  /^[[:space:]]*\[/ { in_table = ($0 ~ header); next }
  in_table && /^[[:space:]]*version[[:space:]]*=/ {
    line = $0
    sub(/^[^=]*=[[:space:]]*/, "", line)
    sub(/[[:space:]]*(#.*)?$/, "", line)
    gsub(/^["\x27]|["\x27]$/, "", line)
    print line
  }
' "${MANIFEST}")"

if [ -z "${VERSIONS}" ]; then
  echo "ERROR: no [${TABLE}] version found in ${MANIFEST}; refusing to release" >&2
  exit 1
fi

COUNT="$(printf '%s\n' "${VERSIONS}" | wc -l | tr -d '[:space:]')"
if [ "${COUNT}" != "1" ]; then
  echo "ERROR: ${MANIFEST} declares ${COUNT} [${TABLE}] version lines; expected exactly 1" >&2
  printf '%s\n' "${VERSIONS}" >&2
  exit 1
fi

VERSION="${VERSIONS}"
if [ -z "${VERSION}" ]; then
  echo "ERROR: [${TABLE}] version in ${MANIFEST} parsed as empty; refusing to release" >&2
  exit 1
fi

if [ "${TAG}" != "v${VERSION}" ]; then
  echo "ERROR: tag ${TAG} does not match the version declared in ${MANIFEST}" >&2
  echo "       manifest says ${VERSION}, so the tag must be v${VERSION}" >&2
  echo "       fix ${MANIFEST} and tag again; do NOT rewrite a published tag" >&2
  exit 1
fi

echo "OK: tag ${TAG} matches ${MANIFEST} [${TABLE}] version ${VERSION}"
