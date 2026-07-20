#!/usr/bin/env bash
#
# Print the shared-region digest of each canonical template, in the
# format fleet/shared-regions.sha256 and every adopter's
# .github/shared-regions.sha256 record use:
#
#   <sha256>  <path as the adopter sees it>
#
# Run it from anywhere:
#
#   bash fleet/shared_region_digest.sh
#
# THE EXTRACTION HERE IS THE SAME EXTRACTION the adopter-side check
# performs, deliberately duplicated in the smallest possible form rather
# than shared, because the two run on opposite sides of the comparison
# and a shared implementation could move the boundary on both at once.
# tests/test_fleet_templates.py runs the adopter-side check against
# these templates and refuses any disagreement, so the duplication is
# held honest rather than trusted.
#
# `\r` is stripped explicitly. Do not remove that on the evidence that a
# CRLF file behaves locally: MSYS gawk strips `\r` on its own and MSYS
# grep is CR-tolerant, so a CRLF copy digests identically on Windows and
# would not on a Linux runner.

set -uo pipefail

FLEET_DIR="$(cd "$(dirname "$0")" && pwd)"

BEGIN_MARK='# ================== CONFIG: the only repo-specific part =================='
END_MARK='# ======================= END CONFIG; shared body ========================='

STATUS=0

for rel in tests/test_release_wiring.sh tests/test_wiring_mutations.sh; do
  src="${FLEET_DIR}/templates/${rel}"
  if [ ! -f "${src}" ]; then
    echo "missing template: ${src}" >&2
    STATUS=1
    continue
  fi
  # The status is tested, not the output. `awk | sha256sum` yields the
  # digest of the EMPTY STRING when awk bails out, which is a perfectly
  # well-formed 64-character answer to a question that failed, so an
  # emptiness check would let a markerless file through with a stable
  # number. `pipefail` is set above and a command substitution reports
  # the pipeline's status.
  if ! digest="$(
    awk -v b="${BEGIN_MARK}" -v e="${END_MARK}" '
      { sub(/\r$/, ""); line[NR] = $0 }
      $0 == b { nb++; if (nb == 1) bl = NR }
      $0 == e { ne++; if (ne == 1) el = NR }
      END {
        if (nb != 1 || ne != 1 || bl > el) {
          print "malformed CONFIG markers" > "/dev/stderr"
          exit 1
        }
        for (i = 1; i <= NR; i++) if (i <= bl || i >= el) print line[i]
      }
    ' "${src}" | sha256sum | cut -d' ' -f1
  )"; then
    echo "could not digest ${rel}" >&2
    STATUS=1
    continue
  fi
  printf '%s  %s\n' "${digest}" "${rel}"
done

exit "${STATUS}"
