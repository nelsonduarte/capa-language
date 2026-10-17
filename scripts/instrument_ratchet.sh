#!/usr/bin/env bash
# The register ratchet for CI: shrink-only against the register of the
# pushed range's BASE commit (the `before` sha of a push, the base sha of
# a pull request), never HEAD~1, so a push of several commits is judged
# once against what was there before the push.
#
# usage: scripts/instrument_ratchet.sh <base sha>
#
# A missing or all-zero base (a brand-new branch) and a base commit that
# has no register are BOOTSTRAPS: said so, and accepted. Everything else
# runs `python -m tests.instruments.ratchet`, which fails on any added or
# re-described entry the candidate does not declare.
set -euo pipefail

base_sha="${1:-}"
register="tests/instrument_register.json"
base_file="$(mktemp)"
trap 'rm -f "$base_file"' EXIT

if [ -z "$base_sha" ] || [ "$base_sha" = "0000000000000000000000000000000000000000" ]; then
  echo "BOOTSTRAP: no base commit for this push (new branch or no event base)"
  python -m tests.instruments.ratchet --base NONE --candidate "$register"
  exit $?
fi

# A depth-1 checkout does not hold the base commit; fetch it by its full sha
# (what the event carries) unless it is already present.
if ! git cat-file -e "$base_sha^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$base_sha"
fi
if git cat-file -e "$base_sha:$register" 2>/dev/null; then
  git show "$base_sha:$register" > "$base_file"
  echo "base register: $base_sha:$register"
  python -m tests.instruments.ratchet --base "$base_file" --candidate "$register"
else
  echo "BOOTSTRAP: the base commit $base_sha has no $register"
  python -m tests.instruments.ratchet --base NONE --candidate "$register"
fi
