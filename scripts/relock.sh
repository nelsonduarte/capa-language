#!/usr/bin/env bash
#
# Regenerate the pinned CI lockfile (requirements-ci.lock).
#
# When to run this
# ----------------
# The lock is the single, universal, fully-hashed dependency set CI
# installs under `pip install --require-hashes`. It is a CI-only input:
# the published wheel/sdist stays dependency-free (the extras in
# pyproject.toml are version FLOORS, never pins). Regenerate it whenever
# you:
#
#   - bump a version floor in pyproject.toml's [lsp], [wasm], or [test]
#     extras,
#   - add or remove a dependency in any of those extras,
#   - want to pick up newer patched wheels for the pinned transitive set.
#
# The [eval] extra (matplotlib) is DELIBERATELY not locked: it is in no
# CI job, only the paper-figure scripts under evaluation/.
#
# Requirements
# ------------
# uv (https://docs.astral.sh/uv/). Install it into a throwaway env, e.g.
# `pipx install uv` or `pip install uv`; do NOT add uv to pyproject.toml.
#
# After running, review the diff, run scripts described in CONTRIBUTING.md
# to confirm a fresh `pip install --require-hashes -r requirements-ci.lock`
# still installs clean, and commit the updated lock.

set -euo pipefail

cd "$(dirname "$0")/.."

uv pip compile --universal --generate-hashes \
  --extra lsp --extra wasm --extra test \
  pyproject.toml -o requirements-ci.lock
