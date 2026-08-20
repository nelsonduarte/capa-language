#!/usr/bin/env bash
#
# Regenerate the pinned CI lockfiles (requirements-test.lock and
# requirements-ci.lock).
#
# When to run this
# ----------------
# The locks are universal, fully-hashed dependency sets CI installs under
# `pip install --require-hashes`. requirements-test.lock (the `[test]`
# extra) feeds the 9-cell test matrix; requirements-ci.lock (the
# `[lsp,wasm,test]` union) feeds the audit and wasi jobs, which install
# the wasm binding anyway. They are CI-only inputs: the published
# wheel/sdist stays dependency-free (the extras in pyproject.toml are
# version FLOORS, never pins). Regenerate them whenever you:
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
# The `--python-version 3.10` flag is load-bearing: it pins uv to the
# project's floor so the `python_version < '3.11'` conditional transitives
# (exceptiongroup, tomli) get lines and hashes. Without it, a lock built on
# a newer interpreter omits them and --require-hashes fails on the 3.10
# matrix cells. The extra markers are additive on 3.11-3.14.
#
# After running, review the diff, confirm a fresh
# `pip install --require-hashes -r <lock>` still installs clean, and commit
# the updated locks.

set -euo pipefail

cd "$(dirname "$0")/.."

uv pip compile --universal --generate-hashes --python-version 3.10 \
  --extra test \
  pyproject.toml -o requirements-test.lock

uv pip compile --universal --generate-hashes --python-version 3.10 \
  --extra lsp --extra wasm --extra test \
  pyproject.toml -o requirements-ci.lock
