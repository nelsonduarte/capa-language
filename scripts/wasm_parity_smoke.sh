#!/usr/bin/env bash
#
# Wasm/Python parity gate for examples/*.capa.
#
# Why this exists
# ---------------
# The Python backend is the reference implementation; the Wasm backend is a
# separate code generator that must produce the SAME observable behaviour.
# CI runs the example smoke ONLY under the Python interpreter, so a Wasm-only
# codegen regression can ship with a green build. That is exactly what happened
# with PR #31: emitting `?` over `Result<Unit, E>` produced invalid Wasm and
# broke `examples/io.capa` under `--wasm`, yet CI stayed green and only manual
# adversarial review caught it.
#
# This script closes that gap. For a curated set of examples that are KNOWN to
# behave identically on both backends, it runs:
#
#     python -m capa --run              <- oracle (reference stdout + exit code)
#     python -m capa --wasm --run       <- core Wasm backend
#     python -m capa --wasm --component --run   <- Component Model backend
#
# and FAILS if any backend diverges from the oracle in exit code or stdout.
#
# The curated set is maintained BY HAND below. It was cured empirically by
# running all examples on both backends; only examples that (a) exit 0 on both
# and (b) produce byte-identical stdout are included. Everything excluded is
# listed with a reason so the set stays honest and maintainable. When you add a
# new example that runs cleanly under `--wasm`, add it to MUST_PASS. When a
# Wasm codegen gap is fixed, move the relevant example out of the EXCLUDED notes
# and into MUST_PASS.
#
# Determinism: MUST_PASS contains no example whose stdout depends on the clock,
# randomness, or the network, so the gate never flakes.
#
# Usage:
#     scripts/wasm_parity_smoke.sh
# Requires: wasm-tools + wasmtime on PATH and the `wasm` extra installed (the
# CI `wasi` job provides all three). Run from the repository root.

set -uo pipefail

# --- Curated must-pass parity set -------------------------------------------
# Each of these exits 0 and prints identical stdout on the Python oracle, the
# core Wasm backend, and the Component Model backend. Grouped by feature so the
# spread of exercised codegen is visible at a glance.
MUST_PASS=(
  # Core language + the PR #31 regression (`?` over Result<Unit, E>, Unit
  # methods, aggregates, string interpolation).
  hello
  basics
  grades
  io
  json
  generics
  documented_demo
  demo_event_stream

  # Capability attenuation (structural, deterministic output).
  clock_attenuation
  net_attenuation
  fs_env_attenuation
  user_capabilities
  llm_tool_sandbox

  # Standard library: lists, maps/sets, strings.
  stdlib_list
  stdlib_map_set
  stdlib_string

  # Sum types / structs / parsers / SBOM tooling.
  sbom_capability_audit
  sbom_diff
  spdx_license_expr
  spdx_tag_parser
  vex_demo
  empirical_config
  migrate_logfetcher_step3_typed

  # Aggregate/payload slot type inference (2026-07 fix): nested
  # builtin-variant match bindings (`Ok(JObj(m))` / `Some(JStr(s))`),
  # match-arm result-type refinement (`None -> [] ; Some(xs) -> xs`),
  # and closure elements in a list literal.
  tasks
  quota_check
  cyclonedx_parser
  spdx_parser

  # Built-in IoError construction (Err(IoError("...")) on the Wasm backend).
  provenance_demo
  llm_agent_runner

  # CVE explainer demos (string handling, pattern matching, control flow).
  cve_eslint_scope
  cve_lxml_xxe
  cve_node_ipc
  cve_pickle
  cve_pyyaml
  cve_torchtriton
  cve_ua_parser_js
  cve_xz_utils
)

# --- Deliberately EXCLUDED (with reasons) -----------------------------------
# Intentional non-zero exit on the Python ORACLE itself (teaching demos where
# the compiler is SUPPOSED to reject the program, or that need stdin) - there
# is no "success" stdout to compare, so they are out of scope for a parity gate:
#   aliasing                       compiler rejects aliased capability (exit 1 by design)
#   cap_violations                 compiler rejects capability in a struct field (exit 1)
#   consume                        compiler rejects reuse of a consumed capability (exit 1)
#   errors                         compiler rejects type errors in constants (exit 1)
#   migrate_logfetcher_step1_unsafe  naive-migration step fails at runtime by design
#   migrate_logfetcher_step2_mixed   mixed-migration step fails at runtime by design
#   interactive                    reads from stdin; blocks with no TTY
#
# Pre-existing Wasm BACKEND limitations (Python runs clean, Wasm cannot yet
# compile/run the program). Tracked as codegen gaps, not parity regressions:
#   python_interop, manifest_demo, llm_anthropic_agent, llm_anthropic_real
#                                  use the `Unsafe` capability, intentionally
#                                  unsupported on the Wasm backend (raw FFI /
#                                  pointers have no sandboxed Wasm equivalent).
#   closures                       higher-order function values ("unknown func $f").
#   patterns                       tuple match with a variant sub-pattern not yet
#                                  supported on the Wasm backend.
# (`tasks`, `quota_check`, `cyclonedx_parser`, `spdx_parser` moved to
# MUST_PASS after the 2026-07 aggregate/payload slot type-inference fix.)
#
# Legitimate Python-vs-Wasm output DIVERGENCE (both exit 0, stdout differs):
#   cve_jinja2_ssti                the Wasm string-substitution path reports
#                                  "unterminated substitution" where the Python
#                                  backend parses the template correctly.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail_count=0
pass_count=0

# compare_mode <example-name> <oracle-stdout> <oracle-rc> <mode-label> <capa-flags...>
compare_mode() {
  local name="$1"; local oracle_out="$2"; local oracle_rc="$3"; local label="$4"
  shift 4
  local out rc
  out="$(python -m capa "$@" --run "examples/${name}.capa" 2>/dev/null)"
  rc=$?
  if [ "$rc" != "$oracle_rc" ]; then
    echo "FAIL [$name] ($label): exit code ${rc} != Python oracle ${oracle_rc}"
    fail_count=$((fail_count + 1))
    return 1
  fi
  if [ "$out" != "$oracle_out" ]; then
    echo "FAIL [$name] ($label): stdout differs from the Python oracle"
    echo "----- oracle (python --run) -----"
    printf '%s\n' "$oracle_out"
    echo "----- $label -----"
    printf '%s\n' "$out"
    echo "---------------------------------"
    fail_count=$((fail_count + 1))
    return 1
  fi
  return 0
}

echo "Wasm/Python parity gate over ${#MUST_PASS[@]} curated examples"
echo

for name in "${MUST_PASS[@]}"; do
  src="examples/${name}.capa"
  if [ ! -f "$src" ]; then
    echo "FAIL [$name]: examples/${name}.capa is missing (stale MUST_PASS entry)"
    fail_count=$((fail_count + 1))
    continue
  fi

  # Oracle: the Python backend defines expected exit code + stdout.
  oracle_out="$(python -m capa --run "$src" 2>/dev/null)"
  oracle_rc=$?
  if [ "$oracle_rc" != "0" ]; then
    echo "FAIL [$name]: Python oracle itself exited ${oracle_rc} (MUST_PASS entries must run clean)"
    fail_count=$((fail_count + 1))
    continue
  fi

  ok=1
  compare_mode "$name" "$oracle_out" "$oracle_rc" "wasm --run" --wasm || ok=0
  compare_mode "$name" "$oracle_out" "$oracle_rc" "wasm --component --run" --wasm --component || ok=0
  if [ "$ok" = "1" ]; then
    echo "ok   [$name]"
    pass_count=$((pass_count + 1))
  fi
done

echo
if [ "$fail_count" != "0" ]; then
  echo "Wasm parity gate FAILED: ${fail_count} check(s) diverged from the Python oracle."
  exit 1
fi
echo "Wasm parity gate passed: ${pass_count}/${#MUST_PASS[@]} examples identical across Python, --wasm, and --wasm --component."
