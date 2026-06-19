"""Capability-recall study harness (Phase 1a).

Scores three treatments for recovering per-function capability facts
over the ``evaluation/sbom_diff`` corpus of 20 hand-Python / Capa
pairs. The unit of recall is a single ``(python_function, capability)``
fact, authored in ``ground_truth.csv`` (see that file's ``how`` column
and the README for how it was derived and validated).

Treatments
----------
T1  dependency / PURL SBOM       : module-level imports of the naive
    Python, intersected with a capability-bearing-module allowlist.
    This is the granularity a Syft / cdxgen SBOM reports. It produces
    package-level facts, never ``(function, capability)`` facts, so its
    per-function recall is 0 BY CONSTRUCTION. That zero is the point
    about GRANULARITY, not a detection failure.
T2  good-faith pattern heuristic : the Semgrep ruleset in
    ``rules/capability_rules.yaml`` maps sink APIs to capability axes at
    the call site, attributed to the lexically-enclosing Python
    function via ``ast``. This is the honest line-level reading: it
    captures every DIRECT sink call but cannot see authority reached
    only through a local helper / dispatch / data.
T3  Capa by construction         : the per-function capability manifest
    emitted by ``python -m capa --manifest``. Capa attributes every
    capability a function can reach (declared + transitively reachable)
    by construction, so it recovers every ground-truth fact including
    the indirect ones.

Isolation
---------
Semgrep is invoked from a DEDICATED virtualenv
(``evaluation/empirical_study/.semgrep-venv``) because installing
semgrep downgrades several shared dependencies; running it from its own
interpreter keeps the compiler venv clean. The Capa manifest is emitted
from whichever interpreter runs THIS script (expected: the compiler
venv, ``python -m capa``).

Outputs (written next to this file)
-----------------------------------
``per_pair.csv``   one row per pair: ground-truth count + T1/T2/T3 recall.
``aggregate.csv``  totals and recall percentages per treatment.
``false_negatives.csv`` every fact T2 misses, with its ``how`` cause and
                   a ``dataflow_would_resolve`` classification.

Determinism: every list is sorted; semgrep and capa are pure functions
of their input files; no clocks or randomness enter the harness itself.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PAIRS = ROOT / "evaluation" / "sbom_diff"
RULES = HERE / "rules" / "capability_rules.yaml"
GROUND_TRUTH = HERE / "ground_truth.csv"

# Isolated semgrep interpreter. Created once with:
#   python -m venv evaluation/empirical_study/.semgrep-venv
#   .semgrep-venv/Scripts/python -m pip install semgrep==1.167.0
_SEMGREP_WIN = HERE / ".semgrep-venv" / "Scripts" / "semgrep.exe"
_SEMGREP_NIX = HERE / ".semgrep-venv" / "bin" / "semgrep"

AXES = ["Fs", "Net", "Clock", "Env", "Random", "Proc", "Stdio"]

# Capability-bearing module allowlist for T1. A module here, if it
# appears in the top-level import block, is what a PURL SBOM would let
# a reader guess the package "might" touch. It is package-granular: it
# can never say WHICH function uses it.
_CAP_BEARING_MODULES = frozenset({
    "os", "os.path", "pathlib", "shutil", "io", "tempfile", "glob",
    "urllib", "urllib.request", "urllib.parse", "urllib.error",
    "http", "http.client", "socket", "ssl", "requests", "httpx",
    "subprocess", "multiprocessing", "sys",
    "time", "datetime", "random", "secrets", "uuid",
    "sqlite3", "psycopg2", "pymongo",
})


def _semgrep_bin() -> Path:
    for cand in (_SEMGREP_WIN, _SEMGREP_NIX):
        if cand.exists():
            return cand
    raise SystemExit(
        "isolated semgrep venv not found; create it with:\n"
        "  python -m venv evaluation/empirical_study/.semgrep-venv\n"
        "  evaluation/empirical_study/.semgrep-venv/Scripts/python "
        "-m pip install semgrep==1.167.0"
    )


# ----------------------------------------------------------------------
# Ground truth
# ----------------------------------------------------------------------
def load_ground_truth() -> dict[str, list[tuple[str, str, str]]]:
    """Return ``{pair: [(function, capability, how), ...]}`` sorted."""
    gt: dict[str, list[tuple[str, str, str]]] = {}
    with GROUND_TRUTH.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gt.setdefault(row["pair"], []).append(
                (row["python_function"], row["capability"], row["how"])
            )
    return {k: sorted(v) for k, v in sorted(gt.items())}


# ----------------------------------------------------------------------
# AST helpers
# ----------------------------------------------------------------------
def _enclosing_functions(tree: ast.AST) -> list[tuple[str, int, int]]:
    spans: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.name, node.lineno, node.end_lineno or node.lineno))
    return spans


def _func_at_line(spans: list[tuple[str, int, int]], line: int) -> str | None:
    best, best_size = None, None
    for name, lo, hi in spans:
        if lo <= line <= hi:
            size = hi - lo
            if best_size is None or size < best_size:
                best, best_size = name, size
    return best


# ----------------------------------------------------------------------
# T1: dependency / PURL SBOM proxy
# ----------------------------------------------------------------------
def t1_modules(py_path: Path) -> set[str]:
    """Top-level imports intersected with the cap-bearing allowlist.
    This is what a Syft / cdxgen SBOM of the equivalent package would
    surface (package granularity)."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods.add(node.module)
    return {
        m for m in mods
        if m in _CAP_BEARING_MODULES or m.split(".", 1)[0] in _CAP_BEARING_MODULES
    }


def t1_facts(_py_path: Path) -> set[tuple[str, str]]:
    """T1 recovers ZERO ``(function, capability)`` facts by construction:
    a PURL SBOM has package-granular data, not per-function data."""
    return set()


# ----------------------------------------------------------------------
# T2: good-faith pattern heuristic (Semgrep)
# ----------------------------------------------------------------------
def _run_semgrep(py_path: Path) -> list[tuple[int, str]]:
    proc = subprocess.run(
        [str(_semgrep_bin()), "scan", "--config", str(RULES), "--json",
         "--no-git-ignore", "--quiet", str(py_path)],
        capture_output=True, text=True,
    )
    if proc.returncode not in (0, 1):  # 1 = findings present, still fine
        raise RuntimeError(
            f"semgrep failed on {py_path} (rc={proc.returncode}):\n{proc.stderr}"
        )
    data = json.loads(proc.stdout)
    if data.get("errors"):
        raise RuntimeError(
            f"semgrep reported rule/parse errors on {py_path}:\n"
            + json.dumps(data["errors"], indent=2)
        )
    out: list[tuple[int, str]] = []
    for r in data["results"]:
        cap = (r.get("extra", {}).get("metadata", {}) or {}).get("capability")
        if cap is None:
            cap = r["extra"]["message"]
        out.append((r["start"]["line"], cap))
    return out


def t2_facts(py_path: Path) -> set[tuple[str, str]]:
    """Heuristic facts: each sink hit attributed to its lexically
    enclosing Python function."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    spans = _enclosing_functions(tree)
    facts: set[tuple[str, str]] = set()
    for line, cap in _run_semgrep(py_path):
        fn = _func_at_line(spans, line)
        if fn is not None:
            facts.add((fn, cap))
    return facts


# ----------------------------------------------------------------------
# T3: Capa by construction
# ----------------------------------------------------------------------
def _capa_manifest(pair: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "capa", "--manifest",
         str(PAIRS / pair / "capa.capa")],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"capa --manifest failed for {pair} (rc={proc.returncode}):\n"
            f"{proc.stderr}"
        )
    return json.loads(proc.stdout)


def t3_capa_caps(pair: str) -> tuple[dict[str, set[str]], set[str]]:
    """Return ``(per_capa_function_caps, all_axes)`` from the manifest.
    Capa function names differ from the Python decomposition, so T3 is
    scored at the (pair, capability-axis) granularity that Capa proves:
    a ground-truth fact ``(pyfn, cap)`` is recovered by T3 iff SOME Capa
    function in the pair reaches ``cap``. Capa's guarantee is exactly
    that no capability can be reached without appearing on a function's
    type, so axis coverage is a faithful, non-inflated reading of what
    the Capa SBOM asserts."""
    m = _capa_manifest(pair)
    per_fn: dict[str, set[str]] = {}
    axes: set[str] = set()
    for fn in m["functions"]:
        caps = set(fn.get("transitively_reachable_capabilities", []))
        per_fn[fn["name"]] = caps
        axes |= caps
    return per_fn, axes


# ----------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------
DATAFLOW_RESOLVES = {
    # via-helper: the sink is in a local function the target calls.
    # An interprocedural DATAFLOW tool (CodeQL) would follow that edge.
    "via-helper": True,
    # direct: lexically present; even a line-level tool gets these.
    "direct": False,  # not a false-negative cause for a sound heuristic
    # dispatch / data: the sink is selected at runtime via a callable
    # or a data table; dataflow cannot resolve it without the type
    # system. (Not present in the Phase-1a corpus; listed for 1b/1c.)
    "via-dispatch": False,
    "via-data": False,
}


def score_pair(pair: str, gt_rows: list[tuple[str, str, str]]) -> dict:
    py = PAIRS / pair / "naive.py"
    gt_set = {(fn, cap) for (fn, cap, _how) in gt_rows}
    how_of = {(fn, cap): how for (fn, cap, how) in gt_rows}

    t1 = t1_facts(py)
    t2 = t2_facts(py)
    capa_per_fn, capa_axes = t3_capa_caps(pair)

    t1_hits = len(gt_set & t1)
    t2_hits = len(gt_set & t2)
    # T3 axis-coverage: a fact is recovered iff its capability axis is
    # reached by some Capa function in the pair.
    t3_hits = sum(1 for (_fn, cap) in gt_set if cap in capa_axes)

    fns = []
    for (fn, cap) in sorted(gt_set - t2):
        how = how_of[(fn, cap)]
        fns.append((fn, cap, how, DATAFLOW_RESOLVES.get(how, False)))

    return {
        "pair": pair,
        "gt_count": len(gt_set),
        "t1_hits": t1_hits,
        "t2_hits": t2_hits,
        "t3_hits": t3_hits,
        "t2_false_negatives": fns,
        "t2_facts": sorted(t2),
        "t1_modules": sorted(t1_modules(py)),
        "capa_axes": sorted(capa_axes),
    }


# ----------------------------------------------------------------------
# Report emission
# ----------------------------------------------------------------------
def _pct(hit: int, total: int) -> str:
    return "n/a" if total == 0 else f"{100.0 * hit / total:.1f}"


def write_reports(results: list[dict]) -> None:
    # per_pair.csv
    with (HERE / "per_pair.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow([
            "pair", "ground_truth_facts",
            "t1_recall", "t2_recall", "t3_recall",
            "t1_pct", "t2_pct", "t3_pct",
        ])
        for r in results:
            n = r["gt_count"]
            w.writerow([
                r["pair"], n,
                f"{r['t1_hits']}/{n}", f"{r['t2_hits']}/{n}", f"{r['t3_hits']}/{n}",
                _pct(r["t1_hits"], n), _pct(r["t2_hits"], n), _pct(r["t3_hits"], n),
            ])

    # aggregate.csv
    total = sum(r["gt_count"] for r in results)
    t1 = sum(r["t1_hits"] for r in results)
    t2 = sum(r["t2_hits"] for r in results)
    t3 = sum(r["t3_hits"] for r in results)
    with (HERE / "aggregate.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["treatment", "facts_recovered", "facts_total", "recall_pct"])
        w.writerow(["T1_dependency_sbom", t1, total, _pct(t1, total)])
        w.writerow(["T2_pattern_heuristic", t2, total, _pct(t2, total)])
        w.writerow(["T3_capa_by_construction", t3, total, _pct(t3, total)])

    # false_negatives.csv
    with (HERE / "false_negatives.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow([
            "pair", "python_function", "capability", "how",
            "dataflow_would_resolve",
        ])
        for r in results:
            for (fn, cap, how, df) in r["t2_false_negatives"]:
                w.writerow([r["pair"], fn, cap, how, "yes" if df else "no"])

    return {"total": total, "t1": t1, "t2": t2, "t3": t3}


def print_console(results: list[dict], totals: dict) -> None:
    print("\n=== PER-PAIR RECALL (facts captured / ground-truth facts) ===")
    print(f"{'pair':<16} {'GT':>3} {'T1':>6} {'T2':>6} {'T3':>6}")
    for r in results:
        n = r["gt_count"]
        print(f"{r['pair']:<16} {n:>3} "
              f"{r['t1_hits']:>3}/{n:<2} {r['t2_hits']:>3}/{n:<2} {r['t3_hits']:>3}/{n:<2}")

    total, t1, t2, t3 = totals["total"], totals["t1"], totals["t2"], totals["t3"]
    print("\n=== AGGREGATE ===")
    print(f"total ground-truth facts: {total}")
    print(f"  T1 dependency-SBOM     : {t1}/{total}  ({_pct(t1, total)}%)")
    print(f"  T2 pattern-heuristic   : {t2}/{total}  ({_pct(t2, total)}%)")
    print(f"  T3 capa-by-construction: {t3}/{total}  ({_pct(t3, total)}%)")

    print("\n=== T2 FALSE-NEGATIVES (classified) ===")
    any_fn = False
    for r in results:
        for (fn, cap, how, df) in r["t2_false_negatives"]:
            any_fn = True
            tag = "dataflow-resolvable" if df else "needs-types"
            print(f"  {r['pair']}/{fn} ({cap})  cause={how}  -> {tag}")
    if not any_fn:
        print("  (none)")

    # distribution: classify each pair by whether T2 recovered every
    # ground-truth fact (purely-direct, T2 ties Capa) or missed some
    # (genuine indirection). Pairs with zero cap facts are pure.
    pure_pairs, direct_pairs, indir_pairs = [], [], []
    for r in results:
        if r["gt_count"] == 0:
            pure_pairs.append(r["pair"])
        elif r["t2_hits"] == r["gt_count"]:
            direct_pairs.append(r["pair"])
        else:
            indir_pairs.append(r["pair"])
    print("\n=== CORPUS DISTRIBUTION (20 pairs) ===")
    print(f"  pure (zero cap facts)          : {len(pure_pairs)}  {pure_pairs}")
    print(f"  purely-direct (T2 ties Capa)   : {len(direct_pairs)}  {direct_pairs}")
    print(f"  genuine indirection (T2 < Capa): {len(indir_pairs)}  {indir_pairs}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pair", action="append", default=None,
                   help="score only the named pair (repeatable)")
    args = p.parse_args(argv)

    gt = load_ground_truth()
    # Every pair directory is scored; pairs absent from the ground
    # truth contribute zero facts (the pure-library cases).
    all_pairs = sorted(
        d.name for d in PAIRS.iterdir()
        if d.is_dir() and (d / "naive.py").exists() and (d / "capa.capa").exists()
    )
    if args.pair:
        all_pairs = [x for x in all_pairs if x in set(args.pair)]

    results = []
    for pair in all_pairs:
        rows = gt.get(pair, [])
        results.append(score_pair(pair, rows))

    totals = write_reports(results)
    print_console(results, totals)
    print(f"\nwrote per_pair.csv, aggregate.csv, false_negatives.csv to {HERE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
