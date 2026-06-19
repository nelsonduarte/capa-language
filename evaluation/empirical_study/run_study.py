"""Capability-recall study harness (Phases 1a + 1b).

Scores three treatments over two corpora: the Phase-1a
``evaluation/sbom_diff`` pairs (direct and via-helper calls) and the
Phase-1b ``dispatch_pairs`` directory beside this file (via-dispatch
and via-data indirection, where the sink is selected at runtime through
a callable or a data table). The unit is a single
``(python_function, capability)`` fact, authored in ``ground_truth.csv``
(see that file's ``how`` column and the README for how it was derived
and validated).

Two distinct questions, ONE criterion each
------------------------------------------
The study asks two SEPARATE questions and scores all treatments by the
SAME criterion within each. They are never collapsed into one column,
because a treatment can do well on one and badly on the other.

Q1  Positive-attribution recall : does the treatment attribute
    capability C to the NAMED function F that exercises it? Identical
    criterion for all three: C appears in the treatment's output FOR F
    (not merely somewhere in the pair). This is a MODEST measure. On it
    Capa does NOT dramatically beat a good-faith heuristic: Capa is
    sound, not omniscient. It honestly does not resolve which handler a
    dispatcher will run, so it does not positively attribute the
    handler's authority to the dispatcher.

Q2  False-clearance under closed-world SBOM semantics : under the
    semantics of an SBOM (a CLOSED list: what is not listed for a
    function is implicitly EXCLUDED), a treatment commits a
    false-clearance for a true fact ``(F, C)`` if it gives the consumer
    no way to know F can exercise C. This is the HEADLINE and the real
    argument for Capa. Operational definition per treatment is in
    ``false_clearance`` below.

Treatments
----------
T1  dependency / PURL SBOM       : module-level imports of the naive
    Python, intersected with a capability-bearing-module allowlist.
    This is the granularity a Syft / cdxgen SBOM reports. It produces
    package-level facts, never ``(function, capability)`` facts, so its
    per-function Q1 recall is 0 BY CONSTRUCTION, and under closed-world
    semantics it false-clears EVERY per-function fact (it cannot
    distinguish functions at all). That is the point about GRANULARITY.
T2  good-faith pattern heuristic : the Semgrep ruleset in
    ``rules/capability_rules.yaml`` maps sink APIs to capability axes at
    the call site, attributed to the lexically-enclosing Python
    function via ``ast``. It captures every DIRECT sink call (so its Q1
    is strong) but cannot see authority reached only through a local
    helper / dispatch / data; for those facts it has no detection, and
    under closed-world reading ABSENCE is exclusion, so it false-clears
    exactly the facts it misses.
T3  Capa by construction         : the per-function capability manifest
    emitted by ``python -m capa --manifest``. The manifest gives each
    function THREE states per axis C: reachable (positively attributed),
    provably-excluded (sound exclusion, proved in Agda), or
    not-determined. For Q1, C is attributed to F iff C is in F's
    ``transitively_reachable_capabilities``. For Q2, Capa false-clears
    ``(F, C)`` ONLY if C is in F's ``provably_excluded_capabilities``
    while F truly exercises C -- which never happens, because
    provably-excluded is sound (used capabilities are a subset of
    declared, and used intersect provably-excluded is empty). On the
    dispatchers Capa reports NEITHER reachable NOR provably-excluded for
    the handler axes: not-determined, never a false clearance. So Capa
    ties the heuristic on Q1 but commits ZERO false-clearances on Q2.

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
``per_pair.csv``   one row per pair: ground-truth count + both Q1
                   (positive attribution) and Q2 (false-clearance)
                   columns for T1/T2/T3.
``aggregate.csv``  totals for BOTH questions per treatment.
``false_negatives.csv`` every fact each treatment fails to attribute
                   (Q1 miss) and whether that miss is a closed-world
                   false-clearance (Q2), with the ``how`` cause and a
                   ``dataflow_would_resolve`` classification.

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
# Two corpus roots are scored together. ``sbom_diff`` is the Phase-1a
# corpus of direct / via-helper pairs; ``dispatch_pairs`` is the
# Phase-1b corpus of via-dispatch / via-data indirection pairs (the
# sink is selected at runtime through a callable or a data table).
# A pair name is resolved to its root by ``pair_dir`` below; the
# harness is otherwise agnostic to which corpus a pair came from.
PAIRS = ROOT / "evaluation" / "sbom_diff"
DISPATCH_PAIRS = HERE / "dispatch_pairs"
CORPORA = (PAIRS, DISPATCH_PAIRS)
RULES = HERE / "rules" / "capability_rules.yaml"
GROUND_TRUTH = HERE / "ground_truth.csv"


def pair_dir(pair: str) -> Path:
    """Resolve a pair name to its directory across both corpus roots.

    A pair lives under exactly one root; the dispatch_pairs root is
    checked first so a name collision (none today) would prefer the
    Phase-1b corpus. Falls back to the sbom_diff root so an unknown
    name still yields a stable, inspectable path in error messages."""
    for root in (DISPATCH_PAIRS, PAIRS):
        if (root / pair).is_dir():
            return root / pair
    return PAIRS / pair

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
def load_ground_truth() -> dict[str, list[tuple[str, str, str, str]]]:
    """Return ``{pair: [(python_function, capa_function, capability, how), ...]}``.

    ``capa_function`` is the name of the Capa-side function that plays
    the SAME role as ``python_function``. Most names coincide; where the
    faithful ``.capa`` transliteration renamed a function (e.g. the
    Python ``_fetch`` handler is ``fetch_handler`` in Capa, or
    ``load_config`` is the orchestrator ``load_full_config``), the
    mapping is recorded EXPLICITLY in this column so the Python<->Capa
    correspondence for Q1 per-function attribution is auditable rather
    than guessed. The dispatcher functions keep the same name on both
    sides (``dispatch``, ``emit``, ``run_action``, ``run_pipeline``)."""
    gt: dict[str, list[tuple[str, str, str, str]]] = {}
    with GROUND_TRUTH.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gt.setdefault(row["pair"], []).append(
                (row["python_function"], row["capa_function"],
                 row["capability"], row["how"])
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
         str(pair_dir(pair) / "capa.capa")],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"capa --manifest failed for {pair} (rc={proc.returncode}):\n"
            f"{proc.stderr}"
        )
    return json.loads(proc.stdout)


def t3_capa_caps(
    pair: str,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return ``(reachable_per_fn, provably_excluded_per_fn)`` from the
    manifest, keyed by Capa function name.

    Both maps are scored PER NAMED FUNCTION (matched to the Python
    ground-truth via the ``capa_function`` column), never collapsed to
    pair-level axis coverage. ``reachable_per_fn`` answers Q1 (positive
    attribution). ``provably_excluded_per_fn`` answers Q2: Capa
    false-clears a true fact ``(F, C)`` only if ``C`` is in F's
    provably-excluded set, which is sound and therefore never happens
    for a fact the function really exercises."""
    m = _capa_manifest(pair)
    reachable: dict[str, set[str]] = {}
    excluded: dict[str, set[str]] = {}
    for fn in m["functions"]:
        reachable[fn["name"]] = set(
            fn.get("transitively_reachable_capabilities", [])
        )
        excluded[fn["name"]] = set(
            fn.get("provably_excluded_capabilities", [])
        )
    return reachable, excluded


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
    # or a data table; interprocedural dataflow cannot resolve it in
    # general without the type system. This is the conservative
    # CLASS-level default. A specific pair can sit anywhere on the
    # spectrum (a constant function table is points-to-resolvable; a
    # name from external input is not) -- that per-pair CodeQL
    # expectation is recorded in each Phase-1b pair's README and will
    # be confirmed empirically in Phase 1c via the ``t2b_codeql`` slot.
    "via-dispatch": False,
    "via-data": False,
}


def score_pair(pair: str, gt_rows: list[tuple[str, str, str, str]]) -> dict:
    py = pair_dir(pair) / "naive.py"
    # Each ground-truth fact carries the Python function (what T1/T2 see)
    # and the Capa function that plays the same role (what T3 is scored
    # against). The pair is the (python_function, capability) key.
    gt_set = {(pyfn, cap) for (pyfn, _cf, cap, _how) in gt_rows}
    capa_fn_of = {(pyfn, cap): cf for (pyfn, cf, cap, _how) in gt_rows}
    how_of = {(pyfn, cap): how for (pyfn, _cf, cap, how) in gt_rows}

    t1 = t1_facts(py)
    t2 = t2_facts(py)
    capa_reach, capa_excl = t3_capa_caps(pair)

    # ---- Q1: positive-attribution recall (same criterion per treatment)
    # The capability is attributed to the NAMED function. For T3 the
    # named function is the Capa-side name from the ground truth; the
    # fact is attributed iff that Capa function reaches the axis.
    q1_t1 = len(gt_set & t1)  # 0 by construction (no per-function facts)
    q1_t2 = len(gt_set & t2)
    q1_t3 = sum(
        1 for (pyfn, cap) in gt_set
        if cap in capa_reach.get(capa_fn_of[(pyfn, cap)], set())
    )

    # ---- Q2: false-clearances under closed-world SBOM semantics.
    # T1: no per-function granularity, so it false-clears EVERY fact.
    # T2: absence is implicit exclusion, so it false-clears exactly the
    #     facts it fails to attribute (the Q1 misses).
    # T3: false-clears (F, C) only if C is provably-excluded for F while
    #     F truly exercises C. provably-excluded is sound, so this is
    #     always 0; we COMPUTE it from the manifest rather than assert it.
    fc_t1 = len(gt_set)
    fc_t2 = len(gt_set - t2)
    fc_t3 = sum(
        1 for (pyfn, cap) in gt_set
        if cap in capa_excl.get(capa_fn_of[(pyfn, cap)], set())
    )

    # Per-fact attribution / clearance detail, sorted for determinism.
    detail = []
    for (pyfn, cap) in sorted(gt_set):
        how = how_of[(pyfn, cap)]
        cf = capa_fn_of[(pyfn, cap)]
        t2_attr = (pyfn, cap) in t2
        t3_attr = cap in capa_reach.get(cf, set())
        t3_fc = cap in capa_excl.get(cf, set())
        # ``dataflow_would_resolve`` is the conservative class-level
        # expectation (via-helper: yes; via-dispatch / via-data: no).
        # ``t2b_codeql`` is the slot for the LITERAL CodeQL verdict,
        # filled in Phase 1c by an actual run; "pending" until then.
        detail.append({
            "python_function": pyfn,
            "capa_function": cf,
            "capability": cap,
            "how": how,
            "t2_attr": t2_attr,
            "t3_attr": t3_attr,
            "t2_false_clear": not t2_attr,
            "t3_false_clear": t3_fc,
            "dataflow_would_resolve": DATAFLOW_RESOLVES.get(how, False),
            "t2b_codeql": "pending",
        })

    return {
        "pair": pair,
        "gt_count": len(gt_set),
        "q1_t1": q1_t1, "q1_t2": q1_t2, "q1_t3": q1_t3,
        "fc_t1": fc_t1, "fc_t2": fc_t2, "fc_t3": fc_t3,
        "detail": detail,
        "t2_facts": sorted(t2),
        "t1_modules": sorted(t1_modules(py)),
    }


# ----------------------------------------------------------------------
# Report emission
# ----------------------------------------------------------------------
def _pct(hit: int, total: int) -> str:
    return "n/a" if total == 0 else f"{100.0 * hit / total:.1f}"


def write_reports(results: list[dict]) -> dict:
    # per_pair.csv -- BOTH questions side by side, never merged.
    with (HERE / "per_pair.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow([
            "pair", "ground_truth_facts",
            # Q1: positive-attribution recall (attributed to the function)
            "q1_t1_attr", "q1_t2_attr", "q1_t3_attr",
            # Q2: closed-world false-clearances (lower is better)
            "q2_t1_falseclear", "q2_t2_falseclear", "q2_t3_falseclear",
        ])
        for r in results:
            n = r["gt_count"]
            w.writerow([
                r["pair"], n,
                f"{r['q1_t1']}/{n}", f"{r['q1_t2']}/{n}", f"{r['q1_t3']}/{n}",
                f"{r['fc_t1']}/{n}", f"{r['fc_t2']}/{n}", f"{r['fc_t3']}/{n}",
            ])

    total = sum(r["gt_count"] for r in results)
    agg = {
        "total": total,
        "q1_t1": sum(r["q1_t1"] for r in results),
        "q1_t2": sum(r["q1_t2"] for r in results),
        "q1_t3": sum(r["q1_t3"] for r in results),
        "fc_t1": sum(r["fc_t1"] for r in results),
        "fc_t2": sum(r["fc_t2"] for r in results),
        "fc_t3": sum(r["fc_t3"] for r in results),
    }

    # aggregate.csv -- one row per (question, treatment), so a reader
    # can never mistake a Q1 number for a Q2 number.
    with (HERE / "aggregate.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["question", "treatment", "count", "facts_total", "pct"])
        w.writerow(["Q1_positive_attribution", "T1_dependency_sbom",
                    agg["q1_t1"], total, _pct(agg["q1_t1"], total)])
        w.writerow(["Q1_positive_attribution", "T2_pattern_heuristic",
                    agg["q1_t2"], total, _pct(agg["q1_t2"], total)])
        w.writerow(["Q1_positive_attribution", "T2b_codeql",
                    "pending", total, "pending"])
        w.writerow(["Q1_positive_attribution", "T3_capa_by_construction",
                    agg["q1_t3"], total, _pct(agg["q1_t3"], total)])
        w.writerow(["Q2_false_clearance", "T1_dependency_sbom",
                    agg["fc_t1"], total, _pct(agg["fc_t1"], total)])
        w.writerow(["Q2_false_clearance", "T2_pattern_heuristic",
                    agg["fc_t2"], total, _pct(agg["fc_t2"], total)])
        w.writerow(["Q2_false_clearance", "T2b_codeql",
                    "pending", total, "pending"])
        w.writerow(["Q2_false_clearance", "T3_capa_by_construction",
                    agg["fc_t3"], total, _pct(agg["fc_t3"], total)])

    # false_negatives.csv -- every fact, with per-treatment attribution
    # and the closed-world false-clearance verdict for T2 and T3.
    with (HERE / "false_negatives.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow([
            "pair", "python_function", "capa_function", "capability", "how",
            "t2_attributes", "t3_attributes",
            "t2_false_clears", "t3_false_clears",
            "dataflow_would_resolve", "t2b_codeql",
        ])
        for r in results:
            for d in r["detail"]:
                # Only emit rows where some treatment fails to attribute,
                # i.e. the facts that distinguish the treatments.
                if d["t2_attr"] and d["t3_attr"]:
                    continue
                w.writerow([
                    r["pair"], d["python_function"], d["capa_function"],
                    d["capability"], d["how"],
                    "yes" if d["t2_attr"] else "no",
                    "yes" if d["t3_attr"] else "no",
                    "yes" if d["t2_false_clear"] else "no",
                    "yes" if d["t3_false_clear"] else "no",
                    "yes" if d["dataflow_would_resolve"] else "no",
                    d["t2b_codeql"],
                ])

    return agg


def print_console(results: list[dict], agg: dict) -> None:
    total = agg["total"]

    print("\n=== Q1: POSITIVE-ATTRIBUTION RECALL "
          "(capability attributed to the named function) ===")
    print(f"{'pair':<16} {'GT':>3} {'T1':>6} {'T2':>6} {'T3':>6}")
    for r in results:
        n = r["gt_count"]
        print(f"{r['pair']:<16} {n:>3} "
              f"{r['q1_t1']:>3}/{n:<2} {r['q1_t2']:>3}/{n:<2} {r['q1_t3']:>3}/{n:<2}")
    print(f"  T1 dependency-SBOM     : {agg['q1_t1']}/{total}  "
          f"({_pct(agg['q1_t1'], total)}%)")
    print(f"  T2 pattern-heuristic   : {agg['q1_t2']}/{total}  "
          f"({_pct(agg['q1_t2'], total)}%)")
    print(f"  T3 capa-by-construction: {agg['q1_t3']}/{total}  "
          f"({_pct(agg['q1_t3'], total)}%)")
    print("  NOTE: on positive attribution Capa does NOT dramatically "
          "beat the good-faith heuristic; it is sound, not omniscient, "
          "and does not vouch which handler a dispatcher runs.")

    print("\n=== Q2: FALSE-CLEARANCES UNDER CLOSED-WORLD SBOM SEMANTICS "
          "(lower is better) ===")
    print(f"{'pair':<16} {'GT':>3} {'T1':>6} {'T2':>6} {'T3':>6}")
    for r in results:
        n = r["gt_count"]
        print(f"{r['pair']:<16} {n:>3} "
              f"{r['fc_t1']:>3}/{n:<2} {r['fc_t2']:>3}/{n:<2} {r['fc_t3']:>3}/{n:<2}")
    print(f"  T1 dependency-SBOM     : {agg['fc_t1']}/{total} false-cleared")
    print(f"  T2 pattern-heuristic   : {agg['fc_t2']}/{total} false-cleared")
    print(f"  T3 capa-by-construction: {agg['fc_t3']}/{total} false-cleared")
    print("  HEADLINE: Capa commits ZERO false-clearances by construction "
          "(provably-excluded is sound); the heuristic false-clears every "
          "fact it cannot see.")

    print("\n=== DISTINGUISHING FACTS (T2 or T3 fails to attribute) ===")
    any_row = False
    for r in results:
        for d in r["detail"]:
            if d["t2_attr"] and d["t3_attr"]:
                continue
            any_row = True
            tag = "dataflow-resolvable" if d["dataflow_would_resolve"] else "needs-types"
            print(f"  {r['pair']}/{d['python_function']} ({d['capability']})"
                  f"  cause={d['how']}  "
                  f"T2attr={'y' if d['t2_attr'] else 'n'} "
                  f"T3attr={'y' if d['t3_attr'] else 'n'} "
                  f"T2fc={'y' if d['t2_false_clear'] else 'n'} "
                  f"T3fc={'y' if d['t3_false_clear'] else 'n'}  -> {tag}")
    if not any_row:
        print("  (none)")

    # distribution: classify each pair by whether T2 attributed every
    # ground-truth fact (purely-direct, T2 ties Capa on Q1) or missed
    # some (genuine indirection). Pairs with zero cap facts are pure.
    pure_pairs, direct_pairs, indir_pairs = [], [], []
    for r in results:
        if r["gt_count"] == 0:
            pure_pairs.append(r["pair"])
        elif r["q1_t2"] == r["gt_count"]:
            direct_pairs.append(r["pair"])
        else:
            indir_pairs.append(r["pair"])
    print(f"\n=== CORPUS DISTRIBUTION ({len(results)} pairs) ===")
    print(f"  pure (zero cap facts)          : {len(pure_pairs)}  {pure_pairs}")
    print(f"  purely-direct (T2 ties Capa)   : {len(direct_pairs)}  {direct_pairs}")
    print(f"  genuine indirection (T2 misses): {len(indir_pairs)}  {indir_pairs}")

    # Split the indirection by cause so the spectrum is visible: a
    # via-helper miss is dataflow-resolvable, a via-dispatch / via-data
    # miss needs the type system. This is the Phase-1b headline.
    helper, dispatch_data = [], []
    for r in results:
        causes = {
            d["how"] for d in r["detail"] if not d["t2_attr"]
        }
        if causes & {"via-dispatch", "via-data"}:
            dispatch_data.append(r["pair"])
        elif "via-helper" in causes:
            helper.append(r["pair"])
    print("  -- of the indirection pairs:")
    print(f"     via-helper (dataflow resolves)        : {len(helper)}  {helper}")
    print(f"     via-dispatch/via-data (needs types)   : {len(dispatch_data)}  {dispatch_data}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pair", action="append", default=None,
                   help="score only the named pair (repeatable)")
    args = p.parse_args(argv)

    gt = load_ground_truth()
    # Every pair directory across both corpus roots is scored; pairs
    # absent from the ground truth contribute zero facts (the
    # pure-library cases). Names are unique across the two roots.
    all_pairs = sorted(
        d.name
        for root in CORPORA
        for d in root.iterdir()
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
