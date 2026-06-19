"""Deterministic unit tests for the capability-recall harness.

These tests cover the pure pieces of the harness (ground-truth
loading, AST function attribution, T1 import extraction, scoring
arithmetic, false-negative classification). They do NOT spawn semgrep
or capa, so they run in any environment, including CI, without the
isolated semgrep venv or a Capa toolchain.

The end-to-end run (T2 via semgrep, T3 via capa) is exercised
separately by invoking ``run_study.py`` directly; see the README.
"""

from __future__ import annotations

import ast
import csv
from pathlib import Path

import run_study as rs

HERE = Path(__file__).resolve().parent


# ----------------------------------------------------------------------
# ground_truth.csv integrity
# ----------------------------------------------------------------------
def test_ground_truth_columns_and_vocabulary():
    valid_caps = set(rs.AXES)
    valid_how = {"direct", "via-helper", "via-dispatch", "via-data"}
    with (HERE / "ground_truth.csv").open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows, "ground_truth.csv must not be empty"
    for r in rows:
        assert set(r) == {
            "pair", "python_function", "capa_function", "capability", "how"
        }
        assert r["capability"] in valid_caps, r
        assert r["how"] in valid_how, r
        assert r["capa_function"], r  # explicit Python<->Capa mapping


def test_ground_truth_facts_reference_real_functions():
    """Every (pair, python_function) in the ground truth must name a
    function that actually exists in that pair's naive.py."""
    gt = rs.load_ground_truth()
    for pair, rows in gt.items():
        py = rs.pair_dir(pair) / "naive.py"
        assert py.exists(), f"missing naive.py for {pair}"
        names = {
            n.name for n in ast.walk(ast.parse(py.read_text(encoding="utf-8")))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for (fn, _cf, _cap, _how) in rows:
            assert fn in names, f"{pair}: ground-truth names unknown fn {fn!r}"


def test_ground_truth_facts_are_unique():
    gt = rs.load_ground_truth()
    for pair, rows in gt.items():
        keys = [(fn, cap) for (fn, _cf, cap, _how) in rows]
        assert len(keys) == len(set(keys)), f"duplicate fact in {pair}"


# ----------------------------------------------------------------------
# AST attribution
# ----------------------------------------------------------------------
SAMPLE = """
import os

def helper():
    return os.walk('.')

def outer():
    x = helper()
    print(x)
"""


def test_func_at_line_picks_innermost():
    tree = ast.parse(SAMPLE)
    spans = rs._enclosing_functions(tree)
    # the os.walk line is inside helper
    walk_line = next(
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "walk"
    )
    assert rs._func_at_line(spans, walk_line) == "helper"


def test_t1_extracts_cap_bearing_imports(tmp_path):
    p = tmp_path / "naive.py"
    p.write_text(SAMPLE, encoding="utf-8")
    assert rs.t1_modules(p) == {"os"}
    # T1 never yields per-function facts.
    assert rs.t1_facts(p) == set()


# ----------------------------------------------------------------------
# Scoring arithmetic + classification (no subprocesses)
# ----------------------------------------------------------------------
def test_q1_positive_attribution_is_per_function(monkeypatch):
    """Q1 scores every treatment by the SAME criterion: the capability
    is attributed to the NAMED function. T3 is scored against the Capa
    function's own reachable set, NOT pair-level axis coverage. Here the
    Capa-side ``g`` does NOT reach Net, so T3 must NOT credit it -- this
    is the asymmetry the Phase-1b honesty fix removed."""
    #            python_fn, capa_fn, capability, how
    gt_rows = [
        ("f", "f", "Fs", "direct"),
        ("g", "g", "Net", "via-helper"),
    ]
    monkeypatch.setattr(rs, "t2_facts", lambda _py: {("f", "Fs")})
    monkeypatch.setattr(rs, "t1_modules", lambda _py: {"os"})
    # Capa attributes Fs to f, but NOT Net to g (g is not-determined for
    # Net even though Net is reachable elsewhere in the pair).
    monkeypatch.setattr(
        rs, "t3_capa_caps",
        lambda _pair: (
            {"f": {"Fs"}, "g": set(), "other": {"Net"}},   # reachable
            {"f": set(), "g": set(), "other": set()},       # provably-excluded
        ),
    )
    r = rs.score_pair("config_loader", gt_rows)
    assert r["gt_count"] == 2
    assert r["q1_t1"] == 0   # never per-function
    assert r["q1_t2"] == 1   # only the direct fact
    # T3 credits f (Fs reachable) but NOT g: the axis is reachable in the
    # pair, yet g does not positively attribute it. The OLD axis-coverage
    # scoring would have wrongly returned 2 here.
    assert r["q1_t3"] == 1


def test_q2_false_clearance_zero_for_capa_dispatcher(monkeypatch):
    """Q2: under closed-world semantics T2 false-clears every fact it
    misses; Capa false-clears a fact ONLY if its axis is in the named
    function's provably-excluded set. A dispatcher with reachable=[] and
    provably_excluded=[] (not-determined) commits ZERO false-clearances,
    while the heuristic false-clears it."""
    #            python_fn, capa_fn, capability, how
    gt_rows = [
        ("dispatch", "dispatch", "Net", "via-dispatch"),
        ("dispatch", "dispatch", "Fs", "via-dispatch"),
    ]
    monkeypatch.setattr(rs, "t2_facts", lambda _py: set())  # heuristic sees nothing
    monkeypatch.setattr(rs, "t1_modules", lambda _py: set())
    # The dispatcher is not-determined: neither reachable nor excluded.
    monkeypatch.setattr(
        rs, "t3_capa_caps",
        lambda _pair: ({"dispatch": set()}, {"dispatch": set()}),
    )
    r = rs.score_pair("command_registry", gt_rows)
    # Q1: neither tool attributes; Capa does not vouch the dispatcher.
    assert r["q1_t2"] == 0
    assert r["q1_t3"] == 0
    # Q2: this is the headline. T2 false-clears both (absence = exclusion
    # under closed-world reading); Capa false-clears NEITHER.
    assert r["fc_t2"] == 2
    assert r["fc_t3"] == 0
    # T1 false-clears everything (no per-function granularity at all).
    assert r["fc_t1"] == 2


def test_q2_capa_false_clears_only_when_provably_excluded(monkeypatch):
    """If (counterfactually) Capa's manifest provably-excluded an axis
    the function truly exercises, THAT would be a false-clearance and the
    metric must catch it. The soundness guarantee is what keeps this 0 in
    practice; the metric itself is honest about what it measures."""
    gt_rows = [("h", "h", "Fs", "direct")]
    monkeypatch.setattr(rs, "t2_facts", lambda _py: {("h", "Fs")})
    monkeypatch.setattr(rs, "t1_modules", lambda _py: set())
    # Deliberately broken manifest: Fs provably-excluded for h.
    monkeypatch.setattr(
        rs, "t3_capa_caps",
        lambda _pair: ({"h": set()}, {"h": {"Fs"}}),
    )
    r = rs.score_pair("config_loader", gt_rows)
    assert r["fc_t3"] == 1  # the metric DOES flag a (hypothetical) unsound clearance


def test_distinguishing_facts_carry_pending_codeql_slot(monkeypatch):
    """Every distinguishing fact (one a tool fails to attribute) carries
    a per-treatment attribution / clearance record plus a 'pending'
    CodeQL slot until Phase 1c fills it."""
    gt_rows = [
        ("d", "d", "Net", "via-dispatch"),
        ("e", "e", "Fs", "via-data"),
    ]
    monkeypatch.setattr(rs, "t2_facts", lambda _py: set())
    monkeypatch.setattr(rs, "t1_modules", lambda _py: set())
    monkeypatch.setattr(
        rs, "t3_capa_caps",
        lambda _pair: ({"d": set(), "e": set()}, {"d": set(), "e": set()}),
    )
    r = rs.score_pair("command_registry", gt_rows)
    assert r["q1_t3"] == 0   # Capa does not attribute the dispatcher axes
    assert r["q1_t2"] == 0   # neither sink is lexical
    distinguishing = [
        d for d in r["detail"] if not (d["t2_attr"] and d["t3_attr"])
    ]
    assert len(distinguishing) == 2
    for d in distinguishing:
        assert d["t2b_codeql"] == "pending"
        assert d["t2_false_clear"] is True   # closed-world: absence excludes
        assert d["t3_false_clear"] is False  # Capa: not-determined, no clearance


def test_dataflow_classification_table():
    assert rs.DATAFLOW_RESOLVES["via-helper"] is True
    assert rs.DATAFLOW_RESOLVES["via-dispatch"] is False
    assert rs.DATAFLOW_RESOLVES["via-data"] is False


# ----------------------------------------------------------------------
# Phase 1b: two-corpus resolution + dispatch/data ground truth
# ----------------------------------------------------------------------
def test_pair_dir_resolves_both_corpora():
    """A Phase-1a pair resolves under sbom_diff and a Phase-1b pair
    under dispatch_pairs; both directories carry the pair files."""
    assert rs.pair_dir("config_loader") == rs.PAIRS / "config_loader"
    assert (
        rs.pair_dir("command_registry")
        == rs.DISPATCH_PAIRS / "command_registry"
    )
    for pair in ("config_loader", "command_registry"):
        assert (rs.pair_dir(pair) / "naive.py").exists()
        assert (rs.pair_dir(pair) / "capa.capa").exists()


def test_dispatch_pairs_present_with_indirection_facts():
    """Each Phase-1b pair contributes at least one via-dispatch or
    via-data fact (the indirection the corpus exists to cover)."""
    gt = rs.load_ground_truth()
    expected = {
        "command_registry", "event_bus", "reflect_dispatch",
        "tagged_factory", "middleware_chain",
    }
    assert expected <= set(gt), "missing a Phase-1b pair from ground truth"
    for pair in expected:
        causes = {how for (_fn, _cf, _cap, how) in gt[pair]}
        assert causes & {"via-dispatch", "via-data"}, (
            f"{pair} has no via-dispatch / via-data fact"
        )
