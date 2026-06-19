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
        assert set(r) == {"pair", "python_function", "capability", "how"}
        assert r["capability"] in valid_caps, r
        assert r["how"] in valid_how, r


def test_ground_truth_facts_reference_real_functions():
    """Every (pair, python_function) in the ground truth must name a
    function that actually exists in that pair's naive.py."""
    gt = rs.load_ground_truth()
    for pair, rows in gt.items():
        py = rs.PAIRS / pair / "naive.py"
        assert py.exists(), f"missing naive.py for {pair}"
        names = {
            n.name for n in ast.walk(ast.parse(py.read_text(encoding="utf-8")))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for (fn, _cap, _how) in rows:
            assert fn in names, f"{pair}: ground-truth names unknown fn {fn!r}"


def test_ground_truth_facts_are_unique():
    gt = rs.load_ground_truth()
    for pair, rows in gt.items():
        keys = [(fn, cap) for (fn, cap, _how) in rows]
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
def test_score_pair_arithmetic(monkeypatch):
    gt_rows = [
        ("f", "Fs", "direct"),
        ("g", "Net", "via-helper"),
    ]
    # Stub out the subprocess-backed pieces.
    monkeypatch.setattr(rs, "t2_facts", lambda _py: {("f", "Fs")})
    monkeypatch.setattr(rs, "t1_modules", lambda _py: {"os"})
    monkeypatch.setattr(
        rs, "t3_capa_caps",
        lambda _pair: ({"f": {"Fs"}, "g": {"Net"}}, {"Fs", "Net"}),
    )
    r = rs.score_pair("config_loader", gt_rows)
    assert r["gt_count"] == 2
    assert r["t1_hits"] == 0          # never per-function
    assert r["t2_hits"] == 1          # only the direct fact
    assert r["t3_hits"] == 2          # both axes covered
    # the via-helper miss is classified as dataflow-resolvable
    assert r["t2_false_negatives"] == [("g", "Net", "via-helper", True)]


def test_dataflow_classification_table():
    assert rs.DATAFLOW_RESOLVES["via-helper"] is True
    assert rs.DATAFLOW_RESOLVES["via-dispatch"] is False
    assert rs.DATAFLOW_RESOLVES["via-data"] is False
