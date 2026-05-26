"""Render ``results.csv`` into the headline Markdown table that feeds
paper §5.

Reads ``results.csv`` (output of ``harness.py``), then emits
``summary.md``: a paper-ready Markdown report containing the
per-pair table, two short interpretive subsections, the study's
"does NOT claim" caveats, and a reproducibility footer.

Unlike its sibling ``evaluation/cve/summary.py``, this script does
not emit a PNG: the SBOM-diff data is a small, dense table that
reads more clearly inline than as a chart.

Usage:
    python -m evaluation.sbom_diff.summary
    python -m evaluation.sbom_diff.summary --in PATH --out PATH
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

DEFAULT_IN = Path(__file__).parent / "results.csv"
DEFAULT_OUT = Path(__file__).parent / "summary.md"

INT_COLUMNS = ("fns_total", "fns_with_caps", "fns_pure", "per_fn_info_bits")
SET_COLUMNS = ("caps_declared", "naive_imports", "naive_cap_modules")

CAVEATS = [
    (
        "The Capa versions are hand-written. No Python-to-Capa "
        "transliteration tool exists; each pair is a faithful "
        "representation of the library's public-API capability "
        "shape, not a feature-by-feature port."
    ),
    (
        "The naive Python is illustrative. It captures the typical "
        "shape (one signature, conflated authorities) that appears "
        "in many real codebases, not the best-engineered form. "
        "Disciplined Python (dependency injection, explicit "
        "handle-passing) lacks Capa's static guarantee but narrows "
        "the gap."
    ),
    (
        "Sample size is small relative to PyPI. The corpus aims for "
        "10-20 libraries spanning the capability axes; PyPI has "
        "hundreds of thousands. The claim is about the mechanism's "
        "information gain, not statistical representativeness of "
        "all Python code."
    ),
]


def _load_csv(path: Path) -> list[dict]:
    """Read ``results.csv``, coerce integer columns, split set
    columns into sorted lists. Returns rows in CSV order."""
    if not path.exists():
        print(
            f"[summary] {path} not found; run "
            f"`python -m evaluation.sbom_diff.harness` first.",
            file=sys.stderr,
        )
        sys.exit(1)
    rows: list[dict] = []
    with path.open(encoding="utf-8", newline="") as f:
        for raw in csv.DictReader(f):
            row: dict = {"pair": raw["pair"]}
            for col in INT_COLUMNS:
                row[col] = int(raw[col])
            for col in SET_COLUMNS:
                value = raw[col].strip()
                row[col] = sorted(v for v in value.split(";") if v)
            rows.append(row)
    return rows


def _render_set(items: list[str]) -> str:
    """Render a set column for Markdown: comma-separated names, or
    italicised ``*(none)*`` when empty."""
    if not items:
        return "*(none)*"
    return ", ".join(items)


def _render_table(rows: list[dict]) -> str:
    """Render the headline per-pair Markdown table. The final row
    is bolded as the TOTAL aggregate."""
    lines: list[str] = []
    lines.append(
        "| Library | Capa functions (pure / with caps / total) "
        "| Capa caps declared | Per-fn (fn x cap) bits "
        "| Naive Python imports | PURL cap-bearing imports |"
    )
    lines.append("|---|---|---|---:|---|---|")
    for row in rows:
        name = row["pair"]
        is_total = name == "TOTAL"
        counts = (
            f"{row['fns_pure']} / "
            f"{row['fns_with_caps']} / "
            f"{row['fns_total']}"
        )
        caps = _render_set(row["caps_declared"])
        bits = str(row["per_fn_info_bits"])
        imports = _render_set(row["naive_imports"])
        cap_mods = _render_set(row["naive_cap_modules"])
        if is_total:
            lines.append(
                f"| **{name}** | **{counts}** | **{caps}** "
                f"| **{bits}** | **{imports}** | **{cap_mods}** |"
            )
        else:
            lines.append(
                f"| {name} | {counts} | {caps} "
                f"| {bits} | {imports} | {cap_mods} |"
            )
    return "\n".join(lines)


def _render_asymmetry_section(rows: list[dict]) -> str:
    """Render the asymmetry-cases bullet list. A pair qualifies
    when it has at least one compiler-verified pure function AND a
    non-empty naive-imports set: in both shapes (PURL lists
    cap-bearing modules but Capa narrows the attribution per
    function, OR PURL lists modules that don't carry capabilities
    at all) the Capa SBOM proves something the PURL view cannot."""
    qualifying: list[dict] = []
    for row in rows:
        if row["pair"] == "TOTAL":
            continue
        if row["fns_pure"] >= 1 and row["naive_imports"]:
            qualifying.append(row)

    lines: list[str] = []
    lines.append("## Asymmetry cases")
    lines.append("")
    lines.append(
        "Two shapes of asymmetry appear in the corpus: (a) PURL "
        "lists cap-bearing modules and Capa narrows the "
        "attribution by proving some functions in the package are "
        "pure, and (b) PURL lists modules that do not carry "
        "capabilities at all (over-attribution) and Capa attributes "
        "zero authority to the corresponding functions. In both "
        "shapes the Capa SBOM proves something the PURL view "
        "cannot express."
    )
    lines.append("")
    if not qualifying:
        lines.append(
            "No pair in the current corpus has both a compiler-"
            "verified pure function and a non-empty PURL import "
            "set."
        )
        return "\n".join(lines)
    for row in qualifying:
        imports = ", ".join(row["naive_imports"])
        cap_mods = row["naive_cap_modules"]
        if cap_mods:
            cap_phrase = (
                f"a PURL SBOM listing `{imports}` "
                f"(of which `{', '.join(cap_mods)}` are cap-bearing) "
                f"cannot make the pure-vs-impure split per-function"
            )
        else:
            cap_phrase = (
                f"a PURL SBOM listing `{imports}` over-attributes "
                f"(none of these imports exercise any capability) "
                f"while Capa attributes zero authority to "
                f"{row['fns_pure']} of {row['fns_total']} functions"
            )
        lines.append(
            f"- `{row['pair']}`: {row['fns_pure']} of "
            f"{row['fns_total']} Capa functions are compiler-"
            f"verified pure; {cap_phrase}."
        )
    return "\n".join(lines)


def _render_summary(rows: list[dict]) -> str:
    """Compose the full summary.md document from parsed rows."""
    non_total = [r for r in rows if r["pair"] != "TOTAL"]
    total_row = next((r for r in rows if r["pair"] == "TOTAL"), None)
    n_pairs = len(non_total)

    lines: list[str] = []
    lines.append("# SBOM diff study: capability-aware vs PURL")
    lines.append("")
    lines.append(
        f"Capability-aware Capa SBOMs encode strictly more "
        f"information than PURL SBOMs for libraries that exercise "
        f"any capability. Every PURL fact (the set of imported "
        f"modules that map to capability-bearing standard-library "
        f"surface) is recoverable from the Capa SBOM, and the Capa "
        f"SBOM additionally reports per-function attribution that "
        f"the PURL view cannot. The table below shows this across "
        f"{n_pairs} pair{'s' if n_pairs != 1 else ''}."
    )
    lines.append("")
    lines.append("## Per-pair results")
    lines.append("")
    lines.append(_render_table(rows))
    lines.append("")
    lines.append("## Per-function attribution density")
    lines.append("")
    total_bits = total_row["per_fn_info_bits"] if total_row else 0
    lines.append(
        f"`per_fn_info_bits` counts the number of (function, "
        f"capability) declarations a Capa SBOM exposes; each such "
        f"fact is of the form \"this specific function exercises "
        f"this specific capability\" and has no counterpart in a "
        f"PURL SBOM, which only attributes capability surface at "
        f"the package level. For the current corpus the aggregate "
        f"is {total_bits} such facts across {n_pairs} pair"
        f"{'s' if n_pairs != 1 else ''}."
    )
    lines.append("")
    asymmetry = _render_asymmetry_section(rows)
    if asymmetry:
        lines.append(asymmetry)
        lines.append("")
    lines.append("## What this study does NOT claim")
    lines.append("")
    for caveat in CAVEATS:
        lines.append(f"- {caveat}")
    lines.append("")
    lines.append("## Reproducibility")
    lines.append("")
    lines.append(
        "Generated by `evaluation/sbom_diff/summary.py` from "
        "`evaluation/sbom_diff/results.csv`. To regenerate from "
        "raw sources:"
    )
    lines.append("")
    lines.append("    .venv/Scripts/python -m evaluation.sbom_diff.harness")
    lines.append("    .venv/Scripts/python -m evaluation.sbom_diff.summary")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render results.csv into summary.md."
    )
    parser.add_argument(
        "--in",
        dest="in_path",
        type=Path,
        default=DEFAULT_IN,
        help="Path to results.csv (default: alongside this script).",
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        type=Path,
        default=DEFAULT_OUT,
        help="Path to write summary.md (default: alongside this script).",
    )
    args = parser.parse_args(argv)

    rows = _load_csv(args.in_path)
    doc = _render_summary(rows)
    args.out_path.write_text(doc, encoding="utf-8")
    print(f"[summary] wrote {args.out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
