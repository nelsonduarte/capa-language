"""SBOM-diff harness: compare Capa per-function CycloneDX SBOMs
against a PURL-style import set extracted from the equivalent
naive Python.

For each ``<pair>/`` sub-directory containing both ``capa.capa``
and ``naive.py``:

- Run ``capa --cyclonedx <pair>/capa.capa``, parse the CycloneDX
  1.5 document from stdout, and extract per-function metrics
  (function count, declared-capability set, per-(fn, cap) info bits).
- Parse ``<pair>/naive.py`` with ``ast`` at module scope only
  (the PURL-SBOM simulation: a syft / pip-licenses run sees the
  top-level import block, not the function bodies), then
  intersect with a hard-coded allowlist of capability-bearing
  stdlib + popular third-party modules.

One CSV row per pair, plus a final ``TOTAL`` row that sums the
integers and unions the sets. Set-valued columns use ``;`` as the
intra-cell separator and the whole CSV is quoted with
``csv.QUOTE_ALL``.

Usage:
    python -m evaluation.sbom_diff.harness
    python -m evaluation.sbom_diff.harness --pair config_loader
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import subprocess
import sys
from pathlib import Path


# Hard-coded allowlist of modules whose presence in a PURL SBOM
# would (in this study's simulation) signal that the package
# *might* exercise some capability. Intentionally narrow:
# capturing the false-positive shape of PURL-level attribution
# (a module appears at the top of the file, but the actual
# function may not use it) is part of the asymmetry case for
# pure libraries like ``slugify``.
_CAPABILITY_BEARING_MODULES = frozenset({
    "os", "os.path", "pathlib", "shutil", "io", "tempfile", "glob",
    "urllib", "urllib.request", "urllib.parse", "urllib.error",
    "http", "http.client", "http.server",
    "socket", "ssl", "requests", "httpx", "aiohttp",
    "subprocess", "multiprocessing",
    "sys",
    "time", "datetime", "random", "secrets", "uuid",
    "sqlite3", "psycopg2", "pymongo",
})


def _discover_pairs(root: Path) -> list[Path]:
    """Return sub-directories of ``root`` that look like library
    pairs, sorted by name for deterministic CSV ordering."""
    return sorted(
        p for p in root.iterdir()
        if p.is_dir() and not p.name.startswith(("_", "."))
    )


def _run_capa_cyclonedx(capa_path: Path) -> dict:
    """Invoke ``python -m capa --cyclonedx <capa_path>`` and
    return the parsed CycloneDX JSON document. Raises ``RuntimeError``
    with the pair name + stderr on non-zero exit."""
    cmd = [sys.executable, "-m", "capa", "--cyclonedx", str(capa_path)]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"capa --cyclonedx failed for {capa_path}: "
            f"exit {e.returncode}\nstderr:\n{e.stderr}"
        ) from e
    return json.loads(proc.stdout)


def _extract_capa_metrics(sbom: dict) -> dict:
    """Pull per-function metrics out of a parsed CycloneDX 1.5
    document. The relevant facts live under ``components[*].properties``:
    ``capa:kind=function`` filters to function components, and
    each ``capa:declared_capability`` property is one declared
    capability of that function."""
    fns_total = 0
    fns_with_caps = 0
    caps_declared: set[str] = set()
    per_fn_info_bits = 0

    for comp in sbom.get("components", []):
        props = comp.get("properties", []) or []
        kinds = [p.get("value") for p in props if p.get("name") == "capa:kind"]
        if "function" not in kinds:
            continue
        fns_total += 1
        caps = [
            p.get("value") for p in props
            if p.get("name") == "capa:declared_capability"
        ]
        if caps:
            fns_with_caps += 1
        per_fn_info_bits += len(caps)
        caps_declared.update(caps)

    return {
        "fns_total": fns_total,
        "fns_with_caps": fns_with_caps,
        "fns_pure": fns_total - fns_with_caps,
        "caps_declared": caps_declared,
        "per_fn_info_bits": per_fn_info_bits,
    }


def _extract_naive_imports(path: Path) -> tuple[set[str], set[str]]:
    """Walk module-level ``Import`` / ``ImportFrom`` nodes (no
    recursion into function bodies, mirroring what a PURL-style
    SBOM tool sees) and return ``(all_imports, cap_bearing)``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    all_imports: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                all_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            # ``from a.b import c`` -> the module is ``a.b``;
            # relative imports (``from . import x``, module=None)
            # are not PURL-attributable so we skip them.
            if node.module is not None and node.level == 0:
                all_imports.add(node.module)

    cap_bearing = {
        imp for imp in all_imports
        if imp in _CAPABILITY_BEARING_MODULES
        or imp.split(".", 1)[0] in _CAPABILITY_BEARING_MODULES
    }
    return all_imports, cap_bearing


def _format_set(s: set[str]) -> str:
    """Sorted, ``;``-joined rendering for a set-valued CSV cell.
    Empty set -> empty string."""
    return ";".join(sorted(s))


def _aggregate_rows(rows: list[dict]) -> dict:
    """Build the trailing ``TOTAL`` row: sum integers, union the
    set-valued columns. Returns a row in the same shape as the
    per-pair rows (sets, not pre-formatted strings)."""
    total: dict = {
        "pair": "TOTAL",
        "fns_total": 0,
        "fns_with_caps": 0,
        "fns_pure": 0,
        "per_fn_info_bits": 0,
        "caps_declared": set(),
        "naive_imports": set(),
        "naive_cap_modules": set(),
    }
    for row in rows:
        total["fns_total"] += row["fns_total"]
        total["fns_with_caps"] += row["fns_with_caps"]
        total["fns_pure"] += row["fns_pure"]
        total["per_fn_info_bits"] += row["per_fn_info_bits"]
        total["caps_declared"] |= row["caps_declared"]
        total["naive_imports"] |= row["naive_imports"]
        total["naive_cap_modules"] |= row["naive_cap_modules"]
    return total


_HEADER = [
    "pair",
    "fns_total",
    "fns_with_caps",
    "fns_pure",
    "caps_declared",
    "per_fn_info_bits",
    "naive_imports",
    "naive_cap_modules",
]


def _format_row(row: dict) -> dict:
    """Render set-valued fields to ``;``-joined strings so the
    CSV is uniform."""
    return {
        "pair": row["pair"],
        "fns_total": row["fns_total"],
        "fns_with_caps": row["fns_with_caps"],
        "fns_pure": row["fns_pure"],
        "caps_declared": _format_set(row["caps_declared"]),
        "per_fn_info_bits": row["per_fn_info_bits"],
        "naive_imports": _format_set(row["naive_imports"]),
        "naive_cap_modules": _format_set(row["naive_cap_modules"]),
    }


def _process_pair(pair_dir: Path) -> dict | None:
    """Build one per-pair row dict (with raw sets) or return
    ``None`` if the pair is missing one of the required files
    (warning emitted to stderr)."""
    capa_path = pair_dir / "capa.capa"
    naive_path = pair_dir / "naive.py"
    if not capa_path.exists() or not naive_path.exists():
        missing = [
            name for name, p in [("capa.capa", capa_path), ("naive.py", naive_path)]
            if not p.exists()
        ]
        print(
            f"[sbom_diff] WARN: skipping {pair_dir.name}: missing "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return None

    sbom = _run_capa_cyclonedx(capa_path)
    capa_metrics = _extract_capa_metrics(sbom)
    naive_imports, naive_caps = _extract_naive_imports(naive_path)

    return {
        "pair": pair_dir.name,
        **capa_metrics,
        "naive_imports": naive_imports,
        "naive_cap_modules": naive_caps,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="SBOM-diff harness: Capa per-function caps vs PURL imports",
    )
    p.add_argument(
        "--pair",
        action="append",
        default=None,
        metavar="NAME",
        help="process only the named pair sub-directory "
        "(may be passed more than once)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "results.csv",
        help="CSV output path (default: evaluation/sbom_diff/results.csv)",
    )
    args = p.parse_args(argv)

    root = Path(__file__).parent
    discovered = _discover_pairs(root)
    if args.pair:
        requested = set(args.pair)
        pairs = [d for d in discovered if d.name in requested]
        missing = requested - {d.name for d in pairs}
        for name in sorted(missing):
            print(
                f"[sbom_diff] WARN: requested pair {name!r} not found under {root}",
                file=sys.stderr,
            )
    else:
        pairs = discovered

    rows: list[dict] = []
    for pair_dir in pairs:
        print(f"[sbom_diff] pair: {pair_dir.name}")
        row = _process_pair(pair_dir)
        if row is None:
            continue
        rows.append(row)
        print(
            f"  fns={row['fns_total']} with_caps={row['fns_with_caps']} "
            f"caps={_format_set(row['caps_declared']) or '(none)'} "
            f"naive_caps={_format_set(row['naive_cap_modules']) or '(none)'}"
        )

    total_row = _aggregate_rows(rows)
    formatted = [_format_row(r) for r in rows] + [_format_row(total_row)]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=_HEADER, quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        for row in formatted:
            writer.writerow(row)
    print(f"[sbom_diff] wrote {args.out} ({len(rows)} pair rows + TOTAL)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
