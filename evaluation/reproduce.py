"""Re-run the paper's section-5 empirical studies and report deltas.

One command that regenerates every empirical headline in §5 of
`docs/paper-draft.md` from the current checkout and diffs it against
the published numbers in `baseline.json`. The point is that on the day
you submit, you are not hand-copying numbers from a months-old run: you
run this against a fresh release tag, see at a glance what (if anything)
moved, and either fix the regression or re-anchor the baseline with
`--update-baseline`.

Two classes of metric:

- **Counts** (fuzz rejections, SBOM-diff attribution facts, CVE
  buckets) are exact-reproducible. Any delta is a real change and makes
  this tool exit non-zero.
- **Timing ratios** (runtime macro, micro overhead) vary by machine and
  load. They are checked within a tolerance band and only warn, unless
  `--strict` is passed.

Usage (from the repo root, venv active):

    python -m evaluation.reproduce              # fast studies (fuzz, sbom_diff, cve)
    python -m evaluation.reproduce --with-runtime   # + macro Python/Wasm timing
    python -m evaluation.reproduce --with-micro     # + micro overhead vs hand-Python
    python -m evaluation.reproduce --all            # everything
    python -m evaluation.reproduce --all --json report.json
    python -m evaluation.reproduce --update-baseline  # re-anchor baseline.json to now

The fast studies need no network: the CVE headline is recomputed from
the committed `cve/decisions.csv`, not from a fresh NVD download.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
_BASELINE_PATH = _HERE / "baseline.json"


# ---------------------------------------------------------------- helpers


def _run_module(module: str, *args: str) -> subprocess.CompletedProcess:
    """Run ``python -m <module> <args>`` from the repo root, capturing
    output. Raises with the captured stderr on a non-zero exit so the
    caller can surface which study failed."""
    proc = subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"`python -m {module} {' '.join(args)}` exited "
            f"{proc.returncode}:\n{proc.stderr or proc.stdout}"
        )
    return proc


def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=_REPO_ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def _provenance() -> dict:
    return {
        "describe": _git("describe", "--tags", "--always", "--dirty"),
        "commit": _git("rev-parse", "--short", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
    }


# ---------------------------------------------------------------- studies
# Each returns a flat {metric_name: value} dict matching baseline.json.


def study_fuzz() -> dict:
    _run_module("evaluation.fuzz.harness", "--all")
    rows = _read_csv(_HERE / "fuzz" / "results.csv")
    return {
        "attempts": len(rows),
        "rejected": sum(1 for r in rows if r["rejected"].strip() == "True"),
        "categories": len({r["category"] for r in rows}),
    }


def study_sbom_diff() -> dict:
    _run_module("evaluation.sbom_diff.harness")
    rows = _read_csv(_HERE / "sbom_diff" / "results.csv")
    # The harness appends its own aggregate "TOTAL" row; use it rather
    # than re-summing the per-pair rows (which would double-count).
    total = next((r for r in rows if r["pair"] == "TOTAL"), None)
    if total is None:  # older harness without a TOTAL row: sum the pairs
        pairs = rows
        agg = {k: sum(int(r[k]) for r in pairs) for k in
               ("fns_total", "fns_with_caps", "fns_pure")}
        agg["info_bits"] = sum(int(r["per_fn_info_bits"]) for r in pairs)
        caps = {c.strip() for r in pairs
                for c in r["caps_declared"].split(";") if c.strip()}
    else:
        agg = {k: int(total[k]) for k in
               ("fns_total", "fns_with_caps", "fns_pure")}
        agg["info_bits"] = int(total["per_fn_info_bits"])
        caps = {c.strip() for c in total["caps_declared"].split(";") if c.strip()}
    agg["caps"] = len(caps)
    return agg


def study_cve() -> dict:
    # Best-effort regenerate summary.csv from decisions.csv (validates the
    # pipeline); the headline counts come straight from decisions.csv, the
    # committed source of truth, so no NVD download is needed.
    try:
        _run_module("evaluation.cve.summary")
    except RuntimeError:
        pass
    rows = _read_csv(_HERE / "cve" / "decisions.csv")
    n = len(rows)
    sr = sum(1 for r in rows if r["bucket"] == "STRUCTURAL_REJECT")
    am = sum(1 for r in rows if r["bucket"] == "ATTENUATION_MITIGATED")
    oos = sum(1 for r in rows if r["bucket"].startswith("OUT_OF_SCOPE"))
    pct = (lambda x: round(100.0 * x / n, 1) if n else 0.0)
    return {
        "n": n,
        "structural_reject": sr,
        "attenuation_mitigated": am,
        "out_of_scope": oos,
        "pct_structural": pct(sr),
        "pct_attenuation": pct(am),
        "pct_capa_relevant": pct(sr + am),
    }


def study_runtime_macro() -> dict:
    _run_module("evaluation.runtime.harness")
    rows = _read_csv(_HERE / "runtime" / "results.csv")
    py = {r["workload"]: float(r["seconds_mean"])
          for r in rows if r["backend"] == "capa_python"}
    wasm = {r["workload"]: float(r["seconds_mean"])
            for r in rows if r["backend"] == "capa_wasm"}
    per = {w: round(wasm[w] / py[w], 3)
           for w in py if w in wasm and py[w] > 0}
    mean = round(sum(per.values()) / len(per), 3) if per else 0.0
    return {"mean_ratio": mean, "per_workload": per}


def study_micro(iterations: int, repeat: int) -> dict:
    # Import the benchmark module and measure in-process; the runner has
    # no CSV output, so we drive its WORKLOADS table directly.
    from benchmarks import runner
    per: dict[str, float] = {}
    for name, (build, _desc) in runner.WORKLOADS.items():
        capa_fn, base_fn = build()
        capa_mean, _ = runner._measure(capa_fn, iterations, repeat)
        base_mean, _ = runner._measure(base_fn, iterations, repeat)
        key = name.split("(")[0].strip()
        per[key] = round(capa_mean / base_mean, 3) if base_mean > 0 else float("inf")
    return {"per_workload": per}


# ---------------------------------------------------------------- compare


def _cmp_rows(study: str, base: dict, cur: dict) -> list[dict]:
    """Produce one comparison row per leaf metric. Counts are compared
    exactly; *_tolerance / tolerance keys drive timing comparisons."""
    rows: list[dict] = []

    def add(metric, b, c, tol=None):
        if b is None or c is None:
            status = "MISSING"
            delta = None
        elif tol is not None:
            delta = round(c - b, 3)
            status = "OK" if abs(delta) <= tol else "DRIFT"
        else:
            delta = round(c - b, 3) if isinstance(b, float) else c - b
            status = "OK" if c == b else "CHANGED"
        rows.append({"study": study, "metric": metric,
                     "baseline": b, "current": c,
                     "delta": delta, "status": status})

    # Per-workload nested timing dicts.
    if "per_workload" in base and isinstance(base["per_workload"], dict):
        tol = base.get("tolerance", 0.35)
        for w, b in base["per_workload"].items():
            add(f"ratio[{w}]", b, cur.get("per_workload", {}).get(w), tol)
        if "mean_ratio" in base:
            add("mean_ratio", base["mean_ratio"], cur.get("mean_ratio"), tol)
        return rows

    # Flat metrics (counts, percentages).
    pct_tol = base.get("pct_tolerance")
    for k, b in base.items():
        if k.startswith("_") or k in ("exact", "tolerance", "pct_tolerance"):
            continue
        c = cur.get(k)
        if pct_tol is not None and k.startswith("pct_"):
            add(k, b, c, pct_tol)
        else:
            add(k, b, c, None)
    return rows


# ---------------------------------------------------------------- report


def _fmt(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".")
    return str(v)


def _print_report(prov: dict, all_rows: list[dict]) -> None:
    print()
    print("Capa section-5 empirical reproduction")
    print(f"  {prov['describe']} (commit {prov['commit']}, branch {prov['branch']})")
    print()
    head = ("study", "metric", "baseline", "current", "delta", "status")
    widths = [12, 22, 10, 10, 8, 8]
    line = "  ".join(h.ljust(w) for h, w in zip(head, widths))
    print(line)
    print("-" * len(line))
    last = None
    for r in all_rows:
        study = r["study"] if r["study"] != last else ""
        last = r["study"]
        cells = (
            study, r["metric"], _fmt(r["baseline"]),
            _fmt(r["current"]), _fmt(r["delta"]), r["status"],
        )
        print("  ".join(c.ljust(w) for c, w in zip(cells, widths)))


# ---------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="evaluation.reproduce",
        description="Re-run the paper's section-5 studies and report deltas.",
    )
    p.add_argument("--with-runtime", action="store_true",
                   help="also run the macro Python/Wasm timing study (slow)")
    p.add_argument("--with-micro", action="store_true",
                   help="also run the micro overhead study vs hand-Python (slow)")
    p.add_argument("--all", action="store_true",
                   help="run every study, including the timing ones")
    p.add_argument("--strict", action="store_true",
                   help="exit non-zero on timing DRIFT too, not just count CHANGED")
    p.add_argument("--iterations", type=int, default=30,
                   help="micro-benchmark iterations per trial (default 30, "
                        "matching the paper's §5.2 measurement)")
    p.add_argument("--repeat", type=int, default=7,
                   help="micro-benchmark trials (default 7, matching §5.2)")
    p.add_argument("--update-baseline", action="store_true",
                   help="overwrite baseline.json with this run's numbers")
    p.add_argument("--json", type=Path, default=None,
                   help="also write the full report as JSON to this path")
    args = p.parse_args(argv)

    baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    prov = _provenance()

    want_runtime = args.with_runtime or args.all
    want_micro = args.with_micro or args.all

    results: dict[str, dict] = {}
    errors: dict[str, str] = {}

    plan = [("fuzz", study_fuzz),
            ("sbom_diff", study_sbom_diff),
            ("cve", study_cve)]
    if want_runtime:
        plan.append(("runtime_macro", study_runtime_macro))
    if want_micro:
        plan.append(("micro_overhead",
                     lambda: study_micro(args.iterations, args.repeat)))

    for name, fn in plan:
        print(f"[reproduce] running {name} ...", file=sys.stderr)
        try:
            results[name] = fn()
        except Exception as e:  # noqa: BLE001 - report, do not abort the run
            errors[name] = str(e)
            print(f"[reproduce] {name} FAILED: {e}", file=sys.stderr)

    if args.update_baseline:
        for name, cur in results.items():
            baseline.setdefault(name, {})
            baseline[name].update(cur)
        _BASELINE_PATH.write_text(
            json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        print(f"[reproduce] baseline.json updated for: "
              f"{', '.join(results)}", file=sys.stderr)
        return 0

    all_rows: list[dict] = []
    for name, cur in results.items():
        all_rows.extend(_cmp_rows(name, baseline.get(name, {}), cur))

    _print_report(prov, all_rows)

    changed = [r for r in all_rows if r["status"] == "CHANGED"]
    drift = [r for r in all_rows if r["status"] == "DRIFT"]
    missing = [r for r in all_rows if r["status"] == "MISSING"]

    print()
    if errors:
        print(f"  {len(errors)} study(ies) failed to run: "
              f"{', '.join(errors)}")
    print(f"  exact metrics changed: {len(changed)}   "
          f"timing drift: {len(drift)}   missing: {len(missing)}")
    if not (changed or drift or missing or errors):
        print("  all section-5 numbers reproduce within tolerance.")

    if args.json is not None:
        args.json.write_text(json.dumps({
            "provenance": prov,
            "results": results,
            "errors": errors,
            "rows": all_rows,
        }, indent=2) + "\n", encoding="utf-8")
        print(f"  wrote {args.json}")

    fail = bool(changed) or bool(errors) or (args.strict and bool(drift))
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
