"""Benchmark runner for Capa vs hand-Python.

For each workload, transpiles the .capa file in-process, execs it
into a fresh namespace, and times the relevant function via
``timeit.repeat``. The baseline is imported from the matching
``*_baseline.py`` module and timed the same way.

Reports mean and stdev of best-of-3 runs of N iterations each,
plus the ratio (capa_mean / baseline_mean) as the headline
overhead figure. The ratio is what a thesis chapter on Capa's
practical overhead actually wants to cite.

Run with:

    python benchmarks/runner.py

Optionally, ``--iterations N`` to override the per-trial loop
count and ``--repeat M`` to override the trial count.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import statistics
import sys
import timeit
from pathlib import Path
from typing import Callable

# Make the Capa package importable when the runner is invoked from
# the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from capa.lexer import Lexer
from capa.parser import Parser
from capa.analyzer import analyze
from capa.transpiler import transpile


def _transpile(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    result = analyze(module, source=source)
    return transpile(module, types=result.types)


def _load_capa_namespace(capa_path: Path) -> dict:
    # Write transpiled output next to the .capa as a sibling .py and
    # import it as a real module. exec()-ing the code instead trips
    # Python 3.14's dataclass machinery, which looks up __module__ in
    # sys.modules. Real-module import is also closer to how a deployed
    # Capa program runs.
    code = _transpile(capa_path)
    out_path = capa_path.with_suffix(".bench.py")
    out_path.write_text(code, encoding="utf-8")
    module_name = f"capa_bench_{capa_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, out_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return vars(module)


def _measure(fn: Callable[[], object], iterations: int, repeat: int) -> tuple[float, float]:
    """Returns (mean_seconds_per_iteration, stdev) over `repeat` trials
    of `iterations` iterations each.
    """
    timer = timeit.Timer(fn)
    trials = timer.repeat(repeat=repeat, number=iterations)
    per_iter = [t / iterations for t in trials]
    return statistics.mean(per_iter), (
        statistics.stdev(per_iter) if len(per_iter) > 1 else 0.0
    )


# ---------------------------------------------------------------
# Workload definitions.
#
# Each entry returns a pair (capa_callable, baseline_callable),
# both zero-argument closures that perform the same logical work.
# ---------------------------------------------------------------


def _workload_fib():
    ns = _load_capa_namespace(_REPO_ROOT / "benchmarks" / "fib.capa")
    fib = ns["fib"]
    baseline = importlib.import_module("benchmarks.fib_baseline")
    return (lambda: fib(25)), baseline.workload


def _workload_scope_analyser():
    ns = _load_capa_namespace(_REPO_ROOT / "benchmarks" / "scope_analyser.capa")
    build_decls = ns["build_decls"]
    analyse_scopes = ns["analyse_scopes"]
    baseline = importlib.import_module("benchmarks.scope_analyser_baseline")
    return (
        lambda: analyse_scopes(build_decls(1000)),
        baseline.workload,
    )


def _workload_ua_parse():
    ns = _load_capa_namespace(_REPO_ROOT / "benchmarks" / "ua_parse.capa")
    build_samples = ns["build_samples"]
    parse_all = ns["parse_all"]
    baseline = importlib.import_module("benchmarks.ua_parse_baseline")
    return (
        lambda: parse_all(build_samples(1000)),
        baseline.workload,
    )


WORKLOADS: dict[str, tuple[Callable, str]] = {
    "fib(25)": (_workload_fib, "pure compute (recursive function call)"),
    "scope_analyser (1000)": (
        _workload_scope_analyser,
        "list-heavy (build + transform List<Struct>)",
    ),
    "ua_parse (1000)": (
        _workload_ua_parse,
        "string-heavy (substring match + struct ctor)",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="emit a Markdown table instead of plain text",
    )
    args = parser.parse_args()

    results = []
    for name, (build, description) in WORKLOADS.items():
        capa_fn, baseline_fn = build()
        capa_mean, capa_stdev = _measure(capa_fn, args.iterations, args.repeat)
        base_mean, base_stdev = _measure(baseline_fn, args.iterations, args.repeat)
        ratio = capa_mean / base_mean if base_mean > 0 else float("inf")
        results.append((name, description, capa_mean, capa_stdev, base_mean, base_stdev, ratio))

    if args.markdown:
        print("| Workload | Description | Capa (ms) | Python (ms) | Overhead |")
        print("|---|---|---:|---:|---:|")
        for name, desc, c_m, _, b_m, _, ratio in results:
            print(f"| `{name}` | {desc} | {c_m*1000:.3f} | {b_m*1000:.3f} | {ratio:.2f}x |")
    else:
        print(f"{'workload':<25} {'capa (ms)':>15} {'python (ms)':>15} {'overhead':>12}")
        print("-" * 70)
        for name, _, c_m, c_s, b_m, b_s, ratio in results:
            print(
                f"{name:<25} "
                f"{c_m*1000:>10.3f} +/- {c_s*1000:>4.3f} "
                f"{b_m*1000:>10.3f} +/- {b_s*1000:>4.3f} "
                f"{ratio:>10.2f}x"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
