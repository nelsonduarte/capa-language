"""Compile-time benchmark for the Capa pipeline.

Measures the wallclock cost of the front-end phases:

- ``Lexer.lex()``                     -- tokenisation
- ``Parser(tokens).parse_module()``   -- AST construction
- ``analyze(module, ...)``            -- semantic checks
- (sum of the above)                  -- ``capa --check`` cost

The runtime ``runner.py`` benchmark explicitly excludes
compile time; this script fills the gap so a regression in
analyser complexity (e.g. an accidental O(n^2) pass) surfaces
in CI / manual review rather than only after a user complains.

Run with:

    python benchmarks/compile_bench.py

Optionally, ``--repeat M`` overrides the trial count.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import timeit
from pathlib import Path
from typing import Callable

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from capa.lexer import Lexer
from capa.parser import Parser
from capa.analyzer import analyze


def _gen_small() -> str:
    """10 plain functions, no caps, no match. Baseline for the
    lex / parse / analyse cost on a tiny program."""
    parts = ["fun main(stdio: Stdio)\n    stdio.println(\"hello\")\n"]
    for i in range(10):
        parts.append(
            f"fun add_{i}(x: Int, y: Int) -> Int\n"
            f"    let s = x + y + {i}\n"
            f"    return s\n"
        )
    return "\n".join(parts)


def _gen_medium() -> str:
    """100 functions, half of them use a capability, the other
    half use a match on a sum variant. Representative of a
    real-world capability-using module."""
    parts = [
        "type Shape =\n"
        "    Circle(Int)\n"
        "    Square(Int)\n"
        "    Triangle(Int, Int)\n",
        "fun area(s: Shape) -> Int\n"
        "    match s\n"
        "        Circle(r) -> r * r\n"
        "        Square(side) -> side * side\n"
        "        Triangle(b, h) -> (b * h) / 2\n",
        "fun main(stdio: Stdio)\n"
        "    stdio.println(\"start\")\n",
    ]
    for i in range(50):
        parts.append(
            f"fun cap_user_{i}(stdio: Stdio, n: Int) -> Int\n"
            f"    if n > 0\n"
            f"        stdio.println(\"${{n}}\")\n"
            f"        return n + {i}\n"
            f"    else\n"
            f"        return {i}\n"
        )
    for i in range(50):
        parts.append(
            f"fun match_user_{i}(s: Shape) -> Int\n"
            f"    match s\n"
            f"        Circle(r) -> r + {i}\n"
            f"        Square(side) -> side - {i}\n"
            f"        Triangle(b, h) -> b * h + {i}\n"
        )
    return "\n".join(parts)


def _gen_large() -> str:
    """1000 functions mixing capabilities, struct field access,
    closures, and matches. Stress test for the analyser's
    per-function passes."""
    parts = [
        "type Point {\n    x: Int,\n    y: Int\n}\n",
        "type Tree =\n"
        "    Leaf(Int)\n"
        "    Branch(Int, Int)\n",
        "fun main(stdio: Stdio)\n"
        "    stdio.println(\"start\")\n",
    ]
    for i in range(250):
        parts.append(
            f"fun plain_{i}(x: Int, y: Int) -> Int\n"
            f"    return x + y + {i}\n"
        )
    for i in range(250):
        parts.append(
            f"fun struct_{i}(p: Point) -> Int\n"
            f"    let s = p.x + p.y + {i}\n"
            f"    return s\n"
        )
    for i in range(250):
        parts.append(
            f"fun cap_{i}(stdio: Stdio, n: Int) -> Int\n"
            f"    stdio.println(\"${{n}}\")\n"
            f"    return n + {i}\n"
        )
    for i in range(250):
        parts.append(
            f"fun tree_{i}(t: Tree) -> Int\n"
            f"    match t\n"
            f"        Leaf(v) -> v + {i}\n"
            f"        Branch(a, b) -> a * b + {i}\n"
        )
    return "\n".join(parts)


_WORKLOADS: dict[str, tuple[Callable[[], str], str]] = {
    "small (10 fns)": (_gen_small, "10 plain functions, no caps, no match"),
    "medium (100 fns)": (
        _gen_medium,
        "100 functions, mix of capability calls and sum-variant match",
    ),
    "large (1000 fns)": (
        _gen_large,
        "1000 functions, structs + caps + sum + match",
    ),
}


def _measure(fn: Callable[[], object], repeat: int) -> tuple[float, float]:
    """Returns (mean_seconds, stdev) over ``repeat`` standalone
    timings. Compile passes are too expensive per-iteration to
    benefit from ``timeit``'s inner loop, so we measure each call
    once and aggregate."""
    timings: list[float] = []
    for _ in range(repeat):
        t = timeit.Timer(fn).timeit(number=1)
        timings.append(t)
    return statistics.mean(timings), (
        statistics.stdev(timings) if len(timings) > 1 else 0.0
    )


def _bench_one(source: str, repeat: int) -> dict[str, tuple[float, float]]:
    """Run the three front-end phases on ``source`` ``repeat``
    times each. Each phase is timed in isolation: lex starts from
    the raw source, parse re-lexes (so the token stream is fresh
    for every trial), analyse re-parses. The redundancy is
    intentional, so a regression in one phase doesn't masquerade
    as a regression in the next."""
    lex_mean, lex_stdev = _measure(
        lambda: Lexer(source).lex(), repeat,
    )

    def parse_one() -> None:
        tokens = Lexer(source).lex()
        Parser(tokens, source=source).parse_module()

    parse_mean, parse_stdev = _measure(parse_one, repeat)

    def analyse_one() -> None:
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        analyze(module, source=source)

    analyse_mean, analyse_stdev = _measure(analyse_one, repeat)

    return {
        "lex": (lex_mean, lex_stdev),
        "parse": (parse_mean, parse_stdev),
        "analyse": (analyse_mean, analyse_stdev),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="emit a Markdown table instead of plain text",
    )
    args = parser.parse_args()

    rows = []
    for name, (gen, description) in _WORKLOADS.items():
        source = gen()
        loc = source.count("\n")
        phases = _bench_one(source, args.repeat)
        rows.append((name, description, loc, phases))

    if args.markdown:
        print(
            "| Workload | LOC | Lex (ms) | Parse (ms) | "
            "Analyse (ms) | Total (ms) |"
        )
        print("|---|---:|---:|---:|---:|---:|")
        for name, _desc, loc, phases in rows:
            lex_ms = phases["lex"][0] * 1000
            parse_ms = phases["parse"][0] * 1000
            analyse_ms = phases["analyse"][0] * 1000
            total_ms = lex_ms + parse_ms + analyse_ms
            print(
                f"| `{name}` | {loc} | {lex_ms:.2f} | "
                f"{parse_ms:.2f} | {analyse_ms:.2f} | "
                f"{total_ms:.2f} |"
            )
    else:
        print(
            f"{'workload':<22} {'LOC':>6} "
            f"{'lex (ms)':>14} {'parse (ms)':>14} "
            f"{'analyse (ms)':>14} {'total (ms)':>12}"
        )
        print("-" * 86)
        for name, _desc, loc, phases in rows:
            lex_m, lex_s = phases["lex"]
            par_m, par_s = phases["parse"]
            ana_m, ana_s = phases["analyse"]
            total = (lex_m + par_m + ana_m) * 1000
            print(
                f"{name:<22} {loc:>6} "
                f"{lex_m*1000:>7.2f} +/- {lex_s*1000:>4.2f} "
                f"{par_m*1000:>7.2f} +/- {par_s*1000:>4.2f} "
                f"{ana_m*1000:>7.2f} +/- {ana_s*1000:>4.2f} "
                f"{total:>10.2f}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
