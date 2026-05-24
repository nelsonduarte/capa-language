"""Fuzz harness: run capability-bypass attack programs against
``capa --check`` and report which were rejected.

A program counts as ``rejected`` iff ``capa --check`` exits
non-zero. The first error line is recorded as the rejection
reason; if any program is accepted (exit 0), the harness marks
the attack ``ESCAPED`` and prints the full source so the finding
is visible without re-running.

Slice 1: a single category (``cat_fs_traversal``) covering 3
hand-written attacks, end-to-end with CSV output.

Slice 6 will add seven more categories and ~20 mutations per
attack via the same loop (the harness contract here is
deliberately category-agnostic).

Usage:
    python -m evaluation.fuzz.harness --category cat_fs_traversal
    python -m evaluation.fuzz.harness --all
"""

from __future__ import annotations

import argparse
import importlib
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from evaluation.shared.runner_utils import (
    CapaRun, run_capa, write_csv,
)

# Category names land here as the panel grows. Slice 1 shipped
# one; slice 6 fills in the rest of the 8-category panel called
# for in the empirical-study plan.
ALL_CATEGORIES = [
    "cat_fs_traversal",
    "cat_env_leak",
    "cat_net_punch",
    "cat_time_channel",
    "cat_subprocess",
    "cat_unsafe_smuggle",
    "cat_capability_in_data",
    "cat_capability_aliasing",
    "cat_llm_dispatch_escape",
]


@dataclass
class Result:
    category: str
    attack_id: str
    rejected: bool
    exit_code: int
    rejection_reason: str
    description: str


def _first_error_line(run: CapaRun) -> str:
    """First line of capa's combined output that looks like an
    error (contains 'error:' or starts with 'capa:'). Used as a
    short rejection-reason summary in the CSV."""
    for line in run.combined.splitlines():
        if "error:" in line or line.startswith("capa:"):
            return line.strip()
    return run.combined.splitlines()[0] if run.combined else ""


def _run_attack(category: str, attack) -> Result:
    """Write the attack source to a temp file, invoke
    ``capa --check``, and classify the outcome."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".capa", delete=False, encoding="utf-8",
    ) as f:
        f.write(attack.source)
        path = Path(f.name)
    try:
        run = run_capa("--check", path)
    finally:
        path.unlink(missing_ok=True)

    rejected = not run.ok
    reason = _first_error_line(run) if rejected else "(none; program was ACCEPTED)"
    return Result(
        category=category,
        attack_id=attack.attack_id,
        rejected=rejected,
        exit_code=run.returncode,
        rejection_reason=reason,
        description=attack.description,
    )


def run_category(category: str) -> list[Result]:
    """Import the category module, generate its panel, run each
    attack, return the list of results."""
    mod = importlib.import_module(f"evaluation.fuzz.attacks.{category}")
    attacks = mod.generate()
    results = []
    for attack in attacks:
        result = _run_attack(category, attack)
        marker = "OK   " if result.rejected else "ESC! "
        print(f"  {marker} {category}/{attack.attack_id}  -> {result.rejection_reason}")
        if not result.rejected:
            # An escape is a paper-relevant finding; print the
            # full attack source so it survives without re-running.
            print("    ====== ESCAPED ATTACK SOURCE ======")
            for line in attack.source.splitlines():
                print(f"    | {line}")
            print("    ====== END ATTACK SOURCE ======")
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Capability-bypass fuzz harness")
    p.add_argument(
        "--category",
        choices=ALL_CATEGORIES,
        help="run a single attack category",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="run every attack category",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "results.csv",
        help="CSV output path (default: evaluation/fuzz/results.csv)",
    )
    args = p.parse_args(argv)

    if not (args.category or args.all):
        p.error("pass --category <name> or --all")

    categories = ALL_CATEGORIES if args.all else [args.category]
    all_results: list[Result] = []
    for cat in categories:
        print(f"[fuzz] category: {cat}")
        all_results.extend(run_category(cat))

    write_csv(
        args.out,
        [
            {
                "category": r.category,
                "attack_id": r.attack_id,
                "rejected": r.rejected,
                "exit_code": r.exit_code,
                "rejection_reason": r.rejection_reason,
                "description": r.description,
            }
            for r in all_results
        ],
        header=[
            "category", "attack_id", "rejected", "exit_code",
            "rejection_reason", "description",
        ],
    )
    print(f"[fuzz] wrote {args.out}")

    escaped = [r for r in all_results if not r.rejected]
    total = len(all_results)
    rejected = total - len(escaped)
    print(f"[fuzz] summary: {rejected}/{total} rejected, {len(escaped)} escaped")
    return 0 if not escaped else 2


if __name__ == "__main__":
    sys.exit(main())
