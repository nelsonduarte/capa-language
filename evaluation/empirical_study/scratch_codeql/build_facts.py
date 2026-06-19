"""Build the consolidated CodeQL fact table for ALL 25 study pairs.

For each pair (20 in ``evaluation/sbom_diff`` + 5 in
``evaluation/empirical_study/dispatch_pairs``):

  1. stage the pair's ``naive.py`` into ``src_<pair>/`` (CodeQL extracts
     a directory, not a single file);
  2. create the Python database ``db_<pair>/`` if it does not exist;
  3. run ``capquery/CapabilityReachability.ql`` against it;
  4. parse the ``(function, axis)`` rows and emit
     ``(pair, python_function, capability)`` facts.

The consolidated rows are written to ``codeql_facts.csv`` (sorted,
deterministic). This script needs the 1.3GB CodeQL CLI under
``codeql/`` and is NOT part of the study harness or the test suite: it
is the one-shot generator. The harness reads only the CSV it produces.

Reproduce with:
  cd evaluation/empirical_study/scratch_codeql
  python build_facts.py            # build every missing db + score all 25
  python build_facts.py --rebuild  # force-recreate every database first
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent
ROOT = STUDY.parents[1]

CODEQL = HERE / "codeql" / ("codeql.exe" if sys.platform == "win32" else "codeql")
QUERY = HERE / "capquery" / "CapabilityReachability.ql"
ADDITIONAL_PACKS = HERE / "codeql" / "qlpacks"

SBOM_DIFF = ROOT / "evaluation" / "sbom_diff"
DISPATCH_PAIRS = STUDY / "dispatch_pairs"


def discover_pairs() -> dict[str, Path]:
    """Return ``{pair_name: naive.py path}`` for every pair across both
    corpus roots that ships a ``naive.py`` (the CodeQL-extractable
    Python artefact)."""
    pairs: dict[str, Path] = {}
    for root in (SBOM_DIFF, DISPATCH_PAIRS):
        for d in sorted(root.iterdir()):
            naive = d / "naive.py"
            if d.is_dir() and naive.exists():
                pairs[d.name] = naive
    return pairs


def stage_src(pair: str, naive: Path) -> Path:
    src = HERE / f"src_{pair}"
    src.mkdir(exist_ok=True)
    shutil.copyfile(naive, src / "naive.py")
    return src


def create_db(pair: str, src: Path, rebuild: bool) -> Path:
    db = HERE / f"db_{pair}"
    if db.exists() and rebuild:
        shutil.rmtree(db)
    if db.exists():
        return db
    print(f"  creating database db_{pair} ...", flush=True)
    proc = subprocess.run(
        [str(CODEQL), "database", "create", str(db),
         "--language=python", f"--source-root={src}", "--overwrite", "--quiet"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"database create failed for {pair} (rc={proc.returncode}):\n"
            f"{proc.stderr}"
        )
    return db


def run_query(pair: str, db: Path) -> list[tuple[str, str]]:
    """Run the reachability query and return sorted ``(function, axis)``."""
    bqrs = db / "results.bqrs"
    proc = subprocess.run(
        [str(CODEQL), "query", "run", f"--database={db}",
         f"--additional-packs={ADDITIONAL_PACKS}",
         f"--output={bqrs}", str(QUERY)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"query run failed for {pair} (rc={proc.returncode}):\n{proc.stderr}"
        )
    dec = subprocess.run(
        [str(CODEQL), "bqrs", "decode", "--format=json", str(bqrs)],
        capture_output=True, text=True,
    )
    if dec.returncode != 0:
        raise SystemExit(
            f"bqrs decode failed for {pair} (rc={dec.returncode}):\n{dec.stderr}"
        )
    data = json.loads(dec.stdout)
    # single result set #select with columns function, axis, line
    tuples = data["#select"]["tuples"]
    out = {(row[0], row[1]) for row in tuples}
    return sorted(out)


# Capability axes, ordered as in the study.
_AXIS_ORDER = {"Fs": 0, "Net": 1, "Clock": 2, "Env": 3,
               "Random": 4, "Proc": 5, "Stdio": 6}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rebuild", action="store_true",
                   help="force re-creation of every database")
    p.add_argument("--pair", action="append", default=None,
                   help="only process the named pair (repeatable)")
    args = p.parse_args(argv)

    if not CODEQL.exists():
        raise SystemExit(
            f"CodeQL CLI not found at {CODEQL}.\n"
            "Install CodeQL 2.25.6 under scratch_codeql/codeql/ "
            "(see REPRODUCE.md)."
        )

    pairs = discover_pairs()
    if args.pair:
        pairs = {k: v for k, v in pairs.items() if k in set(args.pair)}

    facts: list[tuple[str, str, str]] = []
    for pair in sorted(pairs):
        print(f"[{pair}]", flush=True)
        src = stage_src(pair, pairs[pair])
        db = create_db(pair, src, args.rebuild)
        for fn, axis in run_query(pair, db):
            facts.append((pair, fn, axis))

    # Deterministic order: pair, axis-canonical, function.
    facts.sort(key=lambda r: (r[0], _AXIS_ORDER.get(r[2], 99), r[1]))

    # When scoring a SUBSET (--pair), merge into the existing CSV rather
    # than truncating the other pairs' facts.
    out_path = HERE / "codeql_facts.csv"
    if args.pair and out_path.exists():
        existing: list[tuple[str, str, str]] = []
        with out_path.open(encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["pair"] not in set(args.pair):
                    existing.append((r["pair"], r["python_function"],
                                     r["capability"]))
        merged = sorted(
            set(existing) | set(facts),
            key=lambda r: (r[0], _AXIS_ORDER.get(r[2], 99), r[1]),
        )
        facts = merged

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pair", "python_function", "capability"])
        w.writerows(facts)
    print(f"\nwrote {len(facts)} facts for "
          f"{len({r[0] for r in facts})} pairs to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
