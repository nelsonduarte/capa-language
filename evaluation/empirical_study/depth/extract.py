"""Depth-study metric extractor.

Reads a Capa ``--manifest`` JSON (the per-function capability map a Capa
build emits) and prints a deterministic, auditable set of depth metrics:
the function total, the pure fraction, the per-capability reach
distribution, the authority CONCENTRATION (what fraction of functions
hold each sensitive axis), the sound-exclusion fact count, and the
information-flow / constant-time / typestate dimensions a
dependency-level SBOM cannot express.

It is pure: it reads committed manifest JSON under ``manifests/`` and
writes nothing, so the harness is CI-safe and does not depend on the
downstream repos being present. Regenerate the manifests with::

    cd <repo> && python -m capa --manifest main.capa > \
        <this_dir>/manifests/<name>.manifest.json

Run::

    python extract.py                 # both programs, human table
    python extract.py --json          # machine-readable metrics

The metric definitions match the breadth study's unit (a per-function
capability fact). "Pure" means zero transitively-reachable capabilities.
"Holds C" / "reaches C" both mean C is in the function's
``transitively_reachable_capabilities`` set, the same closed-world axis
the breadth study scores. Concentration is reported as the REAL measured
fraction; the narrative follows the number, not the other way around.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST_DIR = HERE / "manifests"

# The nine built-in authority axes, in a fixed order so the report is
# deterministic. User-defined capabilities (traits marked as
# capabilities, e.g. Logger / Notifier) are reported separately because
# they are program-specific.
BUILTIN_AXES = [
    "Stdio",
    "Fs",
    "Net",
    "Db",
    "Clock",
    "Env",
    "Random",
    "Proc",
    "Unsafe",
]

# The subset whose concentration the positioning claim is about: the
# axes that grant real outside authority (read/write the world, run code,
# escape the type system). Stdio / Clock / Env / Random are lower-stakes.
SENSITIVE_AXES = ["Fs", "Net", "Db", "Proc", "Unsafe"]

PROGRAMS = [
    ("capa_paymentguard", "paymentguard.manifest.json"),
    ("capa_claimdesk", "claimdesk.manifest.json"),
]


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def extract(manifest: dict) -> dict:
    fns = manifest["functions"]
    total = len(fns)

    # All axes that appear anywhere (built-in + user-defined), so the
    # reach table covers Logger / Notifier without hard-coding them.
    seen_axes: set[str] = set()
    for f in fns:
        seen_axes.update(f["transitively_reachable_capabilities"])
        seen_axes.update(f["provably_excluded_capabilities"])
    user_axes = sorted(a for a in seen_axes if a not in BUILTIN_AXES)
    all_axes = BUILTIN_AXES + user_axes

    pure = [f for f in fns if not f["transitively_reachable_capabilities"]]

    # Per-axis reach count (functions that transitively reach the axis).
    reach = {a: 0 for a in all_axes}
    for f in fns:
        for a in f["transitively_reachable_capabilities"]:
            reach[a] += 1

    # Sound-exclusion facts: (function, capability) pairs the build has
    # PROVED absent. This is the richness no heuristic gives.
    excluded_facts = sum(
        len(f["provably_excluded_capabilities"]) for f in fns
    )

    declassification_sites = sum(
        len(f.get("declassifications", [])) for f in fns
    )
    constant_time_fns = sum(1 for f in fns if f.get("constant_time"))
    unsafe_fns = sum(1 for f in fns if f.get("has_unsafe"))

    typestates = manifest.get("typestates", [])
    udc = manifest.get("user_defined_capabilities", [])

    def frac(n: int) -> float:
        return round(100.0 * n / total, 1) if total else 0.0

    return {
        "capa_version": manifest.get("capa_version"),
        "entrypoint": manifest.get("filename"),
        "total_functions": total,
        "pure_functions": len(pure),
        "pure_pct": frac(len(pure)),
        "reach": reach,
        "reach_pct": {a: frac(n) for a, n in reach.items()},
        "sensitive_concentration": {
            a: {"functions": reach[a], "pct": frac(reach[a])}
            for a in SENSITIVE_AXES
        },
        "provably_excluded_facts": excluded_facts,
        "declassification_sites": declassification_sites,
        "constant_time_functions": constant_time_fns,
        "unsafe_functions": unsafe_fns,
        "typestates": [
            {"name": t["name"], "states": t["states"]} for t in typestates
        ],
        "user_defined_capabilities": [u["name"] for u in udc],
        # The whole-program declassification_sites the build itself
        # tallied in summary, cross-checked against the per-function sum.
        "summary_declassification_sites": manifest["summary"][
            "declassification_sites"
        ],
        "all_axes": all_axes,
    }


def render_text(name: str, m: dict) -> str:
    lines = []
    lines.append(f"## {name}  (capa {m['capa_version']}, entry {m['entrypoint']})")
    lines.append("")
    lines.append(f"- functions analysed: {m['total_functions']}")
    lines.append(
        f"- pure (zero reachable capabilities): "
        f"{m['pure_functions']} ({m['pure_pct']} %)"
    )
    lines.append(
        f"- provably-excluded (function, capability) facts: "
        f"{m['provably_excluded_facts']}"
    )
    lines.append(
        f"- declassification sites (IFC): {m['declassification_sites']}"
    )
    lines.append(
        f"- @constant_time functions: {m['constant_time_functions']}"
    )
    lines.append(f"- functions crossing unsafe: {m['unsafe_functions']}")
    lines.append(
        f"- typestates: "
        + (
            ", ".join(
                f"{t['name']}({len(t['states'])} states)"
                for t in m["typestates"]
            )
            or "none"
        )
    )
    lines.append(
        f"- user-defined capabilities: "
        + (", ".join(m["user_defined_capabilities"]) or "none")
    )
    lines.append("")
    lines.append("Capability reach (functions that transitively reach the axis):")
    lines.append("")
    lines.append("| Capability | Functions | % of functions |")
    lines.append("|---|---|---|")
    for a in m["all_axes"]:
        n = m["reach"][a]
        lines.append(f"| {a} | {n} | {m['reach_pct'][a]} % |")
    lines.append("")
    lines.append("Authority concentration (sensitive axes):")
    lines.append("")
    lines.append("| Sensitive axis | Functions holding it | % of all functions |")
    lines.append("|---|---|---|")
    for a in SENSITIVE_AXES:
        c = m["sensitive_concentration"][a]
        lines.append(f"| {a} | {c['functions']} | {c['pct']} % |")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    out = {}
    chunks = []
    for name, fname in PROGRAMS:
        path = MANIFEST_DIR / fname
        if not path.exists():
            print(f"missing manifest: {path}", file=sys.stderr)
            return 1
        m = extract(load(path))
        out[name] = m
        chunks.append(render_text(name, m))
    if as_json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print("\n\n".join(chunks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
