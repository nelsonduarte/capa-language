"""Instrument (d): the release differential.

For the ONE class it sees: a DIAGNOSTIC or a MANIFEST FACT that the
previous build produced on a corpus and the candidate does not. It cannot
see a defect already in the previous build, nor a discipline deletion that
changes no diagnostic on its corpus, which is why the corpus must carry
programs that PRODUCE diagnostics on the base (the seeded negative corpus:
the strict condition-position family).

Two halves, both run through the bounded runner on each tree:

- CHECK half: per file, the exit class of ``capa --check`` plus the SET of
  its stderr lines with paths, ``line:col`` and version strings scrubbed.
  A line present on the base and absent on the candidate is LOST; a new
  one is GAINED; an exit class that moved is an RC MOVE.
- MANIFEST half, two layers: the manifest document built in-process by
  each tree, scrubbed of digests, versions and paths, compared WHOLE
  (layer 1, fail-closed: any fact that moved is listed with its key path);
  then the compiler's own ``build_capability_diff`` classifies the move
  (layer 2). The scrub is the one normaliser; the differ is imported on
  top of it, never copied.

Invoked by the release procedure, not by test discovery::

    python -m tests.instruments.release_differential <base tree> <candidate tree>
        <corpus dir>... [--work <dir>] [--no-seeded]

Its output names files and diagnostics, so it runs where that is fine.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from tests.implicit_flow._harness import check_source
from tests.instruments._outcome import NOT_RUN, OK, outcome_type
from tests.instruments._positions import write_programs
from tests.instruments._runner import PROGRAM_BOUND_S, Program, run_cli_leg, run_leg

_PATH = re.compile(r"\S*?\.capa")
_POS = re.compile(r":\d+:\d+")
_VER = re.compile(r"\d+\.\d+\.\d+")
_MANIFEST_VOLATILE = frozenset({
    "content_integrity", "digest", "from_digest", "to_digest", "capa_version",
    "compiler_version", "generated_at", "timestamp", "source_path", "path", "source",
})


def manifest_of_source(src: str, name: str) -> dict:
    """The manifest document of one program, built in process by the
    compiler imported here: THE one way the instruments obtain a manifest
    (the manifest leg of the runner's child and the tests both use it).
    A program the checker refuses yields ``{"_status": "REFUSED"}``, a
    status the manifest differ never sees."""
    from capa import Lexer, Parser
    from capa.manifest import build_manifest
    res = check_source(src)
    if not res.ok:
        return {"_status": "REFUSED"}
    mod = Parser(Lexer(src).lex(), source=src).parse_module()
    return build_manifest(mod, filename=name, bindings=res.bindings, expr_labels=res.expr_labels)


def scrub_line(line: str) -> str:
    return _VER.sub("V", _POS.sub(":L:C", _PATH.sub("PATH", line))).strip()


def diagnostic_set(row: dict) -> tuple:
    """``(rc class, frozenset of scrubbed stderr lines)`` of a cli_check row."""
    lines = {scrub_line(l) for l in (row.get("stderr") or "").splitlines()}
    lines.discard("")
    o = row["outcome"]
    rc = "rc0" if o == OK else (outcome_type(o) if outcome_type(o) in NOT_RUN else "rc!=0")
    return rc, frozenset(lines)


def scrub_manifest(o):
    if isinstance(o, dict):
        return {k: scrub_manifest(v) for k, v in o.items() if k not in _MANIFEST_VOLATILE}
    if isinstance(o, list):
        return [scrub_manifest(x) for x in o]
    if isinstance(o, str):
        return _VER.sub("V", _PATH.sub("PATH", o))
    return o


def first_diff(a, b, path: str = ""):
    if type(a) is not type(b):
        return path or "/"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return path + "/" + k
            d = first_diff(a[k], b[k], path + "/" + k)
            if d:
                return d
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return path + "[len]"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, path + "[%d]" % i)
            if d:
                return d
        return None
    return None if a == b else (path or "/")


def check_half(tree, programs: list, bound: float = PROGRAM_BOUND_S) -> dict:
    rows = run_cli_leg(tree, "cli_check", programs, bound)
    return {name: diagnostic_set(row) for name, row in rows.items()}


def manifest_half(tree, programs: list, workdir, bound: float = PROGRAM_BOUND_S) -> dict:
    rows = run_leg(tree, "manifest", programs, bound, workdir)
    docs = {}
    for name, row in rows.items():
        if row["outcome"] == OK:
            docs[name] = json.loads(row["stdout"])
        else:
            docs[name] = {"_status": row["outcome"], "_detail": row.get("exc", "")[:200]}
    return docs


def diff_check(base: dict, cand: dict) -> dict:
    rc_moves, lost, gained = [], [], []
    for name in sorted(base):
        if name not in cand:
            continue
        (rb, sb), (rc, sc) = base[name], cand[name]
        if rb != rc:
            rc_moves.append((name, rb, rc))
        lost += [(name, l) for l in sorted(sb - sc)]
        gained += [(name, l) for l in sorted(sc - sb)]
    return {"rc_moves": rc_moves, "lost": lost, "gained": gained}


def _semantic(d: dict) -> int:
    s = d.get("summary", {})
    product = d.get("product", {})
    return (len(d.get("functions", [])) + len(d.get("added_functions", []))
            + len(d.get("removed_functions", [])) + len(d.get("grant_changes", []))
            + len(product.get("composed_added", [])) + len(product.get("composed_removed", []))
            + s.get("widenings", 0) + s.get("narrowings", 0)
            + (1 if s.get("authority_unknown_regression") else 0))


def diff_manifest(base: dict, cand: dict) -> dict:
    """Layer 1: scrubbed whole-document equality; layer 2: the compiler's
    own capability differ (the candidate's, imported here)."""
    from capa.manifest._diff import build_capability_diff
    layer1, layer2 = [], []
    for name in sorted(base):
        a, b = base[name], cand.get(name)
        if b is None:
            continue
        if "_status" in a or "_status" in b:
            if a != b:
                layer1.append((name, "status"))
            continue
        d = first_diff(scrub_manifest(a), scrub_manifest(b))
        if d:
            layer1.append((name, d))
        try:
            if _semantic(build_capability_diff(a, b)):
                layer2.append((name, "authority"))
        except Exception as e:
            layer2.append((name, "differ raised " + type(e).__name__))
    return {"layer1": layer1, "layer2": layer2}


def seeded_negative_corpus(directory) -> list:
    """The strict condition-position family written as files: programs
    that PRODUCE a diagnostic on a correct base, so a deletion shows."""
    return [program for program, _src, _verdict in write_programs(directory)]


def programs_in(directory) -> list:
    return [Program(p.name, p) for p in sorted(Path(directory).glob("*.capa"))]


def run(base_tree, cand_tree, programs: list, workdir) -> dict:
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    result = {"files": len(programs)}
    result["check"] = diff_check(check_half(base_tree, programs), check_half(cand_tree, programs))
    result["manifest"] = diff_manifest(manifest_half(base_tree, programs, workdir),
                                       manifest_half(cand_tree, programs, workdir))
    moved = any(result["check"].values()) or any(result["manifest"].values())
    result["verdict"] = "RED" if moved else "GREEN"
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("base_tree")
    ap.add_argument("candidate_tree")
    ap.add_argument("corpus", nargs="*")
    ap.add_argument("--work", default="release_differential_work")
    ap.add_argument("--no-seeded", action="store_true", help="omit the seeded negative corpus")
    args = ap.parse_args(argv)
    programs = []
    for d in args.corpus:
        programs += programs_in(d)
    if not args.no_seeded:
        programs += seeded_negative_corpus(Path(args.work) / "seeded")
    result = run(args.base_tree, args.candidate_tree, programs, args.work)
    c, m = result["check"], result["manifest"]
    print("files=%d rc_moves=%d lost_diagnostics=%d gained_diagnostics=%d manifest_facts=%d authority_changes=%d verdict=%s" % (
        result["files"], len(c["rc_moves"]), len(c["lost"]), len(c["gained"]),
        len(m["layer1"]), len(m["layer2"]), result["verdict"]))
    for item in (c["rc_moves"] + c["lost"] + c["gained"] + m["layer1"] + m["layer2"])[:40]:
        print("  ", item)
    return 0 if result["verdict"] == "GREEN" else 1


if __name__ == "__main__":
    sys.exit(main())
