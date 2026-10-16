"""How a program runs on a backend: ONE place.

Per LEG, one child process (``_leg_child``) runs the whole program list
with a per-program START and RESULT line; this parent times each program
and, on silence past the bound, kills the child, records TIMEOUT for that
program and that leg, and starts a fresh child from the next program.
Legs are separate children, so a hang on one leg never voids another
leg's rows. A leg absent for a program is never silently skipped: the
caller sees no row and treats that as BROKEN.

The child's provenance line is checked here against the tree and against
a hash computed independently in this process; a child whose line is
missing or differs voids its rows (VOID) rather than dropping them.

The command-line legs (``cli_check``, ``cli_run``, ``cli_ir``,
``cli_wasm``) run ``capa`` through ``_cli_child`` one subprocess per
program with the same bound and the same provenance check.

Every row: ``{"file", "leg", "outcome", "stdout", "stderr", "exc", "wall"}``
where ``outcome`` is an exit class (``OK`` / ``ABORT:<kind>``) or REFUSED /
TIMEOUT / BROKEN / VOID. The comparison with a rule is not made here.

The bound is a FIXED floor per (program, leg). The slowest program of the
public corpora measured 0.32 s under load on the development machine; a
hang costs about the bound plus a child restart per hanging (program,
leg).
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tests.instruments._outcome import BROKEN, REFUSED, TIMEOUT, VOID, exit_class_from_rc
from tests.instruments._provenance import REPO_ROOT, file_under, package_hash

HERE = Path(__file__).resolve().parent
LEG_CHILD = HERE / "_leg_child.py"
CLI_CHILD = HERE / "_cli_child.py"

#: Seconds a single (program, leg) may take before it is TIMEOUT.
PROGRAM_BOUND_S = 4.0

IN_PROCESS_LEGS = ("check", "run", "ir", "wasm", "manifest")
CLI_LEGS = {
    "cli_check": ["--check"],
    "cli_run": ["--run"],
    "cli_ir": ["--ir", "--run"],
    "cli_wasm": ["--wasm", "--run"],
}
#: The in-process leg each command-line route must agree with.
ROUTE_OF = {"cli_run": "run", "cli_ir": "ir", "cli_wasm": "wasm"}


@dataclass(frozen=True)
class Program:
    name: str
    path: Path
    cwd: Optional[Path] = None


def _child_env() -> dict:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env


def _python() -> list:
    return [sys.executable, "-I", "-X", "utf8"]


def _row(prog: Program, leg: str, outcome: str, stdout: str = "", stderr: str = "",
         exc: str = "", wall: float = 0.0, **extra) -> dict:
    r = {"file": prog.name, "leg": leg, "outcome": outcome, "stdout": stdout,
         "stderr": stderr, "exc": exc, "wall": wall}
    r.update(extra)
    return r


def _reader(proc, q) -> None:
    for line in proc.stdout:
        q.put(line)
    q.put(None)


def _record_row(prog: Program, leg: str, rec: dict) -> dict:
    phase = rec.get("phase")
    if phase == "check":
        return _row(prog, leg, "OK" if rec["ok"] else REFUSED, wall=rec["s"],
                    ok=rec["ok"], n_errors=rec["n_errors"], n_warnings=rec["n_warnings"],
                    ifc_errors=rec["ifc_errors"], ifc_warnings=rec["ifc_warnings"],
                    errors=rec.get("errors", []))
    if phase == "refused":
        return _row(prog, leg, REFUSED, wall=rec["s"], errors=rec.get("errors", []))
    if phase == "compile":
        return _row(prog, leg, BROKEN, exc=rec["exc"] + ": " + rec.get("msg", ""), wall=rec["s"])
    return _row(prog, leg, rec["exit_class"], stdout=rec["stdout"], stderr=rec.get("stderr", ""),
                exc=rec.get("exc_msg", ""), wall=rec["s"])


def run_leg(tree, leg: str, programs: list, bound: float = PROGRAM_BOUND_S,
            workdir=None, child: Path = LEG_CHILD) -> dict:
    """Drive one in-process leg over ``programs`` under the watchdog.
    Returns ``{name: row}``."""
    tree = os.path.abspath(str(tree))
    parent_hash = package_hash(tree)[0]
    workdir = Path(workdir) if workdir is not None else Path(programs[0].path).parent
    workdir.mkdir(parents=True, exist_ok=True)
    rows: dict = {}
    listfile = workdir / ("list_%s_%d.txt" % (leg, os.getpid()))
    try:
        _drive(tree, leg, programs, bound, listfile, child, parent_hash, rows)
    finally:
        if listfile.exists():
            listfile.unlink()
    return rows


def _release(proc, reader) -> None:
    """Reap a child however it ended and close both of its pipes, once the
    reader has drained stdout to its end."""
    if proc.poll() is None:
        proc.kill()
    proc.wait()
    reader.join(timeout=10)
    proc.stdout.close()
    proc.stderr.close()


def _drive(tree, leg, programs, bound, listfile, child, parent_hash, rows) -> None:
    i = 0
    while i < len(programs):
        with open(listfile, "w", encoding="utf-8") as fh:
            for p in programs[i:]:
                fh.write("%s\t%s\t%s\n" % (p.name, p.path, p.cwd or ""))
        proc = subprocess.Popen(
            _python() + [str(child), tree, leg, str(listfile)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_child_env(), text=True, encoding="utf-8", errors="replace",
        )
        q: queue.Queue = queue.Queue()
        reader = threading.Thread(target=_reader, args=(proc, q), daemon=True)
        reader.start()
        try:
            i = _consume(proc, q, leg, programs, i, bound, parent_hash, tree, rows)
        finally:
            _release(proc, reader)


def _consume(proc, q, leg, programs, i, bound, parent_hash, tree, rows) -> int:
    """Read one child's lines into ``rows`` from program ``i`` on; returns
    the index of the first program the next child must start from."""
    prov_ok = None
    current = None
    t_start = time.perf_counter()
    while True:
        try:
            line = q.get(timeout=bound)
        except queue.Empty:
            rows[programs[i].name] = _row(programs[i], leg, TIMEOUT,
                                          wall=time.perf_counter() - t_start)
            return i + 1
        if line is None:
            err = proc.stderr.read()
            if current is not None:
                rows[programs[i].name] = _row(
                    programs[i], leg, BROKEN,
                    exc="child exited rc=%s during the program: %s" % (proc.returncode, err[-400:]))
                i += 1
            else:
                for p in programs[i:]:
                    rows[p.name] = _row(p, leg, VOID,
                                        exc="child exited rc=%s before any program: %s" % (proc.returncode, err[-400:]))
                i = len(programs)
            return i
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if "prov" in rec:
            prov_ok = file_under(rec["prov"], tree) and rec["hash"] == parent_hash
            if not prov_ok:
                for p in programs[i:]:
                    rows[p.name] = _row(p, leg, VOID, exc="provenance %s" % json.dumps(rec))
                return len(programs)
            continue
        if "start" in rec:
            current = rec["start"]
            t_start = time.perf_counter()
            continue
        if prov_ok is not True or rec.get("file") != programs[i].name:
            rows[programs[i].name] = _row(programs[i], leg, VOID,
                                          exc="order/provenance %s" % json.dumps(rec)[:200])
            i += 1
            current = None
            continue
        rows[programs[i].name] = _record_row(programs[i], leg, rec)
        i += 1
        current = None
        if i >= len(programs):
            proc.wait(timeout=60)
            return i


def run_cli_leg(tree, leg: str, programs: list, bound: float = PROGRAM_BOUND_S,
                child: Path = CLI_CHILD) -> dict:
    """One ``capa`` subprocess per program for a command-line leg."""
    tree = os.path.abspath(str(tree))
    parent_hash = package_hash(tree)[0]
    flags = CLI_LEGS[leg]
    rows: dict = {}
    for p in programs:
        t0 = time.perf_counter()
        try:
            r = subprocess.run(
                _python() + [str(child), tree] + flags + [str(p.path)],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=bound,
                env=_child_env(), cwd=str(p.cwd or Path(p.path).parent),
            )
        except subprocess.TimeoutExpired:
            rows[p.name] = _row(p, leg, TIMEOUT, wall=bound)
            continue
        err = r.stderr.decode("utf-8", "replace")
        prov = [l for l in err.splitlines() if l.startswith("QPROV ")]
        fields = dict(part.split("=", 1) for part in prov[0].split(" ")[1:]) if prov else {}
        if fields.get("hash") != parent_hash or not file_under(fields.get("file", ""), tree):
            rows[p.name] = _row(p, leg, VOID, exc="provenance " + (prov[0] if prov else "missing"))
            continue
        body = "\n".join(l for l in err.splitlines() if not l.startswith("QPROV "))
        rows[p.name] = _row(p, leg, exit_class_from_rc(r.returncode),
                            stdout=r.stdout.decode("utf-8", "replace"), stderr=body,
                            wall=time.perf_counter() - t0)
    return rows


def run_legs(tree, legs, programs: list, bound: float = PROGRAM_BOUND_S, workdir=None,
             cli_programs: Optional[list] = None) -> dict:
    """``{(name, leg): row}`` for every program and every leg. Command-line
    legs run over ``cli_programs`` when given (the route sample), else all."""
    rows: dict = {}
    for leg in legs:
        if leg in CLI_LEGS:
            sample = programs if cli_programs is None else cli_programs
            got = run_cli_leg(tree, leg, sample, bound)
        else:
            got = run_leg(tree, leg, programs, bound, workdir)
        for name, row in got.items():
            rows[(name, leg)] = row
    return rows


def route_divergences(rows: dict, programs: list, cli_leg: str) -> tuple:
    """The ROUTE-AGREEMENT check: for every sampled program, the normalised
    vector of the command-line route must equal the in-process route's.
    Rows whose in-process leg did not run the program (BROKEN, TIMEOUT,
    VOID, REFUSED) are not comparable and are reported apart: the
    command line falls back where the in-process emitter refuses, by
    design. Returns ``(divergences, not_comparable)``. What this sees: a
    route that produces a different result from the in-process leg. It
    cannot see a route swap between two executors that agree."""
    from tests.instruments._outcome import NOT_RUN, norm_text, outcome_type
    inproc = ROUTE_OF[cli_leg]
    divergences, not_comparable = [], []
    for p in programs:
        a, b = rows.get((p.name, inproc)), rows.get((p.name, cli_leg))
        if a is None or b is None:
            continue
        if outcome_type(a["outcome"]) in NOT_RUN:
            not_comparable.append((p.name, a["outcome"]))
            continue
        va = (outcome_type(a["outcome"]), norm_text(a["stdout"]))
        vb = (outcome_type(b["outcome"]), norm_text(b["stdout"]))
        if va != vb:
            divergences.append((p.name, inproc, va[0], cli_leg, vb[0], va[1] != vb[1]))
    return divergences, not_comparable


def default_tree() -> Path:
    return REPO_ROOT
