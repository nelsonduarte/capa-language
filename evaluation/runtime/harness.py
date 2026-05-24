"""Macro-scale runtime harness: Capa --python vs Capa --wasm.

For each macro workload, runs ``python -m capa --run <prog>.capa``
and ``python -m capa --wasm --run <prog>.capa`` as subprocesses,
N trials each, recording wall-clock and peak RSS.

Why subprocesses (not in-process timing): the macros are full
end-to-end programs with their own ``main()``; they take CLI
args, read input files, write output files. Subprocess timing
captures the full user-visible cost (interpreter spin-up,
parse+analyze+transpile / parse+analyze+emit-wasm, exec, output
flush) which is exactly what someone shipping a Capa CLI tool
cares about.

The harness is deliberately conservative: each trial is its own
fresh subprocess, no shared state, output files written to a
temp directory per trial. RSS is sampled via ``psutil.Process``
at ~100Hz from a sidecar thread; the peak across the run is
recorded.

Workloads live in ``evaluation/runtime/workloads.py``. They
hard-code paths to the downstream demo repos (which Nelson keeps
under ``~/Desktop/repos/`` per ``project_repo_layout`` memory).
Missing repos are skipped with a warning, so the harness runs
on any machine that has the demos cloned without rewriting
config.

Out of scope for this slice: hand-Python and Node.js baselines.
Those will land as a follow-up; the headline number for the
paper -- "what does Wasm overhead look like at macro scale?" --
needs only the two Capa columns.

Usage:
    python -m evaluation.runtime.harness --trials 3
"""

from __future__ import annotations

import argparse
import csv
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from evaluation.runtime.workloads import (
    BACKEND_CAPA_PYTHON, BACKEND_CAPA_WASM, WORKLOADS, Workload,
)
from evaluation.shared.runner_utils import python_executable, repo_root


@dataclass
class Trial:
    """One subprocess invocation result."""

    workload: str
    backend: str
    trial: int
    seconds: float
    peak_rss_mb: float
    returncode: int
    stdout_bytes: int
    stderr_bytes: int


def _sample_rss(proc: subprocess.Popen, peak: list[float], stop: threading.Event) -> None:
    """Background sampler: polls the subprocess RSS until it
    exits or the stop flag fires. Records the max into peak[0].
    No-ops if psutil is unavailable."""
    if psutil is None:
        return
    try:
        p = psutil.Process(proc.pid)
    except psutil.NoSuchProcess:
        return
    while not stop.is_set() and proc.poll() is None:
        try:
            rss = p.memory_info().rss / (1024 * 1024)  # MB
            if rss > peak[0]:
                peak[0] = rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return
        time.sleep(0.01)


def _run_once(
    workload: Workload, backend: str, trial: int, scratch: Path,
) -> Trial:
    """Run one trial of one (workload, backend) pair. Output dir
    is a per-trial subdir of ``scratch`` so different runs do not
    overwrite each other's reports."""
    out_dir = scratch / f"{workload.name}_{backend}_{trial}"
    out_dir.mkdir(parents=True, exist_ok=True)

    py = python_executable()
    base_cmd = [py, "-m", "capa"]
    if backend == BACKEND_CAPA_WASM:
        base_cmd.append("--wasm")
    base_cmd.extend(["--run", workload.entry])
    if workload.args:
        # Args after `--` are forwarded to the Capa program.
        base_cmd.append("--")
        base_cmd.extend(workload.args)
        base_cmd.extend(["-o", str(out_dir)])

    start = time.perf_counter()
    proc = subprocess.Popen(
        base_cmd,
        cwd=workload.cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    peak = [0.0]
    stop = threading.Event()
    sampler = threading.Thread(
        target=_sample_rss, args=(proc, peak, stop), daemon=True,
    )
    sampler.start()
    try:
        stdout, stderr = proc.communicate(timeout=workload.timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    elapsed = time.perf_counter() - start
    stop.set()
    sampler.join(timeout=1.0)

    return Trial(
        workload=workload.name,
        backend=backend,
        trial=trial,
        seconds=elapsed,
        peak_rss_mb=peak[0],
        returncode=proc.returncode,
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
    )


@dataclass
class Aggregate:
    """Per-(workload, backend) aggregate across trials."""

    workload: str
    backend: str
    n_trials: int
    seconds_mean: float
    seconds_min: float
    seconds_max: float
    seconds_stdev: float
    rss_mb_max: float
    n_ok: int


def _aggregate(trials: list[Trial]) -> list[Aggregate]:
    by_key: dict[tuple[str, str], list[Trial]] = {}
    for t in trials:
        by_key.setdefault((t.workload, t.backend), []).append(t)
    out: list[Aggregate] = []
    for (workload, backend), ts in sorted(by_key.items()):
        secs = [t.seconds for t in ts]
        out.append(Aggregate(
            workload=workload,
            backend=backend,
            n_trials=len(ts),
            seconds_mean=statistics.mean(secs),
            seconds_min=min(secs),
            seconds_max=max(secs),
            seconds_stdev=statistics.stdev(secs) if len(secs) > 1 else 0.0,
            rss_mb_max=max(t.peak_rss_mb for t in ts),
            n_ok=sum(1 for t in ts if t.returncode == 0),
        ))
    return out


def _print_summary(aggs: list[Aggregate]) -> None:
    print()
    print(
        f"{'workload':<28} {'backend':<14} "
        f"{'n_ok':>5} {'mean (s)':>10} {'min':>8} {'max':>8} "
        f"{'rss (MB)':>10}"
    )
    print("-" * 88)
    for a in aggs:
        marker = "  " if a.n_ok == a.n_trials else "! "
        print(
            f"{marker}{a.workload:<26} {a.backend:<14} "
            f"{a.n_ok:>2}/{a.n_trials:<2}  "
            f"{a.seconds_mean:>8.3f}   {a.seconds_min:>6.3f}   "
            f"{a.seconds_max:>6.3f}   {a.rss_mb_max:>8.1f}"
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--trials", type=int, default=3,
        help="trials per (workload, backend) pair (default: 3)",
    )
    p.add_argument(
        "--workload",
        choices=sorted(WORKLOADS.keys()),
        help="run only this workload (default: all)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "results.csv",
    )
    args = p.parse_args(argv)

    if psutil is None:
        print(
            "[runtime] psutil not installed; RSS column will read 0. "
            "Install with `pip install psutil`.",
            file=sys.stderr,
        )

    chosen = [WORKLOADS[args.workload]] if args.workload else list(WORKLOADS.values())
    backends = [BACKEND_CAPA_PYTHON, BACKEND_CAPA_WASM]

    # Skip workloads whose cwd does not exist (e.g. running on CI
    # without the downstream demo repos cloned).
    runnable: list[Workload] = []
    for w in chosen:
        if not Path(w.cwd).exists():
            print(
                f"[runtime] SKIP {w.name}: cwd {w.cwd} not found",
                file=sys.stderr,
            )
            continue
        runnable.append(w)

    if not runnable:
        print("[runtime] no workloads runnable on this machine.", file=sys.stderr)
        return 0

    with tempfile.TemporaryDirectory(prefix="capa-runtime-") as scratch_str:
        scratch = Path(scratch_str)
        trials: list[Trial] = []
        for w in runnable:
            for backend in backends:
                print(f"[runtime] {w.name} / {backend}", flush=True)
                for i in range(args.trials):
                    t = _run_once(w, backend, i, scratch)
                    print(
                        f"  trial {i}: {t.seconds:6.3f}s  "
                        f"rss={t.peak_rss_mb:6.1f}MB  rc={t.returncode}"
                    )
                    trials.append(t)

    aggs = _aggregate(trials)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "workload", "backend", "n_trials", "n_ok",
            "seconds_mean", "seconds_min", "seconds_max",
            "seconds_stdev", "rss_mb_max",
        ])
        for a in aggs:
            w.writerow([
                a.workload, a.backend, a.n_trials, a.n_ok,
                f"{a.seconds_mean:.4f}", f"{a.seconds_min:.4f}",
                f"{a.seconds_max:.4f}", f"{a.seconds_stdev:.4f}",
                f"{a.rss_mb_max:.2f}",
            ])

    _print_summary(aggs)
    print(f"\n[runtime] wrote {args.out}")
    n_fail = sum(1 for a in aggs if a.n_ok != a.n_trials)
    return 0 if n_fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
