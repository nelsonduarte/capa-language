"""Shared helpers for the fuzz / cve / runtime harnesses.

Three concerns:

- ``run_capa``: invoke ``python -m capa`` as a subprocess against
  source on disk, returning exit code + captured stdout/stderr.
  Used by the fuzz harness against transient ``.capa`` files.
- ``write_csv``: emit a list-of-dicts to a CSV file with stable
  header order. The harnesses all share the same idiom of one row
  per atomic measurement, then aggregate downstream.
- ``timed_subprocess``: wall-time wrapper that returns
  ``(result, seconds)``. Used by the runtime harness for cold-start
  measurements.

The helpers stay deliberately small (no async, no parallelism, no
fancy retry logic) so the harness behaviour is easy to reason about
when a fuzz attempt produces an unexpected result. Each harness
that needs more sophistication can layer on top.
"""

from __future__ import annotations

import csv
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class CapaRun:
    """Result of one ``python -m capa`` invocation."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def combined(self) -> str:
        # The capa CLI writes diagnostics to stderr in some paths
        # and stdout in others. The fuzz harness only cares about
        # rejected-vs-accepted, so joining the two streams keeps
        # rejection-reason matching uniform.
        return (self.stdout + self.stderr).strip()


def repo_root() -> Path:
    """Locate the Capa repository root (the directory containing
    the ``capa/`` package and the ``.venv/`` venv). Resolves from
    this file's location, so the helpers work regardless of the
    caller's cwd."""
    return Path(__file__).resolve().parents[2]


def python_executable() -> str:
    """Path to the venv Python the harness should invoke ``capa``
    with. Falls back to ``sys.executable`` if the standard venv
    location is missing, which lets the harness run in CI / fresh
    clones without a separate config knob."""
    venv_py = repo_root() / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return str(venv_py)
    venv_py_nix = repo_root() / ".venv" / "bin" / "python"
    if venv_py_nix.exists():
        return str(venv_py_nix)
    return sys.executable


def run_capa(
    mode: str,
    source_path: Path,
    extra: Iterable[str] = (),
    timeout_s: float = 30.0,
) -> CapaRun:
    """Invoke ``python -m capa <mode> <source_path> <extra...>``.

    ``mode`` is the primary flag (``--check``, ``--run``,
    ``--transpile``, ...). Returns a ``CapaRun`` even on timeout
    (returncode=-1, stderr noting the timeout) so callers can
    record the outcome uniformly.
    """
    cmd = [python_executable(), "-m", "capa", mode, str(source_path), *extra]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=repo_root(),
        )
    except subprocess.TimeoutExpired as e:
        return CapaRun(
            returncode=-1,
            stdout=e.stdout.decode("utf-8", errors="replace") if e.stdout else "",
            stderr=(
                (e.stderr.decode("utf-8", errors="replace") if e.stderr else "")
                + f"\n[harness] timeout after {timeout_s}s"
            ),
        )
    return CapaRun(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def timed_subprocess(cmd: list[str], timeout_s: float = 60.0) -> tuple[
    subprocess.CompletedProcess, float,
]:
    """Run a command, return the result and wall-time seconds.
    Used by the runtime harness; timing precision is the host
    process's clock (sufficient for cold-start measurements which
    are dominated by interpreter / wasmtime spin-up cost)."""
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout_s,
    )
    elapsed = time.perf_counter() - start
    return proc, elapsed


def write_csv(path: Path, rows: list[dict], header: list[str]) -> None:
    """Emit ``rows`` to ``path`` as CSV with the given header order.
    Creates parent directories as needed. Overwrites; the harnesses
    treat their CSV output as a build artefact, not an append log."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in header})
