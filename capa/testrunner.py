"""``capa test``: discover and run Capa test programs.

Discovery: ``tests/test_*.capa`` directly under the project root,
sorted by file name (deterministic order). The project root is the
nearest ancestor of the starting directory that contains
``capa.toml``, or the starting directory itself when no manifest
is found.

Each test file is a regular Capa program executed through the same
pipeline as ``capa --run <file>``: a fresh ``python -m capa``
subprocess with cwd = project root, so module resolution through
``capa.toml`` (vendored deps, dev-deps, path deps) works exactly
as it does for ``capa --run``. On top of that, the runner prepends
the project root and its parent to ``CAPA_PATH`` for the child, so
both layouts in the wild resolve with zero configuration:

  * flat projects (``import mylib`` -> ``<root>/mylib.capa``), and
  * package-style test suites (``import mypkg.model`` ->
    ``<root>/../mypkg/model.capa``, the seed-library convention of
    running ``CAPA_PATH=.. capa --run tests/test_x.capa``).

**Result contract.** Exit code 0 means the test passed; anything
else means it failed. ``main``'s return value is ignored by the
bootstrap on both backends, so a Capa program's exit code is 0
exactly when ``main`` runs to completion and non-zero (1) when it
aborts: a deliberate ``panic("message")`` (the recommended way for
a test to fail; the message lands on stderr, which the runner
shows inline) or a runtime error escaping ``main`` (division by
zero, an out-of-bounds index, a Wasm trap, an uncaught host
error).

**Backends.** The default runs the Python pipeline. ``--wasm``
runs ``capa --wasm --run`` instead. ``--both`` runs every test on
BOTH backends and, beyond requiring both to exit 0, diffs their
stdout: passing runs whose output diverges are reported as a
failure of their own kind (DIVERGED) with a unified diff. This is
the cross-backend parity check the dual-backend architecture is
for.

Dev-dependencies declared in ``capa.toml`` but not yet vendored
are reported up front with a pointer at ``capa install``; the
runner never installs anything by itself.
"""

from __future__ import annotations

import difflib
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TextIO


TESTS_DIRNAME = "tests"
TEST_GLOB = "test_*.capa"

# Statuses a single test file can end in. PASS keeps the lowercase
# "ok" spelling on the report line (unittest convention); the two
# failure kinds are uppercase so they jump out of a long run.
_STATUS_OK = "ok"
_STATUS_FAIL = "FAIL"
_STATUS_DIVERGED = "DIVERGED"


@dataclass
class TestOutcome:
    """Result of one test file run (on one backend or on both)."""
    file: Path
    status: str          # _STATUS_OK / _STATUS_FAIL / _STATUS_DIVERGED
    duration: float      # seconds, wall clock, all backends included
    detail: str = ""     # captured output / diff; shown for failures

    @property
    def passed(self) -> bool:
        return self.status == _STATUS_OK


def find_project_root(start: Path) -> Path:
    """The nearest ancestor of ``start`` (inclusive) that contains
    ``capa.toml``; ``start`` itself when no manifest is found. The
    same walk-up convention as git's repo discovery, so ``capa
    test`` works from any subdirectory of a project."""
    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / "capa.toml").is_file():
            return candidate
    return start


def discover_tests(root: Path) -> list[Path]:
    """``tests/test_*.capa`` directly under ``root``, sorted by file
    name. Non-recursive: nested directories under ``tests/`` are
    free for fixtures and helpers without being picked up."""
    tests_dir = root / TESTS_DIRNAME
    if not tests_dir.is_dir():
        return []
    return sorted(
        (p for p in tests_dir.glob(TEST_GLOB) if p.is_file()),
        key=lambda p: p.name,
    )


def missing_vendored_deps(root: Path) -> list[str]:
    """Names of git deps (regular + dev) declared in ``capa.toml``
    whose ``vendor/<name>`` directory does not exist. Empty when
    there is no manifest. Raises ``ManifestError`` on a broken
    manifest so the caller can surface it instead of running tests
    against a half-configured project."""
    manifest_path = root / "capa.toml"
    if not manifest_path.is_file():
        return []
    from capa.pkg import read_manifest
    manifest = read_manifest(manifest_path)
    missing: list[str] = []
    for dep in manifest.dependencies + manifest.dev_dependencies:
        if dep.is_git and not (root / "vendor" / dep.name).is_dir():
            missing.append(dep.name)
    return missing


def _child_env(root: Path) -> dict:
    """Environment for a test subprocess: ``CAPA_PATH`` gains the
    project root (flat ``import mylib`` layouts) and its parent
    (package-style ``import mypkg.module``, the seed-library
    ``CAPA_PATH=..`` convention). Existing entries keep priority
    losses minimal: ours are prepended, the user's follow."""
    env = dict(os.environ)
    parts = [str(root), str(root.parent)]
    existing = env.get("CAPA_PATH", "")
    if existing:
        parts.append(existing)
    env["CAPA_PATH"] = os.pathsep.join(parts)
    return env


def _run_file(
    test_file: Path, root: Path, *, wasm: bool,
) -> tuple[int, str, str]:
    """Run one test program exactly like ``capa --run`` (or ``capa
    --wasm --run``) would, in a fresh interpreter with cwd = project
    root. Returns ``(exit_code, stdout, stderr)``."""
    cmd = [sys.executable, "-m", "capa"]
    if wasm:
        cmd.append("--wasm")
    cmd += ["--run", str(test_file)]
    r = subprocess.run(
        cmd,
        cwd=str(root),
        env=_child_env(root),
        capture_output=True, text=True, encoding="utf-8",
        errors="replace",
    )
    return r.returncode, r.stdout or "", r.stderr or ""


def _captured_block(rc: int, stdout: str, stderr: str, label: str = "") -> str:
    """Render a failed run's captured output for the report."""
    suffix = f" [{label}]" if label else ""
    lines = [f"exit code {rc}{suffix}"]
    if stdout.strip():
        lines.append("--- captured stdout ---")
        lines.extend(stdout.rstrip("\n").splitlines())
    if stderr.strip():
        lines.append("--- captured stderr ---")
        lines.extend(stderr.rstrip("\n").splitlines())
    return "\n".join(lines)


def _run_single_backend(
    test_file: Path, root: Path, *, wasm: bool,
) -> TestOutcome:
    started = time.perf_counter()
    rc, out, err = _run_file(test_file, root, wasm=wasm)
    duration = time.perf_counter() - started
    if rc == 0:
        return TestOutcome(test_file, _STATUS_OK, duration)
    return TestOutcome(
        test_file, _STATUS_FAIL, duration,
        detail=_captured_block(rc, out, err),
    )


def _run_both_backends(test_file: Path, root: Path) -> TestOutcome:
    """Run on Python and Wasm; pass requires BOTH to exit 0 AND
    byte-identical stdout. stderr is excluded from the diff on
    purpose: it carries backend-specific diagnostics (tracebacks,
    wasmtime frames) even for healthy programs."""
    started = time.perf_counter()
    rc_py, out_py, err_py = _run_file(test_file, root, wasm=False)
    rc_wasm, out_wasm, err_wasm = _run_file(test_file, root, wasm=True)
    duration = time.perf_counter() - started

    blocks = []
    if rc_py != 0:
        blocks.append(_captured_block(rc_py, out_py, err_py, "python"))
    if rc_wasm != 0:
        blocks.append(_captured_block(rc_wasm, out_wasm, err_wasm, "wasm"))
    if blocks:
        return TestOutcome(
            test_file, _STATUS_FAIL, duration, detail="\n".join(blocks),
        )

    if out_py != out_wasm:
        diff = "\n".join(difflib.unified_diff(
            out_py.splitlines(),
            out_wasm.splitlines(),
            fromfile="python backend",
            tofile="wasm backend",
            lineterm="",
        ))
        return TestOutcome(
            test_file, _STATUS_DIVERGED, duration,
            detail=(
                "both backends exited 0 but their stdout differs:\n"
                + diff
            ),
        )
    return TestOutcome(test_file, _STATUS_OK, duration)


def _indent(text: str, prefix: str = "  ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def run_tests(
    root: Path,
    mode: str = "python",
    out: Optional[TextIO] = None,
    err: Optional[TextIO] = None,
) -> int:
    """Discover and run every test under ``root``. ``mode`` is one
    of ``python`` / ``wasm`` / ``both``. Prints one line per file,
    failure details inline, and a final summary. Returns 0 when
    every test passed, 1 when any failed (or diverged), 2 on a
    configuration problem (no tests, unvendored deps, broken
    manifest)."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr

    from capa.pkg import ManifestError
    try:
        missing = missing_vendored_deps(root)
    except ManifestError as e:
        print(f"capa test: broken capa.toml: {e}", file=err)
        return 2
    if missing:
        names = ", ".join(missing)
        print(
            f"capa test: dependencies declared in capa.toml are not "
            f"vendored yet: {names}. Run `capa install` first.",
            file=err,
        )
        return 2

    tests = discover_tests(root)
    if not tests:
        print(
            f"capa test: no test files ({TESTS_DIRNAME}/{TEST_GLOB}) "
            f"found under {root}",
            file=err,
        )
        return 2

    backend_label = {
        "python": "python", "wasm": "wasm", "both": "python+wasm",
    }[mode]
    print(
        f"capa test: {len(tests)} file(s) under "
        f"{root / TESTS_DIRNAME} [backend: {backend_label}]",
        file=out,
    )

    outcomes: list[TestOutcome] = []
    for test_file in tests:
        if mode == "both":
            outcome = _run_both_backends(test_file, root)
        else:
            outcome = _run_single_backend(
                test_file, root, wasm=(mode == "wasm"),
            )
        outcomes.append(outcome)
        print(
            f"{test_file.name} ... {outcome.status} "
            f"({outcome.duration:.2f}s)",
            file=out,
        )
        if not outcome.passed and outcome.detail:
            print(_indent(outcome.detail), file=out)

    n_passed = sum(1 for o in outcomes if o.passed)
    n_failed = len(outcomes) - n_passed
    n_diverged = sum(1 for o in outcomes if o.status == _STATUS_DIVERGED)
    summary = f"{len(outcomes)} test(s): {n_passed} passed, {n_failed} failed"
    if n_diverged:
        summary += f" ({n_diverged} diverged)"
    print(summary, file=out)
    return 0 if n_failed == 0 else 1
