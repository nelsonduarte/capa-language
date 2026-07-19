#!/usr/bin/env python3
"""Smoke-test a built `capa` binary across the commands that FREEZING
can break, rather than only the ones that happen to have broken.

Run as::

    python deploy/binary_smoke_test.py dist/capa           # Linux / macOS
    python deploy/binary_smoke_test.py dist/capa.exe       # Windows
    python deploy/binary_smoke_test.py dist/capa v1.18.1   # also pin the
                                                           # reported version

WHY THIS EXISTS. Until 1.18.1 the release smoke test ran `--check` and
`--run` on one example. Both are pure in-process compilation, so they
prove the bundle imports and the pipeline works and almost nothing
else. `capa test` was never exercised against a frozen binary, and it
was completely broken in every released binary: it spawned
``sys.executable -m capa``, which under PyInstaller is the capa binary
itself, which rejects ``-m``. Every test failed for every user who
installed the recommended way. The hazard was even documented in
`capa/cli.py`, and had simply reappeared in two other places.

So the rule this file follows is: cover what a frozen binary can
SILENTLY DIFFER on, not the bug we already fixed. That is anything
depending on something other than "parse and analyse text in memory":

  * re-invoking itself as a subprocess  -> `capa test` (the 1.18.1 bug)
  * bundled distribution metadata       -> `capa --version`
  * writing a project to disk           -> `capa init`
  * reading `capa.toml` back            -> `capa install`,
                                           `capa --check-capabilities`
  * a bundled optional dependency       -> `capa repl` (and `capa lsp`,
                                           covered by lsp_smoke_test.py)
  * exit codes crossing the boundary    -> a deliberately FAILING test
                                           and a violated ceiling, both
                                           of which must exit non-zero

Each check runs the binary as a user would, from a temporary project,
and asserts on the exit code and the output. Driven from the runner's
own Python (not the bundled interpreter) so one script serves the
three release platforms with no shell-quoting differences, matching
`deploy/lsp_smoke_test.py`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


TIMEOUT = 180  # generous: a onefile binary self-extracts on every run


class SmokeFailure(Exception):
    """A check did not hold. Carries the message shown to the user."""


def run(binary: str, args: list[str], *, cwd: str | None = None,
        stdin: str | None = None) -> subprocess.CompletedProcess:
    """Invoke the binary and return the completed process. Never
    raises on a non-zero exit: the exit code is what most of these
    checks are about."""
    print(f"  $ capa {' '.join(args)}", flush=True)
    return subprocess.run(
        [binary, *args],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
    )


def expect(cond: bool, message: str, proc: subprocess.CompletedProcess) -> None:
    if cond:
        return
    raise SmokeFailure(
        f"{message}\n"
        f"    exit code: {proc.returncode}\n"
        f"    stdout: {proc.stdout.strip()[:2000]}\n"
        f"    stderr: {proc.stderr.strip()[:2000]}"
    )


def expect_ok(proc: subprocess.CompletedProcess, what: str) -> None:
    expect(proc.returncode == 0, f"{what}: expected exit 0", proc)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------
# The checks
# ---------------------------------------------------------------

def check_version(binary: str, expect_version: str | None) -> None:
    p = run(binary, ["--version"])
    expect_ok(p, "--version")
    out = (p.stdout + p.stderr).strip()
    expect(out.startswith("capa "), "--version: unexpected output shape", p)
    # `capa.__version__` reads pyproject.toml from a source checkout and
    # falls back to importlib.metadata inside the bundle. When the spec
    # fails to copy the dist-info, that fallback yields the sentinel and
    # every released binary reports a version nobody can match to a tag.
    expect("0+unknown" not in out,
           "--version: reports the sentinel version, so the bundle is "
           "missing capa's dist-info metadata", p)
    if expect_version is None:
        return
    # In the release workflow the tag is known, so the check can be the
    # strong one. The release-guards clean room asserts the same
    # property about a DOWNLOADED compiler, which is one release too
    # late to stop a binary reporting a version nobody can match.
    expect(out == f"capa {expect_version}",
           f"--version: reports {out!r}, expected 'capa {expect_version}' "
           f"(the bundled dist-info is from a different build)", p)


def check_compile_surface(binary: str, repo: Path) -> None:
    hello = str(repo / "examples" / "hello.capa")
    expect_ok(run(binary, ["--check", hello]), "--check")
    p = run(binary, ["--run", hello])
    expect_ok(p, "--run")
    p = run(binary, ["--manifest", hello])
    expect_ok(p, "--manifest")
    try:
        json.loads(p.stdout)
    except json.JSONDecodeError as e:
        raise SmokeFailure(f"--manifest: output is not valid JSON ({e})")


def check_repl(binary: str) -> None:
    # The REPL re-synthesises and re-runs a `main` per turn, which is a
    # different execution path from `--run`; drive it over a pipe.
    p = run(binary, ["repl"], stdin="let x = 1 + 1\nx\n")
    expect_ok(p, "repl")
    expect("2" in p.stdout, "repl: did not evaluate `1 + 1`", p)


def check_init_and_project(binary: str, workdir: Path) -> Path:
    p = run(binary, ["init", "proj"], cwd=str(workdir))
    expect_ok(p, "init")
    project = workdir / "proj"
    for name in ("main.capa", "capa.toml", "README.md", ".capa-version"):
        if not (project / name).exists():
            raise SmokeFailure(f"init: scaffolded project has no {name}")
    # The scaffolded program must satisfy the compiler that scaffolded it.
    expect_ok(run(binary, ["--check", "main.capa"], cwd=str(project)),
              "--check on the scaffolded project")
    expect_ok(run(binary, ["--run", "main.capa"], cwd=str(project)),
              "--run on the scaffolded project")
    # No dependencies to fetch, so this exercises manifest reading and
    # lockfile writing without needing the network.
    expect_ok(run(binary, ["install"], cwd=str(project)), "install")
    if not (project / "capa.lock").exists():
        raise SmokeFailure("install: no capa.lock was written")
    return project


def check_test_command(binary: str, project: Path) -> None:
    """THE regression this release exists for, plus the exit-code
    contract around it. A frozen binary that cannot spawn itself fails
    every test, so a green `capa test` here is only meaningful next to a
    red one: we assert a passing suite passes AND a failing test fails."""
    write(project / "tests" / "test_pass.capa",
          'fun main(stdio: Stdio)\n'
          '    stdio.println("test ok")\n')
    p = run(binary, ["test"], cwd=str(project))
    expect_ok(p, "test (all passing)")
    expect("1 test(s): 1 passed, 0 failed" in p.stdout,
           "test: unexpected summary for an all-passing project", p)

    # A test that panics must be REPORTED as a failure and must make the
    # command exit non-zero, and its stderr must survive the trip back
    # through the child process into the report.
    write(project / "tests" / "test_fail.capa",
          'fun main(stdio: Stdio)\n'
          '    stdio.println("before the boom")\n'
          '    panic("boom")\n')
    p = run(binary, ["test"], cwd=str(project))
    expect(p.returncode == 1, "test (one failing): expected exit 1", p)
    expect("2 test(s): 1 passed, 1 failed" in p.stdout,
           "test: unexpected summary with one failing test", p)
    expect("boom" in p.stdout,
           "test: the failing test's panic message never reached the "
           "report, so child output is being lost", p)
    (project / "tests" / "test_fail.capa").unlink()


def check_capability_ceiling(binary: str, project: Path) -> None:
    """`--check-capabilities` reads capa.toml and walks the package
    tree, so it fails differently from `--check` when a bundle is
    wrong. Checked in both directions: a ceiling that holds and one
    that does not."""
    manifest = project / "capa.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8")
        + '\n[capabilities]\nmax = ["Stdio"]\n',
        encoding="utf-8",
    )
    p = run(binary, ["--check-capabilities", "main.capa"], cwd=str(project))
    expect_ok(p, "--check-capabilities on a program within its ceiling")
    expect("OK" in (p.stdout + p.stderr),
           "--check-capabilities: no OK line for a holding ceiling", p)

    write(project / "over.capa",
          'fun main(fs: Fs, stdio: Stdio)\n'
          '    match fs.read("capa.toml")\n'
          '        Ok(text) -> stdio.println(text)\n'
          '        Err(e) -> stdio.println(e)\n')
    p = run(binary, ["--check-capabilities", "over.capa"], cwd=str(project))
    expect(p.returncode != 0,
           "--check-capabilities: a program exceeding its ceiling was "
           "accepted", p)


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 3:
        print("usage: binary_smoke_test.py <path-to-capa-binary> "
              "[expected-version]", file=sys.stderr)
        return 64  # EX_USAGE
    expect_version = argv[2].lstrip("v") if len(argv) == 3 else None

    # Absolute: on Windows, CreateProcess does not resolve a relative
    # command name against the working directory, and every check below
    # runs from a temporary directory anyway.
    binary = os.path.abspath(argv[1])
    if not os.path.isfile(binary):
        print(f"binary smoke test FAILED: binary not found: {binary}",
              file=sys.stderr)
        return 1
    repo = Path(__file__).resolve().parent.parent

    with tempfile.TemporaryDirectory(prefix="capa_smoke_") as td:
        workdir = Path(td)
        try:
            print("version + metadata")
            check_version(binary, expect_version)
            print("compile surface")
            check_compile_surface(binary, repo)
            print("repl")
            check_repl(binary)
            print("init + install")
            project = check_init_and_project(binary, workdir)
            print("capa test")
            check_test_command(binary, project)
            print("capability ceiling")
            check_capability_ceiling(binary, project)
        except SmokeFailure as e:
            print(f"\nbinary smoke test FAILED: {e}", file=sys.stderr)
            return 1
        except subprocess.TimeoutExpired as e:
            print(f"\nbinary smoke test FAILED: timed out after "
                  f"{e.timeout}s running {e.cmd}", file=sys.stderr)
            return 1

    print("\nbinary smoke test PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
