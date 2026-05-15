"""Capa REPL.

Interactive read-eval-print loop. Each user input is appended to
the running program; the full accumulated program is re-lexed,
re-parsed, re-analysed, re-transpiled and re-executed on every
turn, with stdout diffed so the user only sees the *new* output.

This is the MVP REPL: pragmatic, not optimised. Re-running the
whole program on every input is wasteful but stays correct as
state accumulates. A future iteration could maintain an
incremental analyzer state and exec each input into a persistent
Python namespace; that is a substantial change and out of MVP
scope.

What the REPL accepts on each input:

- **Top-level items** (``fun``, ``type``, ``trait``,
  ``capability``, ``impl``, ``const``, ``import``): appended to
  the program's top level.
- **Statements** (``let``, ``var``, assignment, ``if`` / ``for``
  / ``while`` blocks): appended to the body of an implicit
  ``main(stdio: Stdio)`` function.
- **Bare expressions**: auto-wrapped as
  ``stdio.println("${<expr>}")`` so the value is shown.

Meta commands (start with a dot):

- ``.exit`` / ``.quit`` / Ctrl-D: leave the REPL.
- ``.reset``: clear all accumulated state and start over.
- ``.show``: print the current accumulated program.
- ``.help``: show this list.

Pre-bound capabilities in the synthesised ``main``:

- ``stdio: Stdio``, the printing surface.
- ``fs: Fs``, ``net: Net``, ``env: Env``, ``clock: Clock``,
  ``random: Random``: the rest of the built-in capabilities,
  ready to be invoked directly from the REPL prompt.

``Unsafe`` is deliberately not pre-bound; it has to be requested
explicitly the same way it would be in production code (declare
a function that takes ``Unsafe`` and call it from the REPL).

Limitations:

- Continuation / multi-line input is not supported in v1;
  declarations must fit on a single logical "line" (with
  indented blocks delimited by blank-line termination).
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
from typing import Optional

from .analyzer import analyze
from .lexer import Lexer, LexerError
from .parser import Parser
from .transpiler import transpile


# Synthesised main's signature. Every standard built-in capability
# is pre-bound under its conventional lowercase name so users can
# call ``fs.allows(...)``, ``net.allows(...)``, ``clock.now_secs()``,
# etc. directly at the prompt. ``Unsafe`` is left out: it is the
# explicit escape hatch and should keep requiring intent.
_REPL_MAIN_HEADER = (
    "fun main(stdio: Stdio, fs: Fs, net: Net, env: Env, "
    "clock: Clock, random: Random)"
)

# One probe per pre-bound capability so the analyzer's
# "declared but never used" check passes even if the user has not
# touched a given capability yet. The probes are pure-or-near-pure
# read-only calls; their return values are discarded as expression
# statements. They sit on the first body lines of every REPL run.
_REPL_SILENCERS = [
    'stdio.print("")',
    'fs.allows("/")',
    'net.allows("capa-repl-probe")',
    'env.allows("CAPA_REPL_PROBE")',
    'clock.now_secs()',
    'random.float_unit()',
]


class _ReplState:
    """Persistent state across REPL turns. Two buckets:

    - ``top_lines``: top-level declarations (functions, types,
      etc.) in the order entered.
    - ``main_lines``: statements that go inside the synthesised
      ``main`` body, in order. Each line is already indented one
      level so the assembled program is canonical Capa.

    ``last_output`` is the captured stdout from the most recent
    successful run, used to show only the *new* output to the
    user.
    """

    def __init__(self) -> None:
        self.top_lines: list[str] = []
        self.main_lines: list[str] = []
        self.last_output: str = ""

    def reset(self) -> None:
        self.top_lines = []
        self.main_lines = []
        self.last_output = ""

    def assemble(self) -> str:
        """Assemble the full Capa program from the accumulated
        state. Always synthesises a ``main`` function whose body
        starts with one read-only probe per pre-bound capability
        (so the analyzer's "declared but never used" check passes
        even before the user touches a given cap), then any
        user-entered statements.
        """
        top = "\n".join(self.top_lines)
        body_lines = [f"    {s}" for s in _REPL_SILENCERS] + self.main_lines
        body = "\n".join(body_lines)
        program = (top + "\n\n" if top else "") + _REPL_MAIN_HEADER + "\n" + body + "\n"
        return program


def _is_top_level_form(line: str) -> bool:
    """A quick heuristic: lines that start with a top-level
    keyword go into the items bucket; everything else goes into
    main's body. The lexer + parser is the source of truth for
    correctness; this just routes to the right bucket so the
    assembled program has things in the right place.
    """
    stripped = line.lstrip()
    for kw in (
        "fun ", "type ", "trait ", "capability ", "impl ",
        "const ", "import ",
    ):
        if stripped.startswith(kw):
            return True
    return False


def _is_bare_expression(line: str) -> bool:
    """Heuristic: a line that does NOT start with a statement
    keyword and does NOT contain a top-level ``=`` is likely a
    bare expression to print. False positives (statement-shaped
    inputs that slip through) just get wrapped in
    ``stdio.println`` and probably fail to type-check, which the
    user sees as an error and corrects.
    """
    stripped = line.lstrip()
    for kw in ("let ", "var ", "return ", "if ", "while ", "for ",
               "match ", "break", "continue"):
        if stripped.startswith(kw):
            return False
    # Detect statement-shaped assignments. Crude: an `=` token
    # that is not `==` and is not nested inside parens.
    depth = 0
    i = 0
    while i < len(stripped):
        c = stripped[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "=" and depth == 0:
            if i + 1 < len(stripped) and stripped[i + 1] == "=":
                i += 2
                continue
            return False
        i += 1
    return True


def _is_unit_typed_call(line: str) -> bool:
    """Heuristic: lines that look like Unit-typed expression
    statements should NOT be wrapped with ``stdio.println("${...}")``
    because that would try to interpolate ``()`` and fail to
    type-check. Detects the common cases: ``println`` / ``print``
    calls, and bare ``f()`` shapes where the trailing parens close
    at the end of the line.
    """
    stripped = line.lstrip()
    if "println(" in stripped or stripped.startswith("print("):
        return True
    if "eprintln(" in stripped:
        return True
    return False


def _try_compile_and_run(source: str) -> tuple[bool, str, str]:
    """Lex + parse + analyse + transpile + execute the program.

    Returns (ok, stdout, stderr_or_error). On compile errors,
    ``stderr_or_error`` carries the formatted diagnostic and
    ``stdout`` is empty. On runtime errors the Python traceback
    is in ``stderr_or_error``.
    """
    try:
        tokens = Lexer(source, filename="<repl>").lex()
    except LexerError as e:
        return False, "", e.format()
    try:
        module = Parser(tokens, source=source, filename="<repl>").parse_module()
    except LexerError as e:
        return False, "", e.format()
    result = analyze(module, source=source, filename="<repl>")
    if not result.ok:
        return False, "", "\n".join(e.format() for e in result.errors)
    code = transpile(module, types=result.types)
    # Run the transpiled Python as a subprocess so its stdout is
    # cleanly captured and so the REPL process's own state (sys
    # modules, runtime trace, etc.) is not polluted by the user's
    # program.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8",
    ) as f:
        f.write(code)
        py_path = f.name
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        # Ensure the capa package is importable from the venv that
        # is running the REPL; matches the convention used by
        # tests/test_transpiler.run_capa.
        from pathlib import Path
        capa_root = Path(__file__).resolve().parent.parent
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            str(capa_root) + (os.pathsep + existing if existing else "")
        )
        proc = subprocess.run(
            [sys.executable, py_path],
            capture_output=True, text=True, encoding="utf-8",
            env=env, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return False, "", "REPL execution timed out (10 s)"
    finally:
        try:
            os.unlink(py_path)
        except OSError:
            pass
    if proc.returncode != 0:
        return False, proc.stdout, proc.stderr or "exited non-zero"
    return True, proc.stdout, ""


_HELP_TEXT = """Capa REPL meta commands:
  .exit / .quit       leave the REPL
  .reset              clear all accumulated state
  .show               print the current accumulated program
  .help               this list

Input shapes:
  fun foo(...) ...    top-level declaration (accumulated)
  let x = ...         statement (added to the synthesised main)
  x.method()          bare expression (auto-wrapped as println)

Pre-bound capabilities in scope at the prompt:
  stdio  Stdio    println / print / readln
  fs     Fs       allows / read_to_string / write_string / ...
  net    Net      allows / fetch
  env    Env      allows / get
  clock  Clock    now_secs / sleep_secs
  random Random   float_unit / int_range / shuffle

Unsafe is intentionally not pre-bound; declare a function that
takes Unsafe and call it from the REPL when you really mean it.
"""


def serve(prompt: str = "capa> ") -> int:
    """Run the REPL until EOF or .exit. Returns 0 on clean exit."""
    state = _ReplState()
    print(f"Capa REPL. Type .help for commands, .exit to leave.")
    while True:
        try:
            line = input(prompt)
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped in (".exit", ".quit"):
            return 0
        if stripped == ".reset":
            state.reset()
            print("REPL state cleared.")
            continue
        if stripped == ".show":
            print(state.assemble())
            continue
        if stripped == ".help":
            print(_HELP_TEXT, end="")
            continue

        # Bucket the input. Top-level forms (fun, type, etc.) can
        # span multiple lines; gather continuation lines until a
        # blank line terminates the block.
        if _is_top_level_form(line):
            collected = [line]
            while True:
                try:
                    cont = input("... ")
                except EOFError:
                    break
                except KeyboardInterrupt:
                    print()
                    collected = None
                    break
                if cont.strip() == "":
                    break
                collected.append(cont)
            if collected is None:
                continue
            candidate_top = state.top_lines + ["\n".join(collected)]
            candidate_main = state.main_lines
        else:
            # Statement or expression. Bare expressions get
            # auto-wrapped with ``stdio.println("${...}")`` so the
            # value is shown; Unit-typed calls (println, etc.)
            # are emitted as-is to avoid interpolating ``()``.
            if _is_bare_expression(stripped) and not _is_unit_typed_call(stripped):
                rendered = f'    stdio.println("${{{stripped}}}")'
            else:
                rendered = "    " + line.lstrip()
            candidate_top = state.top_lines
            candidate_main = state.main_lines + [rendered]

        # Assemble + run.
        tentative = _ReplState()
        tentative.top_lines = candidate_top
        tentative.main_lines = candidate_main
        ok, stdout, err = _try_compile_and_run(tentative.assemble())
        if not ok:
            sys.stderr.write(err.rstrip() + "\n")
            continue
        # Show only the delta since the last successful run.
        if stdout.startswith(state.last_output):
            delta = stdout[len(state.last_output):]
        else:
            delta = stdout
        if delta:
            sys.stdout.write(delta)
            if not delta.endswith("\n"):
                sys.stdout.write("\n")
        state.top_lines = candidate_top
        state.main_lines = candidate_main
        state.last_output = stdout
