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

REPL v2 (2026-05) keeps the recompile-on-every-turn model but
swaps two coupled pieces:

- **Line editing + persistent history**: ``readline`` (Unix) or
  ``pyreadline3`` (Windows) is loaded best-effort at startup,
  with history read from / written to ``~/.capa_repl_history``
  (capped at 1000 entries). If neither implementation is
  available the REPL still works via plain ``input()``.
- **In-process execution**: the transpiled Python runs via
  ``exec`` into a fresh namespace per turn, with stdout captured
  by :func:`contextlib.redirect_stdout`. The pre-v2 path forked
  ``python <tempfile>`` per turn, paying 30-200 ms of process
  startup on every input. The 10 s hard timeout survives on
  POSIX (via :func:`signal.alarm`); Windows has no
  ``signal.SIGALRM`` and v2 drops the hard cap there. See
  :func:`_exec_in_process`.

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

import contextlib
import io
import sys
import traceback
from pathlib import Path

from . import capa_ast as A
from .analyzer import analyze
from .lexer import Lexer, LexerError
from .parser import Parser
from .transpiler import transpile
from .typesys import ty_str


# Persistent history file for line editing across REPL sessions.
# Lives in the user's home directory; created on first successful
# write, never causes the REPL to crash if it cannot be read or
# written (permission errors, read-only home, etc. are swallowed).
_HISTORY_FILE: Path = Path.home() / ".capa_repl_history"

# Maximum number of history entries kept on disk. ``readline`` will
# truncate the in-memory ring buffer on write; keeps the file from
# growing without bound across long-lived shell habits.
_HISTORY_LENGTH: int = 1000

# Flipped to ``True`` when ``serve`` successfully imports a readline
# implementation. Tests inspect it to verify the import-failure path
# stays silent and harmless.
_HISTORY_LOADED: bool = False


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


def _starts_block_statement(line: str) -> bool:
    """A statement that opens an indented body (``if``, ``for``,
    ``while``, ``match``). When the REPL sees one of these on a
    fresh input it switches to a continuation prompt so the user
    can type the indented body and any ``else`` / ``elif`` arms.

    ``let`` and ``var`` that bind to a multi-line ``match`` or
    ``if`` expression are not detected here; users can either fit
    them on one logical line or wrap them in a top-level function.
    """
    stripped = line.lstrip()
    for kw in ("if ", "for ", "while ", "match "):
        if stripped.startswith(kw):
            return True
    return False


def _is_unit_typed_call(line: str) -> bool:
    """Heuristic: lines that look like Unit-typed expression
    statements should NOT be wrapped with ``stdio.println("${...}")``
    because that would try to interpolate ``()`` and fail to
    type-check. Detects the common cases: ``println`` / ``print``
    calls, and bare ``f()`` shapes where the trailing parens close
    at the end of the line.
    """
    stripped = line.lstrip()
    # ``"println("`` matches ``eprintln(...)`` too because "eprintln"
    # contains "println"; no separate check needed.
    if "println(" in stripped or stripped.startswith("print("):
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
    return _exec_in_process(code)


def _exec_in_process(code: str) -> tuple[bool, str, str]:
    """Execute transpiled Capa-as-Python in this process.

    Returns ``(ok, stdout, stderr_or_error)``. ``stdout`` is
    captured via :func:`contextlib.redirect_stdout` into a
    ``StringIO``; the runtime's ``Stdio`` capability writes to
    ``sys.stdout`` (both ``print`` and ``sys.stdout.write``), so
    everything the user program prints ends up in that buffer.

    The transpiled file ends with an ``if __name__ == "__main__":``
    block that instantiates capabilities and invokes ``main``; the
    namespace's ``__name__`` is set to ``"__main__"`` so that
    bootstrap fires under ``exec``.

    Timeout behaviour:

    - On POSIX systems Python ships ``signal.SIGALRM``; we wire
      :func:`signal.alarm` to raise ``TimeoutError`` after 10 s,
      matching the prior subprocess hard cap.
    - On Windows ``signal.SIGALRM`` does not exist and there is
      no equivalent synchronous interruption in the stdlib; the
      function therefore runs without a hard timeout. A runaway
      program must be stopped with Ctrl-C. The pre-v2 subprocess
      path enforced 10 s on every platform; the in-process v2
      gives up that guarantee on Windows for a 30-200 ms wins
      per turn.

    A fresh namespace dict is built every call so module-level
    state from a previous turn never leaks across runs. The REPL
    state lives in the ``_ReplState`` accumulator, not in the exec
    namespace.
    """
    captured_out = io.StringIO()
    captured_err = io.StringIO()
    namespace: dict = {"__name__": "__main__"}

    timeout_handler_installed = False
    try:
        import signal
        if hasattr(signal, "SIGALRM"):
            def _on_timeout(signum, frame):  # noqa: ARG001
                raise TimeoutError("REPL execution timed out (10 s)")
            signal.signal(signal.SIGALRM, _on_timeout)
            signal.alarm(10)
            timeout_handler_installed = True
    except (ImportError, AttributeError):
        pass

    try:
        with contextlib.redirect_stdout(captured_out), \
                contextlib.redirect_stderr(captured_err):
            try:
                exec(code, namespace, namespace)
            except TimeoutError as e:
                return False, captured_out.getvalue(), str(e)
            except SystemExit:
                # The transpiler does not emit sys.exit, but a user
                # program (or a py_invoke into stdlib) could. Treat
                # a clean exit as success and surface stdout.
                pass
            except BaseException:
                tb = traceback.format_exc()
                return False, captured_out.getvalue(), tb
    finally:
        if timeout_handler_installed:
            try:
                import signal
                signal.alarm(0)
            except Exception:
                pass

    return True, captured_out.getvalue(), ""


def _typeof_expr(
    expr_str: str, state: "_ReplState",
) -> tuple[bool, str]:
    """Return ``(ok, message)`` for the ``.types <expr>`` REPL
    command. The expression is type-checked against the current
    accumulated state by appending it as a bare expression
    statement to main's body and reading the analyzer's inferred
    type back from the typed-nodes map. The program is **not**
    run, so the expression's side effects do not fire.

    A bare expression statement (rather than a ``let`` binding) is
    used so capability references like ``stdio`` still type-check;
    Capa's discipline forbids binding capabilities to ``let``.
    """
    probe_line = f"    {expr_str}"
    tentative = _ReplState()
    tentative.top_lines = state.top_lines
    tentative.main_lines = state.main_lines + [probe_line]
    source = tentative.assemble()
    try:
        tokens = Lexer(source, filename="<repl>").lex()
    except LexerError as e:
        return False, e.format()
    try:
        module = Parser(
            tokens, source=source, filename="<repl>",
        ).parse_module()
    except LexerError as e:
        return False, e.format()
    result = analyze(module, source=source, filename="<repl>")
    if not result.ok:
        return False, "\n".join(e.format() for e in result.errors)
    probe_value = _find_probe_value(module)
    if probe_value is None:
        return False, "internal error: type-probe not found in AST"
    ty = result.types.get(id(probe_value))
    if ty is None:
        return False, "internal error: type-probe expression was not typed"
    return True, f": {ty_str(ty)}"


def _find_probe_value(module: A.Module) -> "A.Expr | None":
    """Return the expression of the last statement in synthesised
    ``main``'s body; the ``.types`` probe is the last line we
    append, so that statement's expression is the one whose type
    we want. ``None`` only on internal-shape regressions.
    """
    for item in module.items:
        if not isinstance(item, A.FunDecl) or item.name != "main":
            continue
        stmts = item.body.stmts
        if not stmts:
            return None
        last = stmts[-1]
        if isinstance(last, A.ExprStmt):
            return last.expr
        return None
    return None


_HELP_TEXT = """Capa REPL meta commands:
  .exit / .quit       leave the REPL
  .reset              clear all accumulated state
  .show               print the current accumulated program
  .types <expr>       print the inferred type of <expr> without
                      running it (uses the current state's scope)
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


def _init_readline() -> "object | None":
    """Best-effort line-editing setup.

    Tries the stdlib ``readline`` first (Unix); falls back to
    ``pyreadline3`` if it is installed (Windows). Returns the
    imported module on success, ``None`` if neither is available.
    Any failure here is silent: a REPL without arrow-key history
    is degraded, not broken, so the user should never see an
    error from this code path.

    Side effects on success: loads :data:`_HISTORY_FILE` if it
    exists and caps the in-memory ring buffer at
    :data:`_HISTORY_LENGTH` so the on-disk file cannot grow
    without bound. Also flips :data:`_HISTORY_LOADED` for tests.
    """
    global _HISTORY_LOADED
    try:
        import readline  # type: ignore[import-not-found]
    except ImportError:
        try:
            import pyreadline3 as readline  # type: ignore[import-not-found]
        except ImportError:
            return None
    try:
        readline.set_history_length(_HISTORY_LENGTH)
    except Exception:
        pass
    if _HISTORY_FILE.exists():
        try:
            readline.read_history_file(str(_HISTORY_FILE))
        except Exception:
            pass
    _HISTORY_LOADED = True
    return readline


def _save_readline(readline_mod: "object | None") -> None:
    """Persist the in-memory history ring to :data:`_HISTORY_FILE`.

    No-op if line editing was not initialised. All errors are
    swallowed: a read-only home directory or a full disk must
    not turn a clean ``.exit`` into a non-zero return.
    """
    if readline_mod is None:
        return
    try:
        readline_mod.write_history_file(str(_HISTORY_FILE))  # type: ignore[attr-defined]
    except Exception:
        pass


def serve(prompt: str = "capa> ") -> int:
    """Run the REPL until EOF or .exit. Returns 0 on clean exit."""
    state = _ReplState()
    readline_mod = _init_readline()
    print(f"Capa REPL. Type .help for commands, .exit to leave.")
    while True:
        try:
            line = input(prompt)
        except EOFError:
            print()
            _save_readline(readline_mod)
            return 0
        except KeyboardInterrupt:
            print()
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped in (".exit", ".quit"):
            _save_readline(readline_mod)
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
        if stripped.startswith(".types"):
            # Strip the command + any whitespace; what remains is
            # the expression to type-check. The bare ``.types``
            # form (no expression) prints a tiny usage hint.
            expr = stripped[len(".types"):].lstrip()
            if not expr:
                print("usage: .types <expression>")
                continue
            ok, msg = _typeof_expr(expr, state)
            if ok:
                print(msg)
            else:
                sys.stderr.write(msg.rstrip() + "\n")
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
        elif _starts_block_statement(line):
            # A statement that opens an indented body (``if``,
            # ``for``, ``while``, ``match``). Gather continuation
            # lines until a blank line terminates the block; each
            # collected line gets the REPL's one-indent prefix so
            # it lands inside the synthesised ``main`` body.
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
            rendered_lines = ["    " + ln.lstrip("\r\n") for ln in collected]
            candidate_top = state.top_lines
            candidate_main = state.main_lines + rendered_lines
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
