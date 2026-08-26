"""Python transpile / execute / IR / parse path for the Capa CLI.

``run_python`` is the tail of ``_main_dispatch`` that handles the DEFAULT
``--run`` (legacy transpiler -> in-process exec), ``--transpile`` (Python
output), ``--ir`` (opt-in CIR pipeline, falling back to the legacy
transpiler), ``--parse`` (AST dump) and the bare token-dump. It runs only
after ``run_execute`` has declined the Wasm/component path.

It reads the small :class:`~capa.cli._ctx.ExecCtx` core slice, the SAME
surface the execute path reads (module, source, filename, result, args,
use_color, program_args), so no parallel near-duplicate slice is
introduced. It also takes two values the execute path never touches:
``linked`` (the loader's :class:`LinkedModule`, for the multi-file source
map used to rewrite a runtime traceback) and ``tokens`` (the lexed token
stream, for the token dump). ``ctx.result`` is an INPUT; the lazy
``analyze`` for a bare ``--transpile`` reassigns a LOCAL and never mutates
the ctx, and this is the terminal dispatch so nothing downstream reads it.

It imports the leaf modules and ``capa.*``; never :mod:`capa.cli`
(``__init__``). The dependency runs one way,
``capa.cli`` -> ``capa.cli._run_python``.
"""

import sys

from capa import TokenKind, analyze, ast_dump, transpile
from capa._debug import _rewrite_traceback
from capa.cli._ctx import ExecCtx
from capa.cli._diagnostics import C, color_for, _recursion_diagnostic


# The layout tokens ``--no-layout`` suppresses in the token dump.
_LAYOUT_KINDS = {
    TokenKind.NEWLINE,
    TokenKind.INDENT,
    TokenKind.DEDENT,
    TokenKind.EOF,
}


def run_python(ctx: ExecCtx, linked, tokens) -> int:
    """Transpile / run / IR / parse / token-dump for this invocation.

    Always returns the process exit code (this is the last dispatch
    branch). ``linked`` is the loader result (or None) whose source map
    lets a runtime traceback show imported-module lines; ``tokens`` is the
    lexed stream printed by the bare token dump.
    """
    result = ctx.result
    if ctx.args.transpile or ctx.args.run:
        # If we haven't yet run analyze (in --transpile mode without --check),
        # we run it now silently to obtain types for the
        # type-aware dispatch in the transpiler.
        if result is None:
            result = analyze(ctx.module, source=ctx.source, filename=ctx.filename)
        code = None
        # Statement-level source map (python_line -> Capa Pos), filled
        # by the legacy transpiler. Stays empty on the --ir path, in
        # which case _rewrite_traceback falls back to the plain
        # Python traceback.
        line_map: dict = {}
        if ctx.args.ir:
            # Opt-in CIR pipeline. UnsupportedInIR drops back to the
            # legacy transpiler so an --ir invocation still produces
            # runnable Python on programs the CIR doesn't yet cover;
            # the user-visible behaviour is identical, only the path
            # differs. A one-line stderr breadcrumb makes the fallback
            # visible to anyone debugging the IR's coverage.
            from capa.ir import compile_program, UnsupportedInIR
            try:
                code = compile_program(
                    ctx.module, filename=ctx.filename,
                    types=result.types if result is not None else None,
                    bindings=result.bindings if result is not None else None,
                )
            except UnsupportedInIR as e:
                msg = f"capa: --ir: falling back to legacy transpiler ({e})"
                if ctx.use_color:
                    print(f"{C.YELLOW}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
        if code is None:
            code = transpile(
                ctx.module, filename=ctx.filename,
                types=result.types if result is not None else None,
                bindings=result.bindings if result is not None else None,
                out_line_map=line_map,
            )

    if ctx.args.transpile and not ctx.args.run:
        print(code)
        return 0

    if ctx.args.run:
        # Execute the transpiled Python in the current interpreter.
        #
        # The ``capa.runtime`` package is already importable here (we
        # are running inside the ``capa`` package), so the transpiled
        # code's ``from capa.runtime import ...`` resolves directly.
        # We give it a ``__name__ = "__main__"`` so the conventional
        # entry-point guard works; ``SystemExit`` is intercepted so
        # the exit code propagates back to the OS naturally; any
        # other exception prints a traceback and returns 1.
        #
        # Historical note: a ``subprocess.run([sys.executable, ...])``
        # used to be invoked here. That does not survive PyInstaller
        # bundling: the bundled binary is not a generic Python
        # interpreter able to run an arbitrary ``.py`` file. In-process
        # exec works in both plain-Python and frozen-binary modes,
        # is faster (no fork), and avoids the temp-file dance.
        import traceback
        run_globals = {
            "__name__": "__main__",
            "__file__": "<transpiled>",
        }
        # Override sys.argv for the duration of the run so the
        # program's ``env.args()`` returns the user-visible arguments.
        # argv[0] is the .capa filename (or ``<transpiled>`` for
        # --stdin); argv[1:] is everything after ``--`` on the
        # Capa command line.
        saved_argv = sys.argv
        sys.argv = [ctx.args.file or "<transpiled>", *ctx.program_args]
        try:
            exec(compile(code, "<transpiled>", "exec"), run_globals)
            return 0
        except SystemExit as e:
            if e.code is None:
                return 0
            if isinstance(e.code, int):
                return e.code
            sys.stderr.write(str(e.code) + "\n")
            return 1
        except BaseException:
            traceback.print_exc(file=sys.stderr)
            # Resolve per-file source text so each Capa frame can show
            # its source line and caret. The root file is always
            # available; the linker's sources map (when present) covers
            # imported modules in a multi-file program.
            sources = {ctx.filename: ctx.source}
            if linked is not None:
                sources.update(linked.sources)
            summary = _rewrite_traceback(
                sys.exc_info(), line_map,
                sources=sources, default_source=ctx.source,
            )
            if summary:
                print(summary, file=sys.stderr)
            return 1
        finally:
            sys.argv = saved_argv

    if ctx.args.parse:
        # Belt-and-braces (see the analyze call above): the parser
        # caps nesting and flat-chain length so the dumped AST is
        # never deep enough to overflow ``ast_dump``'s recursive walk;
        # convert any leaked RecursionError into a clean error rather
        # than a raw stack trace under ``capa --parse``.
        try:
            print(ast_dump(ctx.module))
        except RecursionError:
            return _recursion_diagnostic(
                ctx.filename, "dump", use_color=ctx.use_color
            )
        return 0

    for tok in tokens:
        if ctx.args.no_layout and tok.kind in _LAYOUT_KINDS:
            continue
        pos = f"{tok.start.line:>4}:{tok.start.col:<3}"
        kind_name = tok.kind.name
        text_repr = repr(tok.text) if tok.text else ""
        value_repr = ""
        if tok.value is not None and tok.value != tok.text:
            value_repr = f"  → {tok.value!r}"
        if ctx.use_color:
            col = color_for(tok.kind)
            print(
                f"{C.GRAY}{pos}{C.RESET}  "
                f"{col}{kind_name:<14}{C.RESET}  "
                f"{C.DIM}{text_repr}{C.RESET}"
                f"{value_repr}"
            )
        else:
            print(f"{pos}  {kind_name:<14}  {text_repr}{value_repr}")

    return 0
