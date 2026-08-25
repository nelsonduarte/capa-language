"""capa-lex, command-line utility for the Capa lexer.

Usage:
    python cli.py <file.capa>
    python cli.py --stdin < file.capa

By default, prints each token on a line in the format:
    LINE:COL  TOKEN_KIND  text  [value]

Useful to visually inspect the tokenization of a program,
diagnose indentation problems, or simply verify that
the lexer processes the file without errors.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from capa import (
    Lexer, LexerError, Parser, TokenKind, analyze, ast_dump, transpile,
)
from capa.manifest import (
    resolve_build_timestamp, SourceDateEpochError,
)
from capa.pkg import (
    BrokenRootManifestError, CapaFloorError, VendorVerificationError,
    enforce_root_floor,
)
from capa.cli._diagnostics import C, color_for, _recursion_diagnostic
from capa.cli._grants import (
    _parse_preopen_spec, _classify_internal_ip, _AllowHostSpecError,
    _parse_allow_host_spec, _normalize_allow_hosts, _operator_grants_from_args,
)
from capa.cli._ctx import DispatchCtx, ExecCtx
from capa.cli._floor import _enforce_floor_for_file_root
from capa.cli._emitters import (
    emit_manifest, emit_manifest_digest, emit_compose_sbom,
    emit_check_capabilities, emit_policies, emit_cyclonedx, emit_spdx,
    emit_vex, emit_provenance, emit_doc, emit_wit,
)
from capa.cli._execute import run_execute, _wrap_as_component
from capa.cli._parser import (
    build_parser, _compiler_owned_args, _floor_check_exempt,
)
from capa.cli.subcommands import (
    _wasm_tooling_available, _install_summary,
    _dispatch_init, _dispatch_install, _dispatch_add, _dispatch_search,
    _dispatch_migrate, _dispatch_build, _dispatch_run_aot, _dispatch_test,
    _dispatch_capability_diff,
)
from capa.formatter import format_source, is_formatted
from capa.loader_paths import resolve_loader_paths
from capa._debug import _rewrite_traceback


def main() -> int:
    """CLI entry point. Wraps the dispatch in fail-closed guards, each
    of which is a clean, named error and a non-zero exit on any
    read/build path rather than a traceback:

      * ``VendorVerificationError`` (PKG-1), an unverifiable ./vendor;
      * ``CapaFloorError``, the ``[package].capa`` compiler floor;
      * ``BrokenRootManifestError``, a root ``capa.toml`` that cannot be
        parsed. The wording and the exit code match what ``capa test``
        and ``capa install`` already used, because those two already had
        the right behaviour and this brings the rest of the CLI into
        line with them rather than the other way round.

    ``BrokenRootManifestError`` exits 2 and not 1: 2 is this CLI's code
    for a CONFIGURATION problem (``capa test`` already returns it for
    exactly this input), while 1 is the code for a policy refusal about
    a program that was otherwise fine to build. A broken manifest is the
    former; a violated floor is the latter.
    """
    try:
        return _main_dispatch()
    except VendorVerificationError as e:
        print(f"capa: {e}", file=sys.stderr)
        return 1
    except BrokenRootManifestError as e:
        # ``<path>: <reason>``, guaranteed by ``read_root_manifest``.
        print(f"capa: broken capa.toml: {e}", file=sys.stderr)
        return 2
    except CapaFloorError as e:
        # The message already carries the ``capa: <path>:`` prefix and
        # the full remediation menu; print it verbatim.
        print(str(e), file=sys.stderr)
        return 1


def _main_dispatch() -> int:
    # Make stdout/stderr UTF-8 with replacement so CLI output never
    # crashes the process on a non-ASCII byte. The token dump uses a
    # ``->`` arrow glyph, error messages can carry unicode file names,
    # and the default Windows console codec is cp1252 -- printing
    # either to a redirected file raised UnicodeEncodeError +
    # traceback (audit slice 30 P1-a). ``reconfigure`` exists on the
    # real text streams (3.7+); under the test harness stdout is an
    # ``io.StringIO`` without it (and StringIO is already unicode, so
    # it needs no reconfigure). Guarded so neither case fails.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    # The root manifest, enforced before anything else runs: its
    # declared compiler floor, and its parseability. Placed here rather
    # than after argparse so a violation is reported once, from one
    # place, for every subcommand and every flag-based invocation alike.
    # ``_floor_check_exempt`` documents which invocations bypass it and
    # why.
    #
    # The project root is resolved by ancestor walk, the same way
    # ``--compose-sbom`` / ``--check-capabilities`` /
    # ``--check-policies`` already resolve it (``find_package_root``),
    # and NOT as ``Path.cwd()``. With ``Path.cwd()`` the two disagreed
    # whenever the cwd was a subdirectory of the project: ``capa
    # --compose-sbom main.capa`` from ``sub/`` found the parent's
    # manifest, applied the parent's ceiling and emitted a real composed
    # SBOM for the parent project, while the gate looked at ``sub/``,
    # found no manifest and enforced nothing. Composing that SBOM is the
    # exact artefact the floor exists to protect, so the gate has to
    # answer for the same root the rest of the CLI acts on.
    #
    # This gate is the FIRST layer. ``_enforce_floor_for_file_root`` is
    # the second, and every file-based invocation goes through it below,
    # so a regression in the exemption predicate alone cannot reopen the
    # floor of the project THE FILE BELONGS TO.
    #
    # That is the whole of the second layer's reach, and it is narrower
    # than it sounds. It keys on the root resolved from the FILE, so
    # when the file sits outside this cwd's project, or inside a
    # different one, the cwd project's floor rests on this gate alone.
    # Measured with the predicate forced to always-exempt: from a
    # floor-violating cwd, ``--check`` on a file outside any project and
    # on a file in a different, satisfied project both proceeded at exit
    # 0, while that project's own file was still refused. The cwd
    # project is not a bystander in those two runs: ``_capa_search_paths``
    # (in :mod:`capa.loader_paths`) reads ``Path.cwd() / "capa.toml"``, so
    # it supplies module
    # resolution for the build and materially shapes the artefact while
    # its own floor goes unenforced. Not a live bypass, because the
    # predicate is correct as shipped. It is the reason to keep BOTH
    # layers, rather than concluding that either one makes the other
    # redundant.
    from capa.manifest import find_package_root
    _gated_roots: set[Path] = set()
    if not _floor_check_exempt(sys.argv[1:]):
        _cwd_root = find_package_root(Path.cwd())
        if _cwd_root is not None:
            _gated_roots.add(_cwd_root)
            enforce_root_floor(_cwd_root)

    # Subcommand dispatch happens before argparse so the rest of
    # the CLI can stay flag-based without complicating help output.
    if len(sys.argv) >= 2 and sys.argv[1] == "init":
        return _dispatch_init(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "install":
        return _dispatch_install(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "add":
        return _dispatch_add(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "search":
        return _dispatch_search(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "migrate":
        return _dispatch_migrate(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "build":
        return _dispatch_build(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "run-aot":
        return _dispatch_run_aot(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "test":
        return _dispatch_test(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "lsp":
        from capa.lsp_server import serve
        return serve()
    if len(sys.argv) >= 2 and sys.argv[1] == "repl":
        from capa.repl import serve as repl_serve
        return repl_serve()

    # Split argv on `--`: anything after the separator is forwarded
    # to the transpiled program via ``sys.argv`` when ``--run``
    # executes. Done before argparse so the Capa CLI does not try
    # to interpret the program's own flags. When the separator is
    # absent, ``program_args`` stays empty and behaviour is
    # unchanged.
    #
    # The compiler's half comes from ``_compiler_owned_args``, the same
    # function the floor gate above uses to decide what it is allowed to
    # read. One definition of the boundary, because two definitions is
    # how a ``--help`` meant for the program came to switch the gate off.
    raw_argv = sys.argv[1:]
    cli_argv = _compiler_owned_args(raw_argv)
    # Everything the compiler does not own, minus the separator itself.
    # With no separator ``cli_argv`` IS ``raw_argv``, so the slice starts
    # one past the end and yields ``[]`` without a special case.
    program_args = raw_argv[len(cli_argv) + 1:]

    parser = build_parser()
    args = parser.parse_args(cli_argv)

    # Reject a NEGATIVE foreign resource budget up front. A negative value
    # would otherwise silently DISABLE the bound (opt-out is the explicit
    # ``0``), so a typo like ``--foreign-fuel -5`` would remove the DoS
    # protection without warning. ``0`` remains the documented opt-out.
    if args.foreign_fuel is not None and args.foreign_fuel < 0:
        print(
            "capa: --foreign-fuel must be >= 0 (use 0 to opt out of the "
            f"CPU bound); got {args.foreign_fuel}",
            file=sys.stderr,
        )
        return 2
    if args.foreign_memory_cap is not None and args.foreign_memory_cap < 0:
        print(
            "capa: --foreign-memory-cap must be >= 0 MiB (use 0 to opt out "
            f"of the memory bound); got {args.foreign_memory_cap}",
            file=sys.stderr,
        )
        return 2
    if args.foreign_result_cap is not None and args.foreign_result_cap < 0:
        print(
            "capa: --foreign-result-cap must be >= 0 MiB (use 0 to opt out "
            f"of the result bound); got {args.foreign_result_cap}",
            file=sys.stderr,
        )
        return 2

    # --capability-diff operates on two JSON artifacts, not a .capa
    # source, so it is handled here before the file/lex/analyze flow.
    if getattr(args, "capability_diff", None) is not None:
        return _dispatch_capability_diff(
            args.capability_diff,
            fail_on_widening=bool(getattr(args, "fail_on_widening", False)),
        )

    # --watch wraps the regular --run flow in a re-run-on-change
    # loop. Implemented as an outer process that spawns a fresh
    # `capa --run <file>` subprocess on each iteration; the watch
    # loop just polls mtimes. Trade-off: ~50-100ms process startup
    # per iteration, against zero refactor of main()'s state
    # machine.
    if args.watch:
        if not args.file:
            print(
                "capa: --watch requires a file argument",
                file=sys.stderr,
            )
            return 2
        return _run_watch_loop(args.file, program_args)

    if args.stdin:
        source = sys.stdin.read()
        filename = "<stdin>"
    elif args.file:
        path = Path(args.file)
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as e:
            print(f"error opening {path}: {e}", file=sys.stderr)
            return 2
        except UnicodeDecodeError:
            # A binary / non-UTF-8 file is a user error, not a crash.
            # ``UnicodeDecodeError`` is a ``ValueError``, so the
            # ``OSError`` clause above does not catch it (audit slice
            # 30 P1-b).
            print(
                f"error: {path}: not valid UTF-8 (Capa source must be "
                f"UTF-8 encoded)",
                file=sys.stderr,
            )
            return 2
        filename = str(path)
        # Second layer, for every file-based command rather than only the
        # four that emit a project-wide artefact. The first layer is the
        # cwd gate at the top of this function; this one re-derives the
        # root from the FILE, so it holds even when the cwd is elsewhere
        # and it does not depend on ``_floor_check_exempt`` having got
        # the compiler / program argument boundary right. It is a no-op
        # whenever both layers resolve the same root, which is the
        # ordinary case.
        _file_root = find_package_root(path)
        if _file_root is not None:
            _enforce_floor_for_file_root(_file_root, _gated_roots)
    else:
        parser.print_usage(sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color
    layout_kinds = {
        TokenKind.NEWLINE,
        TokenKind.INDENT,
        TokenKind.DEDENT,
        TokenKind.EOF,
    }

    # --fmt and --fmt-check operate on the raw source text, before
    # lexing, so they work on files with syntax errors as well.
    if args.fmt_check:
        if is_formatted(source):
            return 0
        # Print a one-line diagnostic to stderr (no diff, to keep
        # the output compact for CI). Callers wanting the diff can
        # use --fmt and compare to the original.
        print(
            f"{filename}: not in canonical Capa style "
            f"(use --fmt to reformat)",
            file=sys.stderr,
        )
        return 1
    if args.fmt:
        formatted = format_source(source)
        if args.stdin:
            sys.stdout.write(formatted)
            return 0
        # Only rewrite the file if its contents change, to keep
        # mtimes stable for build systems.
        if formatted != source:
            try:
                path.write_text(formatted, encoding="utf-8")
            except OSError as e:
                print(f"error writing {path}: {e}", file=sys.stderr)
                return 2
        return 0

    try:
        tokens = Lexer(source, filename=filename).lex()
    except LexerError as e:
        if use_color:
            print(f"{C.RED}{e.format()}{C.RESET}", file=sys.stderr)
        else:
            print(e.format(), file=sys.stderr)
        return 1

    needs_analysis = (
        args.check or args.run or args.manifest or args.manifest_digest
        or args.compose_sbom or args.check_capabilities
        or args.conformance_report or args.check_policies
        or args.cyclonedx
        or args.spdx or args.vex or args.provenance or args.doc
        or args.wit or args.wasm
    )
    # --wasi-surface needs the loader-linked AST (so imported helpers are
    # inlined and the argv -> sink surface sees the whole program) but no
    # full semantic analysis: it is a read-only static inspection.
    needs_link = needs_analysis or bool(getattr(args, "wasi_surface", False))
    linked = None
    # Default so the function-scope ExecCtx can always be built: the parse/
    # link block below binds ``module`` only when it runs (parse / transpile
    # / analysis / wasi-surface). A token-dump-only or bare --allow-host /
    # --preopen / --wasi invocation skips it; the execute path never reads
    # ``module`` in those cases (its foreign / wasm blocks are gated on
    # run / wasm / transpile / output).
    module = None
    if args.parse or args.transpile or needs_link:
        try:
            if needs_link or args.transpile:
                # Resolve transitive imports before analysis. The
                # loader does its own lex + parse of the root file
                # so all source positions are consistent; imported
                # modules become extra Items in the linked AST.
                from capa.loader import ModuleLoader, LoaderError
                try:
                    _paths = resolve_loader_paths()
                    loader = ModuleLoader(
                        search_paths=_paths.search_paths,
                        dependency_roots=_paths.dependency_roots,
                    )
                    linked = loader.load_root(source, filename)
                    module = linked.module
                except LoaderError as le:
                    msg = le.format()
                    if use_color:
                        print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                    else:
                        print(msg, file=sys.stderr)
                    return 1
            else:
                # --parse-only: skip the linker so the inspected AST
                # shows the root file's imports verbatim (useful
                # for debugging the module system itself).
                module = Parser(
                    tokens, source=source, filename=filename,
                ).parse_module()
        except LexerError as e:
            if use_color:
                print(f"{C.RED}{e.format()}{C.RESET}", file=sys.stderr)
            else:
                print(e.format(), file=sys.stderr)
            return 1

    # --wasi-surface: read-only inspection of the proven argv -> sink
    # path-arg surface. No semantic analysis / compilation; prints the
    # facts (or a clear "no argv argument reaches a sink" line) and exits.
    if getattr(args, "wasi_surface", False):
        from capa.ir._wasi_path_arg_surface import compute_path_arg_surface
        surface = compute_path_arg_surface(module)
        if surface.is_empty():
            print(
                f"{filename}: no argv (env.args()) argument is proven to "
                f"reach an Fs / Net / Env sink"
            )
        else:
            print(
                f"{filename}: WASI path-arg surface "
                f"(compiler-derived, by-construction):"
            )
            for line in surface.describe_lines():
                print(f"  {line}")
            print(
                "  (sound over-approximation: no reaching argv argument is "
                "omitted; argv[*] = a reaching argument at an indeterminate "
                "index. Closures are sound by construction: a closure whose "
                "param reaches a sink is reported at argv[*] unless proven "
                "applied only locally to non-argv values, so an escaping "
                "closure -- returned, passed to a helper, stored in an "
                "aggregate, or reached through a match/if arm or a name "
                "bound to one -- fails closed. Scope is exhaustively covered: "
                "the traversal descends into every sub-block that holds "
                "statements (if/while/for statement blocks, match-arm blocks, "
                "lambda bodies, at any depth), so a binding or sink in any "
                "sub-scope is never skipped. Residual gap (VALUE-FLOW "
                "only): a closure carried by a value not statically tied back "
                "to a lambda (re-extracted from a runtime container by key, or "
                "threaded through an opaque computed value) may be "
                "under-reported.)"
            )
        return 0

    result = None
    if (args.check or args.run or args.manifest or args.manifest_digest
            or args.compose_sbom or args.check_capabilities
            or args.conformance_report or args.check_policies
            or args.cyclonedx
            or args.spdx or args.vex or args.provenance or args.doc
            or args.wit or args.wasm):
        # Semantic analysis is required before running. If the
        # loader produced a sources map (multi-file program),
        # pass it so errors in imported modules render with the
        # imported file's source snippet.
        sources_map = linked.sources if linked is not None else None
        privates_map = (
            linked.module_privates if linked is not None else None
        )
        # Belt-and-braces: the parser caps both nesting depth and flat
        # chain length, so a pathological expression is rejected before
        # an AST that could blow the analyzer's recursive walks is ever
        # built. Should any path still recurse past the interpreter
        # limit, convert the RecursionError into a clean diagnostic
        # rather than letting a raw stack trace escape ``capa --check``.
        try:
            result = analyze(
                module, source=source, filename=filename,
                sources=sources_map,
                module_privates=privates_map,
            )
        except RecursionError:
            return _recursion_diagnostic(
                filename, "analyze", use_color=use_color
            )
        # Non-fatal warnings (information-flow secret->sink under the
        # warn-then-enforce roll-out, roadmap S2.4; the dead-Unsafe
        # migrate nudge) print regardless of whether the program
        # compiles and never change the exit code.
        for warn in getattr(result, "warnings", []):
            text = warn.format(severity="warning")
            if use_color:
                print(f"{C.YELLOW}{text}{C.RESET}", file=sys.stderr)
            else:
                print(text, file=sys.stderr)
            print(file=sys.stderr)
        if not result.ok:
            for err in result.errors:
                if use_color:
                    print(f"{C.RED}{err.format()}{C.RESET}", file=sys.stderr)
                    print(file=sys.stderr)
                else:
                    print(err.format(), file=sys.stderr)
                    print(file=sys.stderr)
            n_errs = len(result.errors)
            msg = f"{filename}: {n_errs} error{'s' if n_errs != 1 else ''}"
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # WASI Fs layer b1: the operator-declared grant block (--preopen),
        # surfaced in the manifest / CycloneDX / SPDX as Level-2
        # operator-declared authority, distinct from the derived surface.
        try:
            _operator_grants = _operator_grants_from_args(
                getattr(args, "preopen", None),
                getattr(args, "allow_host", None),
            )
        except _AllowHostSpecError as e:
            msg = f"capa: --allow-host: {e}"
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # Bundle the post-analysis state the emitter/run branches share.
        # ``_file_root`` (the file's project root) is resolved a single
        # time here, replacing the per-branch find_package_root(Path(
        # filename)) recomputations. Distinct from the cwd root the floor
        # gate resolved at the top of this function.
        ctx = DispatchCtx(
            module=module, source=source, sources=sources_map,
            filename=filename, result=result, args=args, use_color=use_color,
            operator_grants=_operator_grants, gated_roots=_gated_roots,
            _file_root=find_package_root(Path(filename)),
        )
        if args.manifest:
            return emit_manifest(ctx)
        if args.manifest_digest:
            return emit_manifest_digest(ctx)
        if args.compose_sbom:
            return emit_compose_sbom(ctx)
        if args.check_capabilities:
            return emit_check_capabilities(ctx)
        if args.conformance_report or args.check_policies:
            return emit_policies(ctx)
        if args.cyclonedx or args.spdx or args.vex or args.provenance:
            try:
                build_ts = resolve_build_timestamp()
            except SourceDateEpochError as e:
                print(f"capa: {e}", file=sys.stderr)
                return 2
            if args.cyclonedx:
                return emit_cyclonedx(ctx, build_ts)
            if args.spdx:
                return emit_spdx(ctx, build_ts)
            if args.vex:
                return emit_vex(ctx, build_ts)
            if args.provenance:
                return emit_provenance(ctx, build_ts)
        if args.doc:
            return emit_doc(ctx)
        if args.check and not args.run:
            n_items = len(module.items)
            n_typed = len(result.types)
            n_bound = len(result.bindings)
            msg = (
                f"{filename}: ok ({n_items} items, "
                f"{n_typed} expressions typed, {n_bound} bindings)"
            )
            if use_color:
                print(f"{C.GREEN}{msg}{C.RESET}")
            else:
                print(msg)
            return 0
        if args.wit:
            return emit_wit(ctx)

    exec_ctx = ExecCtx(
        module=module, source=source, filename=filename,
        result=result, args=args, use_color=use_color,
        program_args=program_args,
    )
    rc = run_execute(exec_ctx)
    if rc is not None:
        return rc

    if args.transpile or args.run:
        # If we haven't yet run analyze (in --transpile mode without --check),
        # we run it now silently to obtain types for the
        # type-aware dispatch in the transpiler.
        if result is None:
            result = analyze(module, source=source, filename=filename)
        code = None
        # Statement-level source map (python_line -> Capa Pos), filled
        # by the legacy transpiler. Stays empty on the --ir path, in
        # which case _rewrite_traceback falls back to the plain
        # Python traceback.
        line_map: dict = {}
        if args.ir:
            # Opt-in CIR pipeline. UnsupportedInIR drops back to the
            # legacy transpiler so an --ir invocation still produces
            # runnable Python on programs the CIR doesn't yet cover;
            # the user-visible behaviour is identical, only the path
            # differs. A one-line stderr breadcrumb makes the fallback
            # visible to anyone debugging the IR's coverage.
            from capa.ir import compile_program, UnsupportedInIR
            try:
                code = compile_program(
                    module, filename=filename,
                    types=result.types if result is not None else None,
                    bindings=result.bindings if result is not None else None,
                )
            except UnsupportedInIR as e:
                msg = f"capa: --ir: falling back to legacy transpiler ({e})"
                if use_color:
                    print(f"{C.YELLOW}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
        if code is None:
            code = transpile(
                module, filename=filename,
                types=result.types if result is not None else None,
                bindings=result.bindings if result is not None else None,
                out_line_map=line_map,
            )

    if args.transpile and not args.run:
        print(code)
        return 0

    if args.run:
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
        sys.argv = [args.file or "<transpiled>", *program_args]
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
            sources = {filename: source}
            if linked is not None:
                sources.update(linked.sources)
            summary = _rewrite_traceback(
                sys.exc_info(), line_map,
                sources=sources, default_source=source,
            )
            if summary:
                print(summary, file=sys.stderr)
            return 1
        finally:
            sys.argv = saved_argv

    if args.parse:
        # Belt-and-braces (see the analyze call above): the parser
        # caps nesting and flat-chain length so the dumped AST is
        # never deep enough to overflow ``ast_dump``'s recursive walk;
        # convert any leaked RecursionError into a clean error rather
        # than a raw stack trace under ``capa --parse``.
        try:
            print(ast_dump(module))
        except RecursionError:
            return _recursion_diagnostic(
                filename, "dump", use_color=use_color
            )
        return 0

    for tok in tokens:
        if args.no_layout and tok.kind in layout_kinds:
            continue
        pos = f"{tok.start.line:>4}:{tok.start.col:<3}"
        kind_name = tok.kind.name
        text_repr = repr(tok.text) if tok.text else ""
        value_repr = ""
        if tok.value is not None and tok.value != tok.text:
            value_repr = f"  → {tok.value!r}"
        if use_color:
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


def _run_watch_loop(filename: str, program_args: list[str]) -> int:
    """Re-run ``capa --run <filename>`` whenever the target file or
    any of its imported modules changes on disk.

    Strategy: spawn a fresh ``python -m capa --run <file>``
    subprocess on each iteration so the watch process keeps zero
    compilation state across runs. The set of watched files
    starts at the root and expands after each successful run with
    whatever the loader reported as imported sources.

    Ctrl-C exits cleanly (returning 0). A compile error during
    a rerun is shown via the subprocess's own stderr; the
    watcher keeps polling.
    """
    import time
    from datetime import datetime
    from pathlib import Path

    target = Path(filename)
    if not target.exists():
        print(f"capa: --watch: file not found: {filename}", file=sys.stderr)
        return 2

    print(
        f"Capa watch mode. Watching {filename} for changes. "
        f"Ctrl-C to exit.",
        flush=True,
    )

    watched: dict[str, float] = {}

    def _mtime(p: str) -> float:
        try:
            return os.stat(p).st_mtime
        except OSError:
            return 0.0

    watched[str(target.resolve())] = _mtime(str(target))

    def _expand_watched_after_run() -> None:
        # After a successful run, ask the loader which files it
        # touched and add their mtimes to the watch set. Compile
        # errors don't update the set (the previous set stays
        # in place).
        try:
            from capa.loader import ModuleLoader
            source = target.read_text(encoding="utf-8")
            _paths = resolve_loader_paths()
            loader = ModuleLoader(
                search_paths=_paths.search_paths,
                dependency_roots=_paths.dependency_roots,
            )
            linked = loader.load_root(source, str(target))
            for f in linked.sources.keys():
                f_abs = str(Path(f).resolve())
                if f_abs not in watched:
                    watched[f_abs] = _mtime(f_abs)
        except Exception:
            # Any failure here: parse error in the file, missing
            # import, etc. Keep watching what we already had.
            pass

    def _do_run(separator: bool) -> None:
        if separator:
            # ANSI clear-screen + home; falls back to plain new-
            # lines on terminals that ignore ANSI.
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.write(
                f"--- rerun at {datetime.now().strftime('%H:%M:%S')} ---\n"
            )
            sys.stdout.flush()
        # A fresh child per rerun, which is what "re-run it" means:
        # no state survives from the previous iteration, and a program
        # that crashes hard costs one rerun instead of the watcher.
        # The command is built by capa._selfexec rather than hard-coded
        # as ``python -m capa``, which a frozen binary cannot honour
        # (it is not an interpreter and rejects ``-m``).
        from capa._selfexec import capa_child_command
        args = ["--run", str(target)]
        if program_args:
            args.append("--")
            args.extend(program_args)
        try:
            subprocess.run(capa_child_command(args))
        except KeyboardInterrupt:
            # Ctrl-C during the child's run: re-raise so the
            # watcher exits cleanly.
            raise
        except OSError as e:
            # The child could not be started (executable gone, fork
            # refused). Report it and keep watching: the next change
            # may well be the one that fixes it.
            print(f"capa: --watch: cannot run: {e}", file=sys.stderr)

    # First run is unconditional.
    try:
        _do_run(separator=False)
    except KeyboardInterrupt:
        print()
        return 0
    _expand_watched_after_run()

    # Poll loop.
    try:
        while True:
            time.sleep(0.2)
            changed_any = False
            for f in list(watched.keys()):
                m = _mtime(f)
                if m != watched[f]:
                    watched[f] = m
                    changed_any = True
            if changed_any:
                _do_run(separator=True)
                _expand_watched_after_run()
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
