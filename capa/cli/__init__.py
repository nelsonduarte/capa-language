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

import capa
from capa import (
    Lexer, LexerError, Parser, TokenKind, analyze, ast_dump, transpile,
)
from capa.manifest import (
    build_manifest, build_cyclonedx, build_spdx,
    build_vex_document, build_provenance,
    resolve_build_timestamp, SourceDateEpochError,
)
from capa._artifact_io import emit_artifact
from capa.pkg import (
    BrokenRootManifestError, CapaFloorError, VendorVerificationError,
    enforce_root_floor,
)
from capa.cli._diagnostics import C, color_for, _recursion_diagnostic
from capa.cli._grants import (
    _parse_preopen_spec, _classify_internal_ip, _AllowHostSpecError,
    _parse_allow_host_spec, _normalize_allow_hosts, _operator_grants_from_args,
)
from capa.cli._parser import (
    build_parser, _compiler_owned_args, _floor_check_exempt, _WASM32_MAX_PAGES,
)
from capa.cli.subcommands import (
    _wasm_tooling_available, _install_summary,
    _dispatch_init, _dispatch_install, _dispatch_add, _dispatch_search,
    _dispatch_migrate, _dispatch_build, _dispatch_run_aot, _dispatch_test,
    _dispatch_capability_diff,
)
from capa.docgen import build_html as build_doc_html
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


def _enforce_floor_for_file_root(
    root_dir: Path, gated_roots: set[Path],
) -> None:
    """Enforce the root floor for the project root a FILE resolves to.

    Two jobs, and they are the same check for different reasons.

    The first is correctness of scope. ``--compose-sbom``,
    ``--check-capabilities``, ``--check-policies`` and
    ``--conformance-report`` resolve their project root by walking up
    from the FILE they were given, not from the cwd. When the file lives
    outside the cwd's project tree those two roots differ, and the gate
    in ``_main_dispatch`` will have enforced the wrong one (or none).
    Since these are precisely the commands that emit composed SBOMs and
    ceiling verdicts for a whole project, the floor has to hold for the
    root they actually act on.

    The second is DEPTH. Every file-based invocation re-checks here, not
    just the four artefact-emitting ones, so the floor does not rest on
    a single predicate. It used to have a second layer inside
    ``_capa_search_paths`` (in :mod:`capa.loader_paths`); that one was
    scoped to ``Path.cwd()``, so it
    saw nothing from a subdirectory, and it never ran for a command that
    does not resolve modules (``--parse``). This seam is scoped to the
    root the command actually acts on and runs for every file, which is
    why it replaces that one rather than reinstating it. It is what kept
    the four artefact commands refusing while the ``--`` bypass was open.

    ``gated_roots`` is every root already enforced during this
    invocation, starting with the cwd gate's. Recording them keeps the
    ``CAPA_IGNORE_CAPA_FLOOR`` warning printing exactly ONCE per root in
    the ordinary case where all of them are the same directory. Every
    entry comes from ``find_package_root``, which resolves before
    walking, so plain set membership is the right comparison.
    """
    if root_dir in gated_roots:
        return
    gated_roots.add(root_dir)
    enforce_root_floor(root_dir)


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
        if args.manifest:
            import json
            manifest = build_manifest(
                module, filename=filename,
                bindings=result.bindings,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
                unaudited_secret_sinks=result.unaudited_secret_sinks,
            )
            emit_artifact(json.dumps(manifest, indent=2))
            return 0
        if args.manifest_digest:
            from capa.manifest import canonical_json, canonical_manifest
            manifest = build_manifest(
                module, filename=filename,
                bindings=result.bindings,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
                unaudited_secret_sinks=result.unaudited_secret_sinks,
            )
            # Emit the canonical bytes verbatim (key-sorted, fixed
            # separators): what is printed is exactly what the digest in
            # the content_integrity envelope is taken over, minus the
            # envelope itself. Content-addressable and byte-reproducible.
            emit_artifact(canonical_json(canonical_manifest(manifest)))
            return 0
        if args.compose_sbom:
            from capa.manifest import (
                build_composed_sbom, canonical_json, canonical_manifest,
                find_package_root, ComposeError,
            )
            root_dir = find_package_root(Path(filename))
            if root_dir is None:
                msg = (
                    "capa: --compose-sbom requires a capa.toml project root "
                    f"(none found at or above {filename}). Composing a "
                    "product SBOM needs the package + dependency declarations."
                )
                if use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            _enforce_floor_for_file_root(root_dir, _gated_roots)
            manifest = build_manifest(
                module, filename=filename,
                bindings=result.bindings,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
                unaudited_secret_sinks=result.unaudited_secret_sinks,
            )
            # Feature #4 (F2a): claim the Wasm-sandbox enforcement posture
            # only when the product targets the Wasm backend (--wasm),
            # under which the runtime host-enforces each foreign child's
            # declared capability SET, so a foreign-component call composes
            # as a BOUNDED node instead of authority-unknown TOP. Without
            # --wasm the composed SBOM is backend-agnostic and a foreign
            # call stays TOP (honest: nothing enforces the bound there).
            _enforcement = "wasm-sandbox" if args.wasm else "none"
            try:
                composed = build_composed_sbom(
                    module, manifest, root_dir,
                    enforcement=_enforcement,
                )
            except ComposeError as e:
                msg = f"capa: --compose-sbom: {e}"
                if use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            # Canonical, content-addressable bytes: the composed SBOM is
            # wrapped with the same S1 content_integrity envelope as
            # --manifest-digest, so the product artifact is itself
            # hashable and byte-reproducible across runs / machines.
            emit_artifact(canonical_json(canonical_manifest(composed)))
            return 0
        if args.check_capabilities:
            from capa.manifest import (
                build_composed_sbom, find_package_root, ComposeError,
            )

            def _err(text: str) -> None:
                if use_color:
                    print(f"{C.RED}{text}{C.RESET}", file=sys.stderr)
                else:
                    print(text, file=sys.stderr)

            root_dir = find_package_root(Path(filename))
            if root_dir is None:
                _err(
                    "capa: --check-capabilities requires a capa.toml project "
                    f"root (none found at or above {filename})."
                )
                return 1
            _enforce_floor_for_file_root(root_dir, _gated_roots)
            manifest = build_manifest(
                module, filename=filename,
                bindings=result.bindings,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
                unaudited_secret_sinks=result.unaudited_secret_sinks,
            )
            # Thread the same enforcement posture the composed SBOM /
            # policy gates use: under --wasm the sandbox host-enforces each
            # foreign boundary's declared cap SET, so a foreign-calling
            # package's ceiling is checked against a BOUNDED authority
            # rather than failing closed at authority-unknown TOP. Without
            # --wasm it stays TOP (honest: nothing enforces the bound).
            _enforcement = "wasm-sandbox" if args.wasm else "none"
            try:
                composed = build_composed_sbom(
                    module, manifest, root_dir, enforcement=_enforcement,
                )
            except ComposeError as e:
                _err(f"capa: --check-capabilities: {e}")
                return 1
            ceilings = composed["capability_ceilings"]
            if not ceilings["checked"]:
                print(
                    "capa: --check-capabilities: no package declares a "
                    "[capabilities] ceiling; nothing to verify.",
                    file=sys.stderr,
                )
                return 0
            if ceilings["pass"]:
                print(
                    "capa: --check-capabilities: OK - every declared "
                    "capability ceiling holds.",
                    file=sys.stderr,
                )
                return 0
            _err(
                "capa: --check-capabilities: FAILED - "
                f"{len(ceilings['violations'])} ceiling violation(s):"
            )
            for v in ceilings["violations"]:
                _err(f"  - {v['detail']}")
            return 1
        if args.conformance_report or args.check_policies:
            from capa.manifest import (
                build_composed_sbom, canonical_json, canonical_manifest,
                evaluate_policies, find_package_root, find_policy_file,
                read_policy_file, ComposeError, PolicyError,
            )

            flag = (
                "--conformance-report" if args.conformance_report
                else "--check-policies"
            )

            def _perr(text: str) -> None:
                if use_color:
                    print(f"{C.RED}{text}{C.RESET}", file=sys.stderr)
                else:
                    print(text, file=sys.stderr)

            root_dir = find_package_root(Path(filename))
            if root_dir is None:
                _perr(
                    f"capa: {flag} requires a capa.toml project root "
                    f"(none found at or above {filename})."
                )
                return 1
            _enforce_floor_for_file_root(root_dir, _gated_roots)
            policy_path = find_policy_file(root_dir)
            manifest = build_manifest(
                module, filename=filename,
                bindings=result.bindings,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
                unaudited_secret_sinks=result.unaudited_secret_sinks,
            )
            _enforcement = "wasm-sandbox" if args.wasm else "none"
            try:
                composed = build_composed_sbom(
                    module, manifest, root_dir, enforcement=_enforcement,
                )
            except ComposeError as e:
                _perr(f"capa: {flag}: {e}")
                return 1
            try:
                policies = (
                    read_policy_file(policy_path)
                    if policy_path is not None else []
                )
            except PolicyError as e:
                _perr(f"capa: {flag}: {e}")
                return 1
            report = evaluate_policies(composed, policies)

            if args.conformance_report:
                # Canonical, content-addressable evidence: the report is
                # wrapped with the same S1 content_integrity envelope as
                # --compose-sbom, so the conformance evidence is itself
                # hashable, signABLE, and byte-reproducible.
                emit_artifact(canonical_json(canonical_manifest(report)))
                return 0

            # --check-policies: the CI gate.
            if not policies:
                print(
                    "capa: --check-policies: no capa-policy.toml policies "
                    "found; nothing to verify.",
                    file=sys.stderr,
                )
                return 0
            if report["pass"]:
                print(
                    "capa: --check-policies: OK - every declared compliance "
                    "policy holds.",
                    file=sys.stderr,
                )
                return 0
            failed = [r for r in report["results"] if not r["pass"]]
            n_viol = sum(len(r["violations"]) for r in failed)
            _perr(
                f"capa: --check-policies: FAILED - {len(failed)} policy(ies), "
                f"{n_viol} violation(s):"
            )
            for r in failed:
                _perr(f"  policy {r['policy']!r} (kind {r['kind']}):")
                for v in r["violations"]:
                    _perr(f"    - [{v['verdict']}] {v['detail']}")
            return 1
        if args.cyclonedx or args.spdx or args.vex or args.provenance:
            # Each invocation emits exactly one artefact (every branch
            # below returns), so the instant is derived deterministically
            # from SOURCE_DATE_EPOCH: four separate invocations (one per
            # artefact) with the same value share the same timestamp, and
            # within CycloneDX-with-VEX the one instant feeds both
            # metadata.timestamp and the per-vulnerability firstIssued.
            # When SOURCE_DATE_EPOCH is set, this makes the output
            # byte-reproducible across runs and machines; when it is
            # unset, ``None`` lets the emitters fall back to wall-clock
            # time. An invalid value is a hard error rather than a silent
            # wall-clock fallback.
            try:
                build_ts = resolve_build_timestamp()
            except SourceDateEpochError as e:
                print(f"capa: {e}", file=sys.stderr)
                return 2
        if args.cyclonedx:
            import json
            from capa.manifest import (
                find_package_root, resolve_dependency_identities,
            )
            # When the input belongs to a capa.toml project, list each
            # resolved dependency as a real component (name + version +
            # purl). No project root (a bare .capa file) -> no dependency
            # components, so the output is exactly as before.
            _dep_components = None
            _dep_graph = None
            _cdx_root = find_package_root(Path(filename))
            if _cdx_root is not None:
                _dep_components, _dep_graph = resolve_dependency_identities(
                    _cdx_root,
                )
            sbom = build_cyclonedx(
                module, filename=filename, source=source,
                sources=linked.sources if linked is not None else None,
                timestamp=build_ts,
                bindings=result.bindings,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
                dependency_components=_dep_components,
                dependency_graph=_dep_graph,
            )
            emit_artifact(json.dumps(sbom, indent=2))
            return 0
        if args.spdx:
            import json
            from capa.manifest import (
                find_package_root, resolve_dependency_identities,
            )
            # Symmetric with --cyclonedx: when the input belongs to a
            # capa.toml project, render each resolved dependency as an SPDX
            # Package (name + version + purl externalRef) from the SAME
            # resolve walk. No project root (a bare .capa file) -> no
            # dependency packages, so the output is exactly as before.
            _dep_components = None
            _dep_graph = None
            _spdx_root = find_package_root(Path(filename))
            if _spdx_root is not None:
                _dep_components, _dep_graph = resolve_dependency_identities(
                    _spdx_root,
                )
            sbom = build_spdx(
                module, filename=filename, source=source,
                sources=linked.sources if linked is not None else None,
                timestamp=build_ts,
                bindings=result.bindings,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
                dependency_components=_dep_components,
                dependency_graph=_dep_graph,
            )
            emit_artifact(json.dumps(sbom, indent=2))
            return 0
        if args.vex:
            import json
            doc = build_vex_document(
                module, filename=filename, timestamp=build_ts,
            )
            emit_artifact(json.dumps(doc, indent=2))
            return 0
        if args.provenance:
            import json
            doc = build_provenance(
                source, filename=filename,
                started_on=build_ts, finished_on=build_ts,
                sources=linked.sources if linked is not None else None,
            )
            emit_artifact(json.dumps(doc, indent=2))
            return 0
        if args.doc:
            html = build_doc_html(module, filename=filename)
            print(html)
            return 0
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
            from capa.ir import compile_wit
            try:
                print(compile_wit(module, types=result.types))
                return 0
            except Exception as e:
                print(f"capa: --wit: {e}", file=sys.stderr)
                return 1

    # Feature #4 (F2a): a program that actually INVOKES a typed foreign
    # component. --check / --manifest / the SBOM emitters work fully and
    # have already returned above. A SCALAR foreign call (Int / Bool /
    # Float crossing types) now runs end-to-end on the Wasm backend: the
    # core module imports ``capa:foreign/<component>`` and the host
    # dispatches into a sandboxed child sub-component that physically
    # cannot exceed the declared capability set. The remaining paths are
    # guarded here with clear, actionable errors:
    #   - a String or aggregate crossing type is not yet marshalled at
    #     runtime (feature #4 F2b) -- clean error on any backend;
    #   - the Python backend cannot sandbox a foreign component, so a
    #     foreign call requires the Wasm backend (--wasm);
    #   - the Component Model (--component) wrapping path does not yet
    #     carry foreign imports; F2a runs on the core --wasm path.
    # The bare DECLARATION is inert, so a program that only DECLARES a
    # foreign component (and never calls one) runs normally.
    if (args.run or args.wasm or args.transpile
            or getattr(args, "output", None)):
        from capa.foreign import (
            extern_component_names, extern_components, foreign_call_sites,
            foreign_method_rejection,
        )

        def _foreign_err(_msg: str) -> None:
            if use_color:
                print(f"{C.RED}{_msg}{C.RESET}", file=sys.stderr)
            else:
                print(_msg, file=sys.stderr)

        _foreign_sites = foreign_call_sites(
            module, extern_component_names(module),
        )
        if _foreign_sites:
            _ec_by_name = {ec.name: ec for ec in extern_components(module)}
            # F2a/F2b/F2c marshal scalar (Int / Bool / Float) and String
            # crossing types plus NESTED, non-self-referential aggregates
            # of struct / List / tuple / Option / Result / sum. Two shapes
            # still cannot cross and reject with a SPECIFIC message: a
            # ``Map`` (different, String-keyed structure) and a
            # self-referential (recursive) type (would need
            # named-recursive WIT machinery). The typed boundary stays
            # fully checked (--check) and recorded in the SBOM
            # (--manifest) for a rejected call.
            for _comp, _method, _fpos in _foreign_sites:
                _ec = _ec_by_name.get(_comp)
                _msig = (
                    next((m for m in _ec.methods if m.name == _method), None)
                    if _ec is not None else None
                )
                if _msig is None:
                    continue
                _reason = foreign_method_rejection(_msig, module)
                if _reason is not None:
                    _foreign_err(
                        f"capa: foreign call {_comp}.{_method} at line "
                        f"{_fpos.line}:{_fpos.col} {_reason} The typed "
                        "boundary is still fully checked (--check) and "
                        "recorded in the SBOM (--manifest)."
                    )
                    return 1
            # The Wasm sandbox is what makes the declared bound SOUND; the
            # Python backend cannot physically confine a foreign component.
            if not args.wasm:
                _comp, _method, _fpos = _foreign_sites[0]
                _foreign_err(
                    f"capa: this program invokes a foreign component "
                    f"({_comp}.{_method} at line {_fpos.line}:{_fpos.col}); "
                    "foreign components require the Wasm backend (--wasm), "
                    "whose sandbox physically confines the component to the "
                    "declared capabilities. The Python backend cannot sandbox "
                    "it, so a foreign call is unsupported there."
                )
                return 1
            # F2a runs on the core --wasm path; the --component wrapping
            # path does not yet carry the capa:foreign imports.
            if getattr(args, "component", False):
                _comp, _method, _fpos = _foreign_sites[0]
                _foreign_err(
                    f"capa: this program invokes a foreign component "
                    f"({_comp}.{_method} at line {_fpos.line}:{_fpos.col}); "
                    "foreign-component calls run on the core --wasm path, not "
                    "the --component wrapping path yet (feature #4 F2a). Drop "
                    "--component."
                )
                return 1

    # Auto-prefer the Wasm pipeline when --prefer-wasm or the
    # CAPA_PREFER_WASM env var is set AND the user did not pass
    # --wasm explicitly AND the Wasm toolchain is available
    # (wasmtime importable + wasm-tools on PATH). Any failure
    # (UnsupportedInIR, WasmEmissionError, missing tool, wasmtime
    # trap) falls back silently to the Python pipeline below.
    prefer_wasm = (
        args.prefer_wasm
        or os.environ.get("CAPA_PREFER_WASM") == "1"
    )
    # Audit H1 (2026-05): translate the CLI's ``--wasm-memory-cap``
    # to the (page-count | None) shape the emitter wants. ``0``
    # opts out of the cap; any positive int is the limit; absence
    # falls back to the emitter's default.
    if args.wasm_memory_cap is None:
        wasm_memory_cap: int | None = ...  # type: ignore[assignment]
    elif args.wasm_memory_cap <= 0:
        wasm_memory_cap = None
    elif args.wasm_memory_cap > _WASM32_MAX_PAGES:
        # wasm32 caps linear memory at 65536 64KiB pages (4 GiB). A
        # larger value produces a module wasm-tools rejects, which we
        # used to write to disk with a success message + exit 0 (audit
        # slice 30 P2-b). Reject it up front.
        print(
            f"capa: --wasm-memory-cap must be between 1 and "
            f"{_WASM32_MAX_PAGES} pages (wasm32 caps linear memory at "
            f"4 GiB); got {args.wasm_memory_cap}",
            file=sys.stderr,
        )
        return 2
    else:
        wasm_memory_cap = args.wasm_memory_cap

    # ``--wasi`` only has an effect on the Wasm Component Model path: it
    # rewrites the WIT world and the component's imports to reference the
    # canonical wasi:random / wasi:clocks packages. Passed without
    # ``--wasm`` it would hit the pure-Python backend, which ignores it
    # entirely; that silent no-op masked typos / wrong invocations. Reject
    # it up front with an actionable message. (The companion
    # ``--wasi`` requires ``--component`` guard lives in the Wasm branch.)
    if bool(getattr(args, "wasi", False)) and not args.wasm:
        msg = (
            "capa: --wasi requires --wasm --component (WASI mode only "
            "applies to the Wasm Component Model path; it has no effect "
            "on the default capa:host / pure-Python backend)"
        )
        if use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    # ``--preopen`` (layer b1) is meaningful in --wasi mode (the
    # operator-declared filesystem grant that unblocks dynamic Fs paths)
    # AND when emitting an SBOM / manifest (it records the same grant as
    # operator-declared authority, distinct from the derived surface).
    # Reject it on any OTHER invocation with an actionable message rather
    # than silently ignore it.
    _emitting_sbom = bool(
        getattr(args, "manifest", False)
        or getattr(args, "manifest_digest", False)
        or getattr(args, "cyclonedx", False)
        or getattr(args, "spdx", False)
    )
    if (getattr(args, "preopen", None)
            and not bool(getattr(args, "wasi", False))
            and not _emitting_sbom):
        msg = (
            "capa: --preopen requires --wasi (or an SBOM / --manifest "
            "command): it is the operator-declared filesystem grant for "
            "the WASI mode, recorded in the SBOM; it has no effect on the "
            "default execution backend"
        )
        if use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    # ``--allow-host`` (the Net analogue of --preopen) is meaningful in
    # --wasi mode (the operator-declared Net grant that unblocks a dynamic
    # URL) AND when emitting an SBOM / manifest (it records the same grant
    # as operator-declared authority). Reject it on any OTHER invocation
    # with an actionable message, mirroring --preopen.
    if (getattr(args, "allow_host", None)
            and not bool(getattr(args, "wasi", False))
            and not _emitting_sbom):
        msg = (
            "capa: --allow-host requires --wasi (or an SBOM / --manifest "
            "command): it is the operator-declared Net grant for the WASI "
            "mode, recorded in the SBOM; it has no effect on the default "
            "execution backend"
        )
        if use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    if (
        args.run and not args.wasm and prefer_wasm
        and _wasm_tooling_available()
    ):
        if result is None:
            result = analyze(module, source=source, filename=filename)
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost
        # The silent fallback covers exactly one thing: the Wasm
        # backend cannot COMPILE this program (a construct outside the
        # Phase-6 subset). That is what ``--prefer-wasm`` promises to
        # absorb, and it is safe because nothing has executed yet.
        #
        # It used to wrap ``run_main`` too, under one bare
        # ``except Exception: pass``. Two things were wrong with that.
        # A capability-discipline refusal (``CapBindingError``, or the
        # ``CapHandleError`` a forged binding now raises) was swallowed
        # and the program re-run on the Python pipeline with FULL
        # authority: fail-open in the one mode whose point is to fail
        # closed. And a failure PART-WAY through a run was retried from
        # the top, so whatever the first attempt had already written
        # happened twice. Once execution starts, failures are loud.
        try:
            blob = compile_wasm(
                module, types=result.types,
                bindings=result.bindings,
                memory_cap_pages=wasm_memory_cap,
                filename=filename,
            )
        except Exception:
            blob = None
        if blob is not None:
            WasmHost(args=program_args).run_main(blob)
            return 0

    if args.wasm and (args.transpile or args.run or args.output):
        # Wasm pipeline: AST -> CIR -> WAT -> binary -> (wasmtime
        # | file | component). Failures are loud (no fallback to
        # Python) so coverage gaps in the Wasm backend surface as
        # actionable errors rather than silent shape changes.
        from capa.ir import compile_wat, compile_wasm, compile_wit
        from capa.ir import (
            MainReturnTypeUnsupported, check_main_return_type,
            ComponentExportUnsupported, check_component_exports,
        )
        # Experimental WASI mode is only meaningful for the component
        # path (it rewrites the WIT world + the component imports);
        # ``--transpile`` shows the WAT, which carries the wasi:*
        # imports too, so it is allowed. A bare ``--wasm --output``
        # core module, or ``--wasm --run`` on the core host, would
        # produce wasi:* imports nothing satisfies, so reject early
        # with an actionable message instead of a late link failure.
        wasi_mode = bool(getattr(args, "wasi", False))
        if wasi_mode and not args.component and not args.transpile:
            msg = (
                "capa: --wasi requires --component (the WASI mode "
                "rewrites the Component Model world; the bare core "
                "module / core host has no WASI provider)"
            )
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # WASI Fs layer b1: parse the operator ``--preopen``. b1 supports a
        # SINGLE preopen for dynamic-path resolution; reject more than one
        # with a clear message rather than silently picking one. The
        # presence of a preopen is the signal (``wasi_dynamic_fs``) that
        # suppresses the compiler's dynamic-Fs-path rejection, and the
        # parsed ``(host_dir, read_write)`` is the host grant.
        fs_operator_preopen = None
        wasi_dynamic_fs = False
        preopen_specs = getattr(args, "preopen", None) or []
        if preopen_specs:
            if len(preopen_specs) > 1:
                msg = (
                    "capa: --preopen: this increment (b1) supports a "
                    "single --preopen for dynamic Fs paths; got "
                    f"{len(preopen_specs)}"
                )
                if use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            fs_operator_preopen = _parse_preopen_spec(preopen_specs[0])
            wasi_dynamic_fs = True
        # Net operator grant (--allow-host, 2026-07-05): parse + normalize
        # each granted host through the SAME normalizer the guest gate uses
        # (capa.ir._net_host.normalize_host), so the operator's spelling and
        # the URL host land on the same allowlist key. Unlike --preopen this
        # is REPEATABLE (an allowlist is a set). The presence of any grant is
        # the signal (``net_operator_allow``) that suppresses the compiler's
        # dynamic-URL Net rejection; the normalized set is unioned into the
        # guest-side host ceiling the emitter materialises.
        from capa.ir._net_host import NetGrant
        net_operator_allow_hosts: NetGrant = NetGrant()
        net_operator_allow = False
        allow_host_specs = getattr(args, "allow_host", None) or []
        if allow_host_specs:
            try:
                net_operator_allow_hosts, _bad_hosts = _normalize_allow_hosts(
                    allow_host_specs,
                )
            except _AllowHostSpecError as e:
                msg = f"capa: --allow-host: {e}"
                if use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            if _bad_hosts:
                msg = (
                    "capa: --allow-host: could not parse a host from "
                    + ", ".join(repr(b) for b in _bad_hosts)
                    + " (expected a bare host, host:port, or a URL, "
                    "optionally with a :get / :post method suffix)"
                )
                if use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            net_operator_allow = bool(net_operator_allow_hosts)
            # SSRF footgun warning (warn, do NOT block, 2026-07-05): an
            # operator may have a legitimate reason to grant an internal
            # address, but granting one via a DYNAMIC URL is the classic
            # SSRF sink, so it is called out loudly on stderr.
            for _h in sorted(net_operator_allow_hosts.all_hosts):
                _kind = _classify_internal_ip(_h)
                if _kind is not None:
                    warn = (
                        f"capa: WARNING: --allow-host {_h} grants a {_kind} "
                        "address; this is usually an SSRF risk"
                    )
                    if use_color:
                        print(f"{C.YELLOW}{warn}{C.RESET}", file=sys.stderr)
                    else:
                        print(warn, file=sys.stderr)
        if result is None:
            result = analyze(module, source=source, filename=filename)
        # Component path only: validate ``main``'s return type BEFORE
        # ``compile_wasm``. A String / composite (Struct / Sum / List /
        # Map / tuple / ...) return on ``main`` cannot be lifted into
        # the WIT world export; without this early gate the core
        # emitter would die first with a cryptic wasm-tools dump (a
        # Struct-returning ``main`` lowers to ``return_call $Struct``
        # the module has no function for), never reaching the clean
        # ``compile_wit`` error. Running the check here makes both the
        # ``--output`` and ``--run`` component paths surface the
        # actionable ``capa: --wasm: main returning '<ty>' is not
        # supported ...`` diagnostic + exit 1 instead. Scalars / Unit
        # pass silently; the non-component path is untouched.
        if args.component:
            try:
                check_main_return_type(module, types=result.types)
                # Same early gate for ``@export`` functions: an
                # unsupported name / signature surfaces here as the clean
                # Capa diagnostic instead of dying later in the component
                # wrap step (mirrors the ``main`` return check above).
                check_component_exports(module, types=result.types)
            except (MainReturnTypeUnsupported,
                    ComponentExportUnsupported) as e:
                msg = f"capa: --wasm: {e}"
                if use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
        try:
            if args.transpile:
                wat = compile_wat(
                    module, types=result.types,
                    bindings=result.bindings,
                    memory_cap_pages=wasm_memory_cap,
                    filename=filename,
                    wasi=wasi_mode,
                    wasi_dynamic_fs=wasi_dynamic_fs,
                    net_operator_allow_hosts=net_operator_allow_hosts,
                )
                print(wat)
                return 0
            blob = compile_wasm(
                module, types=result.types,
                bindings=result.bindings,
                memory_cap_pages=wasm_memory_cap,
                filename=filename,
                wasi=wasi_mode,
                wasi_dynamic_fs=wasi_dynamic_fs,
                net_operator_allow_hosts=net_operator_allow_hosts,
            )
        except Exception as e:
            msg = f"capa: --wasm: {e}"
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # --output: save the binary instead of running it. With
        # --component, wrap the core module in a Component Model
        # component first.
        if args.output:
            try:
                if args.component:
                    blob = _wrap_as_component(
                        blob,
                        compile_wit(
                            module, types=result.types, wasi=wasi_mode,
                        ),
                        wasi=wasi_mode,
                    )
                Path(args.output).write_bytes(blob)
                kind = "component" if args.component else "core module"
                print(
                    f"capa: --wasm: wrote {kind} ({len(blob)} bytes) to {args.output}",
                    file=sys.stderr,
                )
                return 0
            except Exception as e:
                print(f"capa: --wasm: {e}", file=sys.stderr)
                return 1
        # --run path: assemble and execute on a wasmtime host.
        # ``--component --run`` wraps the core module in a
        # Component Model component first and dispatches to the
        # component-aware host (different lift/lower semantics,
        # see capa.runtime._wasm_component_host).
        host = None
        try:
            if args.component:
                from capa.runtime._wasm_component_host import (
                    WasmComponentHost,
                )
                component_blob = _wrap_as_component(
                    blob,
                    compile_wit(
                        module, types=result.types, wasi=wasi_mode,
                    ),
                    wasi=wasi_mode,
                )
                # WASI Env Level 1 (2026-06-27): when --wasi is active,
                # compute the program's static Env read ceiling and hand
                # it to the host. A CLOSED ceiling (every env.get key is
                # a string literal) maps to a restricted WASI env-set,
                # so the component never receives a variable outside the
                # ceiling (closes the leak-by-default). A non-closed
                # ceiling (a dynamic env.get key) makes the host fall
                # back to inherit_env (Level 2). The default capa:host
                # path passes no ceiling and is unaffected.
                env_ceiling = None
                fs_ceiling = None
                net_ceiling = None
                if wasi_mode:
                    from capa.ir import (
                        compute_env_ceiling, compute_fs_ceiling,
                        compute_net_ceiling, collect_used_capabilities,
                    )
                    env_ceiling = compute_env_ceiling(
                        module, types=result.types,
                    )
                    # WASI Fs Phase 0 (2026-06-27): the static Fs
                    # preopen ceiling drives the host's preopen_dir
                    # registration (parents of every literal Fs path,
                    # with READ_WRITE for mutating dirs). A non-closed
                    # ceiling (dynamic path) yields no preopens
                    # (fail-closed); the compiler already rejected such
                    # a program in --wasi mode. The default capa:host
                    # path passes no ceiling and is unaffected.
                    fs_ceiling = compute_fs_ceiling(
                        module, types=result.types,
                    )
                    # WASI Net (2026-06-28 Phase 1 / Phase 2): compute the
                    # static Net host ceiling ONLY when the program uses a
                    # Net REQUEST op (get or post). Passing it to the host is
                    # the signal to link wasi:http (the FFI receipt); a
                    # program with no request op keeps net_ceiling None so
                    # wasi:http is never linked (a clean total deny, and it
                    # avoids the C-API context panic). A Net program that
                    # only narrows / queries (restrict_to / allows, Phase 3)
                    # builds no outgoing request, so it needs no wasi:http
                    # either. The ceiling is enforced guest-side (codegen);
                    # the host records it for inspection only.
                    # ``collect_used_capabilities`` walks the CIR, so lower
                    # the AST module first (the same lowering
                    # ``compute_net_ceiling`` uses).
                    from capa.ir._lower import Lowerer
                    cir_for_caps = Lowerer(
                        types=result.types or {},
                    ).lower_module(module)
                    used_caps = collect_used_capabilities(cir_for_caps)
                    net_request_ops = used_caps.get("Net", set())
                    if "get" in net_request_ops or "post" in net_request_ops:
                        net_ceiling = compute_net_ceiling(
                            module, types=result.types,
                        )
                host = WasmComponentHost(
                    args=program_args,
                    wasi=wasi_mode,
                    env_ceiling=env_ceiling,
                    fs_ceiling=fs_ceiling,
                    fs_operator_preopen=fs_operator_preopen,
                    net_ceiling=net_ceiling,
                )
                host.run_main(component_blob)
            else:
                from capa.runtime._wasm_host import WasmHost
                # Pass the user-visible program args (everything
                # after ``--`` on the CLI) through to the host so
                # env.args inside the wasm module sees the same
                # values it would see under --run on the Python
                # path.
                host = WasmHost(args=program_args)
                # Feature #4 (F2a): register the typed foreign-component
                # imports BEFORE instantiation so the host can dispatch
                # each ``capa:foreign/<component>`` call into a sandboxed
                # child sub-component. Artifact paths are resolved
                # relative to the source file.
                from capa.foreign import foreign_runtime_methods
                _foreign_methods = foreign_runtime_methods(module)
                if _foreign_methods:
                    _base = os.path.dirname(os.path.abspath(filename))
                    for _m in _foreign_methods:
                        _art = _m["artifact"]
                        if not os.path.isabs(_art):
                            _art = os.path.normpath(
                                os.path.join(_base, _art)
                            )
                        _m["artifact"] = _art
                    # Feature #4 hardening: tune the untrusted-child
                    # resource ceiling from the CLI. A given flag is
                    # None when absent (keep the generous default); 0
                    # opts out of that bound; a positive value sets it.
                    # --foreign-memory-cap is MiB, converted to bytes.
                    _mem_cap_bytes = (
                        None
                        if args.foreign_memory_cap is None
                        else args.foreign_memory_cap * 1024 * 1024
                    )
                    _result_cap_bytes = (
                        None
                        if args.foreign_result_cap is None
                        else args.foreign_result_cap * 1024 * 1024
                    )
                    host.configure_foreign_limits(
                        fuel=args.foreign_fuel,
                        memory_cap_bytes=_mem_cap_bytes,
                        result_cap_bytes=_result_cap_bytes,
                    )
                    host.register_foreign_methods(_foreign_methods)
                host.run_main(blob)
            return 0
        except Exception as e:
            # A deliberate ``panic`` aborts via the guest's
            # ``unreachable``, which surfaces here as a wasmtime
            # trap. The panic host import already wrote the canonical
            # ``panic: <message>`` line to stderr and set
            # ``host.panicked``; in that case exit non-zero WITHOUT a
            # host traceback, matching the Python backend's clean
            # abort. A genuine runtime trap (out-of-bounds access,
            # integer divide-by-zero, ...) leaves ``panicked`` False
            # and still gets the full traceback, since those point at
            # real defects worth surfacing.
            if host is not None and getattr(host, "panicked", False):
                return 1
            # Feature #4 (F2a): a ForeignDenied is an EXPECTED, actionable
            # sandbox outcome -- the child sub-component imported a
            # capability the call did not grant (structural host-enforced
            # cap-set deny), or its artifact was missing / malformed. It
            # surfaces here wrapped in the wasmtime trap that unwound the
            # foreign import; walk the cause chain and print it cleanly
            # (like a capa diagnostic) instead of a host traceback.
            # A WasmHostError is likewise an EXPECTED, actionable host
            # outcome -- e.g. the parent's ``$alloc`` returned 0 (out of
            # memory) while writing a foreign call's returned aggregate
            # back into the caller's linear memory (feature #4 F2c). It is
            # memory-safe and bounded (the host refuses to write at address
            # 0); surface it as a clean capa diagnostic rather than a host
            # traceback, so a malformed / oversized child return reads as a
            # bounded failure, not a crash.
            from capa.runtime._foreign import ForeignDenied
            from capa.runtime._wasm_host import WasmHostError
            _cur = e
            _seen: set[int] = set()
            while _cur is not None and id(_cur) not in _seen:
                _seen.add(id(_cur))
                if isinstance(_cur, (ForeignDenied, WasmHostError)):
                    _fmsg = f"capa: {_cur}"
                    if use_color:
                        print(f"{C.RED}{_fmsg}{C.RESET}", file=sys.stderr)
                    else:
                        print(_fmsg, file=sys.stderr)
                    return 1
                _cur = _cur.__cause__ or _cur.__context__
            import traceback
            traceback.print_exc(file=sys.stderr)
            return 1

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


def _wrap_as_component(
    core_wasm: bytes, wit_text: str, *, wasi: bool = False,
) -> bytes:
    """Wrap a core Wasm module in a Component Model component by
    shelling out to ``wasm-tools component embed`` + ``component new``.
    Returns the bytes of the resulting .wasm component, which embeds
    the WIT world and declares the capability interfaces as imports.

    The two-step embed/new flow is what wasm-tools uses canonically:
    embed encodes the WIT metadata into the core module as a custom
    section; new then promotes that core module to a CM component.
    Both steps require ``wasm-tools`` on PATH.

    ``wasi`` (experimental, 2026-06-27): when True, the program world
    references the canonical ``wasi:random`` / ``wasi:clocks`` packages
    for the migrated Random / Clock touch-points. ``embed`` resolves
    those package references from a ``deps/`` directory; we vendor a
    minimal subset of the official WASI Preview 2 WIT in
    ``capa/wasi_wit`` and copy it next to the generated world so the
    embed succeeds offline. The default (False) path is unchanged.
    """
    import subprocess
    import shutil
    import tempfile
    from pathlib import Path as _Path
    with tempfile.TemporaryDirectory() as td:
        td_path = _Path(td)
        # In WASI mode the WIT is a directory (the world plus a
        # vendored ``deps/`` the embed resolves wasi:* from); in the
        # default mode it is a single self-contained file.
        if wasi:
            wit_dir = td_path / "wit"
            wit_dir.mkdir()
            (wit_dir / "program.wit").write_text(wit_text, encoding="utf-8")
            vendored = _Path(capa.__file__).resolve().parent / "wasi_wit" / "deps"
            shutil.copytree(vendored, wit_dir / "deps")
            wit_arg = str(wit_dir)
        else:
            wit_path = td_path / "capa.wit"
            wit_path.write_text(wit_text, encoding="utf-8")
            wit_arg = str(wit_path)
        core_path = td_path / "core.wasm"
        embed_path = td_path / "embed.wasm"
        comp_path = td_path / "component.wasm"
        core_path.write_bytes(core_wasm)
        # embed: stamp the WIT world into the core module.
        embed = subprocess.run(
            [
                "wasm-tools", "component", "embed",
                "--world", "program", wit_arg, str(core_path),
                "-o", str(embed_path),
            ],
            capture_output=True, check=False,
        )
        if embed.returncode != 0:
            raise RuntimeError(
                f"wasm-tools component embed failed:\n"
                f"{embed.stderr.decode('utf-8', errors='replace')}"
            )
        # new: promote to a CM component.
        new = subprocess.run(
            [
                "wasm-tools", "component", "new",
                str(embed_path), "-o", str(comp_path),
            ],
            capture_output=True, check=False,
        )
        if new.returncode != 0:
            raise RuntimeError(
                f"wasm-tools component new failed:\n"
                f"{new.stderr.decode('utf-8', errors='replace')}"
            )
        return comp_path.read_bytes()


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
