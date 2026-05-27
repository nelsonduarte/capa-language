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
from capa import __version__ as _CAPA_VERSION
from capa.manifest import (
    build_manifest, build_cyclonedx, build_spdx,
    build_vex_document, build_provenance,
)
from capa.docgen import build_html as build_doc_html
from capa.formatter import format_source, is_formatted
from capa.init_project import init_project
from capa._debug import _rewrite_traceback


# ANSI colors for terminal highlighting
class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    RED = "\033[91m"
    GRAY = "\033[90m"


def color_for(kind: TokenKind) -> str:
    name = kind.name
    if name.startswith("KW_"):
        return C.MAGENTA
    if name in ("INDENT", "DEDENT", "NEWLINE", "EOF"):
        return C.GRAY
    if name in ("INT_LIT", "FLOAT_LIT"):
        return C.CYAN
    if name in ("STRING_LIT", "CHAR_LIT"):
        return C.GREEN
    if name == "IDENT":
        return C.BLUE
    return C.YELLOW


def _wasm_tooling_available() -> bool:
    """Return True iff the Wasm toolchain is fully usable.

    Two pieces must be present: ``wasm-tools`` on ``PATH`` (the Rust
    binary that wraps the core ``.wasm`` into a Component Model
    artefact) and the ``wasmtime`` Python binding (loaded by
    :class:`capa.runtime._wasm_host.WasmHost`). Probed lazily so
    ``capa --run`` without ``--prefer-wasm`` pays nothing.
    """
    import shutil
    if shutil.which("wasm-tools") is None:
        return False
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return False
    return True


def _capa_search_paths() -> list[Path]:
    """Return additional module-search roots.

    Three sources, in priority order:

    1. ``CAPA_PATH`` environment variable. Entries are separated by
       ``os.pathsep`` (``;`` on Windows, ``:`` elsewhere). Empty
       entries and non-existent directories are silently skipped.

    2. ``capa.toml`` in the cwd. When present, the package
       manager's vendor dir (``./vendor``) and the parent of every
       ``path = "..."`` dependency are added so a project that
       declares its deps in the manifest does not need any
       environment variable.

    3. Conventional fallback: ``./libraries`` relative to the cwd,
       if it exists. Mirrors the ``node_modules`` / ``vendor``
       convention and supports projects that vendor by hand.

    Entries are de-duplicated so an explicit ``CAPA_PATH=libraries``
    does not appear twice. A typo in ``CAPA_PATH`` is silently
    skipped so it does not turn into a noisy error on every run; a
    broken ``capa.toml`` emits a one-line warning to stderr but does
    not abort the CLI.
    """
    out: list[Path] = []
    seen: set[Path] = set()

    def _append(p: Path) -> None:
        try:
            resolved = p.resolve()
        except OSError:
            return
        if resolved in seen:
            return
        if p.is_dir():
            out.append(p)
            seen.add(resolved)

    raw = os.environ.get("CAPA_PATH", "")
    if raw:
        for entry in raw.split(os.pathsep):
            entry = entry.strip()
            if not entry:
                continue
            _append(Path(entry).expanduser())

    manifest_path = Path.cwd() / "capa.toml"
    if manifest_path.exists():
        try:
            from capa.pkg import read_manifest
            manifest = read_manifest(manifest_path)
            has_git = any(d.is_git for d in manifest.dependencies)
            if has_git:
                _append(Path.cwd() / "vendor")
            for d in manifest.dependencies:
                if d.is_path and d.path is not None:
                    dep_path = (manifest.manifest_dir / d.path).resolve()
                    _append(dep_path.parent)
        except Exception as e:
            # A broken capa.toml should produce a clear warning but
            # not block unrelated operations (e.g. `capa --check` on
            # a file outside the project).
            print(
                f"capa: warning: ignoring capa.toml ({e})",
                file=sys.stderr,
            )

    # Conventional fallback. Cheap probe: only the cwd is consulted,
    # so this never escalates I/O for a project that does not use
    # the convention.
    _append(Path.cwd() / "libraries")

    return out


def _dispatch_init(argv: list[str]) -> int:
    """Handle ``python -m capa init [name]``.

    Kept separate from the main argparse so the rest of the CLI
    can stay flag-based without disrupting the subcommand shape
    users expect from ``init`` (modelled on ``cargo new`` /
    ``go mod init``).
    """
    sub = argparse.ArgumentParser(
        prog="capa init",
        description=(
            "Scaffold a minimal Capa project (main.capa + README.md "
            "+ .gitignore + .capa-version)."
        ),
    )
    sub.add_argument(
        "name",
        nargs="?",
        default=".",
        help=(
            "directory to create (default: current directory, which "
            "must be empty)"
        ),
    )
    args = sub.parse_args(argv)
    return init_project(Path(args.name), capa_version=_CAPA_VERSION)


def _dispatch_install(argv: list[str]) -> int:
    """Handle ``python -m capa install [directory]``.

    Reads ``capa.toml`` from the target directory, fetches every
    declared git dependency into ``vendor/<name>``, validates every
    path dependency, and writes ``capa.lock``.
    """
    sub = argparse.ArgumentParser(
        prog="capa install",
        description=(
            "Resolve and fetch the dependencies declared in capa.toml "
            "into vendor/, and write capa.lock."
        ),
    )
    sub.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="project directory containing capa.toml (default: current)",
    )
    sub.add_argument(
        "--update",
        action="store_true",
        help=(
            "accept a fresh upstream commit even when capa.lock pins a "
            "different SHA for the same git URL + tag. Use only when "
            "the upstream tag move is deliberate (or you have audited "
            "the new commit); the default refusal exists so a "
            "force-pushed tag cannot slip into your build silently."
        ),
    )
    args = sub.parse_args(argv)
    project_dir = Path(args.directory).resolve()
    try:
        from capa.pkg import install, InstallError, ManifestError
    except ImportError as e:
        print(f"capa install: {e}", file=sys.stderr)
        return 2
    try:
        manifest = install(project_dir, allow_lock_update=args.update)
    except (InstallError, ManifestError) as e:
        print(f"capa install: {e}", file=sys.stderr)
        return 2
    n_git = sum(1 for d in manifest.dependencies if d.is_git)
    n_path = sum(1 for d in manifest.dependencies if d.is_path)
    print(
        f"capa install: {manifest.name} {manifest.version} "
        f"({n_git} git, {n_path} path)"
    )
    return 0


def _dispatch_add(argv: list[str]) -> int:
    """Handle ``python -m capa add <name> --git <url> ...``.

    Declares ``[dependencies.<name>]`` in capa.toml, then (unless
    ``--no-install``) runs the existing install flow so the new dep
    is vendored + locked immediately.
    """
    sub = argparse.ArgumentParser(
        prog="capa add",
        description=(
            "Declare a new dependency in capa.toml and (by default) "
            "install it into vendor/."
        ),
    )
    sub.add_argument("name", help="dependency name (used as vendor/<name>)")
    sub.add_argument(
        "--git", metavar="URL",
        help=(
            "git URL of the dependency. Omit to resolve the name "
            "through the public registry index."
        ),
    )
    pin = sub.add_mutually_exclusive_group()
    pin.add_argument("--tag", metavar="TAG", help="pin to a git tag")
    pin.add_argument("--rev", metavar="SHA", help="pin to a git commit")
    pin.add_argument("--branch", metavar="NAME", help="pin to a git branch")
    sub.add_argument(
        "--verify-key", metavar="FINGERPRINT", dest="verify_key",
        help="40-char GPG fingerprint the dep's tag/commit must be signed by",
    )
    sub.add_argument(
        "--force", action="store_true",
        help="overwrite an existing [dependencies.<name>] block",
    )
    sub.add_argument(
        "--no-install", action="store_true", dest="no_install",
        help="edit capa.toml only; do not fetch the dependency",
    )
    args = sub.parse_args(argv)
    project_dir = Path(".").resolve()
    try:
        from capa.pkg import (
            add_dependency, install, InstallError, ManifestError,
            RegistryError, resolve_name,
        )
    except ImportError as e:
        print(f"capa add: {e}", file=sys.stderr)
        return 2

    git_url = args.git
    tag, rev, branch = args.tag, args.rev, args.branch
    verify_key = args.verify_key
    if git_url is None:
        # No explicit --git: resolve the name through the registry.
        try:
            entry = resolve_name(args.name)
        except RegistryError as e:
            print(f"capa add: {e}", file=sys.stderr)
            return 2
        git_url = entry.git
        if verify_key is None:
            verify_key = entry.verify_key
        if tag is None and rev is None and branch is None:
            if entry.latest is None:
                print(
                    f"capa add: registry has no latest tag for "
                    f"{args.name!r}; pass --tag / --rev / --branch "
                    f"explicitly",
                    file=sys.stderr,
                )
                return 2
            tag = entry.latest
        latest_note = (
            f" (latest {entry.latest})" if entry.latest is not None else ""
        )
        print(
            f"resolved {args.name} -> {git_url}{latest_note} via registry"
        )

    try:
        pin_desc = add_dependency(
            project_dir, args.name, git_url,
            tag=tag, rev=rev, branch=branch,
            verify_key=verify_key, force=args.force,
        )
    except ManifestError as e:
        print(f"capa add: {e}", file=sys.stderr)
        return 2
    print(f"added {args.name} ({pin_desc}) to capa.toml")
    if args.no_install:
        return 0
    try:
        manifest = install(project_dir)
    except (InstallError, ManifestError) as e:
        print(f"capa add: {e}", file=sys.stderr)
        return 2
    n_git = sum(1 for d in manifest.dependencies if d.is_git)
    n_path = sum(1 for d in manifest.dependencies if d.is_path)
    print(
        f"capa install: {manifest.name} {manifest.version} "
        f"({n_git} git, {n_path} path)"
    )
    return 0


def _dispatch_search(argv: list[str]) -> int:
    """Handle ``python -m capa search [query]``.

    Searches the registry index by name and description and prints the
    matching packages as a compact table. With no query term it lists
    the whole registry.
    """
    sub = argparse.ArgumentParser(
        prog="capa search",
        description=(
            "Search the package registry by name and description. "
            "With no query, list every package in the registry."
        ),
    )
    sub.add_argument(
        "query",
        nargs="?",
        default="",
        help="substring to match against package names and descriptions",
    )
    args = sub.parse_args(argv)
    try:
        from capa.pkg import search_packages, RegistryError
    except ImportError as e:
        print(f"capa search: {e}", file=sys.stderr)
        return 2
    try:
        results = search_packages(args.query)
    except RegistryError as e:
        print(f"capa search: {e}", file=sys.stderr)
        return 2

    query = args.query.strip()
    if not results:
        print(f"no packages match {query!r}", file=sys.stderr)
        return 1

    name_w = max(len(e.name) for e in results)
    latest_w = max(len(e.latest or "-") for e in results)
    for e in results:
        desc = e.description or ""
        if len(desc) > 60:
            desc = desc[:60] + "..."
        print(f"{e.name:<{name_w}}  {(e.latest or '-'):<{latest_w}}  {desc}")
    if query:
        print(f"{len(results)} package(s) matching {query!r}")
    else:
        print(f"{len(results)} package(s) in registry")
    return 0


def _dispatch_migrate(argv: list[str]) -> int:
    """Handle ``python -m capa migrate <file.capa>``.

    Reports gradual-hardening progress: what fraction of functions are
    already Unsafe-free, which functions declare an Unsafe they never
    exercise (and can drop it now), and which still-Unsafe functions are
    cheapest to harden next. See :mod:`capa.migrate`.
    """
    sub = argparse.ArgumentParser(
        prog="capa migrate",
        description=(
            "Report Python->Capa gradual-hardening progress for a .capa "
            "file: how far the migration has come and which Unsafe to "
            "drop next."
        ),
    )
    sub.add_argument("file", help=".capa file to analyse")
    sub.add_argument(
        "--json",
        action="store_true",
        help="emit the report as JSON instead of human-readable text",
    )
    args = sub.parse_args(argv)

    path = Path(args.file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"capa migrate: cannot read {path}: {e}", file=sys.stderr)
        return 2
    filename = str(path)

    # Lex + link (multi-file aware) + analyse, mirroring the --manifest
    # path so a mid-migration multi-file project reports correctly.
    from capa.loader import ModuleLoader, LoaderError
    try:
        tokens = Lexer(source, filename=filename).lex()
        del tokens  # lexing validates; the loader re-lexes the root
        loader = ModuleLoader(search_paths=_capa_search_paths())
        linked = loader.load_root(source, filename)
    except LexerError as e:
        print(e.format(), file=sys.stderr)
        return 1
    except LoaderError as le:
        print(le.format(), file=sys.stderr)
        return 1

    result = analyze(
        linked.module, source=source, filename=filename,
        sources=linked.sources,
        module_privates=linked.module_privates,
    )
    if not result.ok:
        for err in result.errors:
            print(err.format(), file=sys.stderr)
        n = len(result.errors)
        print(
            f"capa migrate: {filename}: {n} error{'s' if n != 1 else ''}; "
            "fix analysis errors before checking migration progress.",
            file=sys.stderr,
        )
        return 1

    from capa.migrate import migrate_report, render_report
    report = migrate_report(linked.module, filename=filename)
    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        print(render_report(report))
    return 0


def main() -> int:
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
    program_args: list[str] = []
    cli_argv = sys.argv[1:]
    if "--" in cli_argv:
        sep = cli_argv.index("--")
        program_args = cli_argv[sep + 1:]
        cli_argv = cli_argv[:sep]

    parser = argparse.ArgumentParser(
        description="Lexer, parser and analyzer for the Capa language",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"capa {_CAPA_VERSION}",
        help="print the Capa compiler version and exit",
    )
    parser.add_argument("file", nargs="?", help=".capa file to process")
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read source from standard input",
    )
    parser.add_argument(
        "--parse",
        action="store_true",
        help="parse and print the AST (instead of tokens)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="parse and semantically analyze (lexer + parser + analyzer)",
    )
    parser.add_argument(
        "--transpile",
        action="store_true",
        help="transpile to Python and print the generated code",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help=(
            "transpile and execute the program (calls main with "
            "capabilities). Arguments after `--` are forwarded to the "
            "program (visible via env.args())"
        ),
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help=(
            "re-run the program every time it (or any of its imported "
            "modules) changes on disk. Implies --run. Ctrl-C to exit."
        ),
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help=(
            "emit a JSON capability manifest: per-function declared "
            "capabilities, attributes, signature, and the user-defined "
            "capability declarations and their implementors"
        ),
    )
    parser.add_argument(
        "--cyclonedx",
        action="store_true",
        help=(
            "emit a CycloneDX 1.5 SBOM with the capability manifest "
            "embedded as standard properties[] entries (consumable by "
            "Dependency-Track, OSV-Scanner, syft, etc.)"
        ),
    )
    parser.add_argument(
        "--spdx",
        action="store_true",
        help=(
            "emit an SPDX 2.3 SBOM with the capability manifest "
            "embedded as annotations[] (Linux Foundation companion "
            "to --cyclonedx, consumable by SPDX-aware tools and "
            "OpenChain-conformant pipelines)"
        ),
    )
    parser.add_argument(
        "--vex",
        action="store_true",
        help=(
            "emit a standalone CycloneDX 1.5 VEX-only document "
            "from @vex(cve, status, justification, detail) "
            "attributes on functions. Per-function VEX granularity, "
            "the affects[] of each entry pinpoints the function the "
            "claim was made on, not the package."
        ),
    )
    parser.add_argument(
        "--provenance",
        action="store_true",
        help=(
            "emit a SLSA Build L1 provenance attestation: an "
            "in-toto Statement v1 with a SLSA Provenance v1.0 "
            "predicate, subject = SHA-256 of the source .capa "
            "file. Consumable by SLSA-aware verifiers "
            "(slsa-verifier, in-toto attest, cosign verify-blob)."
        ),
    )
    parser.add_argument(
        "--doc",
        action="store_true",
        help=(
            "emit a self-contained HTML documentation page built from "
            "doc comments (///, /** */), capability signatures, and "
            "attached attributes; the human-readable counterpart to "
            "--manifest"
        ),
    )
    parser.add_argument(
        "--fmt",
        action="store_true",
        help=(
            "rewrite the file in canonical Capa style (line-level: "
            "indentation normalised to 4-space multiples, trailing "
            "whitespace stripped, blank-line clusters collapsed, "
            "final newline ensured); prints to stdout when used "
            "with --stdin"
        ),
    )
    parser.add_argument(
        "--fmt-check",
        action="store_true",
        help=(
            "verify that the file is already in canonical style; "
            "exits 0 if it is, 1 if it is not (no rewrite)"
        ),
    )
    parser.add_argument(
        "--ir",
        action="store_true",
        help=(
            "use the CIR pipeline (AST -> CIR -> Python) instead of "
            "the direct legacy transpiler. Same observable output for "
            "the subset CIR currently covers; falls back to the legacy "
            "path when CIR lowering raises UnsupportedInIR."
        ),
    )
    parser.add_argument(
        "--wasm",
        action="store_true",
        help=(
            "compile via CIR to WebAssembly text (WAT). With "
            "--transpile, prints the WAT. With --run, assembles the "
            "WAT to binary via wasm-tools and executes it on a "
            "wasmtime-backed host that provides the Capa capability "
            "interfaces. Coverage matches Phase 6 of the IR roadmap; "
            "constructs outside that subset fail loudly rather than "
            "fall back to Python."
        ),
    )
    parser.add_argument(
        "--wit",
        action="store_true",
        help=(
            "emit the WIT spec describing the program's capability "
            "imports. Useful for inspecting the capability surface "
            "the Wasm backend would generate; does not produce "
            "executable output."
        ),
    )
    parser.add_argument(
        "--prefer-wasm",
        action="store_true",
        help=(
            "with --run: try the Wasm backend first and fall back "
            "to the Python pipeline only when CIR lowering or Wasm "
            "emission rejects a construct. Honoured automatically "
            "when CAPA_PREFER_WASM=1 is set in the environment. "
            "Requires the [wasm] extra (wasmtime-py) and wasm-tools "
            "on PATH."
        ),
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help=(
            "with --wasm, save the assembled binary to the given "
            "path instead of executing it. Use with --component to "
            "save a Component Model wrapper (.wasm) instead of the "
            "core module."
        ),
    )
    parser.add_argument(
        "--component",
        action="store_true",
        help=(
            "with --wasm --output, wrap the core module in a "
            "Component Model component via 'wasm-tools component "
            "new'. Requires 'wasm-tools' on PATH. The resulting "
            "file embeds the WIT spec and is consumable by any "
            "Component-Model-aware runtime."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in the output",
    )
    parser.add_argument(
        "--no-layout",
        action="store_true",
        help="omit layout tokens (NEWLINE/INDENT/DEDENT/EOF) in the output",
    )
    args = parser.parse_args(cli_argv)

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
        filename = str(path)
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
        args.check or args.run or args.manifest or args.cyclonedx
        or args.spdx or args.vex or args.provenance or args.doc
        or args.wit or args.wasm
    )
    linked = None
    if args.parse or args.transpile or needs_analysis:
        try:
            if needs_analysis or args.transpile:
                # Resolve transitive imports before analysis. The
                # loader does its own lex + parse of the root file
                # so all source positions are consistent; imported
                # modules become extra Items in the linked AST.
                from capa.loader import ModuleLoader, LoaderError
                try:
                    loader = ModuleLoader(
                        search_paths=_capa_search_paths(),
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

    result = None
    if (args.check or args.run or args.manifest or args.cyclonedx
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
        result = analyze(
            module, source=source, filename=filename,
            sources=sources_map,
            module_privates=privates_map,
        )
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
        if args.manifest:
            import json
            manifest = build_manifest(module, filename=filename)
            print(json.dumps(manifest, indent=2))
            return 0
        if args.cyclonedx:
            import json
            sbom = build_cyclonedx(module, filename=filename)
            print(json.dumps(sbom, indent=2))
            return 0
        if args.spdx:
            import json
            sbom = build_spdx(module, filename=filename)
            print(json.dumps(sbom, indent=2))
            return 0
        if args.vex:
            import json
            doc = build_vex_document(module, filename=filename)
            print(json.dumps(doc, indent=2))
            return 0
        if args.provenance:
            import json
            doc = build_provenance(source, filename=filename)
            print(json.dumps(doc, indent=2))
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
    if (
        args.run and not args.wasm and prefer_wasm
        and _wasm_tooling_available()
    ):
        if result is None:
            result = analyze(module, source=source, filename=filename)
        try:
            from capa.ir import compile_wasm
            from capa.runtime._wasm_host import WasmHost
            blob = compile_wasm(module, types=result.types)
            host = WasmHost(args=program_args)
            host.run_main(blob)
            return 0
        except Exception:
            # Fall through to the Python pipeline. The user opted
            # into best-effort Wasm; silent fallback keeps the
            # default execution path predictable.
            pass

    if args.wasm and (args.transpile or args.run or args.output):
        # Wasm pipeline: AST -> CIR -> WAT -> binary -> (wasmtime
        # | file | component). Failures are loud (no fallback to
        # Python) so coverage gaps in the Wasm backend surface as
        # actionable errors rather than silent shape changes.
        from capa.ir import compile_wat, compile_wasm, compile_wit
        if result is None:
            result = analyze(module, source=source, filename=filename)
        try:
            if args.transpile:
                wat = compile_wat(module, types=result.types)
                print(wat)
                return 0
            blob = compile_wasm(module, types=result.types)
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
                        compile_wit(module, types=result.types),
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
        try:
            if args.component:
                from capa.runtime._wasm_component_host import (
                    WasmComponentHost,
                )
                component_blob = _wrap_as_component(
                    blob, compile_wit(module, types=result.types),
                )
                host = WasmComponentHost(args=program_args)
                host.run_main(component_blob)
            else:
                from capa.runtime._wasm_host import WasmHost
                # Pass the user-visible program args (everything
                # after ``--`` on the CLI) through to the host so
                # env.args inside the wasm module sees the same
                # values it would see under --run on the Python
                # path.
                host = WasmHost(args=program_args)
                host.run_main(blob)
            return 0
        except Exception as e:
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
        print(ast_dump(module))
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


def _wrap_as_component(core_wasm: bytes, wit_text: str) -> bytes:
    """Wrap a core Wasm module in a Component Model component by
    shelling out to ``wasm-tools component embed`` + ``component new``.
    Returns the bytes of the resulting .wasm component, which embeds
    the WIT world and declares the capability interfaces as imports.

    The two-step embed/new flow is what wasm-tools uses canonically:
    embed encodes the WIT metadata into the core module as a custom
    section; new then promotes that core module to a CM component.
    Both steps require ``wasm-tools`` on PATH.
    """
    import subprocess
    import tempfile
    from pathlib import Path as _Path
    with tempfile.TemporaryDirectory() as td:
        td_path = _Path(td)
        wit_path = td_path / "capa.wit"
        core_path = td_path / "core.wasm"
        embed_path = td_path / "embed.wasm"
        comp_path = td_path / "component.wasm"
        wit_path.write_text(wit_text, encoding="utf-8")
        core_path.write_bytes(core_wasm)
        # embed: stamp the WIT world into the core module.
        embed = subprocess.run(
            [
                "wasm-tools", "component", "embed",
                "--world", "program", str(wit_path), str(core_path),
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
            loader = ModuleLoader(search_paths=_capa_search_paths())
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
        try:
            cmd = [sys.executable, "-m", "capa", "--run", str(target)]
            if program_args:
                cmd.append("--")
                cmd.extend(program_args)
            subprocess.run(cmd)
        except KeyboardInterrupt:
            # Ctrl-C during the child's run: re-raise so the
            # watcher exits cleanly.
            raise

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
