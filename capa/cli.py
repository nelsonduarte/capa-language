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
import sys
from pathlib import Path

from capa import (
    Lexer, LexerError, Parser, TokenKind, analyze, ast_dump, transpile,
)
from capa import __version__ as _CAPA_VERSION
from capa.manifest import build_manifest, build_cyclonedx
from capa.docgen import build_html as build_doc_html
from capa.formatter import format_source, is_formatted
from capa.init_project import init_project


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


def main() -> int:
    # Subcommand dispatch happens before argparse so the rest of
    # the CLI can stay flag-based without complicating help output.
    if len(sys.argv) >= 2 and sys.argv[1] == "init":
        return _dispatch_init(sys.argv[2:])

    parser = argparse.ArgumentParser(
        description="Lexer, parser and analyzer for the Capa language",
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
        help="transpile and execute the program (calls main with capabilities)",
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
        "--no-color",
        action="store_true",
        help="disable ANSI colors in the output",
    )
    parser.add_argument(
        "--no-layout",
        action="store_true",
        help="omit layout tokens (NEWLINE/INDENT/DEDENT/EOF) in the output",
    )
    args = parser.parse_args()

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

    if (
        args.parse
        or args.check
        or args.transpile
        or args.run
        or args.manifest
        or args.cyclonedx
        or args.doc
    ):
        try:
            module = Parser(
                tokens, source=source, filename=filename
            ).parse_module()
        except LexerError as e:
            if use_color:
                print(f"{C.RED}{e.format()}{C.RESET}", file=sys.stderr)
            else:
                print(e.format(), file=sys.stderr)
            return 1

    result = None
    if args.check or args.run or args.manifest or args.cyclonedx or args.doc:
        # Semantic analysis is required before running.
        result = analyze(module, source=source, filename=filename)
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

    if args.transpile or args.run:
        # If we haven't yet run analyze (in --transpile mode without --check),
        # we run it now silently to obtain types for the
        # type-aware dispatch in the transpiler.
        if result is None:
            result = analyze(module, source=source, filename=filename)
        code = transpile(
            module, filename=filename,
            types=result.types if result is not None else None,
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
            return 1

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


if __name__ == "__main__":
    sys.exit(main())
