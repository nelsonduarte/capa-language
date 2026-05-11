"""capa-lex — command-line utility for the Capa lexer.

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
import tempfile
from pathlib import Path

from capa import (
    Lexer, LexerError, Parser, TokenKind, analyze, ast_dump, transpile,
)
from capa.manifest import build_manifest


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


def main() -> int:
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
    if args.check or args.run or args.manifest:
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
        # Write the transpiled code to a temporary file and execute it
        # as a subprocess, with PYTHONPATH pointing to the capa
        # package (so that the runtime is importable).
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            temp_path = f.name
        try:
            # __file__ is capa/cli.py; we need the directory that CONTAINS
            # the 'capa' package, so the subprocess can do `from capa.runtime
            # import ...`. Hence, .parent.parent.
            pkg_parent = Path(__file__).resolve().parent.parent
            env = os.environ.copy()
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (
                str(pkg_parent) + (os.pathsep + existing if existing else "")
            )
            r = subprocess.run(
                [sys.executable, temp_path], env=env,
            )
            return r.returncode
        finally:
            os.unlink(temp_path)

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
