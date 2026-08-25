"""Terminal colour and CLI diagnostic helpers.

Leaf module for :mod:`capa.cli`: it holds the ANSI colour table, the
token-kind colouring used by ``capa --parse``/token dumps, and the single
converter that turns a leaked ``RecursionError`` into a clean CLI
diagnostic. It must not import from :mod:`capa.cli` (the dependency runs
one way, ``capa.cli`` -> ``capa.cli._diagnostics``).
"""

import sys

from capa import TokenKind


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


def _recursion_diagnostic(filename: str, action: str, *, use_color: bool) -> int:
    """Convert a leaked ``RecursionError`` into a clean CLI diagnostic.

    The parser caps nesting depth and flat-chain length, so a pathological
    expression is rejected before an AST that could overflow a recursive
    walk is ever built. Should any path still recurse past the interpreter
    limit, this prints one diagnostic (in red when ``use_color``) and
    returns exit code 1 rather than letting a raw stack trace escape.
    ``action`` is the verb for the phase that overflowed ("analyze" for the
    ``capa --check`` path, "dump" for the ``capa --parse`` AST dump).
    """
    msg = (
        f"{filename}: error: expression too deep or complex to "
        f"{action}; simplify or split it"
    )
    if use_color:
        print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
    else:
        print(msg, file=sys.stderr)
    return 1
