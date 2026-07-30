"""capa, front-end for the Capa programming language.

This package contains the lexer, parser, AST, type system, semantic
analyzer, transpiler, and runtime for Capa.

Example usage:

    from capa import Lexer, Parser, LexerError

    source = open("program.capa", encoding="utf-8").read()
    try:
        tokens = Lexer(source, filename="program.capa").lex()
        ast = Parser(tokens, source=source, filename="program.capa").parse_module()
    except LexerError as e:
        print(e.format())
"""

# The package version is single-sourced from ``pyproject.toml``
# (``[project].version``). Nothing in the tree hard-codes a version
# string, so a release only ever bumps pyproject.toml and every
# consumer that reads ``capa.__version__`` (the CLI ``--version``,
# ``init_project``'s ``.capa-version`` stamp, the manifest / SBOM /
# provenance / AOT builders, the LSP server) follows automatically.
#
# Resolution order, most-authoritative first:
#
# 1. The ``pyproject.toml`` sitting next to this package on disk.
#    This is the ground truth when running from a source checkout,
#    and it stays correct even when a *stale* editable install has
#    left an out-of-date ``capa`` dist-info on the path (a common
#    dev setup that would otherwise make ``importlib.metadata``
#    report the wrong version).
# 2. Installed distribution metadata via ``importlib.metadata``.
#    This is the path for a real ``pip install`` (no adjacent
#    pyproject.toml under ``site-packages``) and for the PyInstaller
#    binary, whose spec bundles the distribution's dist-info metadata
#    with ``copy_metadata`` precisely so this lookup succeeds when
#    frozen. The distribution is named ``capa-language`` on PyPI, but
#    older installs used ``capa``, so we try the new name first and
#    fall back to the old one.
#
# The final fallback is a clearly-bogus sentinel, never a plausible
# release number: if resolution ever fails we want it to be obvious,
# not to silently re-introduce the stale-literal bug this replaces.


def _resolve_version() -> str:
    import os

    # 1. Adjacent pyproject.toml (source checkout / editable install).
    pyproject = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "pyproject.toml",
    )
    try:
        with open(pyproject, "rb") as fh:
            raw = fh.read()
    except OSError:
        raw = None
    if raw is not None:
        version = _version_from_pyproject(raw)
        if version is not None:
            return version

    # 2. Installed distribution metadata (wheel / frozen binary).
    version = _version_from_metadata()
    if version is not None:
        return version

    # 3. Sentinel: resolution failed. Deliberately not a real version.
    return "0+unknown"


def _version_from_pyproject(raw: bytes) -> "str | None":
    try:
        import tomllib  # Python >= 3.11
    except ImportError:
        tomllib = None
    if tomllib is not None:
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return None
        project = data.get("project")
        if isinstance(project, dict):
            value = project.get("version")
            if isinstance(value, str):
                return value
        return None
    # Python 3.10 has no tomllib: fall back to a minimal regex scan.
    # The only bare ``version = "..."`` assignment in pyproject.toml is
    # the ``[project].version`` line; the dependency pins use ``>=`` in
    # list literals and never match this anchored pattern.
    import re

    match = re.search(
        rb'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']',
        raw,
    )
    if match is not None:
        return match.group(1).decode("utf-8")
    return None


# The distribution names to try, most-current first. The project is
# ``capa-language`` on PyPI; ``capa`` is the legacy name older installs
# still carry, so trying both keeps a wheel or frozen binary reporting
# the real version across the transition instead of the sentinel.
_DIST_NAMES = ("capa-language", "capa")


def _version_from_metadata() -> "str | None":
    try:
        from importlib.metadata import PackageNotFoundError, version as _dist_version
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib >=3.8
        return None
    for name in _DIST_NAMES:
        try:
            return _dist_version(name)
        except PackageNotFoundError:
            continue
    return None


__version__ = _resolve_version()

from . import capa_ast as ast
from .analyzer import Analyzer, AnalysisError, AnalysisResult, Symbol, SymbolKind, analyze
from .capa_ast import dump as ast_dump
from .errors import LexerError
from .formatter import format_source, is_formatted
from .lexer import Lexer
from .parser import Parser, ParserError
from .tokens import KEYWORDS, Pos, Token, TokenKind
from .transpiler import Transpiler, TranspilerError, transpile
from .typesys import Ty, TyName, TyFun, TyTuple, TyVar, TyUnit, TyUnknown, ty_str

__all__ = [
    "__version__",
    "analyze",
    "Analyzer",
    "AnalysisError",
    "AnalysisResult",
    "ast",
    "ast_dump",
    "format_source",
    "is_formatted",
    "KEYWORDS",
    "Lexer",
    "LexerError",
    "Parser",
    "ParserError",
    "Pos",
    "Symbol",
    "SymbolKind",
    "Token",
    "TokenKind",
    "transpile",
    "Transpiler",
    "TranspilerError",
    "Ty",
    "TyName",
    "TyFun",
    "TyTuple",
    "TyVar",
    "TyUnit",
    "TyUnknown",
    "ty_str",
]
