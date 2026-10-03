"""Generated corpus for the reserved built-in names tests.

Shared by ``test_builtin_names_reserved`` (the refusal rule) and
``test_builtin_identity`` (the backends agree on what a built-in-named
call means). Every program here is benign: plain values and no labels;
the only output is a printed marker.

The name sets are DERIVED from the compiler's own built-in table
(``capa.builtins``), never restated, so a new built-in joins every
generated case automatically. The one hand-written table here,
:data:`FUNCTION_SPECS`, gives each built-in FUNCTION a same-shaped user
function with a distinguishable marker; :func:`assert_specs_cover` fails
closed when a built-in function has no entry.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa.builtins import FREE_FUNCTIONS


def builtin_global_names() -> list[str]:
    """Every name the analyzer installs in the global scope as a
    built-in, read off a fresh analyzer run (so the list is exactly what
    the analyzer binds, by construction)."""
    from capa.analyzer import Analyzer
    from capa.builtins import BUILTIN_POS
    az = Analyzer()
    az._install_builtins()
    return sorted(
        n for n, s in az.global_scope.symbols.items() if s.pos == BUILTIN_POS
    )


def builtin_function_names() -> list[str]:
    return sorted(FREE_FUNCTIONS)


def renamed(name: str) -> str:
    """A same-length name that is not a built-in: the control twin."""
    last = name[-1]
    return name[:-1] + ("q" if last != "q" else "z")


# ---------------------------------------------------------------------------
# One user function per built-in FUNCTION, with a marker that tells which
# implementation ran. ``params`` / ``ret`` give the user function's
# signature, ``body`` its return value, ``args`` the call arguments,
# ``post`` how the result ``r`` is printed, ``umark`` the line printed when
# the USER function ran.
# ---------------------------------------------------------------------------

FUNCTION_SPECS: dict[str, dict] = {
    "panic": dict(params="m: String", ptys="String", ret="Int",
                  body="7", args='"benign"', post="r", umark="r=7"),
    "to_int": dict(params="x: Float", ptys="Float", ret="Int", body="999",
                   args="1.5", post="r", umark="r=999"),
    "to_float": dict(params="x: Int", ptys="Int", ret="Float", body="9.5",
                     args="2", post="r", umark="r=9.5"),
    "parse_int": dict(params="s: String", ptys="String", ret="Option<Int>",
                      body="Some(999)", args='"7"', post="r.unwrap_or(0)",
                      umark="r=999"),
    "parse_float": dict(params="s: String", ptys="String",
                        ret="Option<Float>", body="Some(9.5)", args='"7.25"',
                        post="r.unwrap_or(0.0)", umark="r=9.5"),
    "new_map": dict(params="", ptys="", ret="Int", body="2", args="",
                    post="r", umark="r=2"),
    "new_set": dict(params="", ptys="", ret="Int", body="3", args="",
                    post="r", umark="r=3"),
    "parse_json": dict(params="s: String", ptys="String", ret="Int",
                       body="4", args='"1"', post="r", umark="r=4"),
    "to_json": dict(params="j: Int", ptys="Int", ret="String",
                    body='"shadow"', args="5", post="r", umark="r=shadow"),
    "_capa_chr": dict(params="i: Int", ptys="Int", ret="String", body='"Z"',
                      args="65", post="r", umark="r=Z"),
    "_capa_str_span": dict(params="l: List<String>, a: Int, b: Int",
                           ptys="List<String>, Int, Int", ret="String",
                           body='"Y"', args='["a", "b"], 0, 1', post="r",
                           umark="r=Y"),
    "declassify": dict(params="v: String, why: String",
                       ptys="String, String", ret="String", body='"D"',
                       args='"a", "w"', post="r", umark="r=D"),
    "py_import": dict(params="s: String", ptys="String", ret="Int",
                      body="8", args='"os"', post="r", umark="r=8"),
    "py_invoke": dict(params="s: String", ptys="String", ret="Int",
                      body="6", args='"os"', post="r", umark="r=6"),
}


def assert_specs_cover(test) -> None:
    """Fail closed: every built-in function has a user-function spec."""
    test.assertEqual(
        sorted(FUNCTION_SPECS), builtin_function_names(),
        "a built-in function has no FUNCTION_SPECS entry; add one so the "
        "generated corpus covers it",
    )


def fun_type(spec: dict) -> str:
    return f"Fun({spec['ptys']}) -> {spec['ret']}"


def user_fun(name: str, spec: dict, *, pub: bool = False) -> str:
    """A module-level user function named ``name`` with ``spec``'s shape."""
    head = "pub fun" if pub else "fun"
    return (
        f"{head} {name}({spec['params']}) -> {spec['ret']}\n"
        f"    return {spec['body']}\n"
    )


# ---------------------------------------------------------------------------
# Parsing / analysis / linking helpers.
# ---------------------------------------------------------------------------


def parse(src: str, filename: str = "<input>"):
    return Parser(
        Lexer(src, filename=filename).lex(), source=src, filename=filename,
    ).parse_module()


def analyze_source(src: str):
    module = parse(src)
    return module, analyze(module, source=src)


#: The fragment every reserved built-in name refusal carries.
RESERVED_FRAGMENT = "is the name of a built-in"


def assert_only_reserved_refusals(result) -> None:
    """``result`` was refused, and ONLY for taking a reserved built-in
    name: the rest of the program is valid."""
    msgs = [e.message for e in result.errors]
    if not msgs or not all(RESERVED_FRAGMENT in m for m in msgs):
        raise AssertionError(
            f"expected only reserved-name refusals, got {msgs}"
        )


def analyze_past_reserved_refusal(src: str, filename: str = "<input>"):
    """Analyze a program whose ONLY fault is a module-level item with a
    built-in's name, and return ``(module, result)`` anyway, so a test can
    compile it the way the compiler's analysis-free lowering paths do and
    show they still read the one module-scope identity decision."""
    module = parse(src, filename=filename)
    result = analyze(module, source=src, filename=filename)
    assert_only_reserved_refusals(result)
    return module, result


class Project:
    """A throwaway on-disk project (root ``main.capa`` plus dependency
    files), linked by the real module loader exactly as the CLI links
    it."""

    def __init__(self, files: dict[str, str]):
        self.dir = Path(tempfile.mkdtemp(prefix="capa_builtin_names_"))
        for rel, text in files.items():
            p = self.dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8", newline="\n")
        self.main = self.dir / "main.capa"

    def path(self, rel: str) -> str:
        """The absolute path the loader records for ``rel``."""
        return str((self.dir / rel).resolve())

    def link(self):
        """``(linked, None)`` or ``(None, LoaderError)``."""
        from capa.loader import LoaderError, ModuleLoader
        src = self.main.read_text(encoding="utf-8")
        try:
            return ModuleLoader().load_root(src, str(self.main)), None
        except LoaderError as le:
            return None, le

    def analyze(self):
        """``(linked, AnalysisResult)``; raises on a loader error."""
        linked, err = self.link()
        if err is not None:
            raise err
        src = self.main.read_text(encoding="utf-8")
        result = analyze(
            linked.module, source=src, filename=str(self.main),
            sources=linked.sources, module_privates=linked.module_privates,
        )
        return linked, result

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def same_file(a: str, b: str) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(
        os.path.realpath(b)
    )
