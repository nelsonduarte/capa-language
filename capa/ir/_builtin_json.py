"""Lazy loader for the bundled JSON parser/serializer source.

The Wasm backend redirects ``parse_json`` / ``to_json`` calls to
``__capa_parse_json`` / ``__capa_to_json``, which are implemented
in Capa source at ``_builtin_json.capa`` (in this same package).
Routing the calls keeps the Component Model surface free of the
``capa:host/json`` host bridge -- everything happens inside the
guest module's linear memory, so ``--component --run`` works
without leaking the canonical-ABI memory boundary.

This module's single entry point ``inject_into`` merges the
parser's IR functions into a user's IR module so the user's
``parse_json`` calls resolve to local exports. The merge is
idempotent and a no-op when the user's program does not
reference ``parse_json`` / ``to_json``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._nodes import Call, Module
from ._walk import walk_module


_BUNDLED_SOURCE_PATH = Path(__file__).parent / "_builtin_json.capa"


def uses_json_builtins(ir_module: Module) -> bool:
    """True when anything in ``ir_module`` references the built-in
    ``parse_json`` or ``to_json`` free functions. The shared module
    walk covers every nested instruction body -- if / while / for /
    match arms (guard preludes included), impl-method bodies, and
    lambda bodies -- so a call that only appears inside a method or
    a closure still triggers the injection."""
    return any(
        isinstance(instr, Call) and instr.callee_name in (
            "parse_json", "to_json",
        )
        for _fn, instr in walk_module(ir_module)
    )


_cached_ir: Optional[Module] = None


def _load_builtin_ir() -> Module:
    """Parse + analyze + lower the bundled source. Cached at module
    import scope so repeated compilations in the same process don't
    re-do the analyzer + lowerer for an unchanging input."""
    global _cached_ir
    if _cached_ir is not None:
        return _cached_ir
    # Local imports so the IR package can import this module
    # without pulling the lexer / parser / analyzer into its own
    # dependency graph at top level.
    from ..lexer import Lexer
    from ..parser import Parser
    from ..analyzer import analyze
    from . import lower

    source = _BUNDLED_SOURCE_PATH.read_text(encoding="utf-8")
    tokens = Lexer(
        source, filename=str(_BUNDLED_SOURCE_PATH),
    ).lex()
    ast_module = Parser(tokens).parse_module()
    # ``internal=True``: the bundled parser calls the internal
    # ``_capa_chr`` builtin, which the analyzer rejects in user code.
    result = analyze(
        ast_module, source=source, filename=str(_BUNDLED_SOURCE_PATH),
        internal=True,
    )
    if result.errors:
        # The bundled source is compiler-shipped; an analysis error
        # here is a compiler bug. Lowering anyway would miscompile
        # silently, so fail loudly with the first diagnostic.
        raise RuntimeError(
            f"bundled JSON parser failed analysis: {result.errors[0]}"
        )
    _cached_ir = lower(ast_module, types=result.types)
    return _cached_ir


def inject_into(ir_module: Module) -> Module:
    """Splice the bundled JSON parser / serializer functions into
    ``ir_module`` when it references ``parse_json`` or ``to_json``.
    Returns the same module (mutated in place when an injection
    happens; untouched otherwise) so callers can chain the call."""
    if not uses_json_builtins(ir_module):
        return ir_module
    parser_ir = _load_builtin_ir()
    # Don't duplicate when the user's source has its own
    # ``__capa_parse_json`` (defensive against future hand-rolled
    # tests that pre-inject the parser).
    existing = {fn.name for fn in ir_module.functions}
    for fn in parser_ir.functions:
        if fn.name in existing:
            continue
        ir_module.functions.append(fn)
    # Types / impls / traits / consts: the bundled module has none
    # today; copy defensively so a future iteration that introduces
    # a helper struct just works.
    for ty in parser_ir.types:
        ir_module.types.append(ty)
    for impl in parser_ir.impls:
        ir_module.impls.append(impl)
    for trait in parser_ir.traits:
        ir_module.traits.append(trait)
    for const in parser_ir.consts:
        ir_module.consts.append(const)
    return ir_module
