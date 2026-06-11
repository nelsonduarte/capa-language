"""Shared pre-emit traversal of a CIR module.

Every "does this module use feature X?" gate used to hand-roll its
own recursive walk over the instruction tree, and the copies
drifted: some missed impl-method bodies, some missed ``MakeLambda``
bodies, some missed match-arm guard preludes. A feature used ONLY
inside an impl method or a closure body then compiled into a call
against a runtime helper the module never defined ("unknown func"
at wasm-tools parse time) or skipped a required emission entirely.

This module is the single traversal those gates consume:

- :func:`iter_functions` yields every function-like body owner
  (top-level functions, then every impl method).
- :func:`walk_instrs` yields every ``Instr`` reachable from a body
  in pre-order: nested ``If`` / ``While`` / ``For`` bodies,
  ``While.cond_setup``, ``Match`` arm guard preludes + bodies, and
  (unless opted out) ``MakeLambda`` bodies.
- :func:`walk_module` composes the two into ``(owner, instr)``
  pairs over the whole module.

It lives in ``capa.ir`` (not under ``_emit_wasm``) because the WIT
generator (``_emit_wit``) and the bundled-JSON injector
(``_builtin_json``) consume the same traversal; importing only
``_nodes`` keeps it cycle-free for all three.
"""

from __future__ import annotations

from typing import Iterator

from ._nodes import (
    Module, Function, Instr,
    If, While, For, Match, MakeLambda,
)


def iter_functions(module: Module) -> Iterator[Function]:
    """Yield every function-like body owner in ``module``:
    top-level functions first, then every impl block's methods.
    Impl methods are plain :class:`Function` objects whose
    ``locals`` map covers their body, so gates treat them exactly
    like top-level functions."""
    yield from module.functions
    for impl in module.impls:
        yield from impl.methods


def walk_instrs(
    instrs: list[Instr], *, into_lambdas: bool = True,
) -> Iterator[Instr]:
    """Yield every ``Instr`` reachable from ``instrs`` in
    pre-order: each instruction itself, then the contents of every
    nested instruction list it owns -- ``If`` then/else bodies,
    ``While`` cond_setup + body, ``For`` body, ``Match`` arm guard
    preludes (``guard_setup``) + bodies, and ``MakeLambda`` bodies.

    ``into_lambdas=False`` skips lambda bodies (the ``MakeLambda``
    instruction itself is still yielded); the lambda-lift discovery
    uses this to handle each nesting level with its own scope
    stack while reusing the control-flow recursion here."""
    for instr in instrs:
        yield instr
        if isinstance(instr, If):
            yield from walk_instrs(
                instr.then_body, into_lambdas=into_lambdas)
            yield from walk_instrs(
                instr.else_body, into_lambdas=into_lambdas)
        elif isinstance(instr, While):
            yield from walk_instrs(
                instr.cond_setup, into_lambdas=into_lambdas)
            yield from walk_instrs(
                instr.body, into_lambdas=into_lambdas)
        elif isinstance(instr, For):
            yield from walk_instrs(
                instr.body, into_lambdas=into_lambdas)
        elif isinstance(instr, Match):
            for arm in instr.arms:
                yield from walk_instrs(
                    arm.guard_setup, into_lambdas=into_lambdas)
                yield from walk_instrs(
                    arm.body, into_lambdas=into_lambdas)
        elif isinstance(instr, MakeLambda) and into_lambdas:
            yield from walk_instrs(
                instr.body, into_lambdas=into_lambdas)


def walk_module(
    module: Module, *, into_lambdas: bool = True,
) -> Iterator[tuple[Function, Instr]]:
    """Yield ``(owner, instr)`` pairs for every instruction in
    every function and impl-method body of ``module``. The owner
    of an instruction inside a lambda body is the enclosing
    top-level function / impl method (the lowerer's flat
    ``Function.locals`` map covers lambda-body locals, which is
    what type-fallback consumers need)."""
    for fn in iter_functions(module):
        for instr in walk_instrs(fn.body, into_lambdas=into_lambdas):
            yield fn, instr
