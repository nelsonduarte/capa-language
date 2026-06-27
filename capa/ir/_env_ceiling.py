"""Static Env authority-ceiling analysis for the ``--wasi`` mode.

Level 1 of ``docs/design/wasi-attenuation.md`` for the Env capability:
map ``main``'s Env CEILING onto the WASI host configuration
(``wasi:cli/environment`` env-set) so the component is instantiated
with ONLY the environment variables the program can read, closing the
leak-by-default that ``inherit_env`` (Level 2) leaves open.

The ceiling is the set of environment keys the program can ever read
through ``Env.get``. We compute it from the CIR (after the loader has
inlined imported functions, so every reachable ``env.get`` call site is
visible) by scanning every ``MethodCall`` whose receiver is an ``Env``
and whose method is ``get``:

- a STRING-LITERAL argument (``Value(kind="lit_str")``) contributes its
  key to the ceiling;
- any NON-LITERAL argument (a local / param / computed value) makes the
  key indeterminable at compile time, so the ceiling is marked NOT
  CLOSED.

When the ceiling is closed, the union of the literals is the exact set
of keys the program can read; the host instantiates the component with
an env-set restricted to those keys (read from the host environment),
and a key in the ceiling but absent from the host environment reads as
``none`` (fail-closed), so the program's OBSERVABLE behaviour is
identical to the ``inherit_env`` path. The only difference is that the
component never RECEIVES the variables outside the ceiling.

When the ceiling is not closed (at least one dynamic ``env.get`` key),
the host falls back to ``inherit_env`` (Level 2): the guest-side
allow-list still narrows under our host, but the ceiling is not
materialised via env-set.

Why only ``Env.get`` defines the ceiling:

- ``Env.args`` reads argv, never an environment key, so it does not
  widen the ceiling.
- ``Env.restrict_to_keys`` / ``Env.allows`` only NARROW or QUERY the
  allow-list; they can never make the program read a key it does not
  already pass to ``env.get``. A program that reads ``env.get(k)`` for
  a key ``k`` it never restricted still needs ``k`` in the ceiling, and
  that need is captured by the ``get`` literal directly. So the keys a
  program can OBSERVE are exactly the union of its ``env.get`` literals
  (plus the dynamic-key escape hatch above).

A literal bound through an intermediate ``let`` (``let k = "FOO"`` then
``env.get(k)``) appears as a local at the call site, so it is treated
CONSERVATIVELY as dynamic and triggers the ``inherit_env`` fallback.
This never under-delivers a key the program reads (the fallback hands
the full environment); it only declines the Level 1 tightening in a
case the simple literal scan cannot prove. Folding constants into the
scan is a possible future refinement, not a correctness requirement.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import capa_ast as A
from ._lower import Lowerer
from ._nodes import MethodCall, Module
from ._walk import walk_module


# Capability class name and method that define the Env read ceiling.
_ENV_CAP = "Env"
_ENV_GET = "get"


@dataclass(frozen=True)
class EnvCeiling:
    """The result of the static Env ceiling analysis.

    ``closed`` is True when every reachable ``env.get`` call passes a
    string literal, so ``keys`` is the exact, complete set of
    environment variables the program can read. When ``closed`` is
    False at least one ``env.get`` key is computed at runtime and the
    ceiling cannot be materialised; ``keys`` still holds the literals
    seen (informational only) but the host must fall back to
    ``inherit_env``.
    """
    closed: bool
    keys: frozenset[str]

    def host_env_set(self, environ: dict[str, str]) -> dict[str, str]:
        """Project the host ``environ`` onto the ceiling keys.

        Only defined for a CLOSED ceiling: returns the subset of the
        host environment whose keys are in the ceiling, dropping every
        variable the program cannot read. A ceiling key absent from the
        host environment is simply omitted (the guest reads it as
        ``none``, fail-closed, exactly as ``inherit_env`` would)."""
        return {k: environ[k] for k in self.keys if k in environ}


def compute_env_ceiling_from_cir(cir: Module) -> EnvCeiling:
    """Scan a lowered CIR module for the Env read ceiling.

    Walks every function and impl-method body (the loader has already
    inlined imported functions into the AST the CIR was lowered from,
    so this covers the whole reachable program) and inspects every
    ``env.get`` call site. See the module docstring for the literal /
    dynamic rule."""
    keys: set[str] = set()
    closed = True
    for _owner, instr in walk_module(cir):
        if not isinstance(instr, MethodCall):
            continue
        cap = instr.cap_used or (instr.receiver.ty or "")
        if cap != _ENV_CAP or instr.method != _ENV_GET:
            continue
        # env.get takes exactly one argument (the key). Defensive: an
        # unexpected arity is treated as dynamic (cannot prove the
        # literal), never silently narrowing the ceiling.
        if len(instr.args) != 1:
            closed = False
            continue
        arg = instr.args[0]
        if arg.kind == "lit_str" and isinstance(arg.literal, str):
            keys.add(arg.literal)
        else:
            # A computed / local / param key: the program may read a
            # variable name decided at runtime, so the ceiling cannot
            # be materialised statically.
            closed = False
    return EnvCeiling(closed=closed, keys=frozenset(keys))


def compute_env_ceiling(
    module: A.Module, types: dict | None = None,
) -> EnvCeiling:
    """Lower ``module`` to CIR and compute its Env read ceiling.

    Convenience wrapper over :func:`compute_env_ceiling_from_cir` that
    runs the same lowering the Wasm pipeline uses (so the ceiling is
    computed from the exact instruction tree that will be emitted),
    without the monomorphise / char-normalise passes, which do not
    affect ``env.get`` literal arguments."""
    cir = Lowerer(types=types or {}).lower_module(module)
    return compute_env_ceiling_from_cir(cir)
