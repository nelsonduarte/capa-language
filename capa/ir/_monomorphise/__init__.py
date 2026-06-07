"""Monomorphisation pass: specialise generic user functions per
concrete instantiation seen at call sites.

The lowerer leaves generic functions ungeneralised: a
``fun first<T>(items: List<T>) -> Option<T>`` arrives in the IR
with ``type_params=["T"]`` and a body whose ``Value.ty`` /
``locals[name]`` strings still mention ``T`` / ``List<T>`` /
``Option<T>``. The Python backend tolerates this (duck typing),
but the Wasm backend's layout machinery fails on ``T`` because
the type has no Wasm encoding.

This pass walks the IR module and, for each call to a generic
function whose substitution can be inferred from argument types,
synthesises a specialised clone of the function (name mangled,
``T`` replaced by the concrete type throughout the body) and
rewrites the call to target the clone. After the pass, the
module contains no generic functions and no calls to type
variables: the Wasm backend can emit normally.

Scope (v1):

* Free functions only. Generic methods (``impl<T> Trait for ...``),
  generic struct types, and generic capability methods are out
  of scope; the pass leaves them alone, which means programs
  using those features still hit the actionable
  "no Wasm encoding" error.
* String-based unification. The IR stores types as strings; the
  inference walks ``"List<T>"`` against ``"List<Int>"`` to derive
  ``T=Int``. Works for nested arities the backend already
  supports (``Option<T>``, ``Result<T, E>``, ``List<T>``,
  ``Map<K, V>``, ``(T, U)``).
* No partial application; every type parameter must be resolved
  from the concrete argument types.

When a call cannot be monomorphised (callee not found, ambiguous
substitution, etc.), the pass leaves the call alone and the
downstream backend will surface its existing error.

This module is organised as a package:

* :mod:`._typestr` - string-level type parsing / unification /
  substitution / mangling helpers.
* :mod:`._functions` - generic function cloning + body substitution.
* :mod:`._calls` - call-site inference + rewrite and the top-level
  ``monomorphise`` pass.
* :mod:`._types` - generic struct / sum / impl monomorphisation
  (``monomorphise_generic_types``).
"""

from __future__ import annotations

from ._calls import monomorphise
from ._types import monomorphise_generic_types

__all__ = ["monomorphise", "monomorphise_generic_types"]
