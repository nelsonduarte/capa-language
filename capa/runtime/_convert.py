"""Builtin conversion functions and the ``?`` propagation helper.

- ``parse_int`` / ``parse_float``: total parsers that return
  ``Option`` instead of raising.
- ``to_float`` / ``to_int``: explicit numeric conversions; Capa has
  no implicit promotion, so these surface intent.
- ``_propagate_err``: legacy helper used by an earlier transpilation
  scheme for the ``?`` operator. Kept in the public ``__all__`` for
  back-compat with already-emitted code; the current transpiler
  injects its own ``_capa_try`` helper.
"""

from __future__ import annotations

from ._result import Err, None_, Ok, Some


_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1


def parse_int(s):
    """Tries to convert ``s`` to Int. Returns ``Some(n)`` on success,
    ``None_`` on failure (non-numeric, empty, or outside the signed
    64-bit window).

    Audit fix C5: out-of-range inputs (e.g. ``"99999999999999999999"``)
    used to return a ``Some`` carrying a Python-arbitrary-precision int,
    which then silently wrapped on the Wasm backend's i64 accumulator;
    both backends now reject the value loudly by returning ``None_``.
    Same observable failure shape as a typo or an empty string."""
    try:
        n = int(s.strip())
    except (ValueError, AttributeError):
        return None_
    if n < _I64_MIN or n > _I64_MAX:
        return None_
    return Some(n)


def parse_float(s):
    """Tries to convert ``s`` to Float. Returns ``Some(f)`` on success,
    ``None_`` on failure."""
    try:
        return Some(float(s.strip()))
    except (ValueError, AttributeError):
        return None_


def to_float(i):
    """Convert an Int to a Float. Total, every Int has an exact Float
    representation within the range Capa cares about. Used to bridge the
    Int/Float divide in arithmetic when implicit coercion would hide
    intent (Capa has no implicit numeric promotion)."""
    return float(i)


def to_int(f):
    """Truncate a Float to an Int (toward zero). Total. The fractional
    part is discarded; for round-to-nearest use a different primitive
    when one is added."""
    return int(f)


def _propagate_err(result):
    """Helper used by the transpilation of the `?` operator.

    If ``result`` is Err, returns None and signals the caller to return.
    If it is Ok, returns the unwrapped value.
    The caller must check whether it received a _PROPAGATE sentinel.
    """
    if isinstance(result, Err):
        return result, True
    if isinstance(result, Ok):
        return result.value, False
    raise RuntimeError(f"`?` applied to non-Result value: {result!r}")
