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

import math

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
    """Truncate a Float to an Int (toward zero).

    Matches the Wasm backend's ``i64.trunc_f64_s`` semantics: returns
    the truncated integer when the result fits in the signed 64-bit
    window, otherwise raises ``OverflowError``. ``NaN`` and the
    positive / negative infinities also raise ``OverflowError`` (the
    Wasm opcode traps on the same inputs).

    Audit fix C4: ``int(1e20)`` used to return a Python-arbitrary-
    precision int on the Python backend while the Wasm backend trapped
    on the same input; that was the last silent observable divergence
    on the conversion surface. Both backends now fail loud at the same
    input. The fractional part is discarded; for round-to-nearest use
    a different primitive when one is added.
    """
    if math.isnan(f):
        raise OverflowError("to_int: NaN cannot be converted to Int")
    if math.isinf(f):
        raise OverflowError("to_int: infinity cannot be converted to Int")
    # i64.trunc_f64_s traps when the truncated value is outside
    # ``[-2**63, 2**63)``. The boundary on the positive side is the
    # exact float ``2**63``: any f64 value >= that traps. The negative
    # boundary is ``-2**63 - 1`` (any f64 strictly less than -2**63
    # would trap once truncated; -2**63 itself is representable).
    if f >= 9223372036854775808.0 or f < -9223372036854775808.0:
        raise OverflowError(
            f"to_int: {f!r} out of signed 64-bit range"
        )
    return int(f)


def _capa_chr(cp):
    """Internal: one-codepoint String from an Int code point.

    Backs the (undocumented, underscore-prefixed) ``_capa_chr``
    builtin that the bundled Wasm-side JSON parser uses to decode
    ``\\uXXXX`` escapes. Python's ``chr`` already accepts the full
    0..0x10FFFF range including lone surrogates (which Python ``str``
    can hold, exactly like ``json.loads`` produces for an unpaired
    ``\\ud800``); the Wasm runtime helper ``$chr`` mirrors that by
    storing lone surrogates as WTF-8 bytes. Out of range raises here
    and traps on the Wasm side: loud on both backends."""
    if not 0 <= cp <= 0x10FFFF:
        raise ValueError(f"_capa_chr: code point {cp!r} out of range")
    return chr(cp)


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
