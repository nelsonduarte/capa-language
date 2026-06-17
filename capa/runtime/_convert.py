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

# ASCII whitespace trimmed from both ends before parsing. Kept as an
# explicit set (space, tab, LF, VT, FF, CR) rather than ``str.strip()``
# so the Python and Wasm backends agree byte-for-byte: ``str.strip()``
# also strips Unicode whitespace (NBSP, U+2028, ...), which the Wasm
# byte-level scanner cannot see, and that mismatch was a cross-backend
# divergence. The same six bytes are trimmed by ``$parse_int`` in the
# Wasm runtime.
_ASCII_WS = " \t\n\x0b\x0c\r"


def parse_int(s):
    """Tries to convert ``s`` to Int. Returns ``Some(n)`` on success,
    ``None_`` on failure.

    Canonical grammar (identical on both backends):

        surrounding ASCII whitespace, then an optional sign ``[+-]``,
        then one or more decimal digits ``[0-9]``, and nothing else.

    Deliberately stricter than Python's ``int``: underscores (PEP 515,
    ``"1_000"``) are rejected, and so are the ``0x`` / ``0b`` / ``0o``
    bases and any non-decimal form. The value must land in the signed
    64-bit window ``[-2**63, 2**63)``, which includes ``i64::MIN``
    (``-9223372036854775808``); anything else returns ``None_``.

    Out-of-range and malformed inputs share one observable failure
    shape (``None_``) so a typo, an empty string, an overflowing
    magnitude, and ``"1_000"`` are indistinguishable to the caller and
    identical across backends. The Wasm ``$parse_int`` mirrors this
    grammar exactly."""
    if not isinstance(s, str):
        return None_
    body = s.strip(_ASCII_WS)
    if not body:
        return None_
    sign = ""
    digits = body
    if body[0] in "+-":
        sign = body[0]
        digits = body[1:]
    if not digits or not digits.isascii() or not digits.isdigit():
        return None_
    # Reject out-of-range magnitudes BEFORE ``int(body)``. CPython caps
    # int<->str conversion at ~4300 digits and raises an uncaught
    # ValueError past that (a DoS for a server parsing third-party
    # numbers); the Wasm ``$parse_int`` already rejects overflow as
    # ``None``. The screen here is both the overflow check and the DoS
    # guard, and keeps the two backends in lockstep (both ``None`` for
    # out-of-range).
    #
    # The cutoff must be on SIGNIFICANT digits, not raw length: the Wasm
    # ``$parse_int`` accumulates digit-by-digit and only rejects when the
    # i64 accumulator would overflow, so a long run of leading zeros
    # (``"000...0009"``) accumulates harmlessly and yields ``Some(9)``.
    # A raw-length guard rejected that in Python while Wasm accepted it
    # -- a real cross-backend divergence for an in-range value (audit
    # 2026-06-17). Stripping leading zeros first measures the magnitude
    # the way Wasm does. ``i64::MAX`` / ``i64::MIN`` have 19 significant
    # digits, so any magnitude with more than 19 significant digits
    # cannot fit; 20 is the conservative cutoff (a 19-or-20-digit value
    # still goes through the exact i64-window check below).
    significant = digits.lstrip("0")
    if len(significant) > 20:
        return None_
    n = int(sign + (significant or "0"))
    if n < _I64_MIN or n > _I64_MAX:
        return None_
    return Some(n)


def parse_float(s):
    """Tries to convert ``s`` to Float. Returns ``Some(f)`` on success,
    ``None_`` on failure.

    Canonical grammar (identical on both backends, aligned with
    ``parse_int``): surrounding ASCII whitespace, an optional sign
    ``[+-]``, a mantissa of decimal digits with an optional single
    ``.`` (``12`` / ``12.5`` / ``.5`` / ``12.``), an optional exponent
    ``[eE][+-]?digits``, and nothing else.

    Deliberately stricter than Python's ``float``: the ``inf`` / ``nan``
    / ``infinity`` constants are rejected (a parser must not synthesise
    a non-finite Float out of textual input), PEP-515 underscores
    (``"1_000.5"``) are rejected, and so is any Unicode whitespace that
    the byte-level Wasm scanner cannot see. A magnitude that overflows
    to infinity (``"1e400"``) returns ``None_`` rather than ``inf`` so
    the two backends agree and no ``inf`` enters from input; underflow
    returns ``0.0``. ``float()`` itself is correctly rounded, so once
    the grammar and overflow are screened the value matches the Wasm
    ``$parse_float`` (a bignum-backed correctly-rounded parser) bit for
    bit. The same grammar is enforced by ``$parse_float`` in the Wasm
    runtime."""
    if not isinstance(s, str):
        return None_
    body = s.strip(_ASCII_WS)
    if not body:
        return None_
    i = 0
    n = len(body)
    if body[i] in "+-":
        i += 1
    saw_digit = False
    while i < n and body[i].isascii() and body[i].isdigit():
        i += 1
        saw_digit = True
    if i < n and body[i] == ".":
        i += 1
        while i < n and body[i].isascii() and body[i].isdigit():
            i += 1
            saw_digit = True
    if not saw_digit:
        return None_
    if i < n and body[i] in "eE":
        i += 1
        if i < n and body[i] in "+-":
            i += 1
        estart = i
        while i < n and body[i].isascii() and body[i].isdigit():
            i += 1
        if i == estart:
            return None_
    if i != n:
        return None_
    value = float(body)
    if math.isinf(value):
        return None_  # overflow past DBL_MAX
    return Some(value)


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
