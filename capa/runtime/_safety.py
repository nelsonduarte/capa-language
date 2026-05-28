"""Runtime safety helpers for arithmetic and collection indexing.

Capa's stance is that silent unsafety is a security hole: a program
that overflows a 64-bit add must trap, not wrap, and a program that
indexes past the end of a list must raise, not read random heap
bytes. The Wasm backend emits inline overflow-detection bytecode
(audit fix C2 / C3) and inline bounds-check traps (audit fix C1);
the Python backend reaches the same observable failure mode by
routing arithmetic and indexing through these helpers, which raise
``OverflowError`` / ``IndexError`` / ``ValueError`` at the same
input the Wasm backend traps on.

This adds a real per-op call cost on the Python side. That cost
is the price of "secure language" semantics: every Int op and
every collection index gets the same loud failure on both backends
at the same input, no exceptions. Float arithmetic is unaffected
(Float ops have their own quiet domain via IEEE-754 NaN / Inf; the
Float ``%`` zero-check is a separate fix on the Wasm side and is
already loud in Python).

Helpers exported:
- ``_capa_iadd(a, b)`` / ``_capa_isub(a, b)`` / ``_capa_imul(a, b)``:
  signed 64-bit add / sub / mul. Raise ``OverflowError`` when the
  result is outside ``[-(2**63), 2**63)``.
- ``_capa_shl(a, b)`` / ``_capa_shr(a, b)``: i64 left / arithmetic-
  right shift. Raise ``OverflowError`` when ``b`` is outside
  ``[0, 64)``. ``_capa_shl`` additionally traps when the shifted
  result leaves the i64 window (Wasm's ``i64.shl`` discards bits
  silently; we surface the loss).
- ``_capa_list_get(xs, i)``: bounds-checked ``xs[i]``. Raises
  ``IndexError`` on ``i < 0`` (Capa is non-negative-index-only on
  both backends) or ``i >= len(xs)``. Matches the Wasm backend's
  inline trap on the same input.
- ``_capa_substring(s, start, end)``: bounds-checked
  ``s[start:end]``. Raises ``ValueError`` on negative bounds,
  ``start > end``, or ``end > len(s)``. Python's slice operator
  silently clamps; this helper refuses, so a "substring that
  returned less than asked" cannot slip past a parser as a
  silently-shortened token.
"""

from __future__ import annotations


_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1


def _capa_iadd(a: int, b: int) -> int:
    """Signed 64-bit add. Raises ``OverflowError`` on wraparound.

    Matches the Wasm backend's inline ``((a ^ r) & (b ^ r)) < 0``
    overflow detector: both backends trap at the same input.
    """
    r = a + b
    if r < _I64_MIN or r > _I64_MAX:
        raise OverflowError(
            f"Int addition overflows signed 64-bit: {a} + {b} = {r}"
        )
    return r


def _capa_isub(a: int, b: int) -> int:
    """Signed 64-bit subtract. Raises ``OverflowError`` on wraparound."""
    r = a - b
    if r < _I64_MIN or r > _I64_MAX:
        raise OverflowError(
            f"Int subtraction overflows signed 64-bit: {a} - {b} = {r}"
        )
    return r


def _capa_imul(a: int, b: int) -> int:
    """Signed 64-bit multiply. Raises ``OverflowError`` on wraparound."""
    r = a * b
    if r < _I64_MIN or r > _I64_MAX:
        raise OverflowError(
            f"Int multiplication overflows signed 64-bit: {a} * {b} = {r}"
        )
    return r


def _capa_shl(a: int, b: int) -> int:
    """i64 left shift. ``b`` must be in ``[0, 64)``; otherwise raises
    ``OverflowError``. Also raises if the shifted value leaves the
    signed 64-bit window (Wasm's i64.shl discards high bits without
    notice; we surface the loss to match the secure-by-default stance).
    """
    if b < 0 or b >= 64:
        raise OverflowError(
            f"shift count out of range [0, 64): {b}"
        )
    r = a << b
    # Mask to 64 bits then sign-extend so the wrap matches what
    # Wasm's i64.shl would produce, and compare against the source
    # value: any divergence means high bits were dropped.
    masked = r & ((1 << 64) - 1)
    if masked >= (1 << 63):
        masked -= (1 << 64)
    if masked != r:
        raise OverflowError(
            f"Int left shift overflows signed 64-bit: {a} << {b}"
        )
    return r


def _capa_shr(a: int, b: int) -> int:
    """i64 arithmetic right shift. ``b`` must be in ``[0, 64)``;
    otherwise raises ``OverflowError``. Python's ``>>`` on a signed
    int is already arithmetic (sign-extending), so the result side
    needs no further masking once the count is in range."""
    if b < 0 or b >= 64:
        raise OverflowError(
            f"shift count out of range [0, 64): {b}"
        )
    return a >> b


def _capa_list_get(xs, i):
    """Bounds-checked ``xs[i]`` for ``List<T>``. Raises
    ``IndexError`` on ``i < 0`` or ``i >= len(xs)``.

    Capa indices are non-negative-only on both backends: Python's
    native negative-index semantics (``xs[-1]`` -> last element) is
    rejected here so the Python and Wasm backends agree on the same
    inputs. The Wasm backend's ``_emit_index`` emits an equivalent
    inline bounds check that traps via ``unreachable`` on the same
    inputs (the unsigned compare ``i32.ge_u`` also catches negative
    indices, because ``i32.wrap_i64`` of a negative i64 is a huge
    u32 that exceeds any list's length).
    """
    n = len(xs)
    if i < 0 or i >= n:
        raise IndexError(
            f"list index out of range: i={i}, len={n}"
        )
    return xs[i]


def _capa_substring(s: str, start: int, end: int) -> str:
    """Bounds-checked ``s[start:end]`` for ``String``. Raises
    ``ValueError`` on negative bounds, ``start > end``, or
    ``end > len(s)``.

    Python's slice operator clamps silently (``"ab"[0:99]`` returns
    ``"ab"``), but for a parser / tokeniser a substring that
    returned less than asked is a footgun: callers downstream may
    treat the shortened token as if it were the full requested
    range. The Wasm backend's ``_emit_string_substring`` emits an
    equivalent inline guard that traps via ``unreachable`` on the
    same inputs, so both backends now refuse the request rather
    than quietly returning a truncated slice.
    """
    n = len(s)
    if start < 0 or end < 0 or start > end or end > n:
        raise ValueError(
            f"substring out of range: start={start}, end={end}, len={n}"
        )
    return s[start:end]
