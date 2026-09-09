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
- ``_capa_idiv(a, b)``: signed 64-bit floor division (Python ``//``).
  Raises ``ZeroDivisionError`` on ``b == 0`` and ``OverflowError`` on
  ``_I64_MIN / -1`` (whose quotient ``2**63`` overflows i64). The Wasm
  backend traps on the same two inputs.
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


def _capa_idiv(a: int, b: int) -> int:
    """Signed 64-bit floor division (Python ``//`` semantics).

    Raises ``ZeroDivisionError`` when ``b == 0`` and ``OverflowError``
    when ``a == _I64_MIN and b == -1`` (the quotient ``2**63`` leaves
    the signed 64-bit window). The Wasm backend traps on the same two
    inputs (wasmtime's native ``i64.div_s`` traps on ``/0`` and
    ``MIN / -1``), and applies the same floor correction so both
    backends round toward negative infinity (``-7 / 2 == -4``).
    """
    if b == 0:
        raise ZeroDivisionError("Int division by zero")
    if a == _I64_MIN and b == -1:
        raise OverflowError(
            f"Int division overflows signed 64-bit: {a} / {b} = {-a}"
        )
    return a // b


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


# ASCII-only case folding. Capa's ``String.to_upper`` /
# ``String.to_lower`` are ASCII-only by design (Phase 6, parity
# slice): only the 26 Latin letters fold (A-Z <-> a-z), every other
# code point passes through untouched. This matches the Wasm
# backend's ``_emit_string_case_transform``, which walks the UTF-8
# bytes and folds only the bytes in ``0x41-0x5a`` / ``0x61-0x7a``;
# every byte of a multi-byte code point is >= 0x80, so non-ASCII
# code points are never partially affected on either backend.
#
# Python's native ``str.upper()`` / ``str.lower()`` apply full
# Unicode case folding, which diverged silently from Wasm on any
# non-ASCII letter (``"café".upper()`` gave ``"CAFÉ"`` on Python but
# ``"CAFé"`` on Wasm). Routing both methods through these helpers
# closes that divergence: the two backends are now byte-identical.
# For full Unicode case folding, drop down to ``py_import`` / a host
# helper; it is deliberately out of scope for the built-in methods.

def _capa_to_upper(s: str) -> str:
    """ASCII-only upper-casing: fold ``a-z`` to ``A-Z``, leave every
    other code point intact. Byte-identical with the Wasm backend."""
    return "".join(
        chr(ord(c) - 32) if "a" <= c <= "z" else c for c in s
    )


def _capa_to_lower(s: str) -> str:
    """ASCII-only lower-casing: fold ``A-Z`` to ``a-z``, leave every
    other code point intact. Byte-identical with the Wasm backend."""
    return "".join(
        chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s
    )


# ``lines()`` splits on the three line terminators and STRIPS them, so a
# file ending in a newline does not yield a phantom empty last line.
# That is the whole reason the method exists: ``s.split("\n")`` leaves
# the phantom, which is the workaround it replaces.
#
# The terminators are exactly ``\r\n``, ``\n`` and a lone ``\r``.
# ``\r\n`` is matched before ``\n`` so a Windows line does not keep a
# trailing ``\r``, which is the defect this helper exists to make
# impossible to reintroduce on either backend.
#
# NOT Python's ``str.splitlines()``, deliberately: that also breaks on
# ``\v \f \x1c \x1d \x1e \x85 \u2028 \u2029``, none of which is a line
# terminator on any platform Capa targets, and every one of which would
# have to be recognised identically by the Wasm byte scanner where they
# are multi-byte. Three terminators is a rule the two backends can both
# state exactly. Rust's ``str::lines`` recognises two (``\n``,
# ``\r\n``); the lone ``\r`` is added because it is the third spelling
# of the same concept and excluding it makes the rule harder to state
# than to implement.
#
# The empty string yields ZERO lines, and a string that is exactly one
# terminator yields ONE empty line.

def _capa_lines(s: str) -> list[str]:
    """The lines of ``s`` with their terminators removed. Terminators
    are ``\r\n``, ``\n`` and ``\r``. Byte-identical with the Wasm
    backend's ``$emit_string_lines``."""
    out: list[str] = []
    start = 0
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\r":
            out.append(s[start:i])
            i += 2 if i + 1 < n and s[i + 1] == "\n" else 1
            start = i
        elif c == "\n":
            out.append(s[start:i])
            i += 1
            start = i
        else:
            i += 1
    if start < n:
        out.append(s[start:n])
    return out


# ``split_once(sep)`` cuts the receiver at the FIRST occurrence of
# ``sep`` and answers the two sides without the separator, or ``None``
# when ``sep`` does not occur. It exists because ``split`` answers a
# different question: ``"k=v=w".split("=")`` is three parts where a
# key/value parse wants two.
#
# The empty separator aborts, exactly as ``split`` already does on both
# backends ("empty separator" / a Wasm trap), rather than inventing an
# answer for a request that has none. Returning ``("", s)`` would be the
# tempting invention and it is wrong for the same reason the
# empty-needle ``replace`` policy exists: it silently turns a caller
# mistake into a plausible-looking parse.

def _capa_split_once(s: str, sep: str):
    """``(before, after)`` at the first occurrence of ``sep``, or
    ``None`` when absent. Raises ``ValueError`` on an empty separator,
    matching ``split``. Byte-identical with the Wasm backend's
    ``_emit_string_split_once``."""
    if sep == "":
        raise ValueError("empty separator")
    i = s.find(sep)
    if i < 0:
        return None
    return (s[:i], s[i + len(sep):])


# ``find_index(pred)`` answers the CODE-POINT index of the first
# character satisfying ``pred``, matching ``index_of`` / ``char_at`` /
# ``substring``, which are all code-point indexed, and never a byte
# offset. The predicate sees each character as a one-code-point string,
# the same thing ``for c in s`` binds, so the two ways of walking a
# string cannot disagree about what a character is.
#
# Python iteration over ``str`` is already per code point, so this is a
# thin loop rather than a re-implementation; it exists as a helper so
# the Option wrapping and the first-match-wins order are written once
# for both Python emitters, exactly as _capa_lines is.

def _capa_find_index(s: str, pred):
    """The code-point index of the first character of ``s`` for which
    ``pred`` is true, or ``None``. Byte-identical with the Wasm
    backend's ``_emit_string_find_index``."""
    for i, c in enumerate(s):
        if pred(c):
            return i
    return None
