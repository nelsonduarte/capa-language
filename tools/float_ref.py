"""Portable reference for shortest-round-trip f64 -> string formatting.

This module is the BLUEPRINT for the WebAssembly port (task F2). Its
``format_float(x)`` matches Python's ``repr(float)`` byte-for-byte on
every finite double, and it is structured so that every piece can be
transliterated to WAT without relying on Python magic:

- The Grisu fast path (``grisu`` below) is a Grisu3-style variant: it
  carries a real success flag and reports FAILURE rather than guessing
  when the rounding interval makes the shortest digit string ambiguous.
  This mirrors the existing WAT ``$grisu2`` port (capa/ir/_emit_wasm/
  _grisu.py) plus the RoundWeed last-digit nudge, with the safety check
  that Grisu2 alone lacks.

- The EXACT fallback (``dragon4`` below) is the free-format big-integer
  algorithm. Its bignum is implemented as arrays of 32-bit limbs with
  hand-written add / sub / mul-small / mul-bignum / compare / shift -
  the SAME shape a WAT port uses in linear memory. It NEVER uses
  Python's arbitrary-precision ``int`` in the algorithm itself; Python
  ``int`` appears only in test scaffolding (the validation harness).

- ``format_float`` applies Python's spelling rules (fixed vs
  scientific, sign, minimal digits, ``e`` formatting) on top of the
  shortest digit string, matching ``repr`` exactly.

The combined pipeline runs Grisu first; on the (~0.5%) of values where
Grisu reports failure it falls back to Dragon4. Both produce the same
shortest, correctly-rounded digit string; Dragon4 is the oracle.

Run ``python tools/float_ref.py`` for the full validation report, or
import ``validate_sweep`` / ``format_float`` directly.
"""

from __future__ import annotations

import struct


# ----------------------------------------------------------------------
# IEEE 754 double decomposition.
# ----------------------------------------------------------------------

_DBL_MANT_BITS = 52
_DBL_HIDDEN_BIT = 1 << 52
_DBL_MANT_MASK = (1 << 52) - 1
_DBL_EXP_MASK = 0x7FF
_DBL_EXP_BIAS = 1075  # 1023 + 52, so value = mant * 2^(biased_exp-1075)


def _bits_of(x: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def _double_of(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


def _decompose(x: float) -> tuple[int, int]:
    """Return (mantissa, exponent) such that x == mantissa * 2^exponent
    for a positive finite non-zero double, with the hidden bit folded
    in. Both fit in i64-shaped integers (mantissa <= 2^53)."""
    bits = _bits_of(x)
    biased = (bits >> _DBL_MANT_BITS) & _DBL_EXP_MASK
    mant = bits & _DBL_MANT_MASK
    if biased == 0:
        return mant, -1074
    return mant | _DBL_HIDDEN_BIT, biased - _DBL_EXP_BIAS


# ======================================================================
# Grisu fast path (Grisu3 semantics: shortest with a confidence flag).
#
# This is a direct mirror of the WAT $grisu2 + $grisu_round_weed port,
# with the additional "is this provably shortest?" check that turns
# Grisu2 into Grisu3. All arithmetic here is 64-bit-shaped (the values
# never exceed 64 bits); the WAT port uses i64 throughout.
# ======================================================================

_GRISU_MASK64 = (1 << 64) - 1

# 87-entry cached powers of ten (significand, binary_exp, decimal_exp);
# significand top-bit set. These are the canonical double-conversion
# values.
#
# NOTE FOR F2: the table currently embedded in the WAT emitter
# (capa/ir/_emit_wasm/_grisu.py::_CACHED_POWERS) has FOUR wrong entries
# that must be corrected when the fast path is wired up:
#   dexp 196 : 0x88fa513c149a3d75 -> 0x88fcf317f22241e2  (gross typo)
#   dexp 300 : 0xbf21e44003acdd2c -> 0xbf21e44003acdd2d  (off by one)
#   dexp 332 : 0xeb96bf6ebadf77d8 -> 0xeb96bf6ebadf77d9  (off by one)
#   dexp 340 : 0xaf87023b9bf0ee6a -> 0xaf87023b9bf0ee6b  (off by one)
# The dexp-196 typo alone makes every f64 with binary exponent in the
# [-701, -675] band misformat (a high-order digit flips); it was the
# root cause of the systematic tiny-magnitude divergences this
# reference uncovered. The values below are the corrected ones.
_CACHED_POWERS = [
    (0xfa8fd5a0081c0288, -1220, -348), (0xbaaee17fa23ebf76, -1193, -340),
    (0x8b16fb203055ac76, -1166, -332), (0xcf42894a5dce35ea, -1140, -324),
    (0x9a6bb0aa55653b2d, -1113, -316), (0xe61acf033d1a45df, -1087, -308),
    (0xab70fe17c79ac6ca, -1060, -300), (0xff77b1fcbebcdc4f, -1034, -292),
    (0xbe5691ef416bd60c, -1007, -284), (0x8dd01fad907ffc3c, -980, -276),
    (0xd3515c2831559a83, -954, -268), (0x9d71ac8fada6c9b5, -927, -260),
    (0xea9c227723ee8bcb, -901, -252), (0xaecc49914078536d, -874, -244),
    (0x823c12795db6ce57, -847, -236), (0xc21094364dfb5637, -821, -228),
    (0x9096ea6f3848984f, -794, -220), (0xd77485cb25823ac7, -768, -212),
    (0xa086cfcd97bf97f4, -741, -204), (0xef340a98172aace5, -715, -196),
    (0xb23867fb2a35b28e, -688, -188), (0x84c8d4dfd2c63f3b, -661, -180),
    (0xc5dd44271ad3cdba, -635, -172), (0x936b9fcebb25c996, -608, -164),
    (0xdbac6c247d62a584, -582, -156), (0xa3ab66580d5fdaf6, -555, -148),
    (0xf3e2f893dec3f126, -529, -140), (0xb5b5ada8aaff80b8, -502, -132),
    (0x87625f056c7c4a8b, -475, -124), (0xc9bcff6034c13053, -449, -116),
    (0x964e858c91ba2655, -422, -108), (0xdff9772470297ebd, -396, -100),
    (0xa6dfbd9fb8e5b88f, -369, -92), (0xf8a95fcf88747d94, -343, -84),
    (0xb94470938fa89bcf, -316, -76), (0x8a08f0f8bf0f156b, -289, -68),
    (0xcdb02555653131b6, -263, -60), (0x993fe2c6d07b7fac, -236, -52),
    (0xe45c10c42a2b3b06, -210, -44), (0xaa242499697392d3, -183, -36),
    (0xfd87b5f28300ca0e, -157, -28), (0xbce5086492111aeb, -130, -20),
    (0x8cbccc096f5088cc, -103, -12), (0xd1b71758e219652c, -77, -4),
    (0x9c40000000000000, -50, 4), (0xe8d4a51000000000, -24, 12),
    (0xad78ebc5ac620000, 3, 20), (0x813f3978f8940984, 30, 28),
    (0xc097ce7bc90715b3, 56, 36), (0x8f7e32ce7bea5c70, 83, 44),
    (0xd5d238a4abe98068, 109, 52), (0x9f4f2726179a2245, 136, 60),
    (0xed63a231d4c4fb27, 162, 68), (0xb0de65388cc8ada8, 189, 76),
    (0x83c7088e1aab65db, 216, 84), (0xc45d1df942711d9a, 242, 92),
    (0x924d692ca61be758, 269, 100), (0xda01ee641a708dea, 295, 108),
    (0xa26da3999aef774a, 322, 116), (0xf209787bb47d6b85, 348, 124),
    (0xb454e4a179dd1877, 375, 132), (0x865b86925b9bc5c2, 402, 140),
    (0xc83553c5c8965d3d, 428, 148), (0x952ab45cfa97a0b3, 455, 156),
    (0xde469fbd99a05fe3, 481, 164), (0xa59bc234db398c25, 508, 172),
    (0xf6c69a72a3989f5c, 534, 180), (0xb7dcbf5354e9bece, 561, 188),
    (0x88fcf317f22241e2, 588, 196), (0xcc20ce9bd35c78a5, 614, 204),
    (0x98165af37b2153df, 641, 212), (0xe2a0b5dc971f303a, 667, 220),
    (0xa8d9d1535ce3b396, 694, 228), (0xfb9b7cd9a4a7443c, 720, 236),
    (0xbb764c4ca7a44410, 747, 244), (0x8bab8eefb6409c1a, 774, 252),
    (0xd01fef10a657842c, 800, 260), (0x9b10a4e5e9913129, 827, 268),
    (0xe7109bfba19c0c9d, 853, 276), (0xac2820d9623bf429, 880, 284),
    (0x80444b5e7aa7cf85, 907, 292), (0xbf21e44003acdd2d, 933, 300),
    (0x8e679c2f5e44ff8f, 960, 308), (0xd433179d9c8cb841, 986, 316),
    (0x9e19db92b4e31ba9, 1013, 324), (0xeb96bf6ebadf77d9, 1039, 332),
    (0xaf87023b9bf0ee6b, 1066, 340),
]


def _mul_high(a: int, b: int) -> int:
    """High 64 bits of the unsigned 128-bit product a*b, with the
    +2^31 round-half-up bias - exactly the WAT $grisu_mul_high. Written
    with 32-bit halves so the port is a transliteration."""
    a_lo = a & 0xFFFFFFFF
    a_hi = a >> 32
    b_lo = b & 0xFFFFFFFF
    b_hi = b >> 32
    ll = a_lo * b_lo
    lh = a_lo * b_hi
    hl = a_hi * b_lo
    hh = a_hi * b_hi
    mid = (ll >> 32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF) + (1 << 31)
    carry = mid >> 32
    return (hh + (lh >> 32) + (hl >> 32) + carry) & _GRISU_MASK64


def _cached_power_for(e: int) -> tuple[int, int, int]:
    """Mirror of WAT $grisu_cached_power. log10(2) ~ 1292913986/2^32."""
    n = -61 - e
    prod = n * 1292913986
    q = prod >> 32  # arithmetic shift = floor
    r = prod - (q << 32)
    k = q + (1 if r != 0 else 0)
    index = (348 + k - 1) // 8 + 1
    return _CACHED_POWERS[index]


def _round_weed(
    digits: bytearray,
    dist_too_high: int,
    unsafe: int,
    rest: int,
    ten_kappa: int,
    unit: int,
) -> bool:
    """RoundWeed last-digit nudge (Google double-conversion ``RoundWeed``)
    plus the Grisu3 confidence flag.

    ``unit`` is the accumulated rounding error of the scaled boundaries
    in the current digit's units (1 at the integer-loop exit, multiplied
    by 10 each fractional step). The produced digit string is PROVABLY
    the shortest correctly-rounded one only when the
    represented value sits at least ``2*unit`` inside the high boundary
    and the slack to the low boundary still exceeds ``4*unit`` after the
    weeding walk. Otherwise the interval is too tight for Grisu to be
    certain and we return False so the caller falls back to Dragon4.

    Direct line-for-line port of double-conversion's ``RoundWeed``
    (fast-dtoa.cc). Two windows bracket the true value:
    ``small_distance = dist_too_high - unit`` (definitely inside) and
    ``big_distance = dist_too_high + unit`` (possibly outside). The
    last digit is pulled down while it stays within ``small_distance``;
    then if it could ALSO be pulled within ``big_distance`` the value
    is ambiguous and we return False. Final success additionally
    requires >= 2*unit / >= 4*unit slack to the two boundaries.
    """
    small_distance = dist_too_high - unit
    big_distance = dist_too_high + unit

    # Pull the last digit down while it stays definitely inside the
    # interval (small_distance) and ends up closer to w.
    while (
        rest < small_distance
        and unsafe - rest >= ten_kappa
        and (
            rest + ten_kappa < small_distance
            or small_distance - rest >= rest + ten_kappa - small_distance
        )
    ):
        digits[-1] -= 1
        rest += ten_kappa

    # Ambiguity gate: if the last digit could also be pulled within the
    # OUTER window (big_distance), Grisu cannot prove which is shortest.
    if (
        rest < big_distance
        and unsafe - rest >= ten_kappa
        and (
            rest + ten_kappa < big_distance
            or big_distance - rest > rest + ten_kappa - big_distance
        )
    ):
        return False

    # Final slack check: >= 2*unit to the high boundary, >= 4*unit to
    # the low boundary, else not provably shortest.
    return (2 * unit) <= rest <= (unsafe - 4 * unit)


def grisu(x: float) -> tuple[str, int, bool]:
    """Grisu3 fast path for a positive finite non-zero double.

    Returns (digits, K, ok) where the represented value equals
    ``int(digits) * 10^K`` and ``ok`` is True only when the digit
    string is provably the shortest correctly-rounded one. When ``ok``
    is False the caller must use ``dragon4``.

    Mirrors the WAT $grisu2 control flow (integer loop + fractional
    loop + RoundWeed) line for line.
    """
    w_f, w_e = _decompose(x)
    bits = _bits_of(x)
    biased = (bits >> _DBL_MANT_BITS) & _DBL_EXP_MASK
    mant = bits & _DBL_MANT_MASK

    # Boundaries mp (upper) and mm (lower).
    mp_f = (w_f << 1) + 1
    mp_e = w_e - 1
    if mant == 0 and biased > 1:
        mm_f = (w_f << 2) - 1
        mm_e = w_e - 2
    else:
        mm_f = (w_f << 1) - 1
        mm_e = w_e - 1

    # Normalise mp to 64 bits.
    shift = 64 - mp_f.bit_length()
    mp_f = (mp_f << shift) & _GRISU_MASK64
    mp_e -= shift
    mm_f = (mm_f << (mm_e - mp_e)) & _GRISU_MASK64
    mm_e = mp_e
    w_f_at_mpe = (w_f << (w_e - mp_e)) & _GRISU_MASK64

    c_sig, c_bexp, c_dexp = _cached_power_for(mp_e)

    Wf = _mul_high(w_f_at_mpe, c_sig)
    We = mp_e + c_bexp + 64
    Wp_f = (_mul_high(mp_f, c_sig) + 1) & _GRISU_MASK64
    Wm_f = (_mul_high(mm_f, c_sig) - 1) & _GRISU_MASK64
    delta = (Wp_f - Wm_f) & _GRISU_MASK64
    dist_too_high = (Wp_f - Wf) & _GRISU_MASK64

    minus_We = -We
    one_f = (1 << minus_We) & _GRISU_MASK64
    p1 = Wp_f >> minus_We
    p2 = Wp_f & (one_f - 1)

    digits = bytearray()
    kappa = 10
    # Integer-part loop.
    while kappa > 0:
        div = 10 ** (kappa - 1)
        d = p1 // div
        if d != 0 or digits:
            digits.append(d)
        p1 %= div
        kappa -= 1
        rest = (p1 << minus_We) + p2
        if rest < delta:
            ten_kappa = (div << minus_We) & _GRISU_MASK64
            ok = _round_weed(
                digits, dist_too_high, delta, rest, ten_kappa, 1
            )
            return _digits_str(digits), kappa - c_dexp, ok

    # Fractional loop. ``delta`` / ``dist_too_high`` / ``unit`` all
    # scale by 10 each step so the Grisu3 confidence slack stays in the
    # same units as ``p2`` (rest) and ``one_f`` (ten_kappa).
    unit = 1
    while True:
        p2 = (p2 * 10) & _GRISU_MASK64
        delta = (delta * 10) & _GRISU_MASK64
        dist_too_high = (dist_too_high * 10) & _GRISU_MASK64
        unit *= 10
        d = p2 >> minus_We
        p2 &= one_f - 1
        digits.append(d)
        kappa -= 1
        if p2 < delta:
            ok = _round_weed(
                digits, dist_too_high, delta, p2, one_f, unit
            )
            return _digits_str(digits), kappa - c_dexp, ok
        if len(digits) >= 18:
            # Could not terminate confidently.
            return _digits_str(digits), kappa - c_dexp, False


def _digits_str(digits: bytearray) -> str:
    return "".join(chr(48 + d) for d in digits)


# ======================================================================
# Dragon4 exact fallback with explicit fixed-width limb bignum.
#
# Every operation below works on a Python list of 32-bit limbs (least
# significant first). NO Python big-int is used inside the algorithm.
# This is the portability anchor: each helper maps to a WAT loop over
# limbs in linear memory.
# ======================================================================

_LIMB_BITS = 32
_LIMB_BASE = 1 << 32
_LIMB_MASK = _LIMB_BASE - 1


def _bn_from_u64(v: int) -> list[int]:
    """Bignum from a value that fits in 64 bits (v itself is small;
    splitting into two 32-bit limbs uses only fixed-width ops)."""
    lo = v & _LIMB_MASK
    hi = (v >> 32) & _LIMB_MASK
    out = [lo]
    if hi:
        out.append(hi)
    return _bn_norm(out)


def _bn_norm(a: list[int]) -> list[int]:
    """Drop high zero limbs (keep at least one)."""
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def _bn_is_zero(a: list[int]) -> bool:
    return len(a) == 1 and a[0] == 0


def _bn_cmp(a: list[int], b: list[int]) -> int:
    """-1 / 0 / 1 for a < / == / > b."""
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    for i in range(len(a) - 1, -1, -1):
        if a[i] != b[i]:
            return -1 if a[i] < b[i] else 1
    return 0


def _bn_add(a: list[int], b: list[int]) -> list[int]:
    """a + b, limb-wise with carry."""
    n = max(len(a), len(b))
    out = []
    carry = 0
    for i in range(n):
        s = (a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0) + carry
        out.append(s & _LIMB_MASK)
        carry = s >> 32
    if carry:
        out.append(carry)
    return _bn_norm(out)


def _bn_sub(a: list[int], b: list[int]) -> list[int]:
    """a - b for a >= b, limb-wise with borrow."""
    out = []
    borrow = 0
    for i in range(len(a)):
        d = a[i] - (b[i] if i < len(b) else 0) - borrow
        if d < 0:
            d += _LIMB_BASE
            borrow = 1
        else:
            borrow = 0
        out.append(d & _LIMB_MASK)
    return _bn_norm(out)


def _bn_mul_small(a: list[int], m: int) -> list[int]:
    """a * m where m fits in 32 bits. Each limb product is 32x32 -> 64,
    split into low 32 (output) and high 32 (carry)."""
    out = []
    carry = 0
    for i in range(len(a)):
        p = a[i] * m + carry
        out.append(p & _LIMB_MASK)
        carry = p >> 32
    while carry:
        out.append(carry & _LIMB_MASK)
        carry >>= 32
    return _bn_norm(out)


def _bn_mul(a: list[int], b: list[int]) -> list[int]:
    """Schoolbook a * b accumulating 32x32->64 partial products with
    carry, exactly as a WAT nested loop would."""
    out = [0] * (len(a) + len(b))
    for i in range(len(a)):
        carry = 0
        ai = a[i]
        for j in range(len(b)):
            p = ai * b[j] + out[i + j] + carry
            out[i + j] = p & _LIMB_MASK
            carry = p >> 32
        k = i + len(b)
        while carry:
            p = out[k] + carry
            out[k] = p & _LIMB_MASK
            carry = p >> 32
            k += 1
    return _bn_norm(out)


def _bn_shl(a: list[int], bits: int) -> list[int]:
    """a << bits via whole-limb shift + intra-limb shift, all 32-bit."""
    if _bn_is_zero(a):
        return [0]
    limb_shift = bits // 32
    bit_shift = bits % 32
    out = [0] * limb_shift + list(a)
    if bit_shift:
        carry = 0
        for i in range(limb_shift, len(out)):
            v = (out[i] << bit_shift) | carry
            out[i] = v & _LIMB_MASK
            carry = v >> 32
        if carry:
            out.append(carry & _LIMB_MASK)
    return _bn_norm(out)


def _bn_mul_pow10(a: list[int], k: int) -> list[int]:
    """a * 10^k by repeated *10 (k small in Dragon4 scaling loops, but
    we chunk via 10^9 to limit iterations; still all small-mul)."""
    while k >= 9:
        a = _bn_mul_small(a, 1000000000)
        k -= 9
    if k:
        a = _bn_mul_small(a, 10 ** k)
    return a


def _bn_divmod_digit(num: list[int], den: list[int]) -> tuple[int, list[int]]:
    """Return (q, num - q*den) where q is the single decimal digit
    ``num // den`` (0..9), assuming num < 10*den. Implemented by
    repeated subtraction (at most 9 iterations) - the same bounded loop
    a WAT port uses to avoid a full bignum division."""
    q = 0
    while _bn_cmp(num, den) >= 0:
        num = _bn_sub(num, den)
        q += 1
    return q, num


def dragon4(x: float) -> tuple[str, int]:
    """Exact shortest free-format formatting for a positive finite
    non-zero double, using only limb-based bignum arithmetic.

    Returns (digits, K) with value == int(digits) * 10^K, the shortest
    string that round-trips. This is the classic Steele and White /
    Burger and Dubois "free-format" Dragon4 with the even-rounding tie
    rule that IEEE round-to-nearest-even demands.
    """
    f, e = _decompose(x)
    bits = _bits_of(x)
    biased = (bits >> _DBL_MANT_BITS) & _DBL_EXP_MASK
    mant = bits & _DBL_MANT_MASK

    # Set up R / S / M+ / M- as scaled integers (Burger and Dubois
    # 1996, "Printing Floating-Point Numbers Quickly and Accurately").
    # value = f * 2^e. Half-ulp boundaries: m+ above, m- below.
    # Unequal gap when at a power-of-two boundary (mant == 0, not the
    # smallest normal): the lower gap is half the upper.
    #
    # Round-to-nearest-EVEN means the boundaries are INCLUSIVE when the
    # significand is even, EXCLUSIVE when odd. low_ok / high_ok carry
    # that ``<=`` vs ``<`` choice into the termination tests.
    even = (f & 1) == 0
    low_ok = high_ok = even

    unequal_gap = mant == 0 and biased > 1
    if e >= 0:
        be = _bn_shl([1], e)              # 2^e
        if not unequal_gap:
            R = _bn_shl(_bn_mul(_bn_from_u64(f), be), 1)  # 2*f*2^e
            S = [2]
            Mp = be
            Mm = be
        else:
            be1 = _bn_shl([1], e + 1)     # 2^(e+1)
            R = _bn_shl(_bn_mul(_bn_from_u64(f), be1), 1)  # 4*f*2^e
            S = [4]
            Mp = be1
            Mm = be
    else:
        if not unequal_gap:
            R = _bn_shl(_bn_from_u64(f), 1)   # 2*f
            S = _bn_shl([1], 1 - e)           # 2 * 2^-e
            Mp = [1]
            Mm = [1]
        else:
            R = _bn_shl(_bn_from_u64(f), 2)   # 4*f
            S = _bn_shl([1], 2 - e)           # 4 * 2^-e
            Mp = [2]
            Mm = [1]

    # Estimate the decimal exponent k = ceil(log10(value)); the exact
    # fixup loops below correct any off-by-one (or larger) error from
    # the float log10, which is not reliable near subnormal magnitudes.
    import math
    k = int(math.ceil(math.log10(x) - 1e-10))

    # Scale by 10^k so the first generated digit is the most significant
    # one: we want R/S in [1/10, 1). Apply 10^|k| to the correct side.
    if k >= 0:
        S = _bn_mul_pow10(S, k)
    else:
        scale = _bn_mul_pow10([1], -k)
        R = _bn_mul(R, scale)
        Mp = _bn_mul(Mp, scale)
        Mm = _bn_mul(Mm, scale)

    # Exact fixup. The target invariant: the leading digit is the most
    # significant one, i.e. (R + Mp) is in (S/10, S] (inclusive depends
    # on high_ok). Iterate both directions in case log10 was off.
    def _high_over() -> bool:
        c = _bn_cmp(_bn_add(R, Mp), S)
        return c >= 0 if high_ok else c > 0

    # Too small: leading digit would be 0; scale R / M up, lower k.
    while True:
        c = _bn_cmp(_bn_add(R, Mp), _bn_mul_small(S, 1))
        # If (R+Mp)*10 still <= S (resp. <) the first digit is 0.
        big = _bn_add(_bn_mul_small(R, 10), _bn_mul_small(Mp, 10))
        too_small = _bn_cmp(big, S) <= 0 if high_ok else _bn_cmp(big, S) < 0
        if not too_small:
            break
        R = _bn_mul_small(R, 10)
        Mp = _bn_mul_small(Mp, 10)
        Mm = _bn_mul_small(Mm, 10)
        k -= 1

    # Too large: leading digit would be >= 10; scale S up, raise k.
    while _high_over():
        S = _bn_mul_small(S, 10)
        k += 1

    # Generate digits. Each step pulls in one decimal digit, then tests
    # both boundaries to decide whether to stop.
    digits = bytearray()
    while True:
        R = _bn_mul_small(R, 10)
        Mp = _bn_mul_small(Mp, 10)
        Mm = _bn_mul_small(Mm, 10)
        d, R = _bn_divmod_digit(R, S)

        # low: remainder fell below the lower half-ulp boundary.
        c_low = _bn_cmp(R, Mm)
        tc1 = c_low <= 0 if low_ok else c_low < 0
        # high: remainder + upper half-ulp boundary crossed S.
        c_high = _bn_cmp(_bn_add(R, Mp), S)
        tc2 = c_high >= 0 if high_ok else c_high > 0

        if not tc1 and not tc2:
            digits.append(d)
            continue

        # Terminate: choose the final digit.
        if tc2 and not tc1:
            d += 1
        elif tc1 and tc2:
            # Both boundaries crossed: round the remainder. Compare
            # 2*R against S; >0 rounds up, <0 keeps, ==0 ties to even.
            c = _bn_cmp(_bn_shl(R, 1), S)
            if c > 0 or (c == 0 and (d & 1) == 1):
                d += 1
        digits.append(d)
        break

    return _digits_str(digits), k - len(digits)


# ======================================================================
# Decimal string -> f64 (the INVERSE of Dragon4): correctly-rounded
# string-to-double parsing. This is the BLUEPRINT for the WAT
# ``$parse_float`` rewrite (task F-strtod): a Clinger fast path that
# uses one exact f64 operation for the easy cases, with a bignum slow
# path (reusing the same 32-bit-limb ``_bn_*`` family as Dragon4) for
# the hard-rounding cases.
#
# APPROACH (and why Clinger over Eisel-Lemire).
#
# Every number parses to ``(sign, mantissa, e10)`` where the value is
# ``sign * mantissa * 10^e10`` and ``mantissa`` is the integer formed
# by ALL significant decimal digits (the '.' only shifts ``e10``).
#
# - Clinger fast path. When ``mantissa`` is exactly representable in
#   f64 (``mantissa < 2^53``) AND ``10^|e10|`` is exactly representable
#   (``|e10| <= 22``, since 10^22 is the largest power of ten that is
#   an exact f64), a SINGLE IEEE f64 multiply (e10 >= 0) or divide
#   (e10 < 0) is correctly rounded: both operands are exact and round-
#   to-nearest gives the correctly-rounded result of the real product.
#   This is Clinger 1990 ("How to Read Floating Point Numbers
#   Accurately"). It covers the overwhelming majority of real inputs
#   with two f64 constants and one f64 op -- trivial to port to WAT and
#   already bit-identical to CPython's ``float()`` there.
#
# - Bignum slow path. Otherwise compute the exact rational
#   ``mantissa * 10^e10`` and round it to the nearest f64 (ties to
#   even) using the limb bignum. This REUSES ``_bn_mul_pow10`` /
#   ``_bn_shl`` / ``_bn_cmp`` -- the very helpers the Dragon4 WAT port
#   already emits -- so the WAT slow path adds no new bignum primitive.
#   Eisel-Lemire would be faster but needs a 128-bit-product path and a
#   huge 10^k significand table that the existing WAT runtime does not
#   have; the bignum slow path rides infrastructure that is already
#   ported and validated, which the project's oracle-first rule favours.
#
# OVERFLOW -> None (the value exceeds DBL_MAX); UNDERFLOW -> 0.0.
# ======================================================================

# 10^0 .. 10^22 are each exactly representable in f64; beyond that the
# power of ten is no longer exact and the single-op Clinger argument
# breaks. 2^53 is the inclusive bound below which every integer is an
# exact f64.
_F64_EXACT_POW10_MAX = 22
_F64_EXACT_INT_MAX = 1 << 53  # mantissa < this is exact

# Exact f64 powers of ten for the fast path (index i == 10^i).
_POW10_F64 = [float(10 ** i) for i in range(_F64_EXACT_POW10_MAX + 1)]

_DBL_MAX = _double_of(0x7FEFFFFFFFFFFFFF)


def _parse_decimal(s: str):
    """Parse the canonical float grammar into ``(neg, digits, e10)`` or
    ``None`` on a grammar violation.

    Grammar (identical on both backends, aligned with ``parse_int``):
    surrounding ASCII whitespace, optional sign ``[+-]``, a mantissa of
    decimal digits with an optional single ``.`` (``12`` / ``12.5`` /
    ``.5`` / ``12.``), an optional exponent ``[eE][+-]?digits``, and
    nothing else. No inf / nan, no underscores, no hex.

    ``digits`` is the significant-digit string with the decimal point
    removed; ``e10`` is the power-of-ten exponent so that the value is
    ``int(digits) * 10^e10``. Leading zeros are kept in ``digits`` (they
    do not change the integer value); an all-zero mantissa yields
    ``digits == "0"``.
    """
    _ASCII_WS = " \t\n\x0b\x0c\r"
    body = s.strip(_ASCII_WS)
    if not body:
        return None
    i = 0
    n = len(body)
    neg = False
    if body[i] in "+-":
        neg = body[i] == "-"
        i += 1
    int_digits = []
    frac_digits = []
    saw_digit = False
    while i < n and body[i].isascii() and body[i].isdigit():
        int_digits.append(body[i])
        saw_digit = True
        i += 1
    if i < n and body[i] == ".":
        i += 1
        while i < n and body[i].isascii() and body[i].isdigit():
            frac_digits.append(body[i])
            saw_digit = True
            i += 1
    if not saw_digit:
        return None
    exp = 0
    if i < n and body[i] in "eE":
        i += 1
        esign = 1
        if i < n and body[i] in "+-":
            if body[i] == "-":
                esign = -1
            i += 1
        estart = i
        eval_ = 0
        while i < n and body[i].isascii() and body[i].isdigit():
            eval_ = eval_ * 10 + (ord(body[i]) - 48)
            i += 1
        if i == estart:
            return None  # 'e' with no exponent digits
        exp = esign * eval_
    if i != n:
        return None  # trailing garbage
    # Combine: each fractional digit lowers the exponent by one.
    digits = "".join(int_digits) + "".join(frac_digits)
    e10 = exp - len(frac_digits)
    if not digits:
        digits = "0"
    return neg, digits, e10


def _round_bignum_ratio_to_f64(num, den, neg):
    """Round the exact positive rational ``num/den`` (both limb bignums,
    den > 0) to the nearest f64, ties to even, applying ``neg``.

    Returns the f64. Handles overflow (-> raises ``_Overflow``) and
    underflow (-> signed zero). This is the rounding core the slow path
    and the WAT port share; it is written entirely in terms of the
    limb-bignum ``_bn_*`` helpers plus 64-bit integer mantissa math.
    """
    # Find binary exponent e such that 2^52 <= num/den / 2^e < 2^53,
    # i.e. the f64 mantissa is a 53-bit integer q with
    #   value ~= q * 2^e,  q in [2^52, 2^53).
    # We scale num or den by powers of two (bignum shifts) until
    # floor(num/den) has exactly 53 bits, then round.
    #
    # Start by bracketing with bit-length estimates, then refine by
    # exact comparison. All shifts are bignum left-shifts; no Python big
    # int leaks into the WAT-relevant path (here we use ints for the
    # quotient, which fits in 64 bits by construction).
    # Estimate the position. _bn_bitlen gives floor(log2)+1.
    bl_num = _bn_bitlen(num)
    bl_den = _bn_bitlen(den)
    # We want q = floor(num * 2^-e / den) to have 53 bits. Equivalent:
    # choose e so that num*2^(-e) is in [den*2^52, den*2^53).
    # Initial guess from bit lengths.
    e = bl_num - bl_den - 53
    # Scale: compute scaled_num and scaled_den so that
    #   q = floor(scaled_num / scaled_den)  with the 2^-e folded in.
    if e >= 0:
        scaled_num = num
        scaled_den = _bn_shl(den, e)
    else:
        scaled_num = _bn_shl(num, -e)
        scaled_den = den
    # Refine e so q has exactly 53 bits ([2^52, 2^53)).
    two52 = _bn_shl([1], 52)
    two53 = _bn_shl([1], 53)
    while True:
        q, rem = _bn_divmod_full(scaled_num, scaled_den)
        if _bn_cmp(q, two52) < 0:
            # q too small: shrink e (multiply num side by 2).
            e -= 1
            if e >= 0:
                scaled_num = num
                scaled_den = _bn_shl(den, e)
            else:
                scaled_num = _bn_shl(num, -e)
                scaled_den = den
            continue
        if _bn_cmp(q, two53) >= 0:
            e += 1
            if e >= 0:
                scaled_num = num
                scaled_den = _bn_shl(den, e)
            else:
                scaled_num = _bn_shl(num, -e)
                scaled_den = den
            continue
        break
    # q in [2^52, 2^53); the TRUE value is (q + rem/scaled_den) * 2^e
    # with 0 <= rem/scaled_den < 1. The unbiased binary exponent of the
    # value is E = 52 + e. If E < -1022 the result is subnormal and the
    # significand must be rounded at a COARSER step than 1 ULP-of-q,
    # otherwise we double-round (round to 53 bits, then again to the
    # subnormal grid). So fold any extra right-shift into a single
    # half-even rounding step here, against the exact remainder.
    E = 52 + e
    q_int = _bn_to_u64(q)
    if E < -1022:
        drop = -1022 - E  # bits to drop below the 53-bit grid
        if drop >= 54:
            return -0.0 if neg else 0.0
        # Split q into the kept high part and the dropped low part; the
        # discarded fraction is (low + rem/scaled_den) * 2^e, compared
        # against the half-way point (2^(drop-1)).
        kept = q_int >> drop
        low = q_int & ((1 << drop) - 1)
        half = 1 << (drop - 1)
        if low > half:
            round_up = True
        elif low < half:
            round_up = False
        else:
            # low == half exactly at the q grid; the sub-ULP remainder
            # breaks the tie. rem > 0 => strictly above half => up;
            # rem == 0 => exact tie => round to even.
            if not _bn_is_zero(rem):
                round_up = True
            else:
                round_up = (kept & 1) == 1
        if round_up:
            kept += 1
        # kept may carry into 2^52, promoting to the smallest normal;
        # _assemble_f64 handles that via the bits layout.
        return _assemble_subnormal_bits(kept, neg)
    # Normal path: round the 53-bit mantissa half-even against rem.
    twice_rem = _bn_shl(rem, 1)
    c = _bn_cmp(twice_rem, scaled_den)
    round_up = c > 0 or (c == 0 and (q_int & 1) == 1)
    if round_up:
        q_int += 1
        if q_int == _F64_EXACT_INT_MAX:  # carried 2^53 - 1 -> 2^53
            q_int >>= 1
            e += 1
            E = 52 + e
    return _assemble_f64(q_int, e, neg)


class _Overflow(Exception):
    pass


def _assemble_f64(mant53, e, neg):
    """Assemble the NORMAL f64 from a 53-bit mantissa ``mant53`` in
    [2^52, 2^53) and binary exponent ``e`` (value == mant53 * 2^e).
    Raises ``_Overflow`` past DBL_MAX. The subnormal regime is handled
    by the caller (``_round_bignum_ratio_to_f64``) so that rounding
    happens exactly once at the subnormal grid."""
    # value = mant53 * 2^e; unbiased binary exponent E = 52 + e, with
    # value = 1.fraction * 2^E and E in [-1022, 1023] for a normal.
    E = 52 + e
    if E > 1023:
        raise _Overflow()
    biased = E + 1023
    frac = mant53 - (1 << 52)
    bits = (biased << 52) | frac
    if neg:
        bits |= 1 << 63
    return _double_of(bits)


def _assemble_subnormal_bits(mant, neg):
    """Assemble a subnormal (or smallest-normal) f64 directly from the
    already-rounded significand ``mant`` (an integer in [0, 2^52]).
    ``mant == 2^52`` means the rounding carried up into the smallest
    normal, which the IEEE bit layout produces automatically (exponent
    field 1, fraction 0)."""
    bits = mant  # exponent field 0; a carry into bit 52 sets field to 1
    if neg:
        bits |= 1 << 63
    return _double_of(bits)


# --- bignum helpers the slow path adds on top of the Dragon4 family ---


def _bn_bitlen(a):
    """Bit length of the bignum (0 for zero), via the top limb's
    bit length plus the lower limbs' fixed 32 bits each."""
    if _bn_is_zero(a):
        return 0
    top = a[-1]
    bits = 0
    while top:
        bits += 1
        top >>= 1
    return bits + 32 * (len(a) - 1)


def _bn_to_u64(a):
    """Value of a bignum known to fit in 64 bits."""
    v = 0
    for i in range(len(a) - 1, -1, -1):
        v = (v << 32) | a[i]
    return v


def _bn_from_str(digits):
    """Bignum from a decimal-digit string (Horner over limbs, all
    32-bit-mul). Used for mantissas wider than 64 bits."""
    a = [0]
    for ch in digits:
        a = _bn_mul_small(a, 10)
        a = _bn_add(a, [ord(ch) - 48])
    return a


def _bn_divmod_full(num, den):
    """Return ``(q, rem)`` with ``num == q*den + rem`` and ``0 <= rem <
    den``, q and rem fresh bignums. Long division in base 2: shift den
    up to align with num, then subtract-and-shift. All limb ops; the
    bounded inner work mirrors a WAT loop.

    Used only in the slow path where ``q`` is known to be < 2^54 (a
    53-or-54-bit mantissa), so the quotient stays small."""
    if _bn_cmp(num, den) < 0:
        return [0], list(num)
    shift = _bn_bitlen(num) - _bn_bitlen(den)
    # d = den << shift; ensure d <= num by decrementing shift if needed.
    d = _bn_shl(den, shift)
    if _bn_cmp(d, num) > 0:
        shift -= 1
        d = _bn_shl(den, shift)
    q = [0]
    rem = list(num)
    for s in range(shift, -1, -1):
        ds = _bn_shl(den, s)
        if _bn_cmp(rem, ds) >= 0:
            rem = _bn_sub(rem, ds)
            q = _bn_add(q, _bn_shl([1], s))
    return _bn_norm(q), _bn_norm(rem)


def strtod(s: str):
    """Correctly-rounded decimal-string -> f64.

    Returns the f64 ``Some``-value, or ``None`` on a grammar violation
    OR on overflow past DBL_MAX (the value cannot be represented). This
    is the reference the WAT ``$parse_float`` is transliterated from and
    must equal CPython ``float(s)`` bit-for-bit on every grammar-valid,
    non-overflowing input.
    """
    parsed = _parse_decimal(s)
    if parsed is None:
        return None
    neg, digits, e10 = parsed
    # Strip leading zeros from the significant digits; an all-zero
    # mantissa is exact zero (signed).
    stripped = digits.lstrip("0")
    if not stripped:
        return -0.0 if neg else 0.0
    ndigits = len(stripped)

    # Clinger fast path: mantissa exact in f64 and 10^|e10| exact.
    if ndigits <= 15 and abs(e10) <= _F64_EXACT_POW10_MAX:
        mant_int = int(stripped)  # <= 10^15 < 2^53, exact-fits check below
        if mant_int < _F64_EXACT_INT_MAX:
            mf = float(mant_int)
            if e10 >= 0:
                return -(mf * _POW10_F64[e10]) if neg else mf * _POW10_F64[e10]
            return -(mf / _POW10_F64[-e10]) if neg else mf / _POW10_F64[-e10]

    # Quick overflow / underflow screens to bound the bignum work.
    # decimal_point_exp ~= number of digits + e10; |value| ~ 10^that.
    approx_exp10 = ndigits + e10
    if approx_exp10 > 309:  # 10^309 > DBL_MAX (~1.8e308)
        return None
    if approx_exp10 < -324:  # 10^-324 < smallest subnormal half-ulp
        return -0.0 if neg else 0.0

    # Slow path: exact rational mantissa * 10^e10, rounded half-even.
    m = _bn_from_str(stripped)
    if e10 >= 0:
        num = _bn_mul_pow10(m, e10)
        den = [1]
    else:
        num = m
        den = _bn_mul_pow10([1], -e10)
    try:
        return _round_bignum_ratio_to_f64(num, den, neg)
    except _Overflow:
        return None


# ======================================================================
# Combined shortest-digit producer + Python repr spelling.
# ======================================================================


def shortest_digits(x: float) -> tuple[str, int]:
    """(digits, K) for positive finite non-zero x: value == digits*10^K.
    Grisu fast path with Dragon4 exact fallback."""
    d, K, ok = grisu(x)
    if ok:
        return d, K
    return dragon4(x)


def _spell(digits: str, K: int, negative: bool) -> str:
    """Apply Python repr's fixed-vs-scientific spelling to a shortest
    digit string ``digits`` with value digits * 10^K.

    Python's repr uses ``repr`` mode of the dtoa formatter: it picks the
    decimal point position ``decpt = len(digits) + K`` and switches to
    scientific notation when ``decpt < -3`` or ``decpt > 16`` (i.e. the
    exponent ``decpt - 1`` is < -4 or >= 16).
    """
    sign = "-" if negative else ""
    ndigits = len(digits)
    decpt = ndigits + K  # position of decimal point from the left.

    # Scientific iff exponent e = decpt - 1 satisfies e < -4 or e >= 16.
    use_sci = decpt - 1 < -4 or decpt - 1 >= 16

    if use_sci:
        exp = decpt - 1
        if ndigits == 1:
            mant = digits
        else:
            mant = digits[0] + "." + digits[1:]
        esign = "+" if exp >= 0 else "-"
        eabs = abs(exp)
        # Python pads the exponent to at least 2 digits.
        estr = f"{eabs:02d}"
        return f"{sign}{mant}e{esign}{estr}"

    # Fixed notation.
    if decpt <= 0:
        # 0.00...digits
        return f"{sign}0." + ("0" * (-decpt)) + digits
    if decpt >= ndigits:
        # digits followed by trailing zeros, then ".0".
        return f"{sign}{digits}" + ("0" * (decpt - ndigits)) + ".0"
    # Decimal point inside the digit string.
    return f"{sign}{digits[:decpt]}.{digits[decpt:]}"


def format_float(x: float) -> str:
    """Match Python's ``repr(float)`` byte-for-byte for any finite
    double, plus inf / nan exactly as repr spells them."""
    bits = _bits_of(x)
    sign = (bits >> 63) & 1
    biased = (bits >> _DBL_MANT_BITS) & _DBL_EXP_MASK
    mant = bits & _DBL_MANT_MASK

    if biased == _DBL_EXP_MASK:
        if mant != 0:
            return "nan"
        return "-inf" if sign else "inf"

    if biased == 0 and mant == 0:
        return "-0.0" if sign else "0.0"

    negative = bool(sign)
    absx = -x if negative else x
    digits, K = shortest_digits(absx)
    return _spell(digits, K, negative)


# ======================================================================
# Validation harness (Python int allowed here - scaffolding only).
# ======================================================================


def _check(x: float) -> bool:
    """Return True if format_float(x) == repr(x)."""
    return format_float(x) == repr(x)


def validate_edge_cases() -> tuple[int, int, list[tuple[float, str, str]]]:
    """Edge classes. Returns (checked, diverged, examples_of_failures)."""
    cases: list[float] = []

    # Arithmetic repros from the bug report.
    cases += [
        86.0 / 7018.0,
        39890.261 * 297.24217854,
        100.0 / 7.0,
        (1.0 + 2.0 + 4.0) / 3.0,
    ]
    # Grid of a/b and a*b.
    for a in range(1, 60):
        for b in range(1, 60):
            cases.append(a / b)
            cases.append(float(a) * float(b))
            cases.append((a * 1000.0) / (b * 7.0))

    # Special / boundary values.
    cases += [0.0, -0.0]
    cases += [
        5e-324,                 # smallest subnormal
        1e-323, 2.5e-323,
        2.2250738585072014e-308,  # DBL_MIN (smallest normal)
        2.225073858507201e-308,   # largest subnormal
        1.7976931348623157e308,   # DBL_MAX
        float("inf"), float("-inf"), float("nan"),
    ]
    # Powers of two across the whole representable range, including the
    # subnormal ones below 2^-1022 down to the smallest positive 2^-1074.
    for p in range(-1074, 1024):
        cases.append(_double_of(1 << (p + 1074)) if p < -1022 else 2.0 ** p)
    # Integers up to 2^53.
    for p in range(0, 54):
        cases.append(float(2 ** p))
        cases.append(float(2 ** p - 1))
    # 15/16/17 significant digit values.
    cases += [
        1.2345678901234567,
        1.234567890123456,
        1.23456789012345,
        9.999999999999999e22,
        1.1125369292536007e-308,
    ]
    # Fixed/scientific boundary (decpt around -3 and 16/17).
    for n in range(-6, 20):
        cases.append(float(f"1e{n}"))
        cases.append(float(f"1.5e{n}"))
        cases.append(float(f"9.99e{n}"))
    # Negatives mirror.
    cases += [-c for c in list(cases) if c == c and abs(c) != float("inf")]

    checked = 0
    diverged = 0
    failures: list[tuple[float, str, str]] = []
    for c in cases:
        checked += 1
        got = format_float(c)
        exp = repr(c)
        if got != exp:
            diverged += 1
            if len(failures) < 25:
                failures.append((c, got, exp))
    return checked, diverged, failures


def validate_sweep(
    count: int = 3_000_000, seed: int = 0xC0FFEE
) -> tuple[int, int, int, list[tuple[float, str, str]]]:
    """Random sweep over raw 64-bit patterns reinterpreted as doubles,
    skipping inf / nan. Returns (checked, diverged, fallback_count,
    failure_examples).

    Uses Python int / random only as scaffolding to generate inputs and
    cross-check against repr; the algorithm under test uses neither.
    """
    import random
    rng = random.Random(seed)
    checked = 0
    diverged = 0
    fallback = 0
    failures: list[tuple[float, str, str]] = []
    for _ in range(count):
        bits = rng.getrandbits(64)
        biased = (bits >> 52) & 0x7FF
        if biased == 0x7FF:
            continue  # inf / nan
        x = _double_of(bits)
        checked += 1
        # Track fallback rate on non-zero finite values.
        absbits = bits & 0x7FFFFFFFFFFFFFFF
        if absbits != 0:
            ax = -x if (bits >> 63) else x
            _, _, ok = grisu(ax)
            if not ok:
                fallback += 1
        got = format_float(x)
        exp = repr(x)
        if got != exp:
            diverged += 1
            if len(failures) < 25:
                failures.append((x, got, exp))
    return checked, diverged, fallback, failures


def main() -> int:
    print("=== Edge / arithmetic classes ===")
    checked, diverged, failures = validate_edge_cases()
    print(f"  checked={checked}  diverged={diverged}")
    for x, got, exp in failures:
        print(f"  DIVERGE {x!r}: got {got!r} expected {exp!r}")

    print("=== Random f64 bit-pattern sweep ===")
    n = 3_000_000
    s_checked, s_diverged, s_fallback, s_fail = validate_sweep(n)
    pct = 100.0 * s_fallback / s_checked if s_checked else 0.0
    print(f"  checked={s_checked}  diverged={s_diverged}")
    print(f"  grisu_fallback={s_fallback} ({pct:.4f}% needed Dragon4)")
    for x, got, exp in s_fail:
        print(f"  DIVERGE {x!r}: got {got!r} expected {exp!r}")

    total_div = diverged + s_diverged
    print(f"=== TOTAL DIVERGENCES: {total_div} (must be 0) ===")
    return 0 if total_div == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
