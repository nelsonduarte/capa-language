"""Grisu2 shortest-round-trip float-to-string emission.

Owns ``$ftoa`` (the entry point Capa's ``${float}`` interpolation
calls) and the four helpers it depends on:

- ``$pow10_i32(k)`` -- decimal divisors for digit peeling
- ``$grisu_mul_high(a, b)`` -- high 64 bits of the unsigned
  128-bit product, with the +2^31 round-half-up bias
- ``$grisu_cached_power(e)`` -- table lookup keyed by binary exp
- ``$grisu2(f, buf)`` -- the main algorithm; returns
  ``(digits_ptr, digits_len, K)`` where the represented value
  equals ``int(digits) * 10^K``

The 87-entry cached-powers table is module-level data, written
once into linear memory at ``_cached_powers_offset`` (reserved
by ``WasmEmitter.emit`` after string interning).

The Grisu2 algorithm itself is documented in Loitsch 2010
("Printing floating-point numbers quickly and accurately"); the
implementation here matches Google's double-conversion reference
modulo the round-half-up trick in ``$grisu_mul_high``.

Split out of ``_runtime.py`` in audit P1 refactor: the Grisu2
block plus its supporting table grew to ~1100 LOC, dominating
the runtime-helpers file and obscuring the simpler helpers
(``$str_eq``, ``$itoa``, ``$parse_int``, ``$parse_float``,
``$alloc``, ``$cabi_realloc``). One mixin per cohesive concern.
"""

from __future__ import annotations


# Same 87-entry cached-powers-of-10 table as the validated Python
# reference at ``grisu2_ref.py``. Each entry is (significand,
# binary_exp, decimal_exp); the significand is normalised so the
# top bit is set. Stored as one row of 16 bytes (i64 sig, i32 bexp,
# i32 dexp) starting at ``_cached_powers_offset`` in linear memory.
_CACHED_POWERS = [
    (0xfa8fd5a0081c0288, -1220, -348),
    (0xbaaee17fa23ebf76, -1193, -340),
    (0x8b16fb203055ac76, -1166, -332),
    (0xcf42894a5dce35ea, -1140, -324),
    (0x9a6bb0aa55653b2d, -1113, -316),
    (0xe61acf033d1a45df, -1087, -308),
    (0xab70fe17c79ac6ca, -1060, -300),
    (0xff77b1fcbebcdc4f, -1034, -292),
    (0xbe5691ef416bd60c, -1007, -284),
    (0x8dd01fad907ffc3c, -980, -276),
    (0xd3515c2831559a83, -954, -268),
    (0x9d71ac8fada6c9b5, -927, -260),
    (0xea9c227723ee8bcb, -901, -252),
    (0xaecc49914078536d, -874, -244),
    (0x823c12795db6ce57, -847, -236),
    (0xc21094364dfb5637, -821, -228),
    (0x9096ea6f3848984f, -794, -220),
    (0xd77485cb25823ac7, -768, -212),
    (0xa086cfcd97bf97f4, -741, -204),
    (0xef340a98172aace5, -715, -196),
    (0xb23867fb2a35b28e, -688, -188),
    (0x84c8d4dfd2c63f3b, -661, -180),
    (0xc5dd44271ad3cdba, -635, -172),
    (0x936b9fcebb25c996, -608, -164),
    (0xdbac6c247d62a584, -582, -156),
    (0xa3ab66580d5fdaf6, -555, -148),
    (0xf3e2f893dec3f126, -529, -140),
    (0xb5b5ada8aaff80b8, -502, -132),
    (0x87625f056c7c4a8b, -475, -124),
    (0xc9bcff6034c13053, -449, -116),
    (0x964e858c91ba2655, -422, -108),
    (0xdff9772470297ebd, -396, -100),
    (0xa6dfbd9fb8e5b88f, -369, -92),
    (0xf8a95fcf88747d94, -343, -84),
    (0xb94470938fa89bcf, -316, -76),
    (0x8a08f0f8bf0f156b, -289, -68),
    (0xcdb02555653131b6, -263, -60),
    (0x993fe2c6d07b7fac, -236, -52),
    (0xe45c10c42a2b3b06, -210, -44),
    (0xaa242499697392d3, -183, -36),
    (0xfd87b5f28300ca0e, -157, -28),
    (0xbce5086492111aeb, -130, -20),
    (0x8cbccc096f5088cc, -103, -12),
    (0xd1b71758e219652c, -77, -4),
    (0x9c40000000000000, -50, 4),
    (0xe8d4a51000000000, -24, 12),
    (0xad78ebc5ac620000, 3, 20),
    (0x813f3978f8940984, 30, 28),
    (0xc097ce7bc90715b3, 56, 36),
    (0x8f7e32ce7bea5c70, 83, 44),
    (0xd5d238a4abe98068, 109, 52),
    (0x9f4f2726179a2245, 136, 60),
    (0xed63a231d4c4fb27, 162, 68),
    (0xb0de65388cc8ada8, 189, 76),
    (0x83c7088e1aab65db, 216, 84),
    (0xc45d1df942711d9a, 242, 92),
    (0x924d692ca61be758, 269, 100),
    (0xda01ee641a708dea, 295, 108),
    (0xa26da3999aef774a, 322, 116),
    (0xf209787bb47d6b85, 348, 124),
    (0xb454e4a179dd1877, 375, 132),
    (0x865b86925b9bc5c2, 402, 140),
    (0xc83553c5c8965d3d, 428, 148),
    (0x952ab45cfa97a0b3, 455, 156),
    (0xde469fbd99a05fe3, 481, 164),
    (0xa59bc234db398c25, 508, 172),
    (0xf6c69a72a3989f5c, 534, 180),
    (0xb7dcbf5354e9bece, 561, 188),
    (0x88fa513c149a3d75, 588, 196),
    (0xcc20ce9bd35c78a5, 614, 204),
    (0x98165af37b2153df, 641, 212),
    (0xe2a0b5dc971f303a, 667, 220),
    (0xa8d9d1535ce3b396, 694, 228),
    (0xfb9b7cd9a4a7443c, 720, 236),
    (0xbb764c4ca7a44410, 747, 244),
    (0x8bab8eefb6409c1a, 774, 252),
    (0xd01fef10a657842c, 800, 260),
    (0x9b10a4e5e9913129, 827, 268),
    (0xe7109bfba19c0c9d, 853, 276),
    (0xac2820d9623bf429, 880, 284),
    (0x80444b5e7aa7cf85, 907, 292),
    (0xbf21e44003acdd2c, 933, 300),
    (0x8e679c2f5e44ff8f, 960, 308),
    (0xd433179d9c8cb841, 986, 316),
    (0x9e19db92b4e31ba9, 1013, 324),
    (0xeb96bf6ebadf77d8, 1039, 332),
    (0xaf87023b9bf0ee6a, 1066, 340),
]


# Byte size of one row (i64 sig + i32 bexp + i32 dexp).
_CACHED_POWERS_ROW_SIZE = 16
_CACHED_POWERS_BYTE_SIZE = len(_CACHED_POWERS) * _CACHED_POWERS_ROW_SIZE


def _cached_powers_data_bytes() -> bytes:
    """Serialise the cached-powers table as raw little-endian bytes,
    ready to be embedded in a WAT ``(data ...)`` directive via the
    emitter's ``_escape_wat_string`` helper."""
    out = bytearray()
    for sig, bexp, dexp in _CACHED_POWERS:
        out += sig.to_bytes(8, "little", signed=False)
        out += (bexp & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        out += (dexp & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
    return bytes(out)


class _GrisuEmissionMixin:
    # ----- ftoa: Grisu2 + format ----------------------------------

    def _emit_cached_powers_data(self) -> None:
        """Emit the 87-entry cached-powers-of-10 table as a raw
        ``(data ...)`` directive at the offset reserved by the
        dispatcher. The table is read by ``$grisu_cached_power``
        as one 16-byte row (i64 sig, i32 bexp, i32 dexp) per
        cached decimal exponent slice."""
        raw = _cached_powers_data_bytes()
        escaped = "".join(f"\\{b:02x}" for b in raw)
        self._write(
            f'(data (i32.const {self._cached_powers_offset}) "{escaped}")'
        )

    def _emit_pow10_i32_function(self) -> None:
        """``$pow10_i32(k: i32) -> i32``: return 10**k for k in
        [0, 9]. Used during Grisu2 digit generation to peel one
        decimal digit at a time from the integer part of the
        scaled significand. Larger exponents are unreachable
        (kappa starts at 10 but the first divisor is 10**9 so we
        only ever index by 0..9)."""
        self._write("(func $pow10_i32 (param $k i32) (result i32)")
        self._indent += 1
        # Hand-rolled jump table -- ten branches is much smaller
        # than a loop and avoids the i64.div_u that a loop would
        # introduce.
        self._write("local.get $k")
        self._write("i32.const 0")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        for k in range(1, 10):
            self._write("local.get $k")
            self._write(f"i32.const {k}")
            self._write("i32.eq")
            self._write("if")
            self._indent += 1
            self._write(f"i32.const {10 ** k}")
            self._write("return")
            self._indent -= 1
            self._write("end")
        # Fall-through unreachable: callers stay in [0, 9].
        self._write("unreachable")
        self._indent -= 1
        self._write(")")

    def _emit_mul_high_u64_function(self) -> None:
        """``$grisu_mul_high(a: i64, b: i64) -> i64``: high 64 bits
        of the unsigned 128-bit product of two i64s, with a +2^31
        round-half-up correction so the result matches the Python
        reference's ``(a*b + (1<<31)) >> 64``.

        Composes the product from 32-bit halves with explicit carry
        propagation. The classic schoolbook layout:

            a = a_hi << 32 | a_lo
            b = b_hi << 32 | b_lo
            a*b = a_lo*b_lo
                + (a_hi*b_lo + a_lo*b_hi) << 32
                + (a_hi*b_hi) << 64

        We track the carry from the low 64 bits into the high 64
        bits and add the round-half-up bias to the low 64 before
        propagating."""
        self._write(
            "(func $grisu_mul_high (param $a i64) (param $b i64) "
            "(result i64)"
        )
        self._indent += 1
        self._write("(local $a_lo i64)")
        self._write("(local $a_hi i64)")
        self._write("(local $b_lo i64)")
        self._write("(local $b_hi i64)")
        self._write("(local $ll i64)")
        self._write("(local $lh i64)")
        self._write("(local $hl i64)")
        self._write("(local $hh i64)")
        self._write("(local $mid i64)")
        self._write("(local $carry i64)")
        # a_lo = a & 0xFFFFFFFF; a_hi = a >>_u 32
        self._write("local.get $a")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("local.set $a_lo")
        self._write("local.get $a")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("local.set $a_hi")
        # b_lo = b & 0xFFFFFFFF; b_hi = b >>_u 32
        self._write("local.get $b")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("local.set $b_lo")
        self._write("local.get $b")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("local.set $b_hi")
        # ll = a_lo * b_lo  (fits in 64 bits, 32x32 -> <= 64).
        self._write("local.get $a_lo")
        self._write("local.get $b_lo")
        self._write("i64.mul")
        self._write("local.set $ll")
        # lh = a_lo * b_hi  (fits in 64 bits).
        self._write("local.get $a_lo")
        self._write("local.get $b_hi")
        self._write("i64.mul")
        self._write("local.set $lh")
        # hl = a_hi * b_lo  (fits in 64 bits).
        self._write("local.get $a_hi")
        self._write("local.get $b_lo")
        self._write("i64.mul")
        self._write("local.set $hl")
        # hh = a_hi * b_hi  (fits in 64 bits).
        self._write("local.get $a_hi")
        self._write("local.get $b_hi")
        self._write("i64.mul")
        self._write("local.set $hh")
        # We assemble the high 64 bits with round-half-up.
        # Picture the 128-bit product split into four 32-bit lanes
        # [hi3 hi2 lo1 lo0]:
        #   ll      contributes to lanes (lo1 << 32) | lo0
        #   lh*2^32 contributes to lanes (hi2 << 32) | (mid_lh << 0 at lane lo1)
        #   hl*2^32 contributes the same shape as lh
        #   hh*2^64 contributes to lanes (hi3 << 32) | hi2
        # The high 64 bits (which is what we return) is:
        #   hh + (lh >>_u 32) + (hl >>_u 32) + carry_from_lo64
        # where carry_from_lo64 = ((ll >>_u 32) + (lh & 0xFFFFFFFF)
        #                         + (hl & 0xFFFFFFFF)) >>_u 32
        # The +2^31 round-half-up bias is added INSIDE the low 64
        # bits so it can propagate carry into the high 64.
        #
        # Concretely:
        #   mid = (ll >>_u 32) + (lh & 0xFFFFFFFF)
        #       + (hl & 0xFFFFFFFF) + (1 << 31)
        #   carry = mid >>_u 32
        #   high = hh + (lh >>_u 32) + (hl >>_u 32) + carry
        self._write("local.get $ll")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("local.get $lh")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("i64.add")
        self._write("local.get $hl")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("i64.add")
        self._write("i64.const 0x80000000")  # +2^31 round-half-up bias
        self._write("i64.add")
        self._write("local.set $mid")
        self._write("local.get $mid")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("local.set $carry")
        self._write("local.get $hh")
        self._write("local.get $lh")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i64.add")
        self._write("local.get $hl")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i64.add")
        self._write("local.get $carry")
        self._write("i64.add")
        self._indent -= 1
        self._write(")")

    def _emit_grisu_cached_power_function(self) -> None:
        """``$grisu_cached_power(e: i32) -> (i32 row_ptr)``: look up
        the cached-powers row whose bexp matches the input binary
        exponent ``e``, returning a pointer into the cached-powers
        table at the chosen 16-byte row.

        Mirrors the Python reference's:

            k = ceil((-61 - e) * log10(2))
            index = (348 + k - 1) // 8 + 1
            return _CACHED_POWERS[index]

        ceil(N * log10(2)) is computed in fixed-point: log10(2) is
        approximated by 1292913986 / 2^32, exact enough across the
        full f64 exponent range (-1074, 970)."""
        self._write(
            "(func $grisu_cached_power (param $e i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $n i32)")
        self._write("(local $prod i64)")
        self._write("(local $q i64)")
        self._write("(local $r i64)")
        self._write("(local $k i32)")
        self._write("(local $index i32)")
        # n = -61 - e
        self._write("i32.const -61")
        self._write("local.get $e")
        self._write("i32.sub")
        self._write("local.set $n")
        # prod = (i64) n * 1292913986
        self._write("local.get $n")
        self._write("i64.extend_i32_s")
        self._write("i64.const 1292913986")
        self._write("i64.mul")
        self._write("local.set $prod")
        # q = prod >>_s 32  (arithmetic shift; signed floor)
        self._write("local.get $prod")
        self._write("i64.const 32")
        self._write("i64.shr_s")
        self._write("local.set $q")
        # r = prod - (q << 32)
        self._write("local.get $prod")
        self._write("local.get $q")
        self._write("i64.const 32")
        self._write("i64.shl")
        self._write("i64.sub")
        self._write("local.set $r")
        # k = (i32) q + (r != 0 ? 1 : 0)   -- standard ceil-from-floor.
        self._write("local.get $q")
        self._write("i32.wrap_i64")
        self._write("local.get $r")
        self._write("i64.const 0")
        self._write("i64.ne")
        self._write("i32.add")
        self._write("local.set $k")
        # index = (348 + k - 1) // 8 + 1
        self._write("local.get $k")
        self._write("i32.const 347")
        self._write("i32.add")
        self._write("i32.const 8")
        self._write("i32.div_s")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $index")
        # row_ptr = cached_powers_offset + index * 16
        self._write(f"i32.const {self._cached_powers_offset}")
        self._write("local.get $index")
        self._write("i32.const 4")
        self._write("i32.shl")  # x * 16
        self._write("i32.add")
        self._indent -= 1
        self._write(")")

    def _emit_grisu2_function(self) -> None:
        """``$grisu2(v: f64) -> (i32 digits_ptr, i32 digits_len, i32 K)``:
        shortest-round-trip decimal mantissa + decimal exponent.
        ``v`` must be positive, finite, non-zero; the caller
        (``$ftoa``) handles the special cases.

        Line-by-line port of the validated Python reference at
        ``grisu2_ref.py::grisu2``. See that file's docstring for
        the algorithm summary; comments here flag where i64 / i32
        decomposition diverges from Python's big-int form."""
        self._write(
            "(func $grisu2 (param $v f64) "
            "(result i32 i32 i32)"
        )
        self._indent += 1
        # IEEE 754 decomposition.
        self._write("(local $bits i64)")
        self._write("(local $biased_exp i32)")
        self._write("(local $mantissa i64)")
        self._write("(local $w_f i64)")
        self._write("(local $w_e i32)")
        # Boundaries.
        self._write("(local $mp_f i64)")
        self._write("(local $mp_e i32)")
        self._write("(local $mm_f i64)")
        self._write("(local $mm_e i32)")
        # Normalisation.
        self._write("(local $shift i32)")
        self._write("(local $w_f_at_mpe i64)")
        # Cached power.
        self._write("(local $c_row i32)")
        self._write("(local $c_sig i64)")
        self._write("(local $c_bexp i32)")
        self._write("(local $c_dexp i32)")
        # Scaled W / Wp / Wm.
        self._write("(local $Wf i64)")
        self._write("(local $We i32)")
        self._write("(local $Wp_f i64)")
        self._write("(local $Wm_f i64)")
        self._write("(local $delta i64)")
        # Digit generation state.
        self._write("(local $one_f i64)")
        self._write("(local $p1 i64)")
        self._write("(local $p2 i64)")
        self._write("(local $kappa i32)")
        self._write("(local $buf i32)")
        self._write("(local $digit_count i32)")
        self._write("(local $div i64)")
        self._write("(local $d i64)")
        self._write("(local $rest i64)")
        # Step 1: extract IEEE 754.
        # bits = reinterpret(v) as i64
        self._write("local.get $v")
        self._write("i64.reinterpret_f64")
        self._write("local.set $bits")
        # biased_exp = (bits >> 52) & 0x7FF
        self._write("local.get $bits")
        self._write("i64.const 52")
        self._write("i64.shr_u")
        self._write("i64.const 0x7FF")
        self._write("i64.and")
        self._write("i32.wrap_i64")
        self._write("local.set $biased_exp")
        # mantissa = bits & 0x000FFFFFFFFFFFFF
        self._write("local.get $bits")
        self._write("i64.const 0x000FFFFFFFFFFFFF")
        self._write("i64.and")
        self._write("local.set $mantissa")
        # if biased_exp == 0: w_f = mantissa; w_e = -1074
        # else: w_f = mantissa | (1 << 52); w_e = biased_exp - 1075
        self._write("local.get $biased_exp")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $mantissa")
        self._write("local.set $w_f")
        self._write("i32.const -1074")
        self._write("local.set $w_e")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $mantissa")
        self._write("i64.const 0x0010000000000000")
        self._write("i64.or")
        self._write("local.set $w_f")
        self._write("local.get $biased_exp")
        self._write("i32.const 1075")
        self._write("i32.sub")
        self._write("local.set $w_e")
        self._indent -= 1
        self._write("end")
        # Step 2: boundaries.
        # mp_f = (w_f << 1) + 1; mp_e = w_e - 1
        self._write("local.get $w_f")
        self._write("i64.const 1")
        self._write("i64.shl")
        self._write("i64.const 1")
        self._write("i64.add")
        self._write("local.set $mp_f")
        self._write("local.get $w_e")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $mp_e")
        # if mantissa == 0 && biased_exp > 1:
        #     mm_f = (w_f << 2) - 1; mm_e = w_e - 2
        # else:
        #     mm_f = (w_f << 1) - 1; mm_e = w_e - 1
        self._write("local.get $mantissa")
        self._write("i64.eqz")
        self._write("local.get $biased_exp")
        self._write("i32.const 1")
        self._write("i32.gt_s")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        self._write("local.get $w_f")
        self._write("i64.const 2")
        self._write("i64.shl")
        self._write("i64.const 1")
        self._write("i64.sub")
        self._write("local.set $mm_f")
        self._write("local.get $w_e")
        self._write("i32.const 2")
        self._write("i32.sub")
        self._write("local.set $mm_e")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $w_f")
        self._write("i64.const 1")
        self._write("i64.shl")
        self._write("i64.const 1")
        self._write("i64.sub")
        self._write("local.set $mm_f")
        self._write("local.get $w_e")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $mm_e")
        self._indent -= 1
        self._write("end")
        # Step 3: normalize mp to 64 bits.
        # shift = 64 - bit_length(mp_f) = i64.clz(mp_f) when mp_f != 0.
        # mp_f is always non-zero here (denormal mantissa==0 case is
        # handled later via the +1 in mp_f).
        self._write("local.get $mp_f")
        self._write("i64.clz")
        self._write("i32.wrap_i64")
        self._write("local.set $shift")
        # mp_f <<= shift; mp_e -= shift
        self._write("local.get $mp_f")
        self._write("local.get $shift")
        self._write("i64.extend_i32_u")
        self._write("i64.shl")
        self._write("local.set $mp_f")
        self._write("local.get $mp_e")
        self._write("local.get $shift")
        self._write("i32.sub")
        self._write("local.set $mp_e")
        # mm_f <<= (mm_e - mp_e); mm_e = mp_e
        # mm_e - mp_e is always non-negative (shift brings mp_e down
        # below mm_e).
        self._write("local.get $mm_f")
        self._write("local.get $mm_e")
        self._write("local.get $mp_e")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.shl")
        self._write("local.set $mm_f")
        self._write("local.get $mp_e")
        self._write("local.set $mm_e")
        # w_f_at_mpe = w_f << (w_e - mp_e)
        self._write("local.get $w_f")
        self._write("local.get $w_e")
        self._write("local.get $mp_e")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.shl")
        self._write("local.set $w_f_at_mpe")
        # Step 4: cached power lookup.
        self._write("local.get $mp_e")
        self._write("call $grisu_cached_power")
        self._write("local.set $c_row")
        self._write("local.get $c_row")
        self._write("i64.load")  # sig at offset 0
        self._write("local.set $c_sig")
        self._write("local.get $c_row")
        self._write("i32.load offset=8")  # bexp at offset 8
        self._write("local.set $c_bexp")
        self._write("local.get $c_row")
        self._write("i32.load offset=12")  # dexp at offset 12
        self._write("local.set $c_dexp")
        # Step 5: scale.
        # Wf  = mul_high(w_f_at_mpe, c_sig)
        # We  = mp_e + c_bexp + 64
        # Wp_f = mul_high(mp_f, c_sig) + 1
        # Wm_f = mul_high(mm_f, c_sig) - 1
        # delta = Wp_f - Wm_f
        self._write("local.get $w_f_at_mpe")
        self._write("local.get $c_sig")
        self._write("call $grisu_mul_high")
        self._write("local.set $Wf")
        self._write("local.get $mp_e")
        self._write("local.get $c_bexp")
        self._write("i32.add")
        self._write("i32.const 64")
        self._write("i32.add")
        self._write("local.set $We")
        self._write("local.get $mp_f")
        self._write("local.get $c_sig")
        self._write("call $grisu_mul_high")
        self._write("i64.const 1")
        self._write("i64.add")
        self._write("local.set $Wp_f")
        self._write("local.get $mm_f")
        self._write("local.get $c_sig")
        self._write("call $grisu_mul_high")
        self._write("i64.const 1")
        self._write("i64.sub")
        self._write("local.set $Wm_f")
        self._write("local.get $Wp_f")
        self._write("local.get $Wm_f")
        self._write("i64.sub")
        self._write("local.set $delta")
        # Step 6: digit generation.
        # one_f = 1 << -We   (We is negative for in-range floats).
        # p1 = Wp_f >>_u -We; p2 = Wp_f & (one_f - 1)
        self._write("i64.const 1")
        self._write("i32.const 0")
        self._write("local.get $We")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.shl")
        self._write("local.set $one_f")
        self._write("local.get $Wp_f")
        self._write("i32.const 0")
        self._write("local.get $We")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.shr_u")
        self._write("local.set $p1")
        self._write("local.get $Wp_f")
        self._write("local.get $one_f")
        self._write("i64.const 1")
        self._write("i64.sub")
        self._write("i64.and")
        self._write("local.set $p2")
        # Allocate digits buffer (32 bytes is more than enough; 17
        # is the max shortest-round-trip digit count).
        self._write("i32.const 32")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $digit_count")
        # kappa = 10
        self._write("i32.const 10")
        self._write("local.set $kappa")
        # Integer-part loop: while kappa > 0.
        self._block_counter += 1
        iloop = f"$g2{self._block_counter}_iloop"
        iexit = f"$g2{self._block_counter}_iexit"
        self._write(f"block {iexit}")
        self._indent += 1
        self._write(f"loop {iloop}")
        self._indent += 1
        # if kappa <= 0: exit
        self._write("local.get $kappa")
        self._write("i32.const 0")
        self._write("i32.le_s")
        self._write(f"br_if {iexit}")
        # div = 10 ** (kappa - 1)
        self._write("local.get $kappa")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("call $pow10_i32")
        self._write("i64.extend_i32_u")
        self._write("local.set $div")
        # d = p1 / div
        self._write("local.get $p1")
        self._write("local.get $div")
        self._write("i64.div_u")
        self._write("local.set $d")
        # if d != 0 or digit_count > 0: append digit
        self._write("local.get $d")
        self._write("i64.const 0")
        self._write("i64.ne")
        self._write("local.get $digit_count")
        self._write("i32.const 0")
        self._write("i32.gt_s")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        # buf[digit_count] = '0' + d
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("i32.add")
        self._write("local.get $d")
        self._write("i32.wrap_i64")
        self._write("i32.const 48")
        self._write("i32.add")
        self._write("i32.store8")
        self._write("local.get $digit_count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $digit_count")
        self._indent -= 1
        self._write("end")
        # p1 = p1 % div
        self._write("local.get $p1")
        self._write("local.get $div")
        self._write("i64.rem_u")
        self._write("local.set $p1")
        # kappa -= 1
        self._write("local.get $kappa")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $kappa")
        # rest = (p1 << -We) + p2
        self._write("local.get $p1")
        self._write("i32.const 0")
        self._write("local.get $We")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.shl")
        self._write("local.get $p2")
        self._write("i64.add")
        self._write("local.set $rest")
        # if rest < delta: return (buf, digit_count, kappa - c_dexp)
        self._write("local.get $rest")
        self._write("local.get $delta")
        self._write("i64.lt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $kappa")
        self._write("local.get $c_dexp")
        self._write("i32.sub")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"br {iloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Fractional loop: while True.
        self._block_counter += 1
        floop = f"$g2{self._block_counter}_floop"
        fexit = f"$g2{self._block_counter}_fexit"
        self._write(f"block {fexit}")
        self._indent += 1
        self._write(f"loop {floop}")
        self._indent += 1
        # p2 *= 10; delta *= 10
        self._write("local.get $p2")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.set $p2")
        self._write("local.get $delta")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.set $delta")
        # d = p2 >>_u -We
        self._write("local.get $p2")
        self._write("i32.const 0")
        self._write("local.get $We")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.shr_u")
        self._write("local.set $d")
        # p2 &= one_f - 1
        self._write("local.get $p2")
        self._write("local.get $one_f")
        self._write("i64.const 1")
        self._write("i64.sub")
        self._write("i64.and")
        self._write("local.set $p2")
        # buf[digit_count] = '0' + d
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("i32.add")
        self._write("local.get $d")
        self._write("i32.wrap_i64")
        self._write("i32.const 48")
        self._write("i32.add")
        self._write("i32.store8")
        self._write("local.get $digit_count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $digit_count")
        # kappa -= 1
        self._write("local.get $kappa")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $kappa")
        # if p2 < delta: return
        self._write("local.get $p2")
        self._write("local.get $delta")
        self._write("i64.lt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $kappa")
        self._write("local.get $c_dexp")
        self._write("i32.sub")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # if digit_count >= 17: return
        self._write("local.get $digit_count")
        self._write("i32.const 17")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $kappa")
        self._write("local.get $c_dexp")
        self._write("i32.sub")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"br {floop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # The integer + fractional loops both return on exit, so the
        # function never falls through. Make the verifier happy.
        self._write("unreachable")
        self._indent -= 1
        self._write(")")

    def _emit_ftoa_function(self) -> None:
        """``$ftoa(f: f64) -> (i32 ptr, i32 len)``: format a double
        as a decimal string that round-trips through ``f64`` and
        matches Python's ``str(float)`` for the value ranges Capa
        cares about. Handles NaN, +/-inf, +/-0 directly; finite
        non-zero values route through ``$grisu2`` and one of the
        two formatters (decimal vs scientific) based on the
        magnitude of the resulting decimal exponent.

        Output spelling follows Python's rules: ``n = digits_len +
        K`` chooses the form. ``-4 <= n <= 16``: decimal; otherwise
        ``d.ddddde+/-NN`` scientific with the e-exponent computed
        as ``n - 1``."""
        self._write("(func $ftoa (param $f f64) (result i32 i32)")
        self._indent += 1
        self._write("(local $bits i64)")
        self._write("(local $biased_exp i32)")
        self._write("(local $mantissa i64)")
        self._write("(local $sign i32)")
        self._write("(local $abs f64)")
        self._write("(local $digits_ptr i32)")
        self._write("(local $digits_len i32)")
        self._write("(local $K i32)")
        self._write("(local $n i32)")
        self._write("(local $buf i32)")
        self._write("(local $write_pos i32)")
        self._write("(local $i i32)")
        self._write("(local $exp_value i32)")
        self._write("(local $exp_abs i32)")
        # bits = reinterpret(f) as i64; sign = bits >> 63.
        self._write("local.get $f")
        self._write("i64.reinterpret_f64")
        self._write("local.tee $bits")
        self._write("i64.const 63")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write("local.set $sign")
        # biased_exp = (bits >> 52) & 0x7FF
        self._write("local.get $bits")
        self._write("i64.const 52")
        self._write("i64.shr_u")
        self._write("i64.const 0x7FF")
        self._write("i64.and")
        self._write("i32.wrap_i64")
        self._write("local.set $biased_exp")
        # mantissa = bits & 0x000FFFFFFFFFFFFF
        self._write("local.get $bits")
        self._write("i64.const 0x000FFFFFFFFFFFFF")
        self._write("i64.and")
        self._write("local.set $mantissa")
        # Special case: biased_exp == 0x7FF
        self._write("local.get $biased_exp")
        self._write("i32.const 0x7FF")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # if mantissa != 0: NaN -> "nan"
        self._write("local.get $mantissa")
        self._write("i64.const 0")
        self._write("i64.ne")
        self._write("if")
        self._indent += 1
        self._emit_static_literal("nan")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # else: +/-inf
        self._write("local.get $sign")
        self._write("if")
        self._indent += 1
        self._emit_static_literal("-inf")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._emit_static_literal("inf")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Special case: f == 0 (biased_exp == 0 && mantissa == 0)
        self._write("local.get $biased_exp")
        self._write("i32.eqz")
        self._write("local.get $mantissa")
        self._write("i64.eqz")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        self._write("local.get $sign")
        self._write("if")
        self._indent += 1
        self._emit_static_literal("-0.0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._emit_static_literal("0.0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # General path: abs = sign ? -f : f
        self._write("local.get $sign")
        self._write("if")
        self._indent += 1
        self._write("local.get $f")
        self._write("f64.neg")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $f")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("end")
        # (digits_ptr, digits_len, K) = grisu2(abs)
        self._write("local.get $abs")
        self._write("call $grisu2")
        self._write("local.set $K")
        self._write("local.set $digits_len")
        self._write("local.set $digits_ptr")
        # n = digits_len + K
        self._write("local.get $digits_len")
        self._write("local.get $K")
        self._write("i32.add")
        self._write("local.set $n")
        # Format dispatch: decimal if -3 <= n <= 16, else scientific.
        # Matches Python's str(float) which switches to e-notation
        # when exp_value = n - 1 is < -4 or >= 17.
        self._write("local.get $n")
        self._write("i32.const -3")
        self._write("i32.ge_s")
        self._write("local.get $n")
        self._write("i32.const 16")
        self._write("i32.le_s")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # Decimal formatting.
        # Allocate a buffer big enough for any decimal output:
        # sign (1) + leading zeros (5) + digits (17) + dot (1) +
        # trailing zeros (16) + slack (4) = 44. Round up to 48.
        self._write("i32.const 48")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $write_pos")
        # Sign.
        self._write("local.get $sign")
        self._write("if")
        self._indent += 1
        self._emit_store_byte("$buf", "$write_pos", 45)  # '-'
        self._emit_inc("$write_pos", 1)
        self._indent -= 1
        self._write("end")
        # Branch on shape of n.
        # Case A: n >= digits_len -> integer-shape with trailing zeros + ".0"
        self._write("local.get $n")
        self._write("local.get $digits_len")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # Copy digits.
        self._emit_memcopy_digits()
        self._emit_inc_by_local("$write_pos", "$digits_len")
        # Trailing zeros = n - digits_len
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        zloop = f"$ftd{self._block_counter}_zloop"
        zexit = f"$ftd{self._block_counter}_zexit"
        self._write(f"block {zexit}")
        self._indent += 1
        self._write(f"loop {zloop}")
        self._indent += 1
        # if i >= n - digits_len: break
        self._write("local.get $i")
        self._write("local.get $n")
        self._write("local.get $digits_len")
        self._write("i32.sub")
        self._write("i32.ge_s")
        self._write(f"br_if {zexit}")
        # buf[write_pos] = '0'; write_pos++
        self._emit_store_byte("$buf", "$write_pos", 48)
        self._emit_inc("$write_pos", 1)
        self._emit_inc("$i", 1)
        self._write(f"br {zloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Trailing ".0"
        self._emit_store_byte("$buf", "$write_pos", 46)  # '.'
        self._emit_inc("$write_pos", 1)
        self._emit_store_byte("$buf", "$write_pos", 48)  # '0'
        self._emit_inc("$write_pos", 1)
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Case B/C handled below.
        # if n > 0: digits[:n] + "." + digits[n:]
        self._write("local.get $n")
        self._write("i32.const 0")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        # Copy digits[:n]
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $digits_ptr")
        self._write("local.get $n")
        self._write("memory.copy")
        self._emit_inc_by_local("$write_pos", "$n")
        # '.'
        self._emit_store_byte("$buf", "$write_pos", 46)
        self._emit_inc("$write_pos", 1)
        # Copy digits[n:]
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $digits_ptr")
        self._write("local.get $n")
        self._write("i32.add")
        self._write("local.get $digits_len")
        self._write("local.get $n")
        self._write("i32.sub")
        self._write("memory.copy")
        # write_pos += digits_len - n
        self._write("local.get $write_pos")
        self._write("local.get $digits_len")
        self._write("local.get $n")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.set $write_pos")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # n <= 0: "0." + ("0" * -n) + digits
        self._emit_store_byte("$buf", "$write_pos", 48)
        self._emit_inc("$write_pos", 1)
        self._emit_store_byte("$buf", "$write_pos", 46)
        self._emit_inc("$write_pos", 1)
        # Zero-padding: -n leading zeros.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        zploop = f"$ftd{self._block_counter}_zploop"
        zpexit = f"$ftd{self._block_counter}_zpexit"
        self._write(f"block {zpexit}")
        self._indent += 1
        self._write(f"loop {zploop}")
        self._indent += 1
        # if i >= -n: break
        self._write("local.get $i")
        self._write("i32.const 0")
        self._write("local.get $n")
        self._write("i32.sub")
        self._write("i32.ge_s")
        self._write(f"br_if {zpexit}")
        self._emit_store_byte("$buf", "$write_pos", 48)
        self._emit_inc("$write_pos", 1)
        self._emit_inc("$i", 1)
        self._write(f"br {zploop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Copy all digits.
        self._emit_memcopy_digits()
        self._emit_inc_by_local("$write_pos", "$digits_len")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Return (buf, write_pos).
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("return")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Scientific formatting: d.dddde+/-NN
        # exp_value = n - 1
        self._write("local.get $n")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $exp_value")
        # Allocate buffer: sign (1) + d (1) + . (1) + 16 digits (16)
        # + e (1) + sign (1) + 3 exp digits (3) + slack = 32 rounded.
        self._write("i32.const 48")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $write_pos")
        # Sign.
        self._write("local.get $sign")
        self._write("if")
        self._indent += 1
        self._emit_store_byte("$buf", "$write_pos", 45)
        self._emit_inc("$write_pos", 1)
        self._indent -= 1
        self._write("end")
        # First digit: digits[0]
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $digits_ptr")
        self._write("i32.load8_u")
        self._write("i32.store8")
        self._emit_inc("$write_pos", 1)
        # If digits_len > 1: '.' + digits[1:]
        self._write("local.get $digits_len")
        self._write("i32.const 1")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._emit_store_byte("$buf", "$write_pos", 46)
        self._emit_inc("$write_pos", 1)
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $digits_ptr")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.get $digits_len")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("memory.copy")
        self._write("local.get $write_pos")
        self._write("local.get $digits_len")
        self._write("i32.add")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $write_pos")
        self._indent -= 1
        self._write("end")
        # 'e'
        self._emit_store_byte("$buf", "$write_pos", 101)
        self._emit_inc("$write_pos", 1)
        # Sign of exp_value, then magnitude.
        self._write("local.get $exp_value")
        self._write("i32.const 0")
        self._write("i32.lt_s")
        self._write("if")
        self._indent += 1
        self._emit_store_byte("$buf", "$write_pos", 45)  # '-'
        self._emit_inc("$write_pos", 1)
        self._write("i32.const 0")
        self._write("local.get $exp_value")
        self._write("i32.sub")
        self._write("local.set $exp_abs")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._emit_store_byte("$buf", "$write_pos", 43)  # '+'
        self._emit_inc("$write_pos", 1)
        self._write("local.get $exp_value")
        self._write("local.set $exp_abs")
        self._indent -= 1
        self._write("end")
        # Always emit at least 2 digits (Python's str(float) for
        # scientific does ``e+16`` not ``e+016``; but min digit
        # count is 2). For 3-digit exponents the hundreds digit is
        # emitted only when present. We always emit tens + units.
        # if exp_abs >= 100: hundreds digit
        self._write("local.get $exp_abs")
        self._write("i32.const 100")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $exp_abs")
        self._write("i32.const 100")
        self._write("i32.div_s")
        self._write("i32.const 48")
        self._write("i32.add")
        self._write("i32.store8")
        self._emit_inc("$write_pos", 1)
        self._write("local.get $exp_abs")
        self._write("i32.const 100")
        self._write("i32.rem_s")
        self._write("local.set $exp_abs")
        self._indent -= 1
        self._write("end")
        # tens digit
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $exp_abs")
        self._write("i32.const 10")
        self._write("i32.div_s")
        self._write("i32.const 48")
        self._write("i32.add")
        self._write("i32.store8")
        self._emit_inc("$write_pos", 1)
        # units digit
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $exp_abs")
        self._write("i32.const 10")
        self._write("i32.rem_s")
        self._write("i32.const 48")
        self._write("i32.add")
        self._write("i32.store8")
        self._emit_inc("$write_pos", 1)
        # Return.
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Unreachable: both branches returned.
        self._write("unreachable")
        self._indent -= 1
        self._write(")")

    # ----- ftoa small helpers ------------------------------------

    def _emit_static_literal(self, text: str) -> None:
        """Push (ptr, len) for a static string literal interned in
        the data segment. Used by ``$ftoa`` for ``"nan"`` /
        ``"inf"`` / ``"-inf"`` / ``"0.0"`` / ``"-0.0"`` so the
        function returns a real pointer into static memory, not a
        fresh allocation.

        Special-case strings are pre-interned in the dispatcher's
        ``_uses_float_format`` branch before any function body is
        emitted; this helper just looks up the offset and writes
        two ``i32.const`` instructions."""
        offset, length = self._intern_string(text)
        self._write(f"i32.const {offset}")
        self._write(f"i32.const {length}")

    def _emit_store_byte(self, buf_local: str, pos_local: str, byte: int) -> None:
        """Emit ``buf[pos] = byte`` as three opcodes. Shared by
        the decimal / scientific formatters."""
        self._write(f"local.get {buf_local}")
        self._write(f"local.get {pos_local}")
        self._write("i32.add")
        self._write(f"i32.const {byte}")
        self._write("i32.store8")

    def _emit_inc(self, local: str, n: int) -> None:
        """Emit ``local += n``."""
        self._write(f"local.get {local}")
        self._write(f"i32.const {n}")
        self._write("i32.add")
        self._write(f"local.set {local}")

    def _emit_inc_by_local(self, dst_local: str, by_local: str) -> None:
        """Emit ``dst += by``."""
        self._write(f"local.get {dst_local}")
        self._write(f"local.get {by_local}")
        self._write("i32.add")
        self._write(f"local.set {dst_local}")

    def _emit_memcopy_digits(self) -> None:
        """Emit ``memory.copy(buf + write_pos, digits_ptr,
        digits_len)``. Pulled out because both case A and the
        n<=0 case emit this exact three-arg copy."""
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $digits_ptr")
        self._write("local.get $digits_len")
        self._write("memory.copy")

