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
    (0x88fcf317f22241e2, 588, 196),
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
    (0xbf21e44003acdd2d, 933, 300),
    (0x8e679c2f5e44ff8f, 960, 308),
    (0xd433179d9c8cb841, 986, 316),
    (0x9e19db92b4e31ba9, 1013, 324),
    (0xeb96bf6ebadf77d9, 1039, 332),
    (0xaf87023b9bf0ee6b, 1066, 340),
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

    def _emit_grisu_round_weed_function(self) -> None:
        """``$grisu_round_weed(buf, count, dist_too_high, unsafe,
        rest, ten_kappa, unit) -> i32``: the final last-digit nudge
        of Grisu (double-conversion's ``RoundWeed``) PLUS the Grisu3
        confidence flag. Audit C1 (2026-06-09): the original WAT
        port omitted this step, which is why ``${100.0/7.0}`` came
        out ``14.285714285714287`` (one ulp high) instead of
        Python's ``14.285714285714286``. F2 (2026-06-09): the step
        now returns whether Grisu produced a PROVABLY shortest
        result (``ok``); when it cannot, ``$grisu2`` reports failure
        and ``$ftoa`` falls back to the exact Dragon4 path.

        Direct transliteration of ``tools/float_ref.py::_round_weed``.
        Two windows bracket the true value:
        ``small_distance = dist_too_high - unit`` (definitely inside)
        and ``big_distance = dist_too_high + unit`` (possibly
        outside). The last digit is pulled down while it stays within
        ``small_distance``; if it could ALSO be pulled within
        ``big_distance`` the interval is ambiguous and we return 0
        (failure). Otherwise the digit string is provably shortest
        iff ``2*unit <= rest <= unsafe - 4*unit``.

        All seven params are passed on the operand stack:
        - ``buf`` (i32): digits buffer base pointer.
        - ``count`` (i32): number of digits written (>= 1).
        - ``dist_too_high`` (i64): ``Wp_f - Wf``, scaled by the same
          power of ten as ``rest`` / ``ten_kappa`` at the call site.
        - ``unsafe`` (i64): ``delta`` (``Wp_f - Wm_f``), scaled to
          match.
        - ``rest`` (i64): the unconsumed remainder at the exit point.
        - ``ten_kappa`` (i64): the value of one last-digit step in
          the same scaled units.

        Line-by-line port of the validated Python reference
        (``round_weed`` in the oracle): while
        ``rest < dist_too_high`` and ``unsafe - rest >= ten_kappa``
        and (``rest + ten_kappa < dist_too_high`` or
        ``dist_too_high - rest >= rest + ten_kappa - dist_too_high``):
        decrement the last digit, ``rest += ten_kappa``. All
        comparisons are unsigned i64.

        The ~0.5% of values this cannot prove shortest are caught by
        the success flag below and routed to the exact Dragon4
        fallback (``$dragon4``) in ``$ftoa``; F2 (2026-06-10) landed
        that fallback, so the formerly-xfail residual is now
        repr-exact.

        - ``unit`` (i64): the accumulated rounding error of the
          scaled boundaries in the current digit's units (1 at the
          integer-loop exit, multiplied by 10 each fractional step).
          Drives the Grisu3 confidence windows."""
        self._write(
            "(func $grisu_round_weed "
            "(param $buf i32) (param $count i32) "
            "(param $dist_too_high i64) (param $unsafe i64) "
            "(param $rest i64) (param $ten_kappa i64) (param $unit i64) "
            "(result i32)"
        )
        self._indent += 1
        self._write("(local $last_ptr i32)")
        self._write("(local $cond i32)")
        self._write("(local $small_distance i64)")
        self._write("(local $big_distance i64)")
        # last_ptr = buf + count - 1 (the digit RoundWeed mutates).
        self._write("local.get $buf")
        self._write("local.get $count")
        self._write("i32.add")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $last_ptr")
        # small_distance = dist_too_high - unit
        self._write("local.get $dist_too_high")
        self._write("local.get $unit")
        self._write("i64.sub")
        self._write("local.set $small_distance")
        # big_distance = dist_too_high + unit
        self._write("local.get $dist_too_high")
        self._write("local.get $unit")
        self._write("i64.add")
        self._write("local.set $big_distance")
        self._block_counter += 1
        rwloop = f"$grw{self._block_counter}_loop"
        rwexit = f"$grw{self._block_counter}_exit"
        self._write(f"block {rwexit}")
        self._indent += 1
        self._write(f"loop {rwloop}")
        self._indent += 1
        # Guard 1: rest < small_distance  (else exit).
        self._write("local.get $rest")
        self._write("local.get $small_distance")
        self._write("i64.ge_u")
        self._write(f"br_if {rwexit}")
        # Guard 2: unsafe - rest >= ten_kappa  (else exit).
        self._write("local.get $unsafe")
        self._write("local.get $rest")
        self._write("i64.sub")
        self._write("local.get $ten_kappa")
        self._write("i64.lt_u")
        self._write(f"br_if {rwexit}")
        # Guard 3 (closeness): rest + ten_kappa < small_distance
        #   OR  small_distance - rest >= (rest+ten_kappa) - small_distance
        # cond = (rest + ten_kappa < small_distance)
        self._write("local.get $rest")
        self._write("local.get $ten_kappa")
        self._write("i64.add")
        self._write("local.get $small_distance")
        self._write("i64.lt_u")
        self._write("local.set $cond")
        # if !cond: cond = (small_distance - rest) >= ((rest+ten_kappa) - small_distance)
        self._write("local.get $cond")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # lhs = small_distance - rest
        self._write("local.get $small_distance")
        self._write("local.get $rest")
        self._write("i64.sub")
        # rhs = (rest + ten_kappa) - small_distance
        self._write("local.get $rest")
        self._write("local.get $ten_kappa")
        self._write("i64.add")
        self._write("local.get $small_distance")
        self._write("i64.sub")
        self._write("i64.ge_u")
        self._write("local.set $cond")
        self._indent -= 1
        self._write("end")
        # if !cond: exit.
        self._write("local.get $cond")
        self._write("i32.eqz")
        self._write(f"br_if {rwexit}")
        # Body: *last_ptr -= 1 ; rest += ten_kappa.
        self._write("local.get $last_ptr")
        self._write("local.get $last_ptr")
        self._write("i32.load8_u")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.store8")
        self._write("local.get $rest")
        self._write("local.get $ten_kappa")
        self._write("i64.add")
        self._write("local.set $rest")
        self._write(f"br {rwloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Ambiguity gate (Grisu3): if the last digit could ALSO be
        # pulled within the OUTER window (big_distance), Grisu cannot
        # prove which string is shortest -> return 0 (failure).
        #   if rest < big_distance
        #      and unsafe - rest >= ten_kappa
        #      and (rest + ten_kappa < big_distance
        #           or big_distance - rest > (rest+ten_kappa) - big_distance):
        #       return 0
        # cond accumulates the conjunction.
        # cond = rest < big_distance
        self._write("local.get $rest")
        self._write("local.get $big_distance")
        self._write("i64.lt_u")
        self._write("local.set $cond")
        # cond = cond && (unsafe - rest >= ten_kappa)
        self._write("local.get $cond")
        self._write("local.get $unsafe")
        self._write("local.get $rest")
        self._write("i64.sub")
        self._write("local.get $ten_kappa")
        self._write("i64.ge_u")
        self._write("i32.and")
        self._write("local.set $cond")
        # inner = (rest + ten_kappa < big_distance)
        #         || (big_distance - rest > (rest+ten_kappa) - big_distance)
        # Only evaluated when cond still true; fold via i32.and.
        self._write("local.get $cond")
        self._write("if")
        self._indent += 1
        # cond_inner = rest + ten_kappa < big_distance
        self._write("local.get $rest")
        self._write("local.get $ten_kappa")
        self._write("i64.add")
        self._write("local.get $big_distance")
        self._write("i64.lt_u")
        self._write("local.set $cond")
        # if !cond_inner: cond = (big_distance - rest) > ((rest+ten_kappa) - big_distance)
        self._write("local.get $cond")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $big_distance")
        self._write("local.get $rest")
        self._write("i64.sub")
        self._write("local.get $rest")
        self._write("local.get $ten_kappa")
        self._write("i64.add")
        self._write("local.get $big_distance")
        self._write("i64.sub")
        self._write("i64.gt_u")
        self._write("local.set $cond")
        self._indent -= 1
        self._write("end")
        # if cond: ambiguous -> return 0.
        self._write("local.get $cond")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Final slack check: (2*unit) <= rest <= (unsafe - 4*unit).
        # ok = (rest >= 2*unit) && (rest <= unsafe - 4*unit)
        self._write("local.get $rest")
        self._write("local.get $unit")
        self._write("i64.const 1")
        self._write("i64.shl")  # 2*unit
        self._write("i64.ge_u")
        self._write("local.get $rest")
        self._write("local.get $unsafe")
        self._write("local.get $unit")
        self._write("i64.const 2")
        self._write("i64.shl")  # 4*unit
        self._write("i64.sub")
        self._write("i64.le_u")
        self._write("i32.and")
        self._indent -= 1
        self._write(")")

    def _emit_grisu2_function(self) -> None:
        """``$grisu2(v: f64) -> (i32 digits_ptr, i32 digits_len, i32 K,
        i32 ok)``: shortest-round-trip decimal mantissa + decimal
        exponent, with a Grisu3 confidence flag. ``v`` must be
        positive, finite, non-zero; the caller (``$ftoa``) handles
        the special cases. When ``ok`` is 0 the digit string is NOT
        provably shortest and ``$ftoa`` must use the Dragon4 fallback.

        Line-by-line port of the validated Python reference at
        ``tools/float_ref.py::grisu``. See that file's docstring for
        the algorithm summary; comments here flag where i64 / i32
        decomposition diverges from Python's big-int form."""
        self._write(
            "(func $grisu2 (param $v f64) "
            "(result i32 i32 i32 i32)"
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
        # RoundWeed distance: how far the upper boundary Wp sits from
        # W itself. Scaled with delta in the fractional loop so the
        # last-digit nudge compares in consistent units (audit C1).
        self._write("(local $dist_too_high i64)")
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
        # Grisu3 confidence: per-digit rounding-error unit (1 at the
        # integer-loop exit, multiplied by 10 each fractional step)
        # and the success flag returned by $grisu_round_weed.
        self._write("(local $unit i64)")
        self._write("(local $ok i32)")
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
        # dist_too_high = Wp_f - Wf (RoundWeed distance from W).
        self._write("local.get $Wp_f")
        self._write("local.get $Wf")
        self._write("i64.sub")
        self._write("local.set $dist_too_high")
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
        # if rest < delta: RoundWeed, then return (buf, digit_count,
        # kappa - c_dexp). ten_kappa at this exit is div << (-We).
        self._write("local.get $rest")
        self._write("local.get $delta")
        self._write("i64.lt_u")
        self._write("if")
        self._indent += 1
        # ok = $grisu_round_weed(buf, digit_count, dist_too_high,
        #         delta, rest, div << (-We), unit=1)
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $dist_too_high")
        self._write("local.get $delta")
        self._write("local.get $rest")
        self._write("local.get $div")
        self._write("i32.const 0")
        self._write("local.get $We")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.shl")
        self._write("i64.const 1")  # unit = 1
        self._write("call $grisu_round_weed")
        self._write("local.set $ok")
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $kappa")
        self._write("local.get $c_dexp")
        self._write("i32.sub")
        self._write("local.get $ok")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"br {iloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # unit = 1 (scales by 10 each fractional step, like p2/delta).
        self._write("i64.const 1")
        self._write("local.set $unit")
        # Fractional loop: while True.
        self._block_counter += 1
        floop = f"$g2{self._block_counter}_floop"
        fexit = f"$g2{self._block_counter}_fexit"
        self._write(f"block {fexit}")
        self._indent += 1
        self._write(f"loop {floop}")
        self._indent += 1
        # p2 *= 10; delta *= 10; dist_too_high *= 10; unit *= 10 (keep
        # the RoundWeed distance and confidence unit in the same scaled
        # units as delta / p2).
        self._write("local.get $p2")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.set $p2")
        self._write("local.get $delta")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.set $delta")
        self._write("local.get $dist_too_high")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.set $dist_too_high")
        self._write("local.get $unit")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.set $unit")
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
        # if p2 < delta: RoundWeed (ten_kappa = one_f), then return.
        self._write("local.get $p2")
        self._write("local.get $delta")
        self._write("i64.lt_u")
        self._write("if")
        self._indent += 1
        # ok = $grisu_round_weed(buf, digit_count, dist_too_high,
        #         delta, p2, one_f, unit)
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $dist_too_high")
        self._write("local.get $delta")
        self._write("local.get $p2")
        self._write("local.get $one_f")
        self._write("local.get $unit")
        self._write("call $grisu_round_weed")
        self._write("local.set $ok")
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $kappa")
        self._write("local.get $c_dexp")
        self._write("i32.sub")
        self._write("local.get $ok")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # if digit_count >= 18: could not terminate confidently -
        # return ok=0 (mirror of the reference's len>=18 guard).
        self._write("local.get $digit_count")
        self._write("i32.const 18")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("local.get $digit_count")
        self._write("local.get $kappa")
        self._write("local.get $c_dexp")
        self._write("i32.sub")
        self._write("i32.const 0")
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

    # ----- Dragon4 exact fallback (limb bignum) -------------------

    def _emit_wat_block(self, body: str) -> None:
        """Emit a multi-line WAT fragment, one instruction per line,
        at the current indent. WAT's folded control flow does not
        depend on whitespace, so the Dragon4 helpers below are written
        as readable transliterations of the limb-bignum reference
        (``tools/float_ref.py``) rather than as opcode-per-call
        Python. Blank lines and ``#``/``;;`` comment-only lines are
        dropped; trailing ``# ...`` Python-style comments are
        converted to WAT ``;;`` comments."""
        for raw in body.splitlines():
            line = raw.strip()
            # Strip Python-style trailing comments (no WAT operand uses
            # ``#``), then drop blank / comment-only lines.
            hash_at = line.find("#")
            if hash_at != -1:
                line = line[:hash_at].strip()
            if not line:
                continue
            self._write(line)

    def _emit_dragon4_functions(self) -> None:
        """Emit the exact Dragon4 fallback (``$dragon4``) on top of the
        shared limb-bignum helpers. The helpers themselves are emitted
        by ``_emit_bignum_helpers`` (which both the Dragon4 fallback and
        the string-to-float parser depend on); this method emits them if
        they are not already present, then ``$dragon4``."""
        self._emit_bignum_helpers()
        self._emit_dragon4_main()

    def _emit_bignum_helpers(self) -> None:
        """Emit the limb-bignum ``_bn_*`` family once. A faithful
        transliteration of ``tools/float_ref.py``'s ``_bn_*`` helpers.

        BIGNUM LAYOUT. A bignum is an i32 pointer to a buffer from
        ``$alloc``: i32 limb-count at offset 0, then ``count`` 32-bit
        limbs (least significant first) at offsets 4, 8, .... Limbs
        hold values in [0, 2^32). Every operation returns a FRESH
        bignum (the reference's list semantics); inputs are never
        mutated, so aliasing is safe. Buffers are bounded (a few
        hundred limbs for DBL_MAX / smallest subnormal) and never
        freed - the bump allocator just advances.

        HELPERS:
        - ``$bn_alloc(n) -> ptr``   zeroed buffer, count = n
        - ``$bn_norm(a) -> a``      drop high zero limbs in place
        - ``$bn_from_u64(v) -> ptr``
        - ``$bn_cmp(a, b) -> i32``  -1 / 0 / 1
        - ``$bn_add(a, b) -> ptr``
        - ``$bn_sub(a, b) -> ptr``  (a >= b)
        - ``$bn_mul_small(a, m) -> ptr``  (m < 2^32)
        - ``$bn_mul(a, b) -> ptr``  schoolbook
        - ``$bn_shl(a, bits) -> ptr``
        - ``$bn_mul_pow10(a, k) -> ptr``
        - ``$bn_divmod_digit(num, den) -> (i32 q, ptr rem)``
        - ``$bn_bitlen(a) -> i32``   bit length (0 for zero)
        - ``$bn_to_u64(a) -> i64``   value of a <= 64-bit bignum
        - ``$bn_divmod_full(num, den) -> (ptr q, ptr rem)``
        """
        if self._bignum_helpers_emitted:
            return
        self._bignum_helpers_emitted = True
        # $bn_alloc(n) -> ptr : 4 + n*4 bytes, count=n, limbs zeroed.
        self._emit_wat_block(
            """
            (func $bn_alloc (param $n i32) (result i32)
              (local $ptr i32)
              (local $i i32)
              local.get $n
              i32.const 1
              i32.add
              i32.const 2
              i32.shl                 # (n+1) * 4 bytes
              call $alloc
              local.set $ptr
              local.get $ptr
              local.get $n
              i32.store               # count = n
              # zero the n limbs
              i32.const 0
              local.set $i
              block $bz_exit
                loop $bz_loop
                  local.get $i
                  local.get $n
                  i32.ge_s
                  br_if $bz_exit
                  local.get $ptr
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add               # &limb[i]
                  i32.const 0
                  i32.store
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $bz_loop
                end
              end
              local.get $ptr
            )
            """
        )
        # $bn_norm(a) -> a : shrink count while top limb is zero (keep
        # at least one limb).
        self._emit_wat_block(
            """
            (func $bn_norm (param $a i32) (result i32)
              (local $count i32)
              local.get $a
              i32.load
              local.set $count
              block $bn_exit
                loop $bn_loop
                  local.get $count
                  i32.const 1
                  i32.le_s
                  br_if $bn_exit          # keep >= 1 limb
                  # if limb[count-1] != 0: break
                  local.get $a
                  local.get $count
                  i32.const 2
                  i32.shl                 # count*4 == &limb[count-1] + 4? -> offset (count)*4
                  i32.add                 # a + count*4 == &limb[count-1]
                  i32.load
                  i32.const 0
                  i32.ne
                  br_if $bn_exit
                  local.get $count
                  i32.const 1
                  i32.sub
                  local.set $count
                  br $bn_loop
                end
              end
              local.get $a
              local.get $count
              i32.store
              local.get $a
            )
            """
        )
        # $bn_from_u64(v) -> ptr : 1 or 2 limbs.
        self._emit_wat_block(
            """
            (func $bn_from_u64 (param $v i64) (result i32)
              (local $ptr i32)
              (local $hi i64)
              local.get $v
              i64.const 32
              i64.shr_u
              local.set $hi
              local.get $hi
              i64.eqz
              if (result i32)
                i32.const 1
                call $bn_alloc
              else
                i32.const 2
                call $bn_alloc
              end
              local.set $ptr
              # limb[0] = v & 0xFFFFFFFF
              local.get $ptr
              i32.const 4
              i32.add
              local.get $v
              i32.wrap_i64
              i32.store
              local.get $hi
              i64.eqz
              i32.eqz
              if
                local.get $ptr
                i32.const 8
                i32.add
                local.get $hi
                i32.wrap_i64
                i32.store
              end
              local.get $ptr
            )
            """
        )
        # $bn_cmp(a, b) -> i32 : -1 / 0 / 1.
        self._emit_wat_block(
            """
            (func $bn_cmp (param $a i32) (param $b i32) (result i32)
              (local $ca i32)
              (local $cb i32)
              (local $i i32)
              (local $va i32)
              (local $vb i32)
              local.get $a
              i32.load
              local.set $ca
              local.get $b
              i32.load
              local.set $cb
              local.get $ca
              local.get $cb
              i32.ne
              if
                local.get $ca
                local.get $cb
                i32.lt_s
                if
                  i32.const -1
                  return
                end
                i32.const 1
                return
              end
              # equal length: compare from most significant limb down.
              local.get $ca
              i32.const 1
              i32.sub
              local.set $i
              block $cmp_exit
                loop $cmp_loop
                  local.get $i
                  i32.const 0
                  i32.lt_s
                  br_if $cmp_exit
                  local.get $a
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  local.set $va
                  local.get $b
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  local.set $vb
                  local.get $va
                  local.get $vb
                  i32.ne
                  if
                    local.get $va
                    local.get $vb
                    i32.lt_u
                    if
                      i32.const -1
                      return
                    end
                    i32.const 1
                    return
                  end
                  local.get $i
                  i32.const 1
                  i32.sub
                  local.set $i
                  br $cmp_loop
                end
              end
              i32.const 0
            )
            """
        )
        # $bn_add(a, b) -> ptr : limb-wise with carry.
        self._emit_wat_block(
            """
            (func $bn_add (param $a i32) (param $b i32) (result i32)
              (local $ca i32)
              (local $cb i32)
              (local $n i32)
              (local $out i32)
              (local $i i32)
              (local $s i64)
              (local $carry i64)
              local.get $a
              i32.load
              local.set $ca
              local.get $b
              i32.load
              local.set $cb
              # n = max(ca, cb)
              local.get $ca
              local.get $cb
              i32.gt_s
              if (result i32)
                local.get $ca
              else
                local.get $cb
              end
              local.set $n
              # out has n+1 limbs to hold the final carry.
              local.get $n
              i32.const 1
              i32.add
              call $bn_alloc
              local.set $out
              i64.const 0
              local.set $carry
              i32.const 0
              local.set $i
              block $add_exit
                loop $add_loop
                  local.get $i
                  local.get $n
                  i32.ge_s
                  br_if $add_exit
                  # s = a[i] + b[i] + carry
                  local.get $i
                  local.get $ca
                  i32.lt_s
                  if (result i64)
                    local.get $a
                    local.get $i
                    i32.const 1
                    i32.add
                    i32.const 2
                    i32.shl
                    i32.add
                    i32.load
                    i64.extend_i32_u
                  else
                    i64.const 0
                  end
                  local.get $i
                  local.get $cb
                  i32.lt_s
                  if (result i64)
                    local.get $b
                    local.get $i
                    i32.const 1
                    i32.add
                    i32.const 2
                    i32.shl
                    i32.add
                    i32.load
                    i64.extend_i32_u
                  else
                    i64.const 0
                  end
                  i64.add
                  local.get $carry
                  i64.add
                  local.set $s
                  # out[i] = s & 0xFFFFFFFF
                  local.get $out
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get $s
                  i32.wrap_i64
                  i32.store
                  # carry = s >> 32
                  local.get $s
                  i64.const 32
                  i64.shr_u
                  local.set $carry
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $add_loop
                end
              end
              # out[n] = carry (the extra limb)
              local.get $out
              local.get $n
              i32.const 1
              i32.add
              i32.const 2
              i32.shl
              i32.add
              local.get $carry
              i32.wrap_i64
              i32.store
              local.get $out
              call $bn_norm
            )
            """
        )
        # $bn_sub(a, b) -> ptr : a - b for a >= b, limb-wise borrow.
        self._emit_wat_block(
            """
            (func $bn_sub (param $a i32) (param $b i32) (result i32)
              (local $ca i32)
              (local $cb i32)
              (local $out i32)
              (local $i i32)
              (local $d i64)
              (local $borrow i64)
              local.get $a
              i32.load
              local.set $ca
              local.get $b
              i32.load
              local.set $cb
              local.get $ca
              call $bn_alloc
              local.set $out
              i64.const 0
              local.set $borrow
              i32.const 0
              local.set $i
              block $sub_exit
                loop $sub_loop
                  local.get $i
                  local.get $ca
                  i32.ge_s
                  br_if $sub_exit
                  # d = a[i] - b[i] - borrow   (as signed i64)
                  local.get $a
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  i64.extend_i32_u
                  local.get $i
                  local.get $cb
                  i32.lt_s
                  if (result i64)
                    local.get $b
                    local.get $i
                    i32.const 1
                    i32.add
                    i32.const 2
                    i32.shl
                    i32.add
                    i32.load
                    i64.extend_i32_u
                  else
                    i64.const 0
                  end
                  i64.sub
                  local.get $borrow
                  i64.sub
                  local.set $d
                  # if d < 0: d += 2^32; borrow = 1 else borrow = 0
                  local.get $d
                  i64.const 0
                  i64.lt_s
                  if
                    local.get $d
                    i64.const 0x100000000
                    i64.add
                    local.set $d
                    i64.const 1
                    local.set $borrow
                  else
                    i64.const 0
                    local.set $borrow
                  end
                  # out[i] = d & 0xFFFFFFFF
                  local.get $out
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get $d
                  i32.wrap_i64
                  i32.store
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $sub_loop
                end
              end
              local.get $out
              call $bn_norm
            )
            """
        )
        # $bn_mul_small(a, m) -> ptr : a * m, m in [0, 2^32).
        self._emit_wat_block(
            """
            (func $bn_mul_small (param $a i32) (param $m i64) (result i32)
              (local $ca i32)
              (local $out i32)
              (local $i i32)
              (local $p i64)
              (local $carry i64)
              local.get $a
              i32.load
              local.set $ca
              # result needs at most ca + 2 limbs (carry can be 2 limbs).
              local.get $ca
              i32.const 2
              i32.add
              call $bn_alloc
              local.set $out
              i64.const 0
              local.set $carry
              i32.const 0
              local.set $i
              block $ms_exit
                loop $ms_loop
                  local.get $i
                  local.get $ca
                  i32.ge_s
                  br_if $ms_exit
                  # p = a[i] * m + carry
                  local.get $a
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  i64.extend_i32_u
                  local.get $m
                  i64.mul
                  local.get $carry
                  i64.add
                  local.set $p
                  # out[i] = p & 0xFFFFFFFF
                  local.get $out
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get $p
                  i32.wrap_i64
                  i32.store
                  # carry = p >> 32
                  local.get $p
                  i64.const 32
                  i64.shr_u
                  local.set $carry
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $ms_loop
                end
              end
              # Spill remaining carry across the extra limbs.
              block $msc_exit
                loop $msc_loop
                  local.get $carry
                  i64.eqz
                  br_if $msc_exit
                  local.get $out
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get $carry
                  i32.wrap_i64
                  i32.store
                  local.get $carry
                  i64.const 32
                  i64.shr_u
                  local.set $carry
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $msc_loop
                end
              end
              local.get $out
              call $bn_norm
            )
            """
        )
        # $bn_mul(a, b) -> ptr : schoolbook, 32x32->64 partials.
        self._emit_wat_block(
            """
            (func $bn_mul (param $a i32) (param $b i32) (result i32)
              (local $ca i32)
              (local $cb i32)
              (local $out i32)
              (local $i i32)
              (local $j i32)
              (local $k i32)
              (local $ai i64)
              (local $p i64)
              (local $carry i64)
              local.get $a
              i32.load
              local.set $ca
              local.get $b
              i32.load
              local.set $cb
              local.get $ca
              local.get $cb
              i32.add
              call $bn_alloc          # ca + cb limbs, zeroed
              local.set $out
              i32.const 0
              local.set $i
              block $mo_exit
                loop $mo_loop
                  local.get $i
                  local.get $ca
                  i32.ge_s
                  br_if $mo_exit
                  i64.const 0
                  local.set $carry
                  local.get $a
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  i64.extend_i32_u
                  local.set $ai
                  i32.const 0
                  local.set $j
                  block $mi_exit
                    loop $mi_loop
                      local.get $j
                      local.get $cb
                      i32.ge_s
                      br_if $mi_exit
                      # p = ai*b[j] + out[i+j] + carry
                      local.get $ai
                      local.get $b
                      local.get $j
                      i32.const 1
                      i32.add
                      i32.const 2
                      i32.shl
                      i32.add
                      i32.load
                      i64.extend_i32_u
                      i64.mul
                      local.get $out
                      local.get $i
                      local.get $j
                      i32.add
                      i32.const 1
                      i32.add
                      i32.const 2
                      i32.shl
                      i32.add
                      i32.load
                      i64.extend_i32_u
                      i64.add
                      local.get $carry
                      i64.add
                      local.set $p
                      # out[i+j] = p & 0xFFFFFFFF
                      local.get $out
                      local.get $i
                      local.get $j
                      i32.add
                      i32.const 1
                      i32.add
                      i32.const 2
                      i32.shl
                      i32.add
                      local.get $p
                      i32.wrap_i64
                      i32.store
                      local.get $p
                      i64.const 32
                      i64.shr_u
                      local.set $carry
                      local.get $j
                      i32.const 1
                      i32.add
                      local.set $j
                      br $mi_loop
                    end
                  end
                  # propagate carry into out[i+cb], out[i+cb+1], ...
                  local.get $i
                  local.get $cb
                  i32.add
                  local.set $k
                  block $mc_exit
                    loop $mc_loop
                      local.get $carry
                      i64.eqz
                      br_if $mc_exit
                      local.get $out
                      local.get $k
                      i32.const 1
                      i32.add
                      i32.const 2
                      i32.shl
                      i32.add
                      i32.load
                      i64.extend_i32_u
                      local.get $carry
                      i64.add
                      local.set $p
                      local.get $out
                      local.get $k
                      i32.const 1
                      i32.add
                      i32.const 2
                      i32.shl
                      i32.add
                      local.get $p
                      i32.wrap_i64
                      i32.store
                      local.get $p
                      i64.const 32
                      i64.shr_u
                      local.set $carry
                      local.get $k
                      i32.const 1
                      i32.add
                      local.set $k
                      br $mc_loop
                    end
                  end
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $mo_loop
                end
              end
              local.get $out
              call $bn_norm
            )
            """
        )
        # $bn_shl(a, bits) -> ptr : whole-limb + intra-limb shift.
        self._emit_wat_block(
            """
            (func $bn_shl (param $a i32) (param $bits i32) (result i32)
              (local $ca i32)
              (local $limb_shift i32)
              (local $bit_shift i32)
              (local $out i32)
              (local $n i32)
              (local $i i32)
              (local $v i64)
              (local $carry i64)
              local.get $a
              i32.load
              local.set $ca
              local.get $bits
              i32.const 32
              i32.div_u
              local.set $limb_shift
              local.get $bits
              i32.const 32
              i32.rem_u
              local.set $bit_shift
              # out has ca + limb_shift + 1 limbs (room for intra-limb carry)
              local.get $ca
              local.get $limb_shift
              i32.add
              i32.const 1
              i32.add
              local.set $n
              local.get $n
              call $bn_alloc
              local.set $out
              # copy a into out shifted up by limb_shift limbs, with the
              # intra-limb shift folded in.
              i64.const 0
              local.set $carry
              i32.const 0
              local.set $i
              block $shl_exit
                loop $shl_loop
                  local.get $i
                  local.get $ca
                  i32.ge_s
                  br_if $shl_exit
                  # v = (a[i] << bit_shift) | carry
                  local.get $a
                  local.get $i
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  i64.extend_i32_u
                  local.get $bit_shift
                  i64.extend_i32_u
                  i64.shl
                  local.get $carry
                  i64.or
                  local.set $v
                  # out[i+limb_shift] = v & 0xFFFFFFFF
                  local.get $out
                  local.get $i
                  local.get $limb_shift
                  i32.add
                  i32.const 1
                  i32.add
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get $v
                  i32.wrap_i64
                  i32.store
                  # carry = v >> 32
                  local.get $v
                  i64.const 32
                  i64.shr_u
                  local.set $carry
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $shl_loop
                end
              end
              # final carry limb
              local.get $out
              local.get $ca
              local.get $limb_shift
              i32.add
              i32.const 1
              i32.add
              i32.const 2
              i32.shl
              i32.add
              local.get $carry
              i32.wrap_i64
              i32.store
              local.get $out
              call $bn_norm
            )
            """
        )
        # $bn_mul_pow10(a, k) -> ptr : repeated *10^9 then *10^r.
        self._emit_wat_block(
            """
            (func $bn_mul_pow10 (param $a i32) (param $k i32) (result i32)
              (local $cur i32)
              local.get $a
              local.set $cur
              block $p10_exit
                loop $p10_loop
                  local.get $k
                  i32.const 9
                  i32.lt_s
                  br_if $p10_exit
                  local.get $cur
                  i64.const 1000000000
                  call $bn_mul_small
                  local.set $cur
                  local.get $k
                  i32.const 9
                  i32.sub
                  local.set $k
                  br $p10_loop
                end
              end
              local.get $k
              i32.const 0
              i32.gt_s
              if
                local.get $cur
                local.get $k
                call $pow10_i32
                i64.extend_i32_u
                call $bn_mul_small
                local.set $cur
              end
              local.get $cur
            )
            """
        )
        # $bn_divmod_digit(num, den) -> (q, rem) : repeated subtraction,
        # at most 9 iterations (num < 10*den at the call site).
        self._emit_wat_block(
            """
            (func $bn_divmod_digit (param $num i32) (param $den i32) (result i32 i32)
              (local $q i32)
              (local $cur i32)
              local.get $num
              local.set $cur
              i32.const 0
              local.set $q
              block $dd_exit
                loop $dd_loop
                  local.get $cur
                  local.get $den
                  call $bn_cmp
                  i32.const 0
                  i32.lt_s
                  br_if $dd_exit          # cur < den -> stop
                  local.get $cur
                  local.get $den
                  call $bn_sub
                  local.set $cur
                  local.get $q
                  i32.const 1
                  i32.add
                  local.set $q
                  br $dd_loop
                end
              end
              local.get $q
              local.get $cur
            )
            """
        )
        # $bn_bitlen(a) -> i32 : bit length (0 for zero). Top limb's
        # bit length (32 - clz) plus 32 per lower limb.
        self._emit_wat_block(
            """
            (func $bn_bitlen (param $a i32) (result i32)
              (local $count i32)
              (local $top i32)
              local.get $a
              i32.load
              local.set $count
              # zero bignum: single limb == 0 -> bitlen 0
              local.get $a
              i32.const 4
              i32.add
              i32.load
              i32.eqz
              local.get $count
              i32.const 1
              i32.eq
              i32.and
              if
                i32.const 0
                return
              end
              # top = limb[count-1]
              local.get $a
              local.get $count
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.set $top
              # 32 - clz(top) + 32*(count-1)
              i32.const 32
              local.get $top
              i32.clz
              i32.sub
              local.get $count
              i32.const 1
              i32.sub
              i32.const 5
              i32.shl
              i32.add
            )
            """
        )
        # $bn_to_u64(a) -> i64 : value of a bignum known to fit in 64
        # bits (limb[0] | limb[1] << 32).
        self._emit_wat_block(
            """
            (func $bn_to_u64 (param $a i32) (result i64)
              (local $count i32)
              (local $v i64)
              local.get $a
              i32.load
              local.set $count
              local.get $a
              i32.const 4
              i32.add
              i32.load
              i64.extend_i32_u
              local.set $v
              local.get $count
              i32.const 1
              i32.gt_s
              if
                local.get $a
                i32.const 8
                i32.add
                i32.load
                i64.extend_i32_u
                i64.const 32
                i64.shl
                local.get $v
                i64.or
                local.set $v
              end
              local.get $v
            )
            """
        )
        # $bn_divmod_full(num, den) -> (q, rem) with num == q*den + rem,
        # 0 <= rem < den. Binary long division: align den by shifting up
        # to the bit-length gap, then subtract-and-shift down. q stays
        # small (< 2^54) at every call site. Transliteration of
        # ``tools/float_ref.py::_bn_divmod_full``.
        self._emit_wat_block(
            """
            (func $bn_divmod_full (param $num i32) (param $den i32) (result i32 i32)
              (local $shift i32)
              (local $q i32)
              (local $rem i32)
              (local $ds i32)
              (local $s i32)
              # if num < den: q = 0, rem = num
              local.get $num
              local.get $den
              call $bn_cmp
              i32.const 0
              i32.lt_s
              if
                i32.const 1
                call $bn_alloc
                local.get $num
                return
              end
              # shift = bitlen(num) - bitlen(den)
              local.get $num
              call $bn_bitlen
              local.get $den
              call $bn_bitlen
              i32.sub
              local.set $shift
              # if (den << shift) > num: shift -= 1
              local.get $den
              local.get $shift
              call $bn_shl
              local.get $num
              call $bn_cmp
              i32.const 0
              i32.gt_s
              if
                local.get $shift
                i32.const 1
                i32.sub
                local.set $shift
              end
              # q = 0 ; rem = num
              i32.const 1
              call $bn_alloc
              local.set $q
              local.get $num
              local.set $rem
              local.get $shift
              local.set $s
              block $df_exit
                loop $df_loop
                  local.get $s
                  i32.const 0
                  i32.lt_s
                  br_if $df_exit
                  # ds = den << s
                  local.get $den
                  local.get $s
                  call $bn_shl
                  local.set $ds
                  # if rem >= ds: rem -= ds ; q += (1 << s)
                  local.get $rem
                  local.get $ds
                  call $bn_cmp
                  i32.const 0
                  i32.ge_s
                  if
                    local.get $rem
                    local.get $ds
                    call $bn_sub
                    local.set $rem
                    local.get $q
                    i64.const 1
                    call $bn_from_u64
                    local.get $s
                    call $bn_shl
                    call $bn_add
                    local.set $q
                  end
                  local.get $s
                  i32.const 1
                  i32.sub
                  local.set $s
                  br $df_loop
                end
              end
              local.get $q
              call $bn_norm
              local.get $rem
              call $bn_norm
            )
            """
        )
        # $bn_from_digits(start, end) -> ptr : bignum from the ASCII
        # decimal digits in the byte range [start, end), Horner over
        # limbs (bn = bn*10 + digit). The span may straddle a single '.'
        # (the integer/fraction join); any non-digit byte is skipped so
        # the significand stays exact. Mirrors
        # tools/float_ref.py::_bn_from_str over the concatenated digits.
        self._emit_wat_block(
            """
            (func $bn_from_digits (param $start i32) (param $end i32) (result i32)
              (local $a i32)
              (local $p i32)
              (local $byte i32)
              i32.const 1
              call $bn_alloc
              local.set $a
              local.get $start
              local.set $p
              block $bd_exit
                loop $bd_loop
                  local.get $p
                  local.get $end
                  i32.ge_u
                  br_if $bd_exit
                  local.get $p
                  i32.load8_u
                  local.set $byte
                  # skip non-digits (the '.' separator).
                  local.get $byte
                  i32.const 48
                  i32.ge_u
                  local.get $byte
                  i32.const 57
                  i32.le_u
                  i32.and
                  if
                    # a = a*10 + (byte - 48)
                    local.get $a
                    i64.const 10
                    call $bn_mul_small
                    local.get $byte
                    i32.const 48
                    i32.sub
                    i64.extend_i32_u
                    call $bn_from_u64
                    call $bn_add
                    local.set $a
                  end
                  local.get $p
                  i32.const 1
                  i32.add
                  local.set $p
                  br $bd_loop
                end
              end
              local.get $a
            )
            """
        )
        # $bn_ratio_to_f64(num, den, neg) -> (f64 value, i32 overflow) :
        # round the exact positive rational num/den (den > 0) to the
        # nearest f64, ties to even, applying the sign $neg. Returns
        # overflow = 1 (value f64 unused) when the magnitude exceeds
        # DBL_MAX. Faithful transliteration of
        # tools/float_ref.py::_round_bignum_ratio_to_f64 +
        # _assemble_f64 / _assemble_subnormal_bits.
        self._emit_wat_block(
            """
            (func $bn_ratio_to_f64 (param $num i32) (param $den i32) (param $neg i32) (result f64 i32)
              (local $e i32)
              (local $E i32)
              (local $snum i32)
              (local $sden i32)
              (local $q i32)
              (local $rem i32)
              (local $two52 i32)
              (local $two53 i32)
              (local $qi i64)
              (local $cmp i32)
              (local $twice i32)
              (local $bits i64)
              (local $biased i64)
              (local $frac i64)
              (local $drop i32)
              (local $kept i64)
              (local $low i64)
              (local $half i64)
              (local $roundup i32)
              # two52 / two53 constants as bignums.
              i64.const 1
              call $bn_from_u64
              i32.const 52
              call $bn_shl
              local.set $two52
              i64.const 1
              call $bn_from_u64
              i32.const 53
              call $bn_shl
              local.set $two53
              # e = bitlen(num) - bitlen(den) - 53
              local.get $num
              call $bn_bitlen
              local.get $den
              call $bn_bitlen
              i32.sub
              i32.const 53
              i32.sub
              local.set $e
              # initial scaling
              %SCALE%
              # refine e so q has exactly 53 bits.
              block $rf_exit
                loop $rf_loop
                  local.get $snum
                  local.get $sden
                  call $bn_divmod_full
                  local.set $rem
                  local.set $q
                  local.get $q
                  local.get $two52
                  call $bn_cmp
                  i32.const 0
                  i32.lt_s
                  if
                    local.get $e
                    i32.const 1
                    i32.sub
                    local.set $e
                    %SCALE%
                    br $rf_loop
                  end
                  local.get $q
                  local.get $two53
                  call $bn_cmp
                  i32.const 0
                  i32.ge_s
                  if
                    local.get $e
                    i32.const 1
                    i32.add
                    local.set $e
                    %SCALE%
                    br $rf_loop
                  end
                  br $rf_exit
                end
              end
              # q in [2^52, 2^53); E = 52 + e.
              local.get $q
              call $bn_to_u64
              local.set $qi
              i32.const 52
              local.get $e
              i32.add
              local.set $E
              # ---- Subnormal regime: E < -1022. ----
              local.get $E
              i32.const -1022
              i32.lt_s
              if
                # drop = -1022 - E
                i32.const -1022
                local.get $E
                i32.sub
                local.set $drop
                local.get $drop
                i32.const 54
                i32.ge_s
                if
                  i64.const -9223372036854775808   # -0.0 bits
                  i64.const 0                       # +0.0 bits
                  local.get $neg
                  select
                  f64.reinterpret_i64
                  i32.const 0
                  return
                end
                # kept = qi >> drop ; low = qi & ((1<<drop)-1)
                local.get $qi
                local.get $drop
                i64.extend_i32_u
                i64.shr_u
                local.set $kept
                local.get $qi
                i64.const 1
                local.get $drop
                i64.extend_i32_u
                i64.shl
                i64.const 1
                i64.sub
                i64.and
                local.set $low
                # half = 1 << (drop-1)
                i64.const 1
                local.get $drop
                i32.const 1
                i32.sub
                i64.extend_i32_u
                i64.shl
                local.set $half
                # roundup?
                local.get $low
                local.get $half
                i64.gt_u
                if
                  i32.const 1
                  local.set $roundup
                else
                  local.get $low
                  local.get $half
                  i64.eq
                  if
                    # tie at the q grid: remainder breaks it.
                    local.get $rem
                    i32.const 4
                    i32.add
                    i32.load           # rem limb[0]
                    local.get $rem
                    i32.load            # rem count
                    i32.const 1
                    i32.gt_s
                    i32.or              # rem != 0  (count>1 or limb0!=0)
                    if
                      i32.const 1
                      local.set $roundup
                    else
                      local.get $kept
                      i64.const 1
                      i64.and
                      i64.const 1
                      i64.eq
                      if
                        i32.const 1
                        local.set $roundup
                      end
                    end
                  end
                end
                local.get $roundup
                if
                  local.get $kept
                  i64.const 1
                  i64.add
                  local.set $kept
                end
                # bits = kept (exp field 0; carry into bit52 -> normal).
                # OR in the sign bit when negative.
                local.get $kept
                i64.const -9223372036854775808   # 1<<63
                i64.const 0
                local.get $neg
                select
                i64.or
                f64.reinterpret_i64
                i32.const 0
                return
              end
              # ---- Normal regime: round 53-bit mantissa half-even. ----
              # twice_rem = rem << 1 ; cmp vs sden
              local.get $rem
              i32.const 1
              call $bn_shl
              local.set $twice
              local.get $twice
              local.get $sden
              call $bn_cmp
              local.set $cmp
              # roundup = cmp>0 || (cmp==0 && (qi&1)==1)
              local.get $cmp
              i32.const 0
              i32.gt_s
              local.get $cmp
              i32.eqz
              local.get $qi
              i64.const 1
              i64.and
              i64.const 1
              i64.eq
              i32.and
              i32.or
              if
                local.get $qi
                i64.const 1
                i64.add
                local.set $qi
                # carry 2^53-1 -> 2^53: halve, e += 1.
                local.get $qi
                i64.const 9007199254740992    # 2^53
                i64.eq
                if
                  local.get $qi
                  i64.const 1
                  i64.shr_u
                  local.set $qi
                  local.get $e
                  i32.const 1
                  i32.add
                  local.set $e
                  i32.const 52
                  local.get $e
                  i32.add
                  local.set $E
                end
              end
              # overflow past DBL_MAX: E > 1023.
              local.get $E
              i32.const 1023
              i32.gt_s
              if
                f64.const 0
                i32.const 1
                return
              end
              # bits = ((E+1023)<<52) | (qi - 2^52) | sign
              local.get $E
              i32.const 1023
              i32.add
              i64.extend_i32_u
              i64.const 52
              i64.shl
              local.get $qi
              i64.const 4503599627370496     # 2^52
              i64.sub
              i64.or
              i64.const -9223372036854775808
              i64.const 0
              local.get $neg
              select
              i64.or
              f64.reinterpret_i64
              i32.const 0
            )
            """.replace("%SCALE%", self._bn_ratio_scale_fragment())
        )

    def _bn_ratio_scale_fragment(self) -> str:
        """WAT fragment for ``$bn_ratio_to_f64``: set ``$snum`` /
        ``$sden`` from ``$num`` / ``$den`` and the current ``$e``. When
        ``e >= 0`` shift the denominator up by ``e``; otherwise shift the
        numerator up by ``-e`` (so the quotient folds in ``2^-e``)."""
        return """
            local.get $e
            i32.const 0
            i32.ge_s
            if
              local.get $num
              local.set $snum
              local.get $den
              local.get $e
              call $bn_shl
              local.set $sden
            else
              local.get $num
              i32.const 0
              local.get $e
              i32.sub
              call $bn_shl
              local.set $snum
              local.get $den
              local.set $sden
            end
        """

    def _emit_dragon4_main(self) -> None:
        """``$dragon4(v: f64) -> (i32 digits_ptr, i32 len, i32 K)``:
        exact shortest free-format formatting (Steele and White /
        Burger and Dubois) using only the limb-bignum helpers above.
        ``v`` must be positive, finite, non-zero. Returns the ASCII
        digit string and decimal exponent K such that value ==
        int(digits) * 10^K. Faithful transliteration of
        ``tools/float_ref.py::dragon4``."""
        self._emit_wat_block(
            """
            (func $dragon4 (param $v f64) (result i32 i32 i32)
              (local $bits i64)
              (local $biased i32)
              (local $mant i64)
              (local $f i64)
              (local $e i32)
              (local $even i32)
              (local $low_ok i32)
              (local $high_ok i32)
              (local $unequal i32)
              (local $R i32)
              (local $S i32)
              (local $Mp i32)
              (local $Mm i32)
              (local $scale i32)
              (local $k i32)
              (local $e2 i32)
              (local $blen i32)
              (local $prod i64)
              (local $big i32)
              (local $too_small i32)
              (local $digits i32)
              (local $dcount i32)
              (local $d i32)
              (local $tmp i32)
              (local $c i32)
              (local $tc1 i32)
              (local $tc2 i32)
              # ---- decompose v into f * 2^e (hidden bit folded in) ----
              local.get $v
              i64.reinterpret_f64
              local.set $bits
              local.get $bits
              i64.const 52
              i64.shr_u
              i64.const 0x7FF
              i64.and
              i32.wrap_i64
              local.set $biased
              local.get $bits
              i64.const 0x000FFFFFFFFFFFFF
              i64.and
              local.set $mant
              local.get $biased
              i32.eqz
              if
                local.get $mant
                local.set $f
                i32.const -1074
                local.set $e
              else
                local.get $mant
                i64.const 0x0010000000000000
                i64.or
                local.set $f
                local.get $biased
                i32.const 1075
                i32.sub
                local.set $e
              end
              # even = (f & 1) == 0 ; low_ok = high_ok = even
              local.get $f
              i64.const 1
              i64.and
              i64.eqz
              local.set $even
              local.get $even
              local.set $low_ok
              local.get $even
              local.set $high_ok
              # unequal_gap = (mant == 0) && (biased > 1)
              local.get $mant
              i64.eqz
              local.get $biased
              i32.const 1
              i32.gt_s
              i32.and
              local.set $unequal
              # ---- set up R / S / Mp / Mm ----
              local.get $e
              i32.const 0
              i32.ge_s
              if
                # e >= 0
                local.get $unequal
                i32.eqz
                if
                  # R = (f * 2^e) << 1 ; S = 2 ; Mp = Mm = 2^e
                  local.get $f
                  call $bn_from_u64
                  i32.const 1
                  call $bn_shl
                  local.get $e
                  call $bn_shl
                  local.set $R
                  i64.const 2
                  call $bn_from_u64
                  local.set $S
                  i64.const 1
                  call $bn_from_u64
                  local.get $e
                  call $bn_shl
                  local.set $Mp
                  local.get $Mp
                  local.set $Mm
                else
                  # R = (f * 2^(e+1)) << 1 ; S = 4 ; Mp = 2^(e+1) ; Mm = 2^e
                  local.get $f
                  call $bn_from_u64
                  i32.const 1
                  call $bn_shl
                  local.get $e
                  i32.const 1
                  i32.add
                  call $bn_shl
                  local.set $R
                  i64.const 4
                  call $bn_from_u64
                  local.set $S
                  i64.const 1
                  call $bn_from_u64
                  local.get $e
                  i32.const 1
                  i32.add
                  call $bn_shl
                  local.set $Mp
                  i64.const 1
                  call $bn_from_u64
                  local.get $e
                  call $bn_shl
                  local.set $Mm
                end
              else
                # e < 0
                local.get $unequal
                i32.eqz
                if
                  # R = f << 1 ; S = 1 << (1 - e) ; Mp = Mm = 1
                  local.get $f
                  call $bn_from_u64
                  i32.const 1
                  call $bn_shl
                  local.set $R
                  i64.const 1
                  call $bn_from_u64
                  i32.const 1
                  local.get $e
                  i32.sub
                  call $bn_shl
                  local.set $S
                  i64.const 1
                  call $bn_from_u64
                  local.set $Mp
                  i64.const 1
                  call $bn_from_u64
                  local.set $Mm
                else
                  # R = f << 2 ; S = 1 << (2 - e) ; Mp = 2 ; Mm = 1
                  local.get $f
                  call $bn_from_u64
                  i32.const 2
                  call $bn_shl
                  local.set $R
                  i64.const 1
                  call $bn_from_u64
                  i32.const 2
                  local.get $e
                  i32.sub
                  call $bn_shl
                  local.set $S
                  i64.const 2
                  call $bn_from_u64
                  local.set $Mp
                  i64.const 1
                  call $bn_from_u64
                  local.set $Mm
                end
              end
              # ---- estimate k = ceil(log10(value)) via fixed point ----
              # bit_length(f): blen = 64 - clz(f)
              i32.const 64
              local.get $f
              i64.clz
              i32.wrap_i64
              i32.sub
              local.set $blen
              # e2 = (blen - 1) + e  == floor(log2(value))
              local.get $blen
              i32.const 1
              i32.sub
              local.get $e
              i32.add
              local.set $e2
              # k = ceil((e2 + 1) * log10(2))   (log10(2) ~ 1292913986/2^32)
              # use prod = (e2 + 1) * 1292913986 ; k = ceil(prod / 2^32)
              local.get $e2
              i32.const 1
              i32.add
              i64.extend_i32_s
              i64.const 1292913986
              i64.mul
              local.set $prod
              # k = floor; then +1 if remainder != 0 (ceil)
              local.get $prod
              i64.const 32
              i64.shr_s
              i32.wrap_i64
              local.get $prod
              local.get $prod
              i64.const 32
              i64.shr_s
              i64.const 32
              i64.shl
              i64.sub
              i64.const 0
              i64.ne
              i32.add
              local.set $k
              # ---- scale by 10^k ----
              local.get $k
              i32.const 0
              i32.ge_s
              if
                local.get $S
                local.get $k
                call $bn_mul_pow10
                local.set $S
              else
                i64.const 1
                call $bn_from_u64
                i32.const 0
                local.get $k
                i32.sub
                call $bn_mul_pow10
                local.set $scale
                local.get $R
                local.get $scale
                call $bn_mul
                local.set $R
                local.get $Mp
                local.get $scale
                call $bn_mul
                local.set $Mp
                local.get $Mm
                local.get $scale
                call $bn_mul
                local.set $Mm
              end
              # ---- fixup: too-small loop (leading digit would be 0) ----
              block $ts_exit
                loop $ts_loop
                  # big = (R*10) + (Mp*10)
                  local.get $R
                  i64.const 10
                  call $bn_mul_small
                  local.get $Mp
                  i64.const 10
                  call $bn_mul_small
                  call $bn_add
                  local.set $big
                  # too_small = high_ok ? big <= S : big < S
                  local.get $big
                  local.get $S
                  call $bn_cmp
                  local.set $c
                  local.get $high_ok
                  if (result i32)
                    local.get $c
                    i32.const 0
                    i32.le_s
                  else
                    local.get $c
                    i32.const 0
                    i32.lt_s
                  end
                  local.set $too_small
                  local.get $too_small
                  i32.eqz
                  br_if $ts_exit
                  local.get $R
                  i64.const 10
                  call $bn_mul_small
                  local.set $R
                  local.get $Mp
                  i64.const 10
                  call $bn_mul_small
                  local.set $Mp
                  local.get $Mm
                  i64.const 10
                  call $bn_mul_small
                  local.set $Mm
                  local.get $k
                  i32.const 1
                  i32.sub
                  local.set $k
                  br $ts_loop
                end
              end
              # ---- fixup: too-large loop (leading digit would be >= 10) ----
              block $tl_exit
                loop $tl_loop
                  # high_over = high_ok ? (R+Mp >= S) : (R+Mp > S)
                  local.get $R
                  local.get $Mp
                  call $bn_add
                  local.get $S
                  call $bn_cmp
                  local.set $c
                  local.get $high_ok
                  if (result i32)
                    local.get $c
                    i32.const 0
                    i32.ge_s
                  else
                    local.get $c
                    i32.const 0
                    i32.gt_s
                  end
                  i32.eqz
                  br_if $tl_exit
                  local.get $S
                  i64.const 10
                  call $bn_mul_small
                  local.set $S
                  local.get $k
                  i32.const 1
                  i32.add
                  local.set $k
                  br $tl_loop
                end
              end
              # ---- digit generation ----
              i32.const 32
              call $alloc
              local.set $digits
              i32.const 0
              local.set $dcount
              block $gen_exit
                loop $gen_loop
                  # R *= 10 ; Mp *= 10 ; Mm *= 10
                  local.get $R
                  i64.const 10
                  call $bn_mul_small
                  local.set $R
                  local.get $Mp
                  i64.const 10
                  call $bn_mul_small
                  local.set $Mp
                  local.get $Mm
                  i64.const 10
                  call $bn_mul_small
                  local.set $Mm
                  # (d, R) = divmod_digit(R, S)
                  local.get $R
                  local.get $S
                  call $bn_divmod_digit
                  local.set $R
                  local.set $d
                  # tc1: low boundary. c_low = cmp(R, Mm)
                  local.get $R
                  local.get $Mm
                  call $bn_cmp
                  local.set $c
                  local.get $low_ok
                  if (result i32)
                    local.get $c
                    i32.const 0
                    i32.le_s
                  else
                    local.get $c
                    i32.const 0
                    i32.lt_s
                  end
                  local.set $tc1
                  # tc2: high boundary. c_high = cmp(R + Mp, S)
                  local.get $R
                  local.get $Mp
                  call $bn_add
                  local.get $S
                  call $bn_cmp
                  local.set $c
                  local.get $high_ok
                  if (result i32)
                    local.get $c
                    i32.const 0
                    i32.ge_s
                  else
                    local.get $c
                    i32.const 0
                    i32.gt_s
                  end
                  local.set $tc2
                  # if not tc1 and not tc2: append d, continue
                  local.get $tc1
                  i32.eqz
                  local.get $tc2
                  i32.eqz
                  i32.and
                  if
                    local.get $digits
                    local.get $dcount
                    i32.add
                    local.get $d
                    i32.const 48
                    i32.add
                    i32.store8
                    local.get $dcount
                    i32.const 1
                    i32.add
                    local.set $dcount
                    br $gen_loop
                  end
                  # terminate: choose final digit.
                  # if tc2 and not tc1: d += 1
                  local.get $tc2
                  local.get $tc1
                  i32.eqz
                  i32.and
                  if
                    local.get $d
                    i32.const 1
                    i32.add
                    local.set $d
                  else
                    # if tc1 and tc2: round on 2*R vs S
                    local.get $tc1
                    local.get $tc2
                    i32.and
                    if
                      local.get $R
                      i32.const 1
                      call $bn_shl
                      local.get $S
                      call $bn_cmp
                      local.set $c
                      # if c > 0 or (c == 0 and d odd): d += 1
                      local.get $c
                      i32.const 0
                      i32.gt_s
                      local.get $c
                      i32.eqz
                      local.get $d
                      i32.const 1
                      i32.and
                      i32.and
                      i32.or
                      if
                        local.get $d
                        i32.const 1
                        i32.add
                        local.set $d
                      end
                    end
                  end
                  local.get $digits
                  local.get $dcount
                  i32.add
                  local.get $d
                  i32.const 48
                  i32.add
                  i32.store8
                  local.get $dcount
                  i32.const 1
                  i32.add
                  local.set $dcount
                  br $gen_exit
                end
              end
              # return (digits, dcount, k - dcount)
              local.get $digits
              local.get $dcount
              local.get $k
              local.get $dcount
              i32.sub
            )
            """
        )

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
        self._write("(local $ok i32)")
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
        # (digits_ptr, digits_len, K, ok) = grisu2(abs)
        self._write("local.get $abs")
        self._write("call $grisu2")
        self._write("local.set $ok")
        self._write("local.set $K")
        self._write("local.set $digits_len")
        self._write("local.set $digits_ptr")
        # Grisu3 fallback: if not provably shortest, recompute the
        # digit string exactly with Dragon4. Both paths feed the same
        # (digits_ptr, digits_len, K) shape into the spelling layer.
        self._write("local.get $ok")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $abs")
        self._write("call $dragon4")
        self._write("local.set $K")
        self._write("local.set $digits_len")
        self._write("local.set $digits_ptr")
        self._indent -= 1
        self._write("end")
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

