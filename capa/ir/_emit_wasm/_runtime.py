"""Runtime-helper emission mixin.

Owns the four self-contained Wasm helper functions every emitted
module ships with:

- ``$alloc(size: i32) -> i32`` -- 8-byte-aligned bump allocator,
  exported so host bridges can construct Option/Result wrappers.
- ``$str_eq(p1, l1, p2, l2) -> i32`` -- byte-by-byte string
  equality, used by Map's String-keyed linear scan.
- ``$itoa(n: i64) -> (i32 ptr, i32 len)`` -- decimal integer
  formatting for ``${int}`` interpolation.
- ``$ftoa(f: f64) -> (i32 ptr, i32 len)`` -- fixed-6-decimal float
  formatting for ``${float}`` interpolation.

These are pure emission methods: they only call ``self._write``
and read/bump ``self._block_counter`` / ``self._indent``. Splitting
them into a mixin removes ~400 lines from ``__init__.py`` without
touching control flow.
"""

from __future__ import annotations

import struct


# -------------------------------------------------------------
# Grisu2 cached powers of 10
# -------------------------------------------------------------
#
# 87 entries spanning decimal exponents [-348, 340] in steps of 8.
# Each entry is the normalised DiyFp representation of 10^k with a
# 64-bit significand whose top bit is set. ``binary_exp`` is the
# exponent applied to ``significand`` (10^k ~ significand * 2^bexp).
# ``decimal_exp`` is k, the decimal exponent the entry represents.
#
# The numerical constants are standard across every Grisu2
# implementation in the wild (Loitsch 2010, Google's double-
# conversion, Rust's libcore::num::flt2dec) and are not derived
# from anything in this codebase. They are immutable and would
# never need to change.
#
# Memory layout (little-endian, 12 bytes per entry):
#   offset 0: u64 significand
#   offset 8: i16 binary_exp
#   offset 10: i16 decimal_exp
_CACHED_POWERS: list[tuple[int, int, int]] = [
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

# Pre-pack as little-endian bytes so the WAT data segment can
# emit the table verbatim. 12 bytes per entry; 87 * 12 = 1044.
_CACHED_POWERS_BYTES: bytes = b"".join(
    struct.pack("<Qhh", sig, bexp, dexp)
    for sig, bexp, dexp in _CACHED_POWERS
)
_CACHED_POWERS_TABLE_BYTES: int = len(_CACHED_POWERS_BYTES)
# Standard Grisu2 constant: the lowest decimal exponent the table
# covers. ``index = (k_minus_e_minus_63_in_decimal + 348) / 8``
# shifts the lookup so entry 0 is 10^-348.
_CACHED_POWERS_OFFSET_K: int = 348
# Decimal-exponent step between adjacent table entries.
_CACHED_POWERS_STEP: int = 8


class _RuntimeHelpersMixin:
    def _emit_str_eq_function(self) -> None:
        """Helper: ``$str_eq(p1: i32, l1: i32, p2: i32, l2: i32) -> i32``
        returns 1 if the two byte slices are equal, 0 otherwise.
        Length mismatch is the fast-path no-match; the byte-by-byte
        compare loops only when lengths match.

        Used by Map.set / Map.get / Map.contains_key to identify
        the matching slot in the linear-scan key array."""
        self._write(
            "(func $str_eq (param $p1 i32) (param $l1 i32) "
            "(param $p2 i32) (param $l2 i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        # Length mismatch: return 0.
        self._write("local.get $l1")
        self._write("local.get $l2")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Byte-by-byte loop.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("block $eq_exit (result i32)")
        self._indent += 1
        self._write("loop $eq_loop")
        self._indent += 1
        # if i >= l1: exit with 1.
        self._write("local.get $i")
        self._write("local.get $l1")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("br $eq_exit")
        self._indent -= 1
        self._write("end")
        # Load byte from p1+i and p2+i, compare.
        self._write("local.get $p1")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $p2")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_exit")
        self._indent -= 1
        self._write("end")
        # i += 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $eq_loop")
        self._indent -= 1
        self._write("end")
        # Wasm's stack type checker wants a value at every path's
        # exit; the loop never falls through (every iteration ends
        # with either ``br $eq_exit`` or ``br $eq_loop``) but the
        # verifier cannot prove that. Mark the fall-through as
        # unreachable so the block's i32 result type is satisfied.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_itoa_function(self) -> None:
        """Helper: ``$itoa(n: i64) -> (i32 ptr, i32 len)`` writes
        the decimal representation of ``n`` into freshly-allocated
        heap memory and returns its (ptr, len). Handles negative
        numbers with a leading ``-``; max output is 21 bytes
        (``-9223372036854775808`` is 20 chars + sign), so we always
        reserve 32 to leave room for a future hex prefix.

        Algorithm: write digits backwards into a scratch buffer at
        the top of the alloc, then memory.copy them forward into a
        tight result buffer. The two-step approach keeps the loop
        trivial; the cost is one extra alloc + copy per int."""
        self._write("(func $itoa (param $n i64) (result i32 i32)")
        self._indent += 1
        self._write("(local $abs i64)")
        self._write("(local $neg i32)")
        self._write("(local $buf i32)")
        self._write("(local $i i32)")
        self._write("(local $digit i32)")
        self._write("(local $ret_ptr i32)")
        self._write("(local $ret_len i32)")
        # Allocate 32-byte scratch buffer.
        self._write("i32.const 32")
        self._write("call $alloc")
        self._write("local.set $buf")
        # Handle sign.
        self._write("local.get $n")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $neg")
        self._write("i64.const 0")
        self._write("local.get $n")
        self._write("i64.sub")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $n")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("end")
        # Write digits backwards into buf+31, buf+30, ... at index $i.
        # $i tracks how many digits we wrote.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        loop = f"$itoa{self._block_counter}_loop"
        exit_ = f"$itoa{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # digit = abs % 10
        self._write("local.get $abs")
        self._write("i64.const 10")
        self._write("i64.rem_u")
        self._write("i32.wrap_i64")
        self._write("local.set $digit")
        # buf[31 - i] = '0' + digit
        self._write("local.get $buf")
        self._write("i32.const 31")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $digit")
        self._write("i32.const 48")    # '0'
        self._write("i32.add")
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        # abs /= 10
        self._write("local.get $abs")
        self._write("i64.const 10")
        self._write("i64.div_u")
        self._write("local.tee $abs")
        # if abs == 0: exit.
        self._write("i64.eqz")
        self._write(f"br_if {exit_}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Optionally prepend '-'.
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        # Write '-' at buf[31 - i] -- the slot just before the
        # lowest-order digit written at buf[32 - i]. The returned
        # slice is buf[32 - (i+1)..32] = buf[31 - i..32], so this
        # position lies inside the result. Without the correction
        # the '-' lands at buf[30 - i], outside the slice.
        self._write("local.get $buf")
        self._write("i32.const 31")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.const 45")    # '-'
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._indent -= 1
        self._write("end")
        # ret_ptr = buf + 32 - i; ret_len = i. Return (ret_ptr, ret_len).
        self._write("local.get $buf")
        self._write("i32.const 32")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $i")
        self._indent -= 1
        self._write(")")

    # ---------------------------------------------------------
    # Grisu2 float-to-string support
    # ---------------------------------------------------------
    #
    # Three helpers below feed the Grisu2 main routine that
    # replaces the legacy fixed-6-decimal ``$ftoa``:
    # the cached-powers-of-10 data segment, a 128-bit unsigned
    # multiply, and the cached-power table lookup. The remaining
    # pieces (``$grisu_digit_gen``, ``$grisu2``, the format
    # dispatch, and the rewritten ``$ftoa``) follow further down.

    def _emit_cached_powers_data(self) -> None:
        """Emit the Grisu2 cached-powers-of-10 table as a
        ``(data ...)`` segment. The 87 entries cover decimal
        exponents [-348, +340] in steps of 8. Layout per entry:
        i64 significand at +0, i16 binary_exp at +8, i16
        decimal_exp at +10. Total 1044 bytes.

        Called from ``WasmEmitter.emit`` after the string-pool
        data segments; ``self._cached_powers_offset`` is the
        base offset in linear memory that was reserved during
        the discovery pass."""
        escaped = "".join(f"\\{b:02x}" for b in _CACHED_POWERS_BYTES)
        self._write(
            f'(data (i32.const {self._cached_powers_offset}) "{escaped}")'
        )

    def _emit_mul_high_u64_function(self) -> None:
        """``$mul_high_u64(a: i64, b: i64) -> i64`` returns the
        high 64 bits of the 128-bit unsigned product. Wasm has no
        native u128, so the 64x64 multiply is composed from four
        32-bit cross products with carry propagation:

            a = a_hi:2^32 + a_lo
            b = b_hi:2^32 + b_lo
            a*b = a_hi*b_hi:2^64
                + (a_hi*b_lo + a_lo*b_hi):2^32
                + a_lo*b_lo

        The intermediate ``tmp`` collects the carry from the
        low-low product plus the low halves of the cross products
        and adds ``1 << 31`` so the final ``tmp >> 32`` round-
        ups halfway cases (matches the reference Grisu2
        ``DiyFp::Times`` rounding).
        """
        self._write("(func $mul_high_u64 (param $a i64) (param $b i64) (result i64)")
        self._indent += 1
        self._write("(local $a_hi i64)")
        self._write("(local $a_lo i64)")
        self._write("(local $b_hi i64)")
        self._write("(local $b_lo i64)")
        self._write("(local $ad i64)")
        self._write("(local $bc i64)")
        self._write("(local $tmp i64)")
        # Split a and b into 32-bit halves.
        self._write("local.get $a")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("local.set $a_hi")
        self._write("local.get $a")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("local.set $a_lo")
        self._write("local.get $b")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("local.set $b_hi")
        self._write("local.get $b")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("local.set $b_lo")
        # ad = a_hi * b_lo
        self._write("local.get $a_hi")
        self._write("local.get $b_lo")
        self._write("i64.mul")
        self._write("local.set $ad")
        # bc = a_lo * b_hi
        self._write("local.get $a_lo")
        self._write("local.get $b_hi")
        self._write("i64.mul")
        self._write("local.set $bc")
        # tmp = (a_lo*b_lo >> 32) + (ad & low32) + (bc & low32)
        #       + 0x80000000  (round-half-up)
        self._write("local.get $a_lo")
        self._write("local.get $b_lo")
        self._write("i64.mul")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("local.get $ad")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("i64.add")
        self._write("local.get $bc")
        self._write("i64.const 0xFFFFFFFF")
        self._write("i64.and")
        self._write("i64.add")
        self._write("i64.const 0x80000000")
        self._write("i64.add")
        self._write("local.set $tmp")
        # result = a_hi*b_hi + (ad >> 32) + (bc >> 32) + (tmp >> 32)
        self._write("local.get $a_hi")
        self._write("local.get $b_hi")
        self._write("i64.mul")
        self._write("local.get $ad")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i64.add")
        self._write("local.get $bc")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i64.add")
        self._write("local.get $tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i64.add")
        self._indent -= 1
        self._write(")")

    def _emit_grisu_cached_power_function(self) -> None:
        """``$grisu_cached_power(e: i32) -> (i64 sig, i32 bexp, i32 dexp)``
        returns the cached power of 10 with binary exponent that,
        combined with the input's binary exponent ``e``, produces
        a product whose binary exponent lies in Grisu2's target
        range [alpha=-59, gamma=-32] after the ``Times``
        operation adds 64.

        Formula:
            k = ceil((-59 - e - 64) * log_10(2))
            index = (k + 348) / 8

        ``k`` is the decimal exponent of the cached power we
        want. The table covers k in [-348, +340] step 8, so
        ``index`` directly addresses the entry. Uses f64 math
        for the multiply-by-log10(2)-then-ceil step; integer
        approximation would need careful tuning to avoid off-
        by-one at boundary inputs.
        """
        self._write(
            "(func $grisu_cached_power (param $e i32) "
            "(result i64 i32 i32)"
        )
        self._indent += 1
        self._write("(local $index i32)")
        self._write("(local $entry_ptr i32)")
        # k = ceil((-59 - e - 64) * log_10(2))
        self._write("i32.const -123")  # -59 - 64
        self._write("local.get $e")
        self._write("i32.sub")
        self._write("f64.convert_i32_s")
        self._write("f64.const 0x1.34413509f79ffp-2")  # log_10(2)
        self._write("f64.mul")
        self._write("f64.ceil")
        self._write("i32.trunc_f64_s")
        # index = (k + 348) / 8
        self._write(f"i32.const {_CACHED_POWERS_OFFSET_K}")
        self._write("i32.add")
        self._write(f"i32.const {_CACHED_POWERS_STEP}")
        self._write("i32.div_s")
        self._write("local.set $index")
        # entry_ptr = base + index * 12
        self._write(f"i32.const {self._cached_powers_offset}")
        self._write("local.get $index")
        self._write("i32.const 12")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.tee $entry_ptr")
        # significand (i64) at offset 0
        self._write("i64.load offset=0")
        # binary_exp (i32) at offset 8 (i16 sign-extended)
        self._write("local.get $entry_ptr")
        self._write("i32.load16_s offset=8")
        # decimal_exp (i32) at offset 10 (i16 sign-extended)
        self._write("local.get $entry_ptr")
        self._write("i32.load16_s offset=10")
        self._indent -= 1
        self._write(")")

    def _emit_ftoa_function(self) -> None:
        """``$ftoa(f: f64) -> (i32 ptr, i32 len)``: format a double
        as ``<int>.<6 decimal digits>`` (with optional leading
        minus). Fixed 6-decimal precision; sufficient for the
        ``${time}`` style interpolation in Capa source. Allocates
        a fresh buffer per call.

        Strategy: separate integer and fractional parts via
        ``f64.trunc``, reuse the existing ``$itoa`` for the
        integer part, then write 6 zero-padded fractional digits
        into the buffer at the trailing positions.
        """
        self._write("(func $ftoa (param $f f64) (result i32 i32)")
        self._indent += 1
        self._write("(local $abs f64)")
        self._write("(local $neg i32)")
        self._write("(local $int_part i64)")
        self._write("(local $frac_int i64)")
        self._write("(local $int_ptr i32)")
        self._write("(local $int_len i32)")
        self._write("(local $buf i32)")
        self._write("(local $write_pos i32)")
        self._write("(local $i i32)")
        self._write("(local $digit i32)")
        # neg = f < 0; abs = neg ? -f : f
        self._write("local.get $f")
        self._write("f64.const 0")
        self._write("f64.lt")
        self._write("local.tee $neg")
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
        # int_part = trunc(abs) as i64
        self._write("local.get $abs")
        self._write("f64.trunc")
        self._write("i64.trunc_f64_u")
        self._write("local.set $int_part")
        # frac_int = (abs - trunc(abs)) * 1_000_000 as i64
        self._write("local.get $abs")
        self._write("local.get $abs")
        self._write("f64.trunc")
        self._write("f64.sub")
        self._write("f64.const 1000000")
        self._write("f64.mul")
        self._write("i64.trunc_f64_u")
        self._write("local.set $frac_int")
        # itoa(int_part) -> (int_ptr, int_len)
        self._write("local.get $int_part")
        self._write("call $itoa")
        self._write("local.set $int_len")
        self._write("local.set $int_ptr")
        # Allocate result buffer = int_len + 1 ('.') + 6 (digits) + 1 ('-')
        self._write("local.get $int_len")
        self._write("i32.const 8")
        self._write("i32.add")
        self._write("call $alloc")
        self._write("local.set $buf")
        # Write '-' if neg, increment write_pos accordingly.
        self._write("i32.const 0")
        self._write("local.set $write_pos")
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("i32.const 45")  # '-'
        self._write("i32.store8")
        self._write("i32.const 1")
        self._write("local.set $write_pos")
        self._indent -= 1
        self._write("end")
        # memory.copy(buf + write_pos, int_ptr, int_len)
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $int_ptr")
        self._write("local.get $int_len")
        self._write("memory.copy")
        # write_pos += int_len
        self._write("local.get $write_pos")
        self._write("local.get $int_len")
        self._write("i32.add")
        self._write("local.set $write_pos")
        # Write '.'
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("i32.const 46")  # '.'
        self._write("i32.store8")
        self._write("local.get $write_pos")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $write_pos")
        # Pre-fill 6 zeros for fractional region, then overwrite
        # right-to-left from frac_int.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        zloop = f"$ftoa{self._block_counter}_zloop"
        zexit = f"$ftoa{self._block_counter}_zexit"
        self._write(f"block {zexit}")
        self._indent += 1
        self._write(f"loop {zloop}")
        self._indent += 1
        self._write("local.get $i")
        self._write("i32.const 6")
        self._write("i32.ge_s")
        self._write(f"br_if {zexit}")
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.const 48")  # '0'
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {zloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Overwrite from frac_int. Each digit goes to
        # buf + write_pos + (5 - i), then frac /= 10, i++ until
        # i == 6 or frac == 0.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        dloop = f"$ftoa{self._block_counter}_dloop"
        dexit = f"$ftoa{self._block_counter}_dexit"
        self._write(f"block {dexit}")
        self._indent += 1
        self._write(f"loop {dloop}")
        self._indent += 1
        self._write("local.get $i")
        self._write("i32.const 6")
        self._write("i32.ge_s")
        self._write(f"br_if {dexit}")
        # digit = frac_int % 10
        self._write("local.get $frac_int")
        self._write("i64.const 10")
        self._write("i64.rem_u")
        self._write("i32.wrap_i64")
        self._write("local.set $digit")
        # buf + write_pos + 5 - i = '0' + digit
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("i32.const 5")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $digit")
        self._write("i32.const 48")
        self._write("i32.add")
        self._write("i32.store8")
        # frac_int /= 10
        self._write("local.get $frac_int")
        self._write("i64.const 10")
        self._write("i64.div_u")
        self._write("local.set $frac_int")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {dloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Return: ptr = buf, len = write_pos + 6
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.const 6")
        self._write("i32.add")
        self._indent -= 1
        self._write(")")

    def _emit_parse_int_function(self) -> None:
        """Emit ``$parse_int(ptr: i32, len: i32) -> i32`` returning
        a freshly-allocated ``Option<Int>`` pointer.

        Algorithm: linear scan, optional leading '-' or '+',
        accumulate digits in i64. On any non-digit (or empty
        input), return None. Otherwise return Some(value).

        Builtin name in source is ``parse_int(s: String) ->
        Option<Int>``; the user-call interceptor routes the bare
        ``parse_int`` to a ``call $parse_int`` against this
        function."""
        self._write(
            "(func $parse_int (param $ptr i32) (param $len i32) "
            "(result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $byte i32)")
        self._write("(local $acc i64)")
        self._write("(local $neg i32)")
        self._write("(local $any i32)")
        self._write("(local $result i32)")
        # alloc Option<Int> result up front (16 bytes).
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $result")
        # Default to None (tag = 1). Filled in below on success.
        self._write("local.get $result")
        self._write("i32.const 1")
        self._write("i32.store")
        # Empty string -> None (already default).
        self._write("local.get $len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Check sign byte.
        self._write("local.get $ptr")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        self._write("local.get $byte")
        self._write("i32.const 45")  # '-'
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $neg")
        self._write("i32.const 1")
        self._write("local.set $i")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $byte")
        self._write("i32.const 43")  # '+'
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $i")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Loop: i in [i, len). Reject non-digit; accumulate.
        self._block_counter += 1
        loop = f"$pi{self._block_counter}_loop"
        exit_ = f"$pi{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if i >= len: break
        self._write("local.get $i")
        self._write("local.get $len")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # byte = ptr[i]
        self._write("local.get $ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        # if byte < '0' or byte > '9': return None.
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.lt_u")
        self._write("local.get $byte")
        self._write("i32.const 57")
        self._write("i32.gt_u")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # acc = acc * 10 + (byte - '0')
        self._write("local.get $acc")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.add")
        self._write("local.set $acc")
        # any = 1; i++
        self._write("i32.const 1")
        self._write("local.set $any")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # If no digits seen at all -> None (sign-only input).
        self._write("local.get $any")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Apply sign.
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        self._write("i64.const 0")
        self._write("local.get $acc")
        self._write("i64.sub")
        self._write("local.set $acc")
        self._indent -= 1
        self._write("end")
        # Some(acc): tag=0, payload i64 at offset 8.
        self._write("local.get $result")
        self._write("i32.const 0")
        self._write("i32.store")
        self._write("local.get $result")
        self._write("local.get $acc")
        self._write("i64.store offset=8")
        self._write("local.get $result")
        self._indent -= 1
        self._write(")")

    def _emit_parse_float_function(self) -> None:
        """Emit ``$parse_float(ptr: i32, len: i32) -> i32``
        returning a freshly-allocated ``Option<Float>`` pointer.

        Algorithm: scan integer part, then optional '.' + fraction.
        Accumulate as f64. Reject malformed input (returns None).
        Doesn't handle scientific notation or hex; the demos that
        need it stick to the canonical ``-12.345`` shape."""
        self._write(
            "(func $parse_float (param $ptr i32) (param $len i32) "
            "(result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $byte i32)")
        self._write("(local $val f64)")
        self._write("(local $frac f64)")
        self._write("(local $neg i32)")
        self._write("(local $any i32)")
        self._write("(local $result i32)")
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $result")
        self._write("local.get $result")
        self._write("i32.const 1")
        self._write("i32.store")
        # Empty -> None.
        self._write("local.get $len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Sign.
        self._write("local.get $ptr")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        self._write("local.get $byte")
        self._write("i32.const 45")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $neg")
        self._write("i32.const 1")
        self._write("local.set $i")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $byte")
        self._write("i32.const 43")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $i")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Integer part.
        self._block_counter += 1
        iloop = f"$pf{self._block_counter}_iloop"
        iexit = f"$pf{self._block_counter}_iexit"
        self._write(f"block {iexit}")
        self._indent += 1
        self._write(f"loop {iloop}")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $len")
        self._write("i32.ge_s")
        self._write(f"br_if {iexit}")
        self._write("local.get $ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        # Decimal point -> break to fraction.
        self._write("local.get $byte")
        self._write("i32.const 46")  # '.'
        self._write("i32.eq")
        self._write(f"br_if {iexit}")
        # Non-digit and not '.': reject.
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.lt_u")
        self._write("local.get $byte")
        self._write("i32.const 57")
        self._write("i32.gt_u")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $val")
        self._write("f64.const 10")
        self._write("f64.mul")
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.sub")
        self._write("f64.convert_i32_u")
        self._write("f64.add")
        self._write("local.set $val")
        self._write("i32.const 1")
        self._write("local.set $any")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {iloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # If we stopped at '.', consume it and parse fraction.
        self._write("local.get $i")
        self._write("local.get $len")
        self._write("i32.lt_s")
        self._write("if")
        self._indent += 1
        # We're at '.'; advance past it.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        # frac multiplier starts at 0.1.
        self._write("f64.const 0.1")
        self._write("local.set $frac")
        self._block_counter += 1
        floop = f"$pf{self._block_counter}_floop"
        fexit = f"$pf{self._block_counter}_fexit"
        self._write(f"block {fexit}")
        self._indent += 1
        self._write(f"loop {floop}")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $len")
        self._write("i32.ge_s")
        self._write(f"br_if {fexit}")
        self._write("local.get $ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.lt_u")
        self._write("local.get $byte")
        self._write("i32.const 57")
        self._write("i32.gt_u")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # val += digit * frac
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.sub")
        self._write("f64.convert_i32_u")
        self._write("local.get $frac")
        self._write("f64.mul")
        self._write("local.get $val")
        self._write("f64.add")
        self._write("local.set $val")
        # frac /= 10
        self._write("local.get $frac")
        self._write("f64.const 10")
        self._write("f64.div")
        self._write("local.set $frac")
        self._write("i32.const 1")
        self._write("local.set $any")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {floop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # No digits at all -> None.
        self._write("local.get $any")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Apply sign.
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        self._write("local.get $val")
        self._write("f64.neg")
        self._write("local.set $val")
        self._indent -= 1
        self._write("end")
        # Some(val).
        self._write("local.get $result")
        self._write("i32.const 0")
        self._write("i32.store")
        self._write("local.get $result")
        self._write("local.get $val")
        self._write("f64.store offset=8")
        self._write("local.get $result")
        self._indent -= 1
        self._write(")")

    def _emit_alloc_function(self) -> None:
        """Emit a bump allocator: ``$alloc(size: i32) -> i32`` that
        returns the current heap_top, aligned to 8, and advances it
        by the requested size. Grows linear memory in 64 KB pages
        when the bump would cross the current ``memory.size``
        boundary; traps via ``unreachable`` if the host refuses to
        grow further. No free, no GC; the simplest allocator that
        survives realistic input sizes.

        Exported so host bridges (capa:host/env etc.) can allocate
        Option / Result wrappers in linear memory before handing
        them back to the wasm code."""
        self._write('(func $alloc (export "alloc") (param $size i32) (result i32)')
        self._indent += 1
        self._write("(local $ret i32)")
        self._write("(local $new_top i32)")
        self._write("(local $needed_pages i32)")
        self._write("(local $cur_pages i32)")
        # ret = align_up(heap_top, 8)
        self._write("global.get $heap_top")
        self._write("i32.const 7")
        self._write("i32.add")
        self._write("i32.const -8")
        self._write("i32.and")
        self._write("local.set $ret")
        # new_top = ret + size
        self._write("local.get $ret")
        self._write("local.get $size")
        self._write("i32.add")
        self._write("local.set $new_top")
        # needed_pages = ceil(new_top / 65536) = (new_top + 65535) >> 16
        self._write("local.get $new_top")
        self._write("i32.const 65535")
        self._write("i32.add")
        self._write("i32.const 16")
        self._write("i32.shr_u")
        self._write("local.set $needed_pages")
        # cur_pages = memory.size
        self._write("memory.size")
        self._write("local.set $cur_pages")
        # if needed_pages > cur_pages: memory.grow(needed_pages - cur_pages)
        self._write("local.get $needed_pages")
        self._write("local.get $cur_pages")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $needed_pages")
        self._write("local.get $cur_pages")
        self._write("i32.sub")
        self._write("memory.grow")
        self._write("i32.const -1")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # heap_top = new_top; return ret
        self._write("local.get $new_top")
        self._write("global.set $heap_top")
        self._write("local.get $ret")
        self._indent -= 1
        self._write(")")

    def _emit_cabi_realloc_function(self) -> None:
        """Emit the ``cabi_realloc`` export the Component Model
        canonical ABI requires. Signature:

            cabi_realloc(old_ptr: i32, old_size: i32, align: i32,
                         new_size: i32) -> i32

        Semantics:
        - ``new_size == 0`` is a free; the bump allocator has no
          free, so return null.
        - Otherwise allocate ``new_size`` bytes and -- if there
          was prior content -- copy ``min(old_size, new_size)``
          bytes from the old location into the new one. The
          alignment argument is observed by ``$alloc`` (which
          aligns to 8 already).

        Required by ``wasm-tools component new`` whenever a host
        import lowering needs to allocate caller-owned memory
        (e.g. the data buffer for a ``list<string>`` result)."""
        self._write(
            '(func $cabi_realloc (export "cabi_realloc") '
            '(param $old_ptr i32) (param $old_size i32) '
            '(param $align i32) (param $new_size i32) (result i32)'
        )
        self._indent += 1
        self._write("(local $new_ptr i32)")
        self._write("(local $copy_size i32)")
        # new_size == 0 -> free path: return null (no real free
        # because the bump allocator has nothing to release).
        self._write("local.get $new_size")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Fresh allocation.
        self._write("local.get $new_size")
        self._write("call $alloc")
        self._write("local.set $new_ptr")
        # If old_ptr != 0 and old_size != 0, copy min(old, new).
        self._write("local.get $old_ptr")
        self._write("i32.const 0")
        self._write("i32.ne")
        self._write("local.get $old_size")
        self._write("i32.const 0")
        self._write("i32.ne")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # copy_size = min(old_size, new_size). The ``if/else``
        # produces an i32 result on both arms, so the block's
        # result type must be annotated; without ``(result i32)``
        # the validator rejects the value on the arm's stack.
        self._write("local.get $old_size")
        self._write("local.get $new_size")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $old_size")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $new_size")
        self._indent -= 1
        self._write("end")
        self._write("local.set $copy_size")
        # memory.copy(dst=new_ptr, src=old_ptr, n=copy_size)
        self._write("local.get $new_ptr")
        self._write("local.get $old_ptr")
        self._write("local.get $copy_size")
        self._write("memory.copy")
        self._indent -= 1
        self._write("end")
        self._write("local.get $new_ptr")
        self._indent -= 1
        self._write(")")
