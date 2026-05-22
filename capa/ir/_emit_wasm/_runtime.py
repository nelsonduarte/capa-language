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
        returns the current heap_top and advances it by the
        requested size aligned to 8 bytes. No free, no GC; this is
        the simplest correct allocator and matches Phase 6C's
        no-collections scope. A later phase that adds growth or
        compaction replaces this implementation.

        Exported so host bridges (capa:host/env etc.) can allocate
        Option / Result wrappers in linear memory before handing
        them back to the wasm code."""
        self._write('(func $alloc (export "alloc") (param $size i32) (result i32)')
        self._indent += 1
        self._write("(local $ret i32)")
        # Align $heap_top up to 8 bytes before returning.
        self._write("global.get $heap_top")
        self._write("i32.const 7")
        self._write("i32.add")
        self._write("i32.const -8")
        self._write("i32.and")
        self._write("local.tee $ret")
        self._write("local.get $size")
        self._write("i32.add")
        self._write("global.set $heap_top")
        self._write("local.get $ret")
        self._indent -= 1
        self._write(")")
