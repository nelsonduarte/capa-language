"""Runtime-helper emission mixin.

Owns the small self-contained Wasm helper functions every emitted
module ships with:

- ``$alloc(size: i32) -> i32`` -- 8-byte-aligned bump allocator,
  exported so host bridges can construct Option/Result wrappers.
- ``$str_eq(p1, l1, p2, l2) -> i32`` -- byte-by-byte string
  equality, used by Map's String-keyed linear scan.
- ``$itoa(n: i64) -> (i32 ptr, i32 len)`` -- decimal integer
  formatting for ``${int}`` interpolation.
- ``$parse_int``, ``$parse_float`` -- inverse of the toa helpers
  for the Capa-side ``parse_int(s)`` / ``parse_float(s)`` builtins.
- ``$cabi_realloc`` -- the Component Model canonical-ABI realloc
  the host expects from any component import.

``$ftoa`` plus its Grisu2 machinery live in ``_grisu.py`` since
the algorithm alone is ~1100 LOC. The two files share no state
beyond ``self._cached_powers_offset`` and the standard emitter
state set up by ``WasmEmitter.__init__``.
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

    def _emit_str_starts_with_function(self) -> None:
        """Helper: ``$str_starts_with(hp, hl, np, nl) -> i32`` returns
        1 if the haystack ``hp[..hl]`` begins with the needle
        ``np[..nl]``, 0 otherwise. Used by the dynamic-arg
        ``Fs.allows(path)`` / ``Db.allows(path)`` queries: the
        runtime check answers the question without crossing the
        host bridge. The privileged ops (Fs.read / Db.exec / ...)
        moved to the host handle table in slice 25 (2026-05-30);
        the host enforces ``cap.allows(arg)`` from the receiver's
        recorded restriction before each syscall, so no inline
        emit-time check fires for them.

        Empty needle (``nl == 0``) returns 1, mirroring the Python
        ``str.startswith`` semantic. A needle longer than the
        haystack returns 0 (fast path)."""
        self._write(
            "(func $str_starts_with (param $hp i32) (param $hl i32) "
            "(param $np i32) (param $nl i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        # Needle longer than haystack -> 0.
        self._write("local.get $nl")
        self._write("local.get $hl")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Reuse $str_eq on (hp, nl) vs (np, nl) by walking nl bytes.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("block $ssw_exit (result i32)")
        self._indent += 1
        self._write("loop $ssw_loop")
        self._indent += 1
        # if i >= nl: exit with 1.
        self._write("local.get $i")
        self._write("local.get $nl")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("br $ssw_exit")
        self._indent -= 1
        self._write("end")
        # if hp[i] != np[i]: exit with 0.
        self._write("local.get $hp")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $np")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $ssw_exit")
        self._indent -= 1
        self._write("end")
        # i += 1; loop.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $ssw_loop")
        self._indent -= 1
        self._write("end")
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_proc_allows_function(self) -> None:
        """Helper: ``$proc_allows(cp, cl, pp, pl) -> i32`` returns
        1 if the command at ``cp[..cl]`` is admitted by the prefix
        at ``pp[..pl]``, 0 otherwise. Mirrors the Python runtime's
        ``Proc.allows`` rule on the Wasm side so all three backends
        agree on attenuation outcomes for any (cmd, prefix) pair.

        Algorithm:
        - basename = substring of cmd after the last '/'; if cmd
          contains no '/', basename = cmd. Walk from the end so
          we find the LAST slash (e.g. ``/usr/local/bin/git`` ->
          ``git``).
        - Return 1 if basename == prefix OR
          basename.startswith(prefix + '-'). The second arm uses an
          inline byte-by-byte compare against the prefix bytes
          (admitting ``git-lfs`` for prefix ``git``) followed by a
          single ``-`` boundary byte test (rejecting ``gitlab``).

        Used by:
        - ``Proc.allows`` dynamic-arg path. The privileged op
          (``Proc.exec``) moved to the host handle table in
          slice 25.4 (2026-05-30); the host enforces
          ``proc.allows(cmd)`` from the receiver's recorded
          restriction, so no inline emit-time check fires for
          the syscall. Only the guest-side ``.allows(cmd)``
          query still calls this helper."""
        self._write(
            "(func $proc_allows (param $cp i32) (param $cl i32) "
            "(param $pp i32) (param $pl i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")        # scan index
        self._write("(local $bs i32)")       # basename start (cp + offset)
        self._write("(local $bl i32)")       # basename length
        self._write("(local $j i32)")        # byte-cmp index
        # Find the last '/' in cmd. Walk i from cl - 1 down to 0;
        # break on the first match. ``bs`` defaults to cp + 0 (no
        # slash found -> basename = full cmd).
        self._write("local.get $cp")
        self._write("local.set $bs")
        self._write("local.get $cl")
        self._write("local.set $bl")
        self._write("local.get $cl")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $i")
        self._write("block $scan_exit")
        self._indent += 1
        self._write("loop $scan_loop")
        self._indent += 1
        # If i < 0: exit (no slash found, defaults stand).
        self._write("local.get $i")
        self._write("i32.const 0")
        self._write("i32.lt_s")
        self._write("br_if $scan_exit")
        # If cp[i] == '/': basename = cp + i + 1, bl = cl - i - 1; exit.
        self._write("local.get $cp")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")  # '/'
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # bs = cp + i + 1
        self._write("local.get $cp")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $bs")
        # bl = cl - i - 1
        self._write("local.get $cl")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $bl")
        self._write("br $scan_exit")
        self._indent -= 1
        self._write("end")
        # i -= 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $i")
        self._write("br $scan_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Arm 1: basename == prefix via $str_eq(bs, bl, pp, pl).
        self._write("local.get $bs")
        self._write("local.get $bl")
        self._write("local.get $pp")
        self._write("local.get $pl")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Arm 2: basename.startswith(prefix + '-'). Need
        # bl >= pl + 1 AND basename[0..pl] == prefix AND
        # basename[pl] == '-'. Skip the arm if bl < pl + 1.
        self._write("local.get $bl")
        self._write("local.get $pl")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.lt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Byte-by-byte compare basename[0..pl] vs prefix[0..pl].
        self._write("i32.const 0")
        self._write("local.set $j")
        self._write("block $pref_exit")
        self._indent += 1
        self._write("loop $pref_loop")
        self._indent += 1
        # if j >= pl: exit (prefix matched).
        self._write("local.get $j")
        self._write("local.get $pl")
        self._write("i32.ge_s")
        self._write("br_if $pref_exit")
        # if basename[j] != prefix[j]: return 0.
        self._write("local.get $bs")
        self._write("local.get $j")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $pp")
        self._write("local.get $j")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # j += 1; loop.
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $j")
        self._write("br $pref_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Boundary byte: basename[pl] must be '-'.
        self._write("local.get $bs")
        self._write("local.get $pl")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 45")  # '-'
        self._write("i32.eq")
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
        # Overflow check (audit fix C5): before ``acc = acc * 10 +
        # digit``, reject inputs that would push ``acc`` past
        # ``i64::MAX``. Threshold is ``i64::MAX / 10 ==
        # 922337203685477580``; if ``acc`` already exceeds it, the
        # multiply overflows. If ``acc`` equals it and ``digit > 7``,
        # the add overflows. Either case returns None so the Wasm
        # backend mirrors the Python helper's
        # ``-(2**63) <= n < 2**63`` window check; without this the
        # accumulator silently wrapped mod 2^64.
        self._write("local.get $acc")
        self._write("i64.const 922337203685477580")
        self._write("i64.gt_s")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $acc")
        self._write("i64.const 922337203685477580")
        self._write("i64.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $byte")
        self._write("i32.const 55")  # '7'
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
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
        them back to the wasm code.

        Audit H1 (2026-05): the ``memory.grow`` -> ``i32.const -1``
        check below covers the host-refuses-to-grow path. The host
        refuses when the requested page count exceeds the limits
        clause baked into the module's ``(memory ...)`` declaration.
        ``WasmEmitter.__init__(memory_cap_pages=...)`` sets that
        ceiling (default 256 pages = 16 MiB), exposed via the CLI
        as ``--wasm-memory-cap <pages>``. A runaway allocator thus
        traps at the deterministic, source-declared ceiling instead
        of at some host-dependent OOM point."""
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

    def _emit_str_codepoint_count_function(self) -> None:
        """``$str_codepoint_count(p: i32, l: i32) -> i32`` — return
        the number of Unicode code points in the UTF-8 byte slice
        ``[p, p+l)``. Counts bytes whose high bits are NOT
        ``10xxxxxx`` (continuation bytes). Audit fix 2026-05-29
        (post-slice-16): Wasm's ``String.length`` was returning
        the byte count; Python's was returning the code-point
        count. Both backends now agree on code-point semantics."""
        self._write(
            "(func $str_codepoint_count (param $p i32) (param $l i32) "
            "(result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $count i32)")
        self._write("(local $b i32)")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("i32.const 0")
        self._write("local.set $count")
        self._write("block $cp_exit")
        self._indent += 1
        self._write("loop $cp_loop")
        self._indent += 1
        # if i >= l: exit
        self._write("local.get $i")
        self._write("local.get $l")
        self._write("i32.ge_s")
        self._write(f"br_if $cp_exit")
        # b = byte at p+i
        self._write("local.get $p")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $b")
        # if (b & 0xC0) != 0x80: count++ (i.e. not a continuation
        # byte: ASCII 0xxxxxxx or 11xxxxxx leading bytes both count)
        self._write("local.get $b")
        self._write("i32.const 192")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("local.get $count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $count")
        self._indent -= 1
        self._write("end")
        # i++
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br $cp_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write("local.get $count")
        self._indent -= 1
        self._write(")")

    def _emit_str_cp_to_byte_offset_function(self) -> None:
        """``$str_cp_to_byte_offset(p: i32, l: i32, cp_idx: i32)
        -> i32`` — return the byte offset of the ``cp_idx``-th
        code-point boundary in the UTF-8 byte slice ``[p, p+l)``.
        Returns ``l`` if ``cp_idx`` is at or past the end (so the
        caller doesn't need a separate length check; clamps to
        the end naturally).

        Walks the bytes counting code-point starts (bytes NOT in
        ``10xxxxxx``); on the ``cp_idx``-th start it returns the
        current byte offset. If ``cp_idx == 0`` returns 0 (the
        start of the slice is always a code-point boundary by
        definition for valid UTF-8). Audit fix 2026-05-29
        (post-slice-16): Wasm's ``String.substring`` was indexing
        bytes; Python's was indexing code points."""
        self._write(
            "(func $str_cp_to_byte_offset (param $p i32) "
            "(param $l i32) (param $cp_idx i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $count i32)")
        self._write("(local $b i32)")
        # Fast path: cp_idx == 0 returns 0.
        self._write("local.get $cp_idx")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("i32.const 0")
        self._write("local.set $count")
        self._write("block $b2o_exit")
        self._indent += 1
        self._write("loop $b2o_loop")
        self._indent += 1
        # if i >= l: exit (return l as fallback below)
        self._write("local.get $i")
        self._write("local.get $l")
        self._write("i32.ge_s")
        self._write(f"br_if $b2o_exit")
        # b = byte at p+i
        self._write("local.get $p")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $b")
        # if (b & 0xC0) != 0x80: count++; if count == cp_idx,
        # return i.
        self._write("local.get $b")
        self._write("i32.const 192")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("local.get $count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.tee $count")
        self._write("local.get $cp_idx")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # We just stepped onto the cp_idx-th code-point boundary
        # AFTER the byte at position i was its leading byte. The
        # boundary is at i+1's leading byte; walk i forward until
        # we hit either l or the next non-continuation. Easier:
        # return i+1 (since we just passed a leading byte, the
        # next byte is the start of the next code point... unless
        # this codepoint has continuation bytes). Walk past any
        # continuation bytes starting at i+1.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("block $skip_exit")
        self._indent += 1
        self._write("loop $skip_loop")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $l")
        self._write("i32.ge_s")
        self._write(f"br_if $skip_exit")
        self._write("local.get $p")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 192")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.ne")
        self._write(f"br_if $skip_exit")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br $skip_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write("local.get $i")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # i++
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br $b2o_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Fell out: cp_idx past the end. Return l.
        self._write("local.get $l")
        self._indent -= 1
        self._write(")")
