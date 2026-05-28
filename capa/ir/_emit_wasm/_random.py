"""Random capability Wasm emission.

Slice 2 of the "Wasm backend fully functional" arc. The PRNG
algorithm (D1, 2026-05) is **SplitMix64**: one i64 of state, one
mix step per call, byte-identical sequence with the Python
backend's ``capa.runtime._capabilities.Random`` for any given seed.

Everything except entropy lives guest-side:

- ``$rand_state`` (mut i64) holds the current SplitMix64 state.
- ``$rand_state_inited`` (mut i32) is a one-shot init guard so
  ``Random()`` only calls into the host once per module run.
- ``$rand_state_init_if_needed`` lazily draws ``capa:host/random/
  system-seed`` (the sole host import for this capability) the
  first time the state is read. Explicit ``Random().with_seed(s)``
  bypasses the host call entirely: the seed write also flips the
  guard, so an unseeded ``Random()`` constructed *after* a
  ``with_seed`` does not clobber the user's deterministic state.
- ``$rand_next_u64`` (-> i64) runs one SplitMix64 step. The exact
  bit shape mirrors the Python oracle:

      state += 0x9E3779B97F4A7C15
      z  = state
      z ^= z >> 30 ;  z *= 0xBF58476D1CE4E5B9
      z ^= z >> 27 ;  z *= 0x94D049BB133111EB
      z ^= z >> 31
      return z

- ``$rand_int_range`` (low: i64, high: i64) -> i64 uses Lemire-
  style rejection sampling so the distribution is unbiased even
  for non-power-of-two bounds. Bound <= 0 is undefined here; the
  analyzer (with help from the Python runtime) catches the
  ``low >= high`` case before lowering.
- ``$rand_float_unit`` () -> f64 takes the top 53 bits of the
  draw and divides by 2**53 (the standard mantissa trick).

These helpers are emitted at module level (before user functions)
so any function body that lowers a Random method call can refer to
them by name. The discovery walker
(``_uses_random`` in ``_discovery.py``) gates emission so a
program that never touches Random pays no helper-emit or global
cost.

The "with_seed returns a new attenuator" semantic at the Capa
source level maps onto a per-module shared PRNG at the Wasm
level: each ``with_seed`` is a write to ``$rand_state`` and the
guard flip. Multiple Random handles inside one module therefore
share the same state, with "the last seed wins" semantics. This
matches Python's behaviour, which the audit verified: chaining
``Random().with_seed(1).with_seed(2)`` constructs two fresh
instances and the second one's draws are independent of the
first. Since Capa source can't observe two different Random
handles' sequences interleaved (each method call mutates and
returns), the per-module shared state is observably equivalent.
The lone exception would be two distinct Random handles each
seeded then both drawn from -- the Python version isolates them
per-instance, the Wasm version interleaves on one state. A
parity test for that shape lives in
``examples/wasm/random_seeded.capa``; if any future program
relies on per-instance isolation, lift ``$rand_state`` into a
per-handle struct and resolve the dst pointer from the lowered
``Random()`` call.
"""

from __future__ import annotations

from .._nodes import Call, MethodCall
from ._layout import WasmEmissionError


# SplitMix64 magic constants. Repeated here for grep / audit
# visibility; the Python runtime in
# ``capa.runtime._capabilities.Random`` carries the same values
# under different attribute names. The two implementations must
# agree to the bit.
_SPLITMIX_INCREMENT_HEX = "0x9E3779B97F4A7C15"
_SPLITMIX_MIX_1_HEX = "0xBF58476D1CE4E5B9"
_SPLITMIX_MIX_2_HEX = "0x94D049BB133111EB"


class _RandomEmissionMixin:
    def _emit_random_globals_and_helpers(self) -> None:
        """Emit ``$rand_state`` + ``$rand_state_inited`` globals and
        the four SplitMix64 helpers. Called from the WasmEmitter's
        ``emit`` orchestrator only when ``_uses_random`` returns
        True; otherwise an unused PRNG would bloat every module
        with ~80 lines of WAT and force the host to plumb the
        ``system-seed`` import even for programs that don't need
        randomness."""
        # Globals: state (mut i64), inited flag (mut i32).
        self._write("(global $rand_state (mut i64) (i64.const 0))")
        self._write("(global $rand_state_inited (mut i32) (i32.const 0))")
        self._emit_rand_state_init_if_needed()
        self._emit_rand_next_u64()
        self._emit_rand_int_range()
        self._emit_rand_float_unit()

    # ----- helpers ----------------------------------------------

    def _emit_rand_state_init_if_needed(self) -> None:
        """``$rand_state_init_if_needed`` -- no params, no result.

        On first call (``$rand_state_inited == 0``) draws a seed
        from the ``capa:host/random/system-seed`` import, stores
        into ``$rand_state``, and flips the guard. Subsequent
        calls and post-``with_seed`` calls are a single load + br_if
        and return immediately."""
        self._write("(func $rand_state_init_if_needed")
        self._indent += 1
        self._write("global.get $rand_state_inited")
        self._write("if")
        self._indent += 1
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Host gives us a fresh 64-bit seed.
        self._write("call $Random_system_seed")
        self._write("global.set $rand_state")
        self._write("i32.const 1")
        self._write("global.set $rand_state_inited")
        self._indent -= 1
        self._write(")")

    def _emit_rand_next_u64(self) -> None:
        """``$rand_next_u64`` -- () -> i64.

        Runs one SplitMix64 step. Does NOT call init: callers that
        need an initialised state (``$rand_int_range`` /
        ``$rand_float_unit``) call ``$rand_state_init_if_needed``
        first. This split keeps the inner loop in ``$rand_int_range``
        free of a branch on the guard every iteration."""
        self._write("(func $rand_next_u64 (result i64)")
        self._indent += 1
        self._write("(local $z i64)")
        # state += INCREMENT
        self._write("global.get $rand_state")
        self._write(f"i64.const {_SPLITMIX_INCREMENT_HEX}")
        self._write("i64.add")
        self._write("global.set $rand_state")
        # z = state
        self._write("global.get $rand_state")
        self._write("local.set $z")
        # z = (z ^ (z >> 30)) * MIX_1
        self._write("local.get $z")
        self._write("local.get $z")
        self._write("i64.const 30")
        self._write("i64.shr_u")
        self._write("i64.xor")
        self._write(f"i64.const {_SPLITMIX_MIX_1_HEX}")
        self._write("i64.mul")
        self._write("local.set $z")
        # z = (z ^ (z >> 27)) * MIX_2
        self._write("local.get $z")
        self._write("local.get $z")
        self._write("i64.const 27")
        self._write("i64.shr_u")
        self._write("i64.xor")
        self._write(f"i64.const {_SPLITMIX_MIX_2_HEX}")
        self._write("i64.mul")
        self._write("local.set $z")
        # return z ^ (z >> 31)
        self._write("local.get $z")
        self._write("local.get $z")
        self._write("i64.const 31")
        self._write("i64.shr_u")
        self._write("i64.xor")
        self._indent -= 1
        self._write(")")

    def _emit_rand_int_range(self) -> None:
        """``$rand_int_range`` -- (low: i64, high: i64) -> i64.

        Returns a value in ``[low, high)`` matching the Python
        oracle's draws bit-for-bit.

        The Python oracle uses ``limit = (2**64 // bound) * bound``
        and rejects ``rng >= limit``. Naively encoding that in i64
        WAT overflows on power-of-two bounds (``2**64 // 2 * 2 = 2**64``
        which wraps to 0, rejecting every draw). We sidestep the
        overflow by computing the *bias region size* instead:

            bias = 2**64 mod bound = (-bound) mod bound   (unsigned)

        ``bias == 0`` iff ``bound`` divides ``2**64`` (any power of
        two up to ``2**63``); in that case there is no bias region
        and every draw is accepted.

        Otherwise ``limit = 2**64 - bias``, which in i64 wraps to
        ``-bias`` (unsigned). The accept test ``rng < limit`` then
        becomes ``rng < (0 - bias)`` (unsigned compare). Two equivalent
        decisions:

            accept  iff  bias == 0          (the no-rejection path)
            accept  iff  rng < (0 - bias)   (the regular path)

        We fold both into one branchless predicate:

            accept  iff  (bias == 0) | (rng < (0 - bias))

        Result is ``low + (rng % bound)`` once accepted, identical
        to Python's ``low + rng % bound`` because for every accepted
        ``rng`` in the good region [0, limit), ``rng % bound`` is
        uniformly distributed in [0, bound).
        """
        self._write(
            "(func $rand_int_range "
            "(param $low i64) (param $high i64) (result i64)"
        )
        self._indent += 1
        self._write("(local $bound i64)")
        self._write("(local $bias i64)")
        self._write("(local $r i64)")
        # Ensure state is initialised.
        self._write("call $rand_state_init_if_needed")
        # bound = high - low
        self._write("local.get $high")
        self._write("local.get $low")
        self._write("i64.sub")
        self._write("local.set $bound")
        # bias = (0 - bound) % bound  (unsigned). Equivalent to
        # 2**64 mod bound; zero iff bound divides 2**64.
        self._write("i64.const 0")
        self._write("local.get $bound")
        self._write("i64.sub")
        self._write("local.get $bound")
        self._write("i64.rem_u")
        self._write("local.set $bias")
        # Rejection loop. Accept on (bias == 0) | (r < (0 - bias)).
        self._write("block $accept")
        self._indent += 1
        self._write("loop $draw")
        self._indent += 1
        self._write("call $rand_next_u64")
        self._write("local.set $r")
        # No-rejection fast path: bias == 0 means every draw is good.
        self._write("local.get $bias")
        self._write("i64.eqz")
        self._write("br_if $accept")
        # r < (0 - bias) ?
        self._write("local.get $r")
        self._write("i64.const 0")
        self._write("local.get $bias")
        self._write("i64.sub")
        self._write("i64.lt_u")
        self._write("br_if $accept")
        # else: redraw
        self._write("br $draw")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # return low + (r % bound)
        self._write("local.get $low")
        self._write("local.get $r")
        self._write("local.get $bound")
        self._write("i64.rem_u")
        self._write("i64.add")
        self._indent -= 1
        self._write(")")

    def _emit_rand_float_unit(self) -> None:
        """``$rand_float_unit`` -- () -> f64.

        ``(next_u64() >> 11) * (1.0 / (1 << 53))``. Takes the top
        53 bits of the draw so the result lies in ``[0.0, 1.0)`` with
        a uniform distribution at f64 mantissa precision. The
        ``1.0 / (1 << 53)`` constant lowers to the IEEE-754
        bit-exact value ``0x3CA0000000000000``, matching Python's
        ``1.0 / (1 << 53)``.
        """
        self._write("(func $rand_float_unit (result f64)")
        self._indent += 1
        self._write("call $rand_state_init_if_needed")
        self._write("call $rand_next_u64")
        self._write("i64.const 11")
        self._write("i64.shr_u")
        self._write("f64.convert_i64_u")
        self._write("f64.const 0x1p-53")
        self._write("f64.mul")
        self._indent -= 1
        self._write(")")

    # ----- dispatch helpers (called from _caps.py) --------------

    def _emit_random_constructor(self, instr: Call) -> None:
        """``Random()`` source-level constructor.

        At the Wasm layer the capability carries no runtime value
        (BUILTIN_CAPS dsts are erased in the dispatcher), so the
        only side effect is to make sure the PRNG state is live for
        any subsequent ``int_range`` / ``float_unit`` call. The
        actual seed draw is deferred to first read via
        ``$rand_state_init_if_needed``; the constructor only needs
        to ensure the helpers are reachable, which the
        ``_uses_random`` discovery has already guaranteed by the
        time we get here. No-op emission is the correct behaviour;
        kept as a named entry point so the dispatcher's intent is
        readable at the call site."""
        # Nothing to emit. The dst (a Random local) is erased and
        # the lazy-init branch fires on the first int_range /
        # float_unit call.
        return

    def _emit_random_method_call(self, instr: MethodCall) -> None:
        """Dispatch a Random method call. Three methods land here:

        - ``with_seed(seed: Int)``: writes the seed into
          ``$rand_state`` and flips the inited guard, so a
          subsequent ``int_range`` skips the host ``system-seed``
          call. Returns "the Random" at the source level, but at
          the Wasm level that's a cap dst -- erased; emit no
          value.
        - ``int_range(low: Int, high: Int) -> Int``: pushes
          (low, high) as i64s, calls ``$rand_int_range``, binds
          the i64 result.
        - ``float_unit() -> Float``: calls ``$rand_float_unit``,
          binds the f64 result.

        Anything else raises ``WasmEmissionError`` so a future
        method addition cannot silently no-op."""
        method = instr.method
        if method == "with_seed":
            self._emit_random_with_seed(instr)
            return
        if method == "int_range":
            self._emit_random_int_range(instr)
            return
        if method == "float_unit":
            self._emit_random_float_unit(instr)
            return
        raise WasmEmissionError(
            f"Random method {method!r} has no Wasm encoding; "
            f"supported: with_seed, int_range, float_unit"
        )

    def _emit_random_with_seed(self, instr: MethodCall) -> None:
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"Random.with_seed expected 1 Int arg, got "
                f"{len(instr.args)}"
            )
        # Push the seed value, write it into the global, flip the
        # guard so the next int_range / float_unit does not redraw
        # the host seed and clobber the deterministic state.
        self._push_value(instr.args[0])
        self._write("global.set $rand_state")
        self._write("i32.const 1")
        self._write("global.set $rand_state_inited")
        # dst is a Random cap; erased at the Wasm level. Nothing to
        # bind.

    def _emit_random_int_range(self, instr: MethodCall) -> None:
        if len(instr.args) != 2:
            raise WasmEmissionError(
                f"Random.int_range expected 2 Int args, got "
                f"{len(instr.args)}"
            )
        self._push_value(instr.args[0])
        self._push_value(instr.args[1])
        self._write("call $rand_int_range")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_random_float_unit(self, instr: MethodCall) -> None:
        if instr.args:
            raise WasmEmissionError(
                f"Random.float_unit takes no args, got "
                f"{len(instr.args)}"
            )
        self._write("call $rand_float_unit")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")
