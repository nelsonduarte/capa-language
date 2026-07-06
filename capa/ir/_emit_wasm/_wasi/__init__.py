"""Experimental WASI Preview 2 import emission (opt-in ``--wasi``).

A proof-of-concept that migrates the PURE-READER capability
touch-points off the custom ``capa:host`` interfaces and onto
canonical WASI Preview 2 (``0.2.0``) interfaces:

- ``Random.system_seed``   -> ``wasi:random/random@0.2.0`` ``get-random-u64``
- ``Clock.now_monotonic``  -> ``wasi:clocks/monotonic-clock@0.2.0`` ``now``
- ``Clock.now_secs``       -> ``wasi:clocks/wall-clock@0.2.0`` ``now``
- ``Env.get``              -> ``wasi:cli/environment@0.2.0`` ``get-environment``
- ``Env.args``             -> ``wasi:cli/environment@0.2.0`` ``get-arguments``
- ``Env.restrict_to_keys`` -> GUEST-SIDE allow-list narrowing (no host)
- ``Env.allows``           -> GUEST-SIDE allow-list membership (no host)

Everything else the program uses (typically ``Stdio`` for printing
the results, plus any other capability) stays on ``capa:host``. The
component therefore imports the wasi:* interfaces AND the capa:host
ones simultaneously; the host satisfies the former via wasmtime's
``Linker.add_wasip2()`` and the latter via the existing custom
registrations (see ``capa.runtime._wasm_component_host``).

Design choices that keep the rest of the emitter untouched:

- The raw wasi:* imports are bound to private ``$wasi_*`` names.
- A thin adapter wrapper exposes the exact ``$Cap_method`` binding
  the existing call-site emitters already ``call`` (so neither the
  Random helpers, ``_emit_clock_primitive_with_handle`` nor
  ``_emit_indirect_with_cap_handle`` change):

    * ``$Random_system_seed () -> i64``   = ``call $wasi_random_u64``
    * ``$Clock_now_monotonic (i32) -> f64`` drops the handle, reads
      ``monotonic-clock.now`` (u64 nanoseconds) and divides by 1e9.
    * ``$Clock_now_secs (i32) -> f64`` drops the handle, calls
      ``wall-clock.now`` into a fixed 16-byte scratch area, then
      computes ``seconds + nanoseconds / 1e9``.
    * ``$Env_get (handle, key_ptr, key_len, ret_area)`` drops the
      handle, calls ``get-environment`` (an indirect-return
      ``list<tuple<string, string>>``) into a fixed 8-byte scratch,
      linear-scans the (key, value) pairs for ``key``, and writes an
      ``option<string>`` (WIT tag convention) into ``ret_area`` so the
      existing ``option_string`` materialiser is unchanged. A missing
      key yields ``none`` (fail-closed, identical to the Python
      ``Env.get`` and the ``capa:host`` host bridge).
    * ``$Env_args (handle, ret_area)`` drops the handle, calls
      ``get-arguments`` (an indirect-return ``list<string>``) into a
      fixed 8-byte scratch, and copies the ``(data_ptr, len)`` pair
      into ``ret_area``. The canonical-ABI ``list<string>`` data
      layout (N packed ``(str_ptr, str_len)`` i32 pairs) is
      byte-identical to a Capa List<String> data array, so the
      existing ``list_string`` materialiser wraps it in a 16-byte
      header unchanged.

The unit / shape conversions are done guest-side in WAT (the same
strategy the Clock wrappers use for nanos->seconds), so the Capa
surface keeps exposing ``f64`` seconds and ``Option<String>`` /
``List<String>`` identically to the default backend.

Env GUEST-SIDE ATTENUATION (Level 2 of
``docs/design/wasi-attenuation.md``)
------------------------------------------------------------------
``wasi:cli/environment`` is a pure reader: there is no host-side cap
object to hold an allow-list, so Env attenuation has no host runtime
home. Rather than reject it (the prior PoC behaviour), this mode
implements the narrowing GUEST-SIDE, with semantics byte-identical to
the Python oracle (``capa/runtime/_capabilities.py:355-372``).

The Env value (an i32 the host passes to ``main``, and that
``restrict_to_keys`` returns) is REINTERPRETED guest-side:

- ``0``       = UNRESTRICTED (the root Env ``main`` receives; the host
  passes 0 in this mode, since the capa:host handle has no meaning on
  the wasi path).
- non-zero    = a pointer to a ``List<String>`` header (16 bytes:
  len@0, cap@4, data_ptr@8, pad@12) whose data array holds the
  ALLOW-LIST: N packed ``(str_ptr, str_len)`` i32 pairs. The same
  layout a Capa ``List<String>`` uses, so the keys argument of
  ``restrict_to_keys`` (itself a ``List<String>``) and the produced
  allow-list share one shape and one scan helper (``$str_eq``).

The three operations, all in WAT (the wrappers below):

- ``$Env_restrict_to_keys (handle, keys_data_ptr, keys_len) -> i32``
  builds a NEW allow-list = INTERSECTION of the current allow-list
  with ``keys`` (monotonic, never widens; an unrestricted ``handle``
  intersected with ``keys`` becomes restricted to ``keys``), allocates
  a fresh ``List<String>`` for it, returns the pointer. Identical to
  ``Env.restrict_to_keys`` (``new & self._allowed_keys``).
- ``$Env_allows (handle, key_ptr, key_len) -> i32`` returns 1 iff
  ``handle == 0`` (unrestricted) OR ``key`` is in the allow-list.
- ``$Env_get`` is extended to FAIL CLOSED: when ``handle`` is
  restricted and ``key`` is not in the allow-list it writes ``none``
  WITHOUT reading the environment, identical to the Python
  ``Env.get`` (``if not self.allows(name): return None_``).

GUARANTEE LEVEL (honest): this is Level 2. The host still
``inherit_env``s the FULL environment to the component (the ceiling is
NOT yet materialised via env-set, that is Level 1, a later increment),
so the fine allow-list narrowing is imposed by the COMPILER-GENERATED
guest code, not by the WASI host. It is PROVED by the compiler (the
guest only ever narrows) and REINFORCED by our host (which generated
the guest); under a stock / tampered WASI host the full environment is
reachable and the narrowing would not be re-checked.

``Env.args`` is NOT attenuated (matching the oracle: ``Env`` has no
arg restriction); its wrapper ignores the handle.

Excluded from this mode (rejected with a clear error so a program
never silently miscompiles):

- ``Clock.sleep``  -> would pull ``wasi:io/streams`` / poll, out of
  scope.
- Clock attenuation (``restrict_to_after``) -> the wasi:clocks
  interfaces are pure readers with no host-side handle table to
  enforce a deadline; a future design item.
"""

from __future__ import annotations

from ._constants import (  # noqa: F401  (re-exported for callers)
    _WASI_MIGRATED_METHODS,
    _WASI_RANDOM, _WASI_MONOTONIC, _WASI_WALL, _WASI_ENVIRONMENT,
    _WASI_CLI_STDOUT, _WASI_CLI_STDERR, _WASI_CLI_STDIN,
    _WASI_FS_TYPES, _WASI_FS_PREOPENS, _WASI_IO_STREAMS, _WASI_IO_ERROR,
    _WASI_IO_POLL, _WASI_HTTP_TYPES, _WASI_HTTP_HANDLER,
    _WASI_NET_MIGRATED, _WASI_NET_READ_CHUNK,
    _WASI_FS_METADATA, _WASI_FS_STREAM, _WASI_FS_REJECTED,
    _WASI_FS_READ_CHUNK, _WASI_FS_WRITE_CHUNK,
    _WASI_STDIO_MIGRATED, _WASI_STDIO_WRITE_CHUNK,
)
from ._core import _WasiCoreMixin
from ._env import _WasiEnvMixin
from ._fs import _WasiFsMixin
from ._net import _WasiNetMixin


class _WasiEmissionMixin(
    _WasiFsMixin,
    _WasiNetMixin,
    _WasiEnvMixin,
    _WasiCoreMixin,
):
    """The combined ``--wasi`` emission mixin folded into
    ``WasmEmitter``; active only when ``self._wasi`` is True. The
    per-capability method blocks live in the sibling modules; they
    call one another through ``self`` so the combined class resolves
    every cross-capability reference."""

    pass
