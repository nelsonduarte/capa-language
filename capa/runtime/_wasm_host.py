"""Host-side bridge that implements Capa's built-in capability
interfaces for Wasm-compiled programs.

A Capa program compiled to Wasm with ``capa.ir.compile_wasm`` imports
its capability methods by WIT-aligned names (e.g.
``capa:stdio.println``). The host provides those imports via
``wasmtime.Linker``; this module wraps the wiring so a test or
runtime entry point can do:

    from capa.runtime._wasm_host import WasmHost
    host = WasmHost()
    host.run_main(wasm_blob)

and the program's ``main`` export executes with the host's
capabilities live (stdio printing to real stdout, etc.).

Phase 6B scope: ``capa:stdio`` interface (print / println / eprintln)
only. Subsequent phases add Fs / Env / Clock / Net via the same
pattern.

Trust-boundary notes (audit items M1 / H1, 2026-05):

- ``env.get`` is leak-by-default. An unrestricted ``Env`` cap reads
  ``os.environ`` verbatim, so a Capa program with the cap sees every
  environment variable on the host (including secrets). The
  attenuation system narrows it: a program that calls
  ``env.restrict_to_keys([...])`` on a literal allow-list is enforced
  inline by the Wasm emitter (audit C2). Production hosts handing a
  ``.wasm`` blob to untrusted code must restrict first.
- The bump allocator's ``memory.grow`` call is bounded by the
  module's declared ``(memory ... <max>)`` upper-page limit. The
  Wasm emitter ships a sane default (see
  ``capa.ir._emit_wasm.MEMORY_CAP_DEFAULT_PAGES`` = 256 pages = 16
  MiB) so a runaway allocator traps predictably rather than at some
  host-dependent OOM point. Override on the CLI with
  ``--wasm-memory-cap <pages>`` (1 page = 64 KiB).
"""

from __future__ import annotations

import sys
from typing import Optional

import wasmtime

from ._capabilities import _write_safe


class WasmHost:
    """A wasmtime-based host that wires Capa's built-in capabilities
    into a compiled Wasm module."""

    def __init__(self, args: Optional[list[str]] = None) -> None:
        self.engine = wasmtime.Engine()
        self.store = wasmtime.Store(self.engine)
        self.linker = wasmtime.Linker(self.engine)
        # Holds the instance's exported memory after instantiation;
        # host callbacks read string arguments out of this memory.
        self._memory: Optional[wasmtime.Memory] = None
        # Cache the module's exported $alloc once we instantiate;
        # host functions like ``env.get`` need to allocate Option /
        # Result records back into wasm memory, which requires
        # calling ``$alloc`` from the host side.
        self._alloc_export: Optional[wasmtime.Func] = None
        # Program arguments handed to the wasm module via env.args.
        # Defaults to an empty list; callers (e.g. the CLI) pass the
        # real argv when they have it.
        self._args: list[str] = list(args) if args is not None else []
        self._register_stdio()
        self._register_clock()
        self._register_env()
        self._register_fs()
        self._register_json()
        self._register_random()
        self._register_net()
        self._register_db()

    def _register_stdio(self) -> None:
        """Register the ``capa:stdio`` interface methods. Each
        method takes (ptr, len) as i32s describing a UTF-8 byte
        slice in the module's exported memory; the host reads the
        slice and forwards to Python's stdio."""
        ft_string_to_unit = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()], [],
        )

        # Stream lookups are deferred to call time (each invocation
        # consults the live ``sys.stdout`` / ``sys.stderr``) so tests
        # that ``contextlib.redirect_stdout`` AFTER instantiating
        # the host still capture output. Eager capture at host-
        # construction time would freeze the file objects to the
        # values they had then.
        # Stdio has no return value, so it cannot signal failure
        # back to the guest the way Fs / Env do. Audit fix H3: print
        # invalid UTF-8 with the Unicode replacement character (U+FFFD)
        # in place of unparseable bytes rather than raising
        # ``UnicodeDecodeError`` out of the host callback (which would
        # crash the whole wasmtime store). Choice rationale: silent
        # corruption is unacceptable for a security-oriented language,
        # but the alternative (trapping the guest) would propagate a
        # purely cosmetic encoding bug into a hard crash. Replacement
        # is the well-known middle ground that the guest can detect by
        # comparing its outgoing bytes against the observed output.
        def stdio_print(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            _write_safe(
                sys.stdout, bytes(data).decode("utf-8", errors="replace"),
            )
            sys.stdout.flush()

        def stdio_println(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            _write_safe(
                sys.stdout,
                bytes(data).decode("utf-8", errors="replace") + "\n",
            )
            sys.stdout.flush()

        def stdio_eprintln(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            _write_safe(
                sys.stderr,
                bytes(data).decode("utf-8", errors="replace") + "\n",
            )
            sys.stderr.flush()

        self.linker.define_func(
            "capa:host/stdio", "print", ft_string_to_unit,
            stdio_print, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/stdio", "println", ft_string_to_unit,
            stdio_println, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/stdio", "eprintln", ft_string_to_unit,
            stdio_eprintln, access_caller=True,
        )

        # Stdio.read_line: canonical-ABI result<string, io-error>.
        # Same 20-byte indirect-return shape as Fs.read; the host
        # writes the tag + Ok (ptr, len) or Err (m_ptr, m_len, c_ptr,
        # c_len) into the caller-allocated area. Mirrors the Python
        # runtime: empty input (EOF) becomes Err("end of input");
        # invalid UTF-8 becomes Err with the decode exception in the
        # cause field (audit H3 convention).
        ft_read_line = wasmtime.FuncType(
            [wasmtime.ValType.i32()], [],
        )

        def _write_rsio_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _alloc_utf8_local(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._alloc_export(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_rsio_err(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8_local(caller, message)
            c_ptr, c_len = _alloc_utf8_local(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def stdio_read_line(caller, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "stdio.read_line called before memory + $alloc set"
                )
            try:
                line = sys.stdin.readline()
            except OSError as e:
                _write_rsio_err(caller, ret_area, "read failed", str(e))
                return
            except UnicodeDecodeError as e:
                _write_rsio_err(
                    caller, ret_area, "invalid utf-8 on stdin", str(e),
                )
                return
            if not line:
                _write_rsio_err(caller, ret_area, "end of input")
                return
            stripped = line.rstrip("\n")
            s_ptr, s_len = _alloc_utf8_local(caller, stripped)
            _write_rsio_ok_string(caller, ret_area, s_ptr, s_len)

        self.linker.define_func(
            "capa:host/stdio", "read-line", ft_read_line,
            stdio_read_line, access_caller=True,
        )

    def _register_clock(self) -> None:
        """Register the ``capa:host/clock`` interface methods.
        ``now_secs`` returns Unix epoch seconds as f64;
        ``now_monotonic`` returns a monotonic time source's value
        in seconds. Both signatures match the Capa runtime's
        ``Clock`` class so the Wasm and Python paths produce
        identical numbers."""
        import time
        ft_to_f64 = wasmtime.FuncType([], [wasmtime.ValType.f64()])

        def now_secs():
            return time.time()

        def now_monotonic():
            return time.monotonic()

        self.linker.define_func(
            "capa:host/clock", "now-secs", ft_to_f64, now_secs,
        )
        self.linker.define_func(
            "capa:host/clock", "now-monotonic", ft_to_f64, now_monotonic,
        )

        # Clock.sleep(secs: f64). The Python runtime treats a denied
        # Clock as a silent no-op; this host bridge mirrors that by
        # always calling ``time.sleep`` (the Wasm side carries no
        # ``restrict_to_after`` state, just like Fs.restrict_to and
        # Env.restrict_to_keys are no-ops at this layer). Static
        # attenuation discipline still applies. Guard against
        # negative durations (``time.sleep`` raises ValueError) so
        # the guest can't crash the host with a bad literal.
        ft_sleep = wasmtime.FuncType([wasmtime.ValType.f64()], [])

        def clock_sleep(secs):
            if secs < 0:
                return
            time.sleep(secs)

        self.linker.define_func(
            "capa:host/clock", "sleep", ft_sleep, clock_sleep,
        )

        # Clock.allows: queries the cap's ``restrict_to_after``
        # threshold against the wall clock. Wasm caps carry no
        # runtime state, so unrestricted is the only answer the
        # host can give; mirrors the Python runtime's
        # ``self._not_before is None or time.time() >= self._not_before``
        # for the unrestricted case (returns true). Static
        # attenuation chains that the analyzer can resolve are
        # the responsibility of source-level discipline.
        ft_allows = wasmtime.FuncType([], [wasmtime.ValType.i32()])

        def clock_allows():
            return 1

        self.linker.define_func(
            "capa:host/clock", "allows", ft_allows, clock_allows,
        )

    def _register_env(self) -> None:
        """Register the ``capa:host/env`` interface methods.

        ``get(name: string) -> option<string>``: reads the named
        env var from the host process. On miss, allocates an
        Option with tag=None (1); on hit, allocates an Option
        with tag=Some (0) and a packed (ptr, len) payload pointing
        to a copy of the value's UTF-8 bytes in wasm memory.

        The host calls back into ``$alloc`` to materialise both
        the Option container and the string buffer. That side-
        channel keeps the WIT contract clean (``option<string>``)
        and ties allocations to the module's bump heap so memory
        stays linear and traceable.

        **Trust boundary (audit M1, 2026-05).** This host bridge
        reads ``os.environ.get(name)`` without filtering: an
        unrestricted ``Env`` cap held by the wasm guest sees every
        host env var (including secrets like ``OPENAI_API_KEY``,
        ``AWS_*``, ``GITHUB_TOKEN``, ``PATH``). Capa's discipline is
        that the Env cap is itself the trust boundary; the
        attenuation system narrows it. Programs that statically call
        ``env.restrict_to_keys([...])`` on a literal allow-list get
        the restriction enforced inline by the emitter (audit C2);
        unrestricted caps still see the full host environment. Hosts
        wrapping a third-party ``.wasm`` blob should refuse to grant
        an unrestricted Env cap unless they have audited the guest."""
        import os
        # Canonical ABI lowering: ``option<string>`` returns through
        # a 12-byte caller-allocated area (tag i32 @ 0, ptr i32 @ 4,
        # len i32 @ 8). The host writes the flat fields; the IR
        # materialiser repackages them into a Capa Option<String>
        # heap record.
        ft_string_to_unit_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
            ],
            [],
        )

        def env_get(caller, name_ptr, name_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "env.get called before instance memory + $alloc set"
                )
            data = self._memory.read(caller, name_ptr, name_ptr + name_len)
            # Audit fix H3: invalid UTF-8 in the lookup key cannot match
            # any real env var (env names are well-formed strings on every
            # OS we target); return None cleanly instead of bubbling
            # ``UnicodeDecodeError`` up through wasmtime and crashing the
            # store. The WIT shape (``option<string>``) already carries
            # the "no such key" path, so the guest sees the same value
            # it would for a typo.
            try:
                name = bytes(data).decode("utf-8")
            except UnicodeDecodeError:
                value = None
            else:
                value = os.environ.get(name)
            # Tag convention: write the WIT-canonical discriminant
            # (none=0, some=1). The materialiser XOR-flips to Capa's
            # internal Option layout (Some=0, None=1) on read, so
            # the core-host path and the Component Model path
            # produce identical Capa records. Pre-fix the core host
            # wrote Capa-convention tags here which happened to fake-
            # match the materialiser's then-naive copy; the bug
            # surfaced only on the component-wrapped path because
            # the CM adapter writes WIT-convention.
            if value is None:
                # tag = 0 (WIT none); ptr/len fields undefined per
                # WIT, write zeros so memory stays deterministic.
                self._memory.write(
                    caller, (0).to_bytes(4, "little"), ret_area,
                )
                self._memory.write(
                    caller, (0).to_bytes(4, "little"), ret_area + 4,
                )
                self._memory.write(
                    caller, (0).to_bytes(4, "little"), ret_area + 8,
                )
                return
            encoded = value.encode("utf-8")
            if encoded:
                s_ptr = self._alloc_export(caller, len(encoded))
                self._memory.write(caller, encoded, s_ptr)
            else:
                s_ptr = 0
            # tag = 1 (WIT some)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, s_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller,
                len(encoded).to_bytes(4, "little"),
                ret_area + 8,
            )

        self.linker.define_func(
            "capa:host/env", "get", ft_string_to_unit_indirect,
            env_get, access_caller=True,
        )

        # env.args() -> list<string>. Builds a List<String> in
        # linear memory: 16-byte header (len, cap, data_ptr, pad)
        # + N*8-byte data array of packed (ptr, len) i64s. The
        # WasmHost stashes argv at construction time so the
        # Canonical ABI: ``args`` returns ``list<string>`` indirectly
        # via a caller-allocated return area. The host receives the
        # return-area pointer as its single argument, writes
        # ``(data_ptr, len)`` (two i32s) into the area, and returns
        # nothing. The Capa-side caller then assembles the
        # List<String> header (16 bytes) around the data buffer.
        ft_indirect_to_unit = wasmtime.FuncType(
            [wasmtime.ValType.i32()], [],
        )

        def env_args(caller, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "env.args called before memory + $alloc set"
                )
            n = len(self._args)
            # Allocate the data buffer (n * 8 bytes). Each slot
            # holds (str_ptr i32, str_len i32) which is the same
            # byte layout Capa's packed-i64 string convention
            # produces, so downstream List<String> iteration
            # works unchanged.
            data_ptr = self._alloc_export(caller, n * 8) if n else 0
            for i, arg in enumerate(self._args):
                encoded = arg.encode("utf-8")
                if encoded:
                    s_ptr = self._alloc_export(caller, len(encoded))
                    self._memory.write(caller, encoded, s_ptr)
                else:
                    # Empty string: a valid (0, 0) slot; pointer
                    # never read because length is zero.
                    s_ptr = 0
                slot = data_ptr + i * 8
                self._memory.write(
                    caller, s_ptr.to_bytes(4, "little"), slot,
                )
                self._memory.write(
                    caller, len(encoded).to_bytes(4, "little"), slot + 4,
                )
            # Write (data_ptr, len) into the return area.
            self._memory.write(
                caller, data_ptr.to_bytes(4, "little"), ret_area,
            )
            self._memory.write(
                caller, n.to_bytes(4, "little"), ret_area + 4,
            )

        self.linker.define_func(
            "capa:host/env", "args", ft_indirect_to_unit,
            env_args, access_caller=True,
        )

    def _register_fs(self) -> None:
        """Register ``capa:host/fs`` interface methods.

        ``read(path: string) -> result<string, io-error>``: reads
        the file at ``path``. On success, builds Ok(String). On
        any OSError, builds Err(IoError) with ``message = exception
        str``; the IoError record is two adjacent (ptr, len) pairs
        for ``message`` and ``cause``.

        ``write(path, content) -> result<_, io-error>``: writes
        ``content`` to ``path``. On success, builds Ok(Unit) with
        a placeholder payload. On error, builds Err(IoError)
        identically to read.

        Phase 7C scope: no ``Fs.restrict_to`` capability attenuation
        (the wasm-side cap is unrestricted; in production we would
        track the same prefix set as ``capa.runtime.Fs``)."""
        # Canonical ABI: result<T, io-error> returns indirectly via
        # a 20-byte caller area. Layout:
        #   tag i32  @ 0
        #   Ok arm (string): ptr @ 4, len @ 8 (Ok<unit> writes zeros)
        #   Err arm (io-error): m_ptr @ 4, m_len @ 8, c_ptr @ 12,
        #                       c_len @ 16
        ft_fs_read_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )
        ft_fs_write_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
                wasmtime.ValType.i32(),  # content_ptr
                wasmtime.ValType.i32(),  # content_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def _alloc_utf8(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._alloc_export(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_result_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            # Zero the remaining bytes of the Err union for tidiness.
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _write_result_ok_unit(caller, ret_area):
            # Tag = 0, rest zeroed.
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, (0).to_bytes(16, "little"), ret_area + 4,
            )

        def _write_result_err_ioerror(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8(caller, message)
            c_ptr, c_len = _alloc_utf8(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def fs_read(caller, path_ptr, path_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.read called before memory + $alloc set"
                )
            # Audit fix H3: invalid UTF-8 in the path argument is
            # a guest-side bug, not a host-process crash. Surface it
            # through the WIT result<_, io-error> channel so the guest
            # can pattern-match on Err the same way it would for a
            # permission-denied or no-such-file failure.
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            try:
                content = open(path, encoding="utf-8").read()
                s_ptr, s_len = _alloc_utf8(caller, content)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))

        def fs_write(caller, p_ptr, p_len, c_ptr, c_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.write called before memory + $alloc set"
                )
            # Audit fix H3: same as fs.read, but two strings can each
            # be invalid; surface both in the Err message so the guest
            # can tell which arg was malformed.
            try:
                path = bytes(
                    self._memory.read(caller, p_ptr, p_ptr + p_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            try:
                content = bytes(
                    self._memory.read(caller, c_ptr, c_ptr + c_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in content: {e}",
                )
                return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                _write_result_ok_unit(caller, ret_area)
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))

        self.linker.define_func(
            "capa:host/fs", "read", ft_fs_read_indirect,
            fs_read, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/fs", "write", ft_fs_write_indirect,
            fs_write, access_caller=True,
        )

        # fs.restrict_to is a no-op at the Wasm level. Static
        # capability discipline is enforced by the analyzer; this
        # callback only exists so the import resolves. A future
        # phase that threads handles through the Fs interface
        # would replace it with real prefix tracking.
        ft_string_to_unit = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()], [],
        )

        def fs_restrict_to(caller, prefix_ptr, prefix_len):
            return None

        self.linker.define_func(
            "capa:host/fs", "restrict-to", ft_string_to_unit,
            fs_restrict_to, access_caller=True,
        )

        # Fs.exists / Fs.is_dir: (path_ptr, path_len) -> i32 (bool).
        # Mirror the Python runtime's fail-closed-as-absent
        # convention: invalid UTF-8 in the path returns false (the
        # host can't even attempt the syscall), matching what the
        # Python side would do for a path that genuinely does not
        # exist.
        ft_path_to_bool = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
            [wasmtime.ValType.i32()],
        )

        import os as _os_mod

        def fs_exists(caller, path_ptr, path_len):
            if self._memory is None:
                raise RuntimeError(
                    "fs.exists called before memory was set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            return 1 if _os_mod.path.exists(path) else 0

        def fs_is_dir(caller, path_ptr, path_len):
            if self._memory is None:
                raise RuntimeError(
                    "fs.is_dir called before memory was set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            return 1 if _os_mod.path.isdir(path) else 0

        self.linker.define_func(
            "capa:host/fs", "exists", ft_path_to_bool,
            fs_exists, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/fs", "is-dir", ft_path_to_bool,
            fs_is_dir, access_caller=True,
        )

        # Fs.mkdir: (path_ptr, path_len, ret_area) -> ()
        # Same canonical-ABI shape as Fs.write Ok-Unit branch (20-byte
        # area). Idempotent via ``exist_ok=True`` to match the Python
        # runtime's contract; failures (e.g. EACCES, ENOTDIR on a
        # path component) become Err(IoError).
        ft_mkdir = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
            ],
            [],
        )

        def fs_mkdir(caller, path_ptr, path_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.mkdir called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            try:
                _os_mod.makedirs(path, exist_ok=True)
                _write_result_ok_unit(caller, ret_area)
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))

        self.linker.define_func(
            "capa:host/fs", "mkdir", ft_mkdir,
            fs_mkdir, access_caller=True,
        )

        # Fs.list_dir: (path_ptr, path_len, ret_area) -> ()
        # Canonical-ABI result<list<string>, io-error>. ret_area is
        # 20 bytes: tag i32 @ 0; Ok arm (data_ptr i32 @ 4, len i32 @ 8);
        # Err arm (m_ptr @ 4, m_len @ 8, c_ptr @ 12, c_len @ 16).
        # Host allocates the list data buffer (n*8 packed (ptr, len)
        # slots, same layout as Env.args produces); the IR
        # materialiser wraps it in a List<String> header. Entries are
        # sorted to match the Python runtime's
        # ``sorted(os.listdir(path))``.
        def fs_list_dir(caller, path_ptr, path_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.list_dir called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            try:
                entries = sorted(_os_mod.listdir(path))
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))
                return
            n = len(entries)
            data_ptr = self._alloc_export(caller, n * 8) if n else 0
            for i, entry in enumerate(entries):
                encoded = entry.encode("utf-8")
                if encoded:
                    s_ptr = self._alloc_export(caller, len(encoded))
                    self._memory.write(caller, encoded, s_ptr)
                else:
                    s_ptr = 0
                slot = data_ptr + i * 8
                self._memory.write(
                    caller, s_ptr.to_bytes(4, "little"), slot,
                )
                self._memory.write(
                    caller, len(encoded).to_bytes(4, "little"), slot + 4,
                )
            # Ok tag + (data_ptr, len) into the area; zero the unused
            # Err c_ptr / c_len bytes so the layout stays
            # deterministic.
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, data_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, n.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        self.linker.define_func(
            "capa:host/fs", "list-dir", ft_mkdir,
            fs_list_dir, access_caller=True,
        )

    def _register_random(self) -> None:
        """Register the ``capa:host/random`` interface methods.

        Only one method crosses the host boundary: ``system-seed``
        returns 8 bytes of entropy (as a u64) at the moment an
        unseeded guest ``Random()`` lazy-initialises its PRNG state.
        Every subsequent draw runs guest-side in pure WAT (SplitMix64
        over a module-local i64), so seeded sequences are byte-
        identical with the Python backend.
        """
        import os
        ft_seed = wasmtime.FuncType([], [wasmtime.ValType.i64()])

        def random_system_seed():
            # ``os.urandom(8)`` -> little-endian unsigned u64. Matches
            # the Python ``Random.__init__`` entropy path exactly so
            # both backends seed off the same byte-shape on an
            # unseeded construction. Wasmtime's i64 type carries the
            # full 64 bits regardless of Python's signed-int rendering
            # at the binding boundary.
            return int.from_bytes(os.urandom(8), "little", signed=False)

        self.linker.define_func(
            "capa:host/random", "system-seed", ft_seed,
            random_system_seed,
        )

    def _register_net(self) -> None:
        """Register the ``capa:host/net`` interface methods.

        Methods: ``get(url) -> Result<String, IoError>`` and
        ``post(url, body) -> Result<String, IoError>``. Both host
        callbacks mirror ``capa.runtime._capabilities.Net.{get,post}``
        exactly so a ``file://`` URL (get) or a same-process loopback
        (post) produces byte-identical output on both backends:
        ``urllib.request.urlopen(Request(url[, data=body]))`` with a
        10-second timeout, body bytes decoded UTF-8 with
        ``errors="replace"`` so non-UTF-8 responses produce a
        deterministic ``U+FFFD``-substituted string rather than a
        host-side trap.

        Attenuation enforcement (``net.restrict_to(host)``) is
        inlined at emit time via ``$str_contains(url, host)`` in
        the Wasm backend (audit C2); a denied URL never reaches
        this host bridge. The Python ``Net.{get,post}`` does the
        same check against the parsed ``urlparse(url).hostname``.
        Both backends therefore agree on which URLs make it to the
        network layer, and these methods only handle the
        unrestricted / already-allowed path.

        ``net.restrict-to`` is a host no-op like ``fs.restrict-to``
        since capabilities carry no runtime value at the Wasm
        level."""
        from urllib.request import Request, urlopen
        from urllib.error import URLError
        # Canonical ABI: result<string, io-error> returns indirectly
        # via a 20-byte caller area. Same shape as Fs.read. Layout:
        #   tag i32  @ 0
        #   Ok arm (string): ptr @ 4, len @ 8
        #   Err arm (io-error): m_ptr @ 4, m_len @ 8, c_ptr @ 12,
        #                       c_len @ 16
        ft_net_get_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # url_ptr
                wasmtime.ValType.i32(),  # url_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def _alloc_utf8(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._alloc_export(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_result_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _write_result_err_ioerror(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8(caller, message)
            c_ptr, c_len = _alloc_utf8(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def net_get(caller, url_ptr, url_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "net.get called before memory + $alloc set"
                )
            # Audit H3 convention: invalid UTF-8 in the URL bytes
            # is a guest-side bug; route it through the WIT
            # result<_, io-error> Err arm so the guest pattern-
            # matches it the same way it would a real network
            # failure, instead of trapping the host.
            try:
                url = bytes(
                    self._memory.read(caller, url_ptr, url_ptr + url_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid URL", str(e),
                )
                return
            # Mirror ``capa.runtime._capabilities.Net.get`` exactly:
            # any URLError / OSError / ValueError from urlopen lowers
            # to the same Err shape the Python runtime produces, so
            # the two backends' failure messages stay aligned. The
            # body decode uses ``errors="replace"`` so non-UTF-8
            # responses do not surface a UnicodeDecodeError.
            try:
                with urlopen(Request(url), timeout=10) as resp:
                    data = resp.read().decode("utf-8", errors="replace")
                s_ptr, s_len = _alloc_utf8(caller, data)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            except (URLError, OSError, ValueError) as e:
                _write_result_err_ioerror(
                    caller, ret_area, "HTTP GET failed", str(e),
                )

        self.linker.define_func(
            "capa:host/net", "get", ft_net_get_indirect,
            net_get, access_caller=True,
        )

        # net.post: same indirect-return shape as net.get plus a
        # second String arg (the request body).
        ft_net_post_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # url_ptr
                wasmtime.ValType.i32(),  # url_len
                wasmtime.ValType.i32(),  # body_ptr
                wasmtime.ValType.i32(),  # body_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def net_post(caller, url_ptr, url_len, body_ptr, body_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "net.post called before memory + $alloc set"
                )
            # Same UTF-8 decode policy as net.get for the URL; the
            # body is treated as opaque bytes (we don't decode +
            # re-encode it to preserve byte-for-byte semantics with
            # the Python runtime, which calls body.encode("utf-8")
            # on a Capa String -- always valid UTF-8 at the source
            # level since Capa Strings are unicode-safe).
            try:
                url = bytes(
                    self._memory.read(caller, url_ptr, url_ptr + url_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid URL", str(e),
                )
                return
            body_bytes = bytes(
                self._memory.read(caller, body_ptr, body_ptr + body_len)
            )
            try:
                req = Request(
                    url, data=body_bytes,
                    headers={"Content-Type": "application/octet-stream"},
                )
                with urlopen(req, timeout=10) as resp:
                    data = resp.read().decode("utf-8", errors="replace")
                s_ptr, s_len = _alloc_utf8(caller, data)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            except (URLError, OSError, ValueError) as e:
                _write_result_err_ioerror(
                    caller, ret_area, "HTTP POST failed", str(e),
                )

        self.linker.define_func(
            "capa:host/net", "post", ft_net_post_indirect,
            net_post, access_caller=True,
        )

        # net.restrict_to is a no-op at the Wasm level (mirrors
        # fs.restrict_to). Static capability discipline is enforced
        # by the analyzer + the audit C2 inline ``$str_contains``
        # check the Wasm emitter wraps around ``Net.get``; this
        # callback only exists so the import resolves.
        ft_string_to_unit = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()], [],
        )

        def net_restrict_to(caller, host_ptr, host_len):
            return None

        self.linker.define_func(
            "capa:host/net", "restrict-to", ft_string_to_unit,
            net_restrict_to, access_caller=True,
        )

    def _register_db(self) -> None:
        """Register the ``capa:host/db`` interface methods.

        Slice 11 (2026-05): Db is a SQLite-backed capability. Both
        ``exec`` and ``query`` take ``(path: string, sql: string)``
        and return canonical-ABI ``result<...>`` shapes via a
        20-byte caller-allocated return area:

        - ``exec`` returns ``result<_, io-error>`` (same Err arm
          shape as Fs.write; Ok arm carries unit).
        - ``query`` returns ``result<string, io-error>`` (same
          Ok/Err arm shapes as Fs.read; the Ok string is a
          JSON-encoded ``[[col1, col2, ...], ...]`` array of
          arrays of stringified cell values).

        The host opens a fresh ``sqlite3.connect`` per call; the
        cap is stateless from the program's POV. Attenuation
        (``Db.restrict_to(prefix)``) is inlined at the guest
        side by the audit C2 ``$str_contains`` check around the
        privileged op, so a denied path never reaches this
        bridge. ``db.restrict-to`` is a host no-op like
        ``fs.restrict-to``.
        """
        import json
        import sqlite3

        ft_two_string_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
                wasmtime.ValType.i32(),  # sql_ptr
                wasmtime.ValType.i32(),  # sql_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def _alloc_utf8(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._alloc_export(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_result_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _write_result_ok_unit(caller, ret_area):
            # tag=0 (Ok), Ok payload has no flat fields. Zero the
            # remaining 16 bytes so the slot stays deterministic.
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, (0).to_bytes(16, "little"), ret_area + 4,
            )

        def _write_result_err_ioerror(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8(caller, message)
            c_ptr, c_len = _alloc_utf8(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def db_exec(caller, path_ptr, path_len, sql_ptr, sql_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "db.exec called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
                sql = bytes(
                    self._memory.read(caller, sql_ptr, sql_ptr + sql_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid UTF-8", str(e),
                )
                return
            try:
                from ._capabilities import _install_sqlite_authorizer
                conn = sqlite3.connect(path)
                _install_sqlite_authorizer(conn)
                try:
                    conn.executescript(sql)
                    conn.commit()
                finally:
                    conn.close()
                _write_result_ok_unit(caller, ret_area)
            except (sqlite3.Error, OSError, ValueError) as e:
                _write_result_err_ioerror(
                    caller, ret_area, "SQLite exec failed", str(e),
                )

        def db_query(caller, path_ptr, path_len, sql_ptr, sql_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "db.query called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
                sql = bytes(
                    self._memory.read(caller, sql_ptr, sql_ptr + sql_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid UTF-8", str(e),
                )
                return
            try:
                from ._capabilities import _install_sqlite_authorizer
                conn = sqlite3.connect(path)
                _install_sqlite_authorizer(conn)
                try:
                    cur = conn.execute(sql)
                    rows = cur.fetchall()
                finally:
                    conn.close()
                # Same stringify-every-cell policy as the Python
                # runtime so both backends produce identical JSON
                # for the same query against the same on-disk DB.
                stringified = [
                    [
                        "null" if v is None else
                        v if isinstance(v, str) else str(v)
                        for v in row
                    ]
                    for row in rows
                ]
                payload = json.dumps(stringified)
                s_ptr, s_len = _alloc_utf8(caller, payload)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            except (sqlite3.Error, OSError, ValueError) as e:
                _write_result_err_ioerror(
                    caller, ret_area, "SQLite query failed", str(e),
                )

        self.linker.define_func(
            "capa:host/db", "exec", ft_two_string_indirect,
            db_exec, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/db", "query", ft_two_string_indirect,
            db_query, access_caller=True,
        )

        # db.restrict-to: host no-op like fs.restrict-to.
        ft_string_to_unit = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()], [],
        )

        def db_restrict_to(caller, prefix_ptr, prefix_len):
            return None

        self.linker.define_func(
            "capa:host/db", "restrict-to", ft_string_to_unit,
            db_restrict_to, access_caller=True,
        )

    def _register_json(self) -> None:
        """Register the ``capa:host/json`` interface methods.

        ``parse(s) -> Result<JsonValue, String>``: parses a JSON
        document by walking Python's ``json.loads`` output and
        allocating the equivalent JsonValue tree in linear memory.

        ``to_string(jv) -> String``: walks a JsonValue tree out of
        linear memory, builds the equivalent Python value, calls
        ``json.dumps``, copies the bytes back into a fresh alloc.

        Both sides share the 16-byte JsonValue layout: tag at
        offset 0, payload at offset 8 in an 8-byte slot. Nested
        ``JArr`` payloads point to ``List<JsonValue>`` headers;
        nested ``JObj`` payloads point to ``Map<String, JsonValue>``
        headers. Numbers use the f64 storage slot; bools / pointers
        use i64-extended; strings are packed (ptr | (len << 32))."""
        import json as _stdlib_json

        # Canonical ABI:
        #   parse: (s_ptr, s_len, ret_area) -> ()  -- 12-byte ret
        #     area holds tag i32 + max(Ok u32, Err string).
        #   to-string: (jv, ret_area) -> ()  -- 8-byte ret area
        #     holds (ptr i32, len i32).
        ft_parse = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
            ],
            [],
        )
        ft_to_string = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
            [],
        )

        # ---- helpers (closures over caller-local self._memory + alloc) ----

        def _read_u32(caller, ptr: int) -> int:
            return int.from_bytes(
                bytes(self._memory.read(caller, ptr, ptr + 4)), "little",
            )

        def _read_i64(caller, ptr: int) -> int:
            raw = bytes(self._memory.read(caller, ptr, ptr + 8))
            return int.from_bytes(raw, "little", signed=False)

        def _read_f64(caller, ptr: int) -> float:
            import struct
            raw = bytes(self._memory.read(caller, ptr, ptr + 8))
            return struct.unpack("<d", raw)[0]

        def _write_u32(caller, ptr: int, val: int) -> None:
            self._memory.write(caller, val.to_bytes(4, "little"), ptr)

        def _write_i64(caller, ptr: int, val: int) -> None:
            self._memory.write(caller, val.to_bytes(8, "little"), ptr)

        def _write_f64(caller, ptr: int, val: float) -> None:
            import struct
            self._memory.write(caller, struct.pack("<d", val), ptr)

        def _alloc_string(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._alloc_export(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _read_string(caller, ptr: int, length: int) -> str:
            if length <= 0:
                return ""
            return bytes(
                self._memory.read(caller, ptr, ptr + length)
            ).decode("utf-8")

        def _alloc_jv(caller, tag: int) -> int:
            """Allocate a 16-byte JsonValue record with ``tag`` and
            a zero payload slot. Caller fills the payload via the
            appropriate _write_* on offset 8."""
            jv_ptr = self._alloc_export(caller, 16)
            _write_u32(caller, jv_ptr, tag)
            _write_i64(caller, jv_ptr + 8, 0)
            return jv_ptr

        def _alloc_list_of_jv(caller, items: list) -> int:
            """Allocate a 16-byte List header + cap * 4-byte data
            array. Each element is a JsonValue pointer (i32). The
            Wasm side computes elem_size from ``_size_of("JsonValue")``
            which is 4 (sum types are stored by pointer), so the
            data array uses 4-byte slots, NOT 8-byte ones."""
            n = len(items)
            cap = max(n, 8)
            header_ptr = self._alloc_export(caller, 16)
            data_ptr = self._alloc_export(caller, cap * 4) if cap else 0
            _write_u32(caller, header_ptr, n)
            _write_u32(caller, header_ptr + 4, cap)
            _write_u32(caller, header_ptr + 8, data_ptr)
            for i, item in enumerate(items):
                jv_ptr = _py_to_jv(caller, item)
                _write_u32(caller, data_ptr + i * 4, jv_ptr)
            return header_ptr

        def _alloc_map_str_jv(caller, items: dict) -> int:
            """Allocate a 16-byte Map header + cap * 16-byte triple
            array (key_ptr, key_len, value-as-i64)."""
            n = len(items)
            cap = max(n, 8)
            header_ptr = self._alloc_export(caller, 16)
            data_ptr = self._alloc_export(caller, cap * 16) if cap else 0
            _write_u32(caller, header_ptr, n)
            _write_u32(caller, header_ptr + 4, cap)
            _write_u32(caller, header_ptr + 8, data_ptr)
            for i, (k, v) in enumerate(items.items()):
                k_ptr, k_len = _alloc_string(caller, str(k))
                _write_u32(caller, data_ptr + i * 16, k_ptr)
                _write_u32(caller, data_ptr + i * 16 + 4, k_len)
                jv_ptr = _py_to_jv(caller, v)
                _write_i64(caller, data_ptr + i * 16 + 8, jv_ptr & 0xFFFFFFFF)
            return header_ptr

        def _py_to_jv(caller, val) -> int:
            """Recursively walk a Python value (from json.loads) into
            a JsonValue record tree in linear memory; return the
            JsonValue pointer."""
            if val is None:
                return _alloc_jv(caller, 0)  # JNull
            if isinstance(val, bool):
                jv = _alloc_jv(caller, 1)  # JBool
                _write_i64(caller, jv + 8, 1 if val else 0)
                return jv
            if isinstance(val, (int, float)):
                jv = _alloc_jv(caller, 2)  # JNum
                _write_f64(caller, jv + 8, float(val))
                return jv
            if isinstance(val, str):
                jv = _alloc_jv(caller, 3)  # JStr
                s_ptr, s_len = _alloc_string(caller, val)
                packed = (s_ptr & 0xFFFFFFFF) | (
                    (s_len & 0xFFFFFFFF) << 32
                )
                _write_i64(caller, jv + 8, packed)
                return jv
            if isinstance(val, list):
                list_ptr = _alloc_list_of_jv(caller, val)
                jv = _alloc_jv(caller, 4)  # JArr
                _write_i64(caller, jv + 8, list_ptr & 0xFFFFFFFF)
                return jv
            if isinstance(val, dict):
                map_ptr = _alloc_map_str_jv(caller, val)
                jv = _alloc_jv(caller, 5)  # JObj
                _write_i64(caller, jv + 8, map_ptr & 0xFFFFFFFF)
                return jv
            # Fallback: render as String.
            return _py_to_jv(caller, str(val))

        def _list_of_jv_to_py(caller, list_ptr: int) -> list:
            n = _read_u32(caller, list_ptr)
            data_ptr = _read_u32(caller, list_ptr + 8)
            out = []
            for i in range(n):
                # List<JsonValue> slot is i32 (sum types are
                # pointer-stored, size 4 in the Wasm layout).
                jv_ptr = _read_u32(caller, data_ptr + i * 4)
                out.append(_jv_to_py(caller, jv_ptr))
            return out

        def _map_str_jv_to_py(caller, map_ptr: int) -> dict:
            n = _read_u32(caller, map_ptr)
            data_ptr = _read_u32(caller, map_ptr + 8)
            out = {}
            for i in range(n):
                base = data_ptr + i * 16
                k_ptr = _read_u32(caller, base)
                k_len = _read_u32(caller, base + 4)
                key = _read_string(caller, k_ptr, k_len)
                slot = _read_i64(caller, base + 8)
                out[key] = _jv_to_py(caller, slot & 0xFFFFFFFF)
            return out

        def _jv_to_py(caller, jv_ptr: int):
            tag = _read_u32(caller, jv_ptr)
            if tag == 0:  # JNull
                return None
            if tag == 1:  # JBool
                return bool(_read_i64(caller, jv_ptr + 8))
            if tag == 2:  # JNum
                return _read_f64(caller, jv_ptr + 8)
            if tag == 3:  # JStr
                packed = _read_i64(caller, jv_ptr + 8)
                s_ptr = packed & 0xFFFFFFFF
                s_len = (packed >> 32) & 0xFFFFFFFF
                return _read_string(caller, s_ptr, s_len)
            if tag == 4:  # JArr
                inner = _read_i64(caller, jv_ptr + 8) & 0xFFFFFFFF
                return _list_of_jv_to_py(caller, inner)
            if tag == 5:  # JObj
                inner = _read_i64(caller, jv_ptr + 8) & 0xFFFFFFFF
                return _map_str_jv_to_py(caller, inner)
            raise RuntimeError(
                f"unknown JsonValue tag {tag} at ptr {jv_ptr}"
            )

        # ---- the two host functions ----

        def json_parse(caller, s_ptr, s_len, ret_area):
            """result<u32, string> indirect lowering. 12-byte area:
            tag @ 0, Ok-u32 @ 4, Err (msg_ptr, msg_len) @ 4 + 8."""
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "json.parse called before memory + $alloc set"
                )
            # Audit fix H3: invalid UTF-8 in the source bytes is the
            # same shape of guest-side bug as malformed JSON; route it
            # through the WIT result<u32, string> Err arm so the guest
            # sees the same observable failure mode (a parseable Err
            # message) it would for any other unparseable input,
            # instead of bubbling ``UnicodeDecodeError`` up through
            # wasmtime and crashing the store.
            try:
                text = _read_string(caller, s_ptr, s_len)
                py_val = _stdlib_json.loads(text)
                jv_ptr = _py_to_jv(caller, py_val)
                _write_u32(caller, ret_area, 0)            # tag Ok
                _write_u32(caller, ret_area + 4, jv_ptr)   # u32 handle
                _write_u32(caller, ret_area + 8, 0)        # pad
            except (
                ValueError, UnicodeDecodeError,
                _stdlib_json.JSONDecodeError,
            ) as e:
                err_ptr, err_len = _alloc_string(caller, str(e))
                _write_u32(caller, ret_area, 1)            # tag Err
                _write_u32(caller, ret_area + 4, err_ptr)
                _write_u32(caller, ret_area + 8, err_len)

        def json_to_string(caller, jv_ptr, ret_area):
            """string indirect lowering. 8-byte area: (ptr, len)."""
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "json.to_string called before memory + $alloc set"
                )
            py_val = _jv_to_py(caller, jv_ptr)
            text = _stdlib_json.dumps(py_val)
            ptr, length = _alloc_string(caller, text)
            _write_u32(caller, ret_area, ptr)
            _write_u32(caller, ret_area + 4, length)

        self.linker.define_func(
            "capa:host/json", "parse", ft_parse,
            json_parse, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/json", "to-string", ft_to_string,
            json_to_string, access_caller=True,
        )

    def instantiate(self, wasm_blob: bytes) -> wasmtime.Instance:
        """Load ``wasm_blob`` and instantiate it against the
        registered host imports. Caches the exported memory so
        subsequent host callbacks can resolve string pointers."""
        module = wasmtime.Module(self.engine, wasm_blob)
        instance = self.linker.instantiate(self.store, module)
        exports = instance.exports(self.store)
        if "memory" in exports:
            self._memory = exports["memory"]
        if "alloc" in exports:
            self._alloc_export = exports["alloc"]
        return instance

    def run_main(self, wasm_blob: bytes) -> None:
        """Instantiate and call the module's ``main`` export. The
        Capa source's ``fun main(stdio: Stdio)`` lowers to a Wasm
        export named ``main`` with no parameters (capability params
        are dropped); calling it kicks off the program."""
        instance = self.instantiate(wasm_blob)
        main = instance.exports(self.store)["main"]
        main(self.store)
