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
"""

from __future__ import annotations

import sys
from typing import Optional

import wasmtime


class WasmHost:
    """A wasmtime-based host that wires Capa's built-in capabilities
    into a compiled Wasm module."""

    def __init__(self) -> None:
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
        self._register_stdio()
        self._register_clock()
        self._register_env()
        self._register_fs()

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
        def stdio_print(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            sys.stdout.write(bytes(data).decode("utf-8"))
            sys.stdout.flush()

        def stdio_println(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            sys.stdout.write(bytes(data).decode("utf-8") + "\n")
            sys.stdout.flush()

        def stdio_eprintln(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            sys.stderr.write(bytes(data).decode("utf-8") + "\n")
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
            "capa:host/clock", "now_secs", ft_to_f64, now_secs,
        )
        self.linker.define_func(
            "capa:host/clock", "now_monotonic", ft_to_f64, now_monotonic,
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
        stays linear and traceable."""
        import os
        ft_string_to_optptr = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
            [wasmtime.ValType.i32()],
        )

        def env_get(caller, name_ptr, name_len):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "env.get called before instance memory + $alloc set"
                )
            # Read input string out of wasm memory.
            data = self._memory.read(caller, name_ptr, name_ptr + name_len)
            name = bytes(data).decode("utf-8")
            value = os.environ.get(name)
            # Allocate the 16-byte Option container.
            opt_ptr = self._alloc_export(caller, 16)
            if value is None:
                # tag=None (1) at offset 0
                self._memory.write(
                    caller, (1).to_bytes(4, "little"), opt_ptr,
                )
                return opt_ptr
            # tag=Some (0) + packed (str_ptr, str_len) at offset 8
            encoded = value.encode("utf-8")
            str_ptr = self._alloc_export(caller, len(encoded))
            self._memory.write(caller, encoded, str_ptr)
            self._memory.write(
                caller, (0).to_bytes(4, "little"), opt_ptr,
            )
            packed = (str_ptr & 0xFFFFFFFF) | (
                (len(encoded) & 0xFFFFFFFF) << 32
            )
            self._memory.write(
                caller, packed.to_bytes(8, "little"), opt_ptr + 8,
            )
            return opt_ptr

        self.linker.define_func(
            "capa:host/env", "get", ft_string_to_optptr,
            env_get, access_caller=True,
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
        ft_string_to_resultptr = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
            [wasmtime.ValType.i32()],
        )
        ft_path_content_to_resultptr = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(), wasmtime.ValType.i32(),
                wasmtime.ValType.i32(), wasmtime.ValType.i32(),
            ],
            [wasmtime.ValType.i32()],
        )

        def _alloc_string(caller, text: str) -> tuple[int, int]:
            """Helper: allocate UTF-8 bytes for ``text`` in wasm
            memory and return (ptr, len)."""
            encoded = text.encode("utf-8")
            ptr = self._alloc_export(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _alloc_ioerror(caller, message: str, cause: str = "") -> int:
            """Allocate an IoError struct (16 bytes: two String
            (ptr, len) pairs) and return its pointer. Matches
            ``_IOERROR_LAYOUT`` in the Wasm emitter."""
            m_ptr, m_len = _alloc_string(caller, message)
            c_ptr, c_len = _alloc_string(caller, cause)
            ioerror_ptr = self._alloc_export(caller, 16)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ioerror_ptr,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ioerror_ptr + 4,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ioerror_ptr + 8,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ioerror_ptr + 12,
            )
            return ioerror_ptr

        def _alloc_result_ok_string(caller, content: str) -> int:
            """Build Ok(String) Result and return its pointer."""
            ptr, length = _alloc_string(caller, content)
            packed = (ptr & 0xFFFFFFFF) | ((length & 0xFFFFFFFF) << 32)
            result_ptr = self._alloc_export(caller, 16)
            self._memory.write(
                caller, (0).to_bytes(4, "little"), result_ptr,
            )
            self._memory.write(
                caller, packed.to_bytes(8, "little"), result_ptr + 8,
            )
            return result_ptr

        def _alloc_result_err_ioerror(caller, message: str) -> int:
            """Build Err(IoError) Result and return its pointer.
            The IoError is i32-extended-to-i64 in the payload slot."""
            io_ptr = _alloc_ioerror(caller, message)
            result_ptr = self._alloc_export(caller, 16)
            self._memory.write(
                caller, (1).to_bytes(4, "little"), result_ptr,
            )
            self._memory.write(
                caller, io_ptr.to_bytes(8, "little"), result_ptr + 8,
            )
            return result_ptr

        def fs_read(caller, path_ptr, path_len):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.read called before memory + $alloc set"
                )
            path = bytes(
                self._memory.read(caller, path_ptr, path_ptr + path_len)
            ).decode("utf-8")
            try:
                content = open(path, encoding="utf-8").read()
                return _alloc_result_ok_string(caller, content)
            except OSError as e:
                return _alloc_result_err_ioerror(caller, str(e))

        def fs_write(caller, p_ptr, p_len, c_ptr, c_len):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.write called before memory + $alloc set"
                )
            path = bytes(
                self._memory.read(caller, p_ptr, p_ptr + p_len)
            ).decode("utf-8")
            content = bytes(
                self._memory.read(caller, c_ptr, c_ptr + c_len)
            ).decode("utf-8")
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                # Ok(Unit): tag=0, payload slot zero.
                result_ptr = self._alloc_export(caller, 16)
                self._memory.write(
                    caller, (0).to_bytes(4, "little"), result_ptr,
                )
                self._memory.write(
                    caller, (0).to_bytes(8, "little"), result_ptr + 8,
                )
                return result_ptr
            except OSError as e:
                return _alloc_result_err_ioerror(caller, str(e))

        self.linker.define_func(
            "capa:host/fs", "read", ft_string_to_resultptr,
            fs_read, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/fs", "write", ft_path_content_to_resultptr,
            fs_write, access_caller=True,
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
