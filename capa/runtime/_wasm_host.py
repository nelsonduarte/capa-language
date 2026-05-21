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
        self._register_stdio()

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
            "capa:stdio", "print", ft_string_to_unit,
            stdio_print, access_caller=True,
        )
        self.linker.define_func(
            "capa:stdio", "println", ft_string_to_unit,
            stdio_println, access_caller=True,
        )
        self.linker.define_func(
            "capa:stdio", "eprintln", ft_string_to_unit,
            stdio_eprintln, access_caller=True,
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
        return instance

    def run_main(self, wasm_blob: bytes) -> None:
        """Instantiate and call the module's ``main`` export. The
        Capa source's ``fun main(stdio: Stdio)`` lowers to a Wasm
        export named ``main`` with no parameters (capability params
        are dropped); calling it kicks off the program."""
        instance = self.instantiate(wasm_blob)
        main = instance.exports(self.store)["main"]
        main(self.store)
