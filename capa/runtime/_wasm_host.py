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

        # env.args() -> list<string>. Builds a List<String> in
        # linear memory: 16-byte header (len, cap, data_ptr, pad)
        # + N*8-byte data array of packed (ptr, len) i64s. The
        # WasmHost stashes argv at construction time so the
        # callback knows what to materialise.
        ft_to_listptr = wasmtime.FuncType([], [wasmtime.ValType.i32()])

        def env_args(caller):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "env.args called before memory + $alloc set"
                )
            n = len(self._args)
            # Allocate each string and pack its (ptr, len) i64.
            packed_values: list[int] = []
            for arg in self._args:
                encoded = arg.encode("utf-8")
                if encoded:
                    s_ptr = self._alloc_export(caller, len(encoded))
                    self._memory.write(caller, encoded, s_ptr)
                else:
                    # Empty string: a valid (0, 0) packing; pointer
                    # never read because length is zero.
                    s_ptr = 0
                packed = (s_ptr & 0xFFFFFFFF) | (
                    (len(encoded) & 0xFFFFFFFF) << 32
                )
                packed_values.append(packed)
            # Allocate the List header (16 bytes).
            header_ptr = self._alloc_export(caller, 16)
            # Allocate the data array. Use cap = max(n, 8) so a
            # downstream .push lands without an immediate grow,
            # matching the MakeList convention.
            cap = max(n, 8)
            data_ptr = (
                self._alloc_export(caller, cap * 8) if cap else 0
            )
            # Write header.
            self._memory.write(caller, n.to_bytes(4, "little"), header_ptr)
            self._memory.write(caller, cap.to_bytes(4, "little"), header_ptr + 4)
            self._memory.write(
                caller, data_ptr.to_bytes(4, "little"), header_ptr + 8,
            )
            # Write each packed element.
            for i, packed in enumerate(packed_values):
                self._memory.write(
                    caller, packed.to_bytes(8, "little"), data_ptr + i * 8,
                )
            return header_ptr

        self.linker.define_func(
            "capa:host/env", "args", ft_to_listptr,
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
            "capa:host/fs", "restrict_to", ft_string_to_unit,
            fs_restrict_to, access_caller=True,
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

        ft_parse = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
            [wasmtime.ValType.i32()],
        )
        ft_to_string = wasmtime.FuncType(
            [wasmtime.ValType.i32()],
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
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

        def json_parse(caller, s_ptr, s_len):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "json.parse called before memory + $alloc set"
                )
            try:
                text = _read_string(caller, s_ptr, s_len)
                py_val = _stdlib_json.loads(text)
                jv_ptr = _py_to_jv(caller, py_val)
                # Wrap in Ok(JsonValue): 16-byte Result with tag=0
                # and payload = jv_ptr extended to i64.
                result_ptr = self._alloc_export(caller, 16)
                _write_u32(caller, result_ptr, 0)
                _write_i64(caller, result_ptr + 8, jv_ptr & 0xFFFFFFFF)
                return result_ptr
            except (ValueError, _stdlib_json.JSONDecodeError) as e:
                err_ptr, err_len = _alloc_string(caller, str(e))
                packed = (err_ptr & 0xFFFFFFFF) | (
                    (err_len & 0xFFFFFFFF) << 32
                )
                result_ptr = self._alloc_export(caller, 16)
                _write_u32(caller, result_ptr, 1)  # Err
                _write_i64(caller, result_ptr + 8, packed)
                return result_ptr

        def json_to_string(caller, jv_ptr):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "json.to_string called before memory + $alloc set"
                )
            py_val = _jv_to_py(caller, jv_ptr)
            text = _stdlib_json.dumps(py_val)
            ptr, length = _alloc_string(caller, text)
            return (ptr, length)

        self.linker.define_func(
            "capa:host/json", "parse", ft_parse,
            json_parse, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/json", "to_string", ft_to_string,
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
